"""PHP2Shell (CVE-2026-109618, CVE-2026-109619; November 2026): unauthenticated remote code
execution in the PHP runtime itself, under mod_php, PHP-FPM, php-cgi and LiteSpeed.

  status()   every PHP on this server (VortexPanel builds, operating system packages,
             Remi, LiteSpeed lsphp) with its version and whether it carries the fix
  protect()  the setting PHP recommends while patching and keeps recommending after it
             (CVE-2026-115560 is not fixed yet): session.upload_progress.enabled = Off,
             set where websites cannot switch it back on:
               - a drop-in .ini in each PHP binary's own scan folder
               - php_admin_flag in every PHP-FPM pool (also Hosting Module accounts),
                 because a .user.ini can change the plain setting under PHP-FPM
               - php_admin_flag for Apache mod_php, when Apache loads it
  unprotect() takes all of it out again

Settings: data/php2shell.json {"enabled": true}. Upload progress bars (rarely used)
stop working while the protection is on.
"""
import glob
import json
import os
import re
import subprocess
import time

PANEL_DIR = os.environ.get('VP_INSTALL_DIR', '/opt/vortexpanel')
CONF = os.path.join(PANEL_DIR, 'data', 'php2shell.json')
FIXED = {'8.5': (8, 5, 12), '8.4': (8, 4, 27), '8.3': (8, 3, 36), '8.2': (8, 2, 35)}
DROPIN = '00-vortexpanel-php2shell.ini'
DROPIN_TEXT = ('; VortexPanel: PHP2Shell protection (CVE-2026-109618/109619, CVE-2026-115560).\n'
               '; Managed from the PHP page; remove it there.\n'
               'session.upload_progress.enabled = Off\n')
POOL_LINE = 'php_admin_flag[session.upload_progress.enabled] = off'
POOL_MARK = '; VortexPanel: PHP2Shell protection'
APACHE_CONF = {'deb': '/etc/apache2/conf-available/vortexpanel-php2shell.conf',
               'rpm': '/etc/httpd/conf.d/vortexpanel-php2shell.conf'}
APACHE_TEXT = ('# VortexPanel: PHP2Shell protection for mod_php (CVE-2026-109618/109619, CVE-2026-115560)\n'
               '<IfModule php_module>\n    php_admin_flag session.upload_progress.enabled off\n</IfModule>\n'
               '<IfModule php7_module>\n    php_admin_flag session.upload_progress.enabled off\n</IfModule>\n')


def _run(argv, t=60):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=t, errors='replace')
        return r.returncode, (r.stdout or '') + (r.stderr or '')
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


def settings():
    try:
        with open(CONF) as f:
            s = json.load(f)
    except (OSError, ValueError):
        s = {}
    return {'enabled': s.get('enabled', True) is not False, 't': s.get('t', 0), 'applied': s.get('applied', [])}


def _save(s):
    os.makedirs(os.path.dirname(CONF), exist_ok=True)
    tmp = CONF + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(s, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONF)


# ------------------------------------------------------------------- inventory

def _vt(v):
    return tuple(int(x) for x in re.findall(r'\d+', v)[:3])


def _binaries():
    """[(label, kind, binary, layout or None)] of every PHP on this server."""
    out = []
    try:
        from panel.routes.php import installed_php_layouts
        lays = installed_php_layouts()
    except Exception:  # noqa: BLE001
        lays = []
    for lay in lays:
        for kind, key in (('fpm', 'fpm_bin'), ('cli', 'bin')):
            b = lay.get(key)
            if b and os.path.exists(b):
                out.append((f'PHP {lay["ver"]}', kind, b, lay))
    for b in sorted(glob.glob('/usr/local/lsws/lsphp*/bin/lsphp')):
        out.append((f'LiteSpeed {os.path.basename(os.path.dirname(os.path.dirname(b)))}', 'lsphp', b, None))
    return out


def _version(b):
    rc, out = _run([b, '-n', '-v'], 20)          # "PHP 8.5.12 (cli)", "PHP 8.1.2-1ubuntu2.28 (fpm-fcgi)"
    m = re.search(r'PHP (\d+\.\d+\.\d+[^\s]*)', out)
    return m.group(1) if m else ''


def _verdict(ver, flavor):
    """('fixed' | 'vulnerable' | 'nofix' | 'check', explanation)."""
    if not ver:
        return 'check', 'the version could not be read'
    base = _vt(ver)
    branch = f'{base[0]}.{base[1]}' if len(base) >= 2 else ''
    distro = '-' in ver or '+' in ver or flavor in ('debian', 'rhel')
    fixed = FIXED.get(branch)
    if fixed and base >= fixed:
        return 'fixed', f'{ver} carries the fix ({".".join(map(str, fixed))} or newer)'
    if not fixed and base < (8, 2):
        if distro:
            return 'check', (f'PHP {branch} has no official fix; your distribution may have backported it. '
                             'Install the operating system updates and check its security notice.')
        return 'nofix', (f'PHP {branch} has no official fix. Move the websites to PHP 8.2 or newer; '
                         'the protection setting below reduces the risk meanwhile.')
    if distro:
        return 'check', (f'{ver} is an operating system package: distributions backport the fix under their '
                         'own version numbers. Install the operating system updates.')
    return 'vulnerable', f'{ver} is affected; {".".join(map(str, fixed))} has the fix'


def _package_version(lay):
    """The operating system package version (what distribution security notices name)."""
    b = os.path.realpath(lay.get('fpm_bin') or lay.get('bin') or '')
    if not b:
        return ''
    if os.path.exists('/usr/bin/dpkg-query'):
        rc, out = _run(['dpkg-query', '-S', b], 20)
        pk = out.split(':')[0].strip() if rc == 0 else ''
        if pk:
            rc, v = _run(['dpkg-query', '-W', '-f=${Version}', pk], 20)
            return f'{pk} {v.strip()}' if rc == 0 else ''
    elif os.path.exists('/usr/bin/rpm'):
        rc, out = _run(['rpm', '-qf', '--qf', '%{NAME} %{VERSION}-%{RELEASE}', b], 20)
        return out.strip() if rc == 0 else ''
    return ''


def status():
    seen, rows = set(), []
    for label, kind, b, lay in _binaries():
        if kind == 'cli' and label in seen:
            continue                       # one row per PHP version (FPM and CLI are one install)
        seen.add(label)
        ver = _version(b)
        flavor = (lay or {}).get('flavor', 'lsphp')
        verdict, why = _verdict(ver, flavor)
        pkg = _package_version(lay) if flavor in ('debian', 'remi', 'rhel') else ''
        if pkg:
            why += f' Installed package: {pkg}.'
        if flavor == 'vortex' and verdict == 'vulnerable':
            why += ': update it in the App Store.'
        rows.append({'name': label, 'kind': kind, 'version': ver, 'flavor': flavor, 'status': verdict,
                     'detail': why})
    s = settings()
    return {'versions': rows, 'enabled': s['enabled'], 'applied': s['applied'], 't': s['t'],
            'mod_php': _mod_php() != '',
            'worst': ('vulnerable' if any(r['status'] in ('vulnerable', 'nofix') for r in rows)
                      else 'check' if any(r['status'] == 'check' for r in rows) else 'fixed')}


# ------------------------------------------------------------------ protection

def _scan_dir(b, kind):
    """The folder this PHP binary reads additional .ini files from."""
    rc, out = _run([b, '-i'], 30)
    m = re.search(r'Scan this dir for additional \.ini files\s*=>\s*(\S+)', out)
    d = m.group(1) if m else ''
    return d if d and d != '(none)' and os.path.isdir(d) else ''


def _pool_files():
    files = set()
    try:
        from panel.routes.php import installed_php_layouts
        for lay in installed_php_layouts():
            pd = lay.get('pool_dir')
            if pd:
                files.update(glob.glob(os.path.join(pd, '*.conf')))
    except Exception:  # noqa: BLE001
        pass
    # Hosting Module accounts: their own PHP-FPM services name their configuration
    for unit in glob.glob('/etc/systemd/system/vph-php*-*.service'):
        try:
            text = open(unit).read()
        except OSError:
            continue
        for cfg in re.findall(r'(?:--fpm-config|-y)[ =](\S+)', text):
            if os.path.isfile(cfg):
                files.add(cfg)
                try:
                    inc = re.findall(r'^\s*include\s*=\s*(\S+)', open(cfg).read(), re.M)
                except OSError:
                    inc = []
                for pat in inc:
                    files.update(glob.glob(pat))
    return sorted(f for f in files if os.path.isfile(f))


def _pool_add(text):
    """Add the admin flag to every pool section that does not set it."""
    lines = text.splitlines(keepends=True)
    out, changed = [], False
    i = 0
    while i < len(lines):
        out.append(lines[i])
        m = re.match(r'^\s*\[([^\]]+)\]\s*$', lines[i])
        if m and m.group(1).strip().lower() != 'global':
            j = i + 1
            has = False
            while j < len(lines) and not re.match(r'^\s*\[[^\]]+\]\s*$', lines[j]):
                if re.match(r'^\s*php_admin_(flag|value)\[session\.upload_progress\.enabled\]', lines[j]):
                    has = True
                j += 1
            if not has:
                out.append(f'{POOL_MARK}\n{POOL_LINE}\n')
                changed = True
        i += 1
    return ''.join(out), changed


def _pool_remove(text):
    new = re.sub(r'^' + re.escape(POOL_MARK) + r'\n' + re.escape(POOL_LINE) + r'\n', '', text, flags=re.M)
    return new, new != text


def _write_keep_mode(p, text):
    st = os.stat(p)
    with open(p, 'w') as f:
        f.write(text)
    os.chmod(p, st.st_mode & 0o7777)


def _mod_php():
    """'deb' or 'rpm' when Apache from the system loads mod_php, else ''."""
    for fam, pat in (('deb', '/etc/apache2/mods-enabled/php*.load'), ('rpm', '/etc/httpd/conf.modules.d/*php*.conf')):
        for f in glob.glob(pat):
            try:
                if re.search(r'^\s*LoadModule\s+php\d*_module', open(f).read(), re.M):
                    return fam
            except OSError:
                continue
    return ''


def _reload(log):
    """Test and reload what was changed: PHP-FPM of each version (and Hosting Module
    accounts), Apache when mod_php is used, LiteSpeed for lsphp."""
    msgs = []
    try:
        from panel.routes.php import installed_php_layouts, php_fpm_test, php_reload
        for lay in installed_php_layouts():
            ok, out = php_fpm_test(lay)
            if not ok:
                msgs.append(f'PHP {lay["ver"]}: the FPM test failed, not reloaded: {out.strip()[-300:]}')
                continue
            ok, m = php_reload(lay)
            if not ok:
                msgs.append(m)
    except Exception as e:  # noqa: BLE001
        msgs.append(f'PHP-FPM reload: {e}')
    fam = _mod_php()
    if fam:
        ctl = 'apache2ctl' if fam == 'deb' else 'apachectl'
        rc, out = _run([ctl, 'configtest'], 60)
        if rc == 0:
            _run(['systemctl', 'reload', 'apache2' if fam == 'deb' else 'httpd'], 90)
        else:
            msgs.append(f'Apache configuration test failed, not reloaded: {out.strip()[-300:]}')
    if glob.glob('/usr/local/lsws/lsphp*/bin/lsphp') and os.path.exists('/usr/local/lsws/bin/lswsctrl'):
        _run(['/usr/local/lsws/bin/lswsctrl', 'restart'], 120)     # graceful: lsphp workers start again
    for m in msgs:
        log(m)
    return msgs


def protect(log=print):
    """Apply the protection everywhere. Returns the list of files changed."""
    changed = []
    for label, kind, b, lay in _binaries():
        d = _scan_dir(b, kind)
        if not d:
            log(f'{label} ({kind}): no folder for additional settings; the pool setting still applies')
            continue
        p = os.path.join(d, DROPIN)
        try:
            cur = open(p).read()
        except OSError:
            cur = None
        if cur != DROPIN_TEXT:
            with open(p, 'w') as f:
                f.write(DROPIN_TEXT)
            os.chmod(p, 0o644)
            changed.append(p)
    for p in _pool_files():
        try:
            text = open(p).read()
        except OSError:
            continue
        new, ch = _pool_add(text)
        if ch:
            _write_keep_mode(p, new)
            changed.append(p)
    fam = _mod_php()
    if fam:
        p = APACHE_CONF[fam]
        if not os.path.exists(p):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, 'w') as f:
                f.write(APACHE_TEXT)
            os.chmod(p, 0o644)
            if fam == 'deb':
                _run(['a2enconf', '-q', os.path.basename(p)[:-5]], 30)
            changed.append(p)
    msgs = _reload(log) if changed else []
    s = settings()
    s.update(enabled=True, t=int(time.time()), applied=sorted(set(s['applied']) | set(changed)))
    _save(s)
    for p in changed:
        log(f'PHP2Shell protection: {p}')
    return changed, msgs


def unprotect(log=print):
    changed = []
    for label, kind, b, lay in _binaries():
        d = _scan_dir(b, kind)
        p = os.path.join(d, DROPIN) if d else ''
        if p and os.path.exists(p):
            os.remove(p)
            changed.append(p)
    for p in _pool_files():
        try:
            text = open(p).read()
        except OSError:
            continue
        new, ch = _pool_remove(text)
        if ch:
            _write_keep_mode(p, new)
            changed.append(p)
    for fam, p in APACHE_CONF.items():
        if os.path.exists(p):
            if fam == 'deb':
                _run(['a2disconf', '-q', os.path.basename(p)[:-5]], 30)
            os.remove(p)
            changed.append(p)
    msgs = _reload(log) if changed else []
    _save({'enabled': False, 't': int(time.time()), 'applied': []})
    return changed, msgs


def protect_if_enabled(log=print):
    """After PHP is installed or updated, and once after the panel update."""
    if settings()['enabled']:
        return protect(log)
    return [], []


if __name__ == '__main__':
    import sys
    if sys.argv[1:] == ['protect']:
        print(protect())
    elif sys.argv[1:] == ['unprotect']:
        print(unprotect())
    else:
        print(json.dumps(status(), indent=1))
