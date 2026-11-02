"""PHP Security engine: Snuffleupagus per PHP version.

Build:   phpize/configure/make of the pinned Snuffleupagus source with THAT version's
         php-config, installed into its own extension folder (never shared .so files).
Enable:  one ini file of our own in the version's conf.d (FPM only on Debian/Ubuntu,
         so command-line PHP, Composer and cron scripts are not affected there).
Rules:   one generated rules file for all versions; every change is checked by
         starting PHP with it and by php-fpm -t, and rolled back when either fails.
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

from panel import appkit
from vpapp_php_guard import rules as R

APP = 'php-guard'
SRC_REPO = 'https://github.com/jvoisin/snuffleupagus'
SRC_TAG = 'v0.11.0'
SRC_COMMIT = '0ba0c07bc7c9cba401e061ae86ee4adcf9655be9'    # verified after cloning
RULES_DIR = '/etc/vortexpanel/php-guard'
RULES_FILE = os.path.join(RULES_DIR, 'snuffleupagus.rules')
INI_NAME = '99-vortexpanel-php-guard.ini'
BUILD_UNIT = appkit.unit_name(APP, 'build')


def _php():
    from panel.routes import php as P
    return P


def settings():
    s = appkit.read_json(APP, 'settings.json', {})
    modes = dict(R.DEFAULT_MODES)
    modes.update({k: v for k, v in (s.get('modes') or {}).items() if k in modes and v in ('block', 'log', 'off')})
    trusted = [t for t in (s.get('trusted') or []) if isinstance(t, str) and t.startswith('/')][:200]
    return {'modes': modes, 'trusted': trusted}


def save_settings(s):
    appkit.write_json(APP, 'settings.json', s)


# ---------------------------------------------------------------- versions

def layouts():
    return _php().installed_php_layouts()


def tools(lay):
    """phpize, php-config and the dev package for one version."""
    v, vn = lay['ver'], lay['ver'].replace('.', '')
    if lay['flavor'] == 'debian':
        return f'/usr/bin/phpize{v}', f'/usr/bin/php-config{v}', [f'php{v}-dev']
    if lay['flavor'] == 'remi':
        root = f'/opt/remi/php{vn}/root/usr/bin'
        return f'{root}/phpize', f'{root}/php-config', [f'php{vn}-php-devel']
    return '/usr/bin/phpize', '/usr/bin/php-config', ['php-devel']


def ext_dir(lay):
    _, cfg, _ = tools(lay)
    if os.path.exists(cfg):
        rc, out, _ = appkit.run([cfg, '--extension-dir'], timeout=20)
        if rc == 0 and out.strip():
            return out.strip()
    rc, out, _ = appkit.run([lay['bin'], '-r', 'echo ini_get("extension_dir");'], timeout=20)
    return out.strip() if rc == 0 else ''


def ini_path(lay):
    v, vn = lay['ver'], lay['ver'].replace('.', '')
    if lay['flavor'] == 'debian':
        return f'/etc/php/{v}/fpm/conf.d/{INI_NAME}'
    if lay['flavor'] == 'remi':
        return f'/etc/opt/remi/php{vn}/php.d/{INI_NAME}'
    return f'/etc/php.d/{INI_NAME}'


def so_path(lay):
    d = ext_dir(lay)
    return os.path.join(d, 'snuffleupagus.so') if d else ''


def version_status(lay):
    so = so_path(lay)
    ini = ini_path(lay)
    loaded = 'snuffleupagus' in _php().php_loaded_modules(lay) if os.path.exists(ini) else False
    return {'ver': lay['ver'], 'flavor': lay['flavor'], 'built': bool(so and os.path.exists(so)),
            'enabled': os.path.exists(ini), 'loaded': loaded, 'svc': lay['svc'], 'svc_state': _php().php_svc_status(lay),
            'ini': ini, 'so': so}


def all_status():
    return [version_status(l) for l in layouts()]


# ------------------------------------------------------------------ build

def build_progress():
    return appkit.read_json(APP, 'build.json', {})


def build_running():
    return appkit.service_state(BUILD_UNIT) in ('active', 'activating')


def start_build(ver, enable=True):
    if build_running():
        return False, 'A build is already running.'
    lay = _php().php_layout(ver)
    if not lay:
        return False, f'PHP {ver} is not installed.'
    appkit.write_json(APP, 'build.json', {'ver': ver, 'state': 'running', 'lines': ['Starting...'], 't': int(time.time())})
    plugin_dir = os.path.join(appkit.PANEL_DIR, 'plugins', APP)
    argv = ['systemd-run', '--unit', BUILD_UNIT, '--collect', '--quiet', f'--working-directory={appkit.PANEL_DIR}',
            f'--setenv=PYTHONPATH={plugin_dir}:{appkit.PANEL_DIR}', appkit.venv_python(), '-m', 'vpapp_php_guard.engine',
            'build', ver] + (['--enable'] if enable else [])
    rc, out, err = appkit.run(argv, timeout=30)
    return rc == 0, (err or out).strip()[-300:]


def _source(log):
    """Pinned Snuffleupagus source, verified by its git commit id."""
    cache = os.path.join(appkit.data_dir(APP), 'src-' + SRC_TAG)
    if os.path.isdir(os.path.join(cache, 'src')):
        rc, out, _ = appkit.run(['git', '-C', cache, 'rev-parse', 'HEAD'], timeout=20)
        if rc == 0 and out.strip() == SRC_COMMIT:
            return cache
        shutil.rmtree(cache, ignore_errors=True)
    if not appkit.have('git'):
        appkit.pkg_install(['git'], log)
    log(f'Downloading Snuffleupagus {SRC_TAG}...')
    rc, _, err = appkit.run(['git', 'clone', '--depth', '1', '--branch', SRC_TAG, SRC_REPO, cache], timeout=600)
    if rc != 0:
        raise RuntimeError('download failed (github.com unreachable?): ' + err.strip()[-200:])
    rc, out, _ = appkit.run(['git', '-C', cache, 'rev-parse', 'HEAD'], timeout=20)
    if out.strip() != SRC_COMMIT:
        shutil.rmtree(cache, ignore_errors=True)
        raise RuntimeError(f'the downloaded source is not the expected release (commit {out.strip()[:12]}); refusing to build it')
    log(f'Source verified (commit {SRC_COMMIT[:12]}).')
    return cache


def build(ver, log):
    lay = _php().php_layout(ver)
    if not lay:
        raise RuntimeError(f'PHP {ver} is not installed')
    phpize, phpcfg, devpkgs = tools(lay)
    need = [] if (os.path.exists(phpize) and os.path.exists(phpcfg)) else devpkgs
    if not appkit.have('gcc') or not appkit.have('make'):
        need += ['build-essential'] if appkit.os_family() == 'debian' else ['gcc', 'make']
    if need:
        if not appkit.pkg_install(need, log):
            raise RuntimeError('could not install the build tools: ' + ' '.join(need))
    if not (os.path.exists(phpize) and os.path.exists(phpcfg)):
        raise RuntimeError(f'{phpize} is missing after installing {" ".join(devpkgs)}')
    src = _source(log)
    work = tempfile.mkdtemp(prefix='vp-snuff-')
    try:
        shutil.copytree(os.path.join(src, 'src'), os.path.join(work, 'src'), ignore=shutil.ignore_patterns('tests'))
        d = os.path.join(work, 'src')
        for step, argv, t in (('phpize', [phpize], 180),
                              ('configure', ['./configure', '--enable-snuffleupagus', f'--with-php-config={phpcfg}'], 300),
                              ('make', ['make', f'-j{max(1, os.cpu_count() or 1)}'], 1200),
                              ('install', ['make', 'install'], 120)):
            log(f'{step}...')
            r = subprocess.run(argv, cwd=d, capture_output=True, text=True, timeout=t)
            if r.returncode != 0:
                raise RuntimeError(f'{step} failed: ' + (r.stderr or r.stdout).strip()[-600:])
    finally:
        shutil.rmtree(work, ignore_errors=True)
    so = so_path(lay)
    if not so or not os.path.exists(so):
        raise RuntimeError('the module was not installed into the PHP extension folder')
    log(f'Built {so}')
    return so


# ------------------------------------------------------------------ rules

def write_rules(text):
    os.makedirs(RULES_DIR, mode=0o755, exist_ok=True)
    tmp = RULES_FILE + '.tmp'
    with open(tmp, 'w') as f:
        f.write(text)
    os.chmod(tmp, 0o644)       # PHP workers (www-data, hosting users) must read it
    os.replace(tmp, RULES_FILE)


def check_rules(lay, rules_file):
    """Start this PHP with the module and these rules. (ok, output)."""
    so = so_path(lay)
    if not so or not os.path.exists(so):
        return True, ''
    rc, out, err = appkit.run([lay['bin'], '-n', '-d', f'extension={so}', '-d', f'sp.configuration_file={rules_file}',
                               '-r', 'echo "VP-PHP-OK";'], timeout=30)
    text = (out + err)
    bad = 'VP-PHP-OK' not in text or re.search(r'\[snuffleupagus\]\[[^\]]*\]\[config\]', text)
    return (not bad), text.strip()[-600:]


def apply_rules(s=None):
    """Write the rules from the settings, test on every enabled version, reload; restore on failure."""
    s = s or settings()
    text = R.build(s['modes'], s['trusted'])
    old = open(RULES_FILE).read() if os.path.exists(RULES_FILE) else None
    os.makedirs(RULES_DIR, mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=RULES_DIR, suffix='.test')
    with os.fdopen(fd, 'w') as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    try:
        for lay in layouts():
            if os.path.exists(ini_path(lay)):
                ok, out = check_rules(lay, tmp)
                if not ok:
                    return False, f'PHP {lay["ver"]} rejected the rules (nothing was changed): {out}'
    finally:
        os.remove(tmp)
    write_rules(text)
    P = _php()
    for lay in layouts():
        if not os.path.exists(ini_path(lay)):
            continue
        ok, out = P.php_fpm_test(lay)
        if ok:
            ok, out = P.php_reload(lay)
        if not ok:
            if old is None:
                os.remove(RULES_FILE)
            else:
                write_rules(old)
            P.php_reload(lay)
            return False, f'PHP {lay["ver"]} did not reload with the new rules; the previous rules were restored: {out}'
    return True, ''


def enable(ver, log=print):
    P = _php()
    lay = P.php_layout(ver)
    if not lay:
        return False, f'PHP {ver} is not installed'
    so = so_path(lay)
    if not so or not os.path.exists(so):
        return False, 'The module is not built for this version yet'
    if not os.path.exists(RULES_FILE):
        write_rules(R.build(settings()['modes'], settings()['trusted']))
    ok, out = check_rules(lay, RULES_FILE)
    if not ok:
        return False, f'PHP {ver} does not start with the module: {out}'
    ini = ini_path(lay)
    os.makedirs(os.path.dirname(ini), exist_ok=True)
    with open(ini, 'w') as f:
        f.write('; Managed by VortexPanel PHP Security (App). Remove it from the panel, not by hand.\n'
                f'extension={so}\nsp.configuration_file={RULES_FILE}\n')
    ok, out = P.php_fpm_test(lay)
    if ok:
        ok, out = P.php_reload(lay)
    if not ok:
        os.remove(ini)
        P.php_reload(lay)
        return False, f'PHP-FPM {ver} did not accept the module (removed again): {out}'
    log(f'PHP {ver}: protection on')
    return True, ''


def disable(ver):
    P = _php()
    lay = P.php_layout(ver)
    if not lay:
        return False, f'PHP {ver} is not installed'
    ini = ini_path(lay)
    if os.path.exists(ini):
        os.remove(ini)
    ok, out = P.php_reload(lay)
    return ok, out


def disable_all():
    for lay in layouts():
        if os.path.exists(ini_path(lay)):
            disable(lay['ver'])


# ----------------------------------------------------------------- events

def read_events(limit=3000):
    """Newest first. Snuffleupagus logs to syslog (auth facility, tag 'snuffleupagus')."""
    lines = []
    rc, out, _ = appkit.run(['journalctl', '--no-pager', '-o', 'json', '-t', 'snuffleupagus', '-n', str(limit)], timeout=30)
    if rc == 0 and out.strip():
        for ln in out.splitlines():
            try:
                j = json.loads(ln)
            except ValueError:
                continue
            msg = j.get('MESSAGE')
            if isinstance(msg, list):
                msg = bytes(msg).decode('utf-8', 'replace')
            t = int(int(j.get('__REALTIME_TIMESTAMP', '0')) / 1_000_000)
            lines.append((t, msg or ''))
    else:
        for p in ('/var/log/auth.log', '/var/log/secure', '/var/log/syslog', '/var/log/messages'):
            if not os.path.isfile(p):
                continue
            with open(p, 'rb') as f:
                f.seek(0, 2)
                f.seek(max(0, f.tell() - 8 * 1024 * 1024))
                for raw in f.read().decode('utf-8', 'replace').splitlines():
                    if '[snuffleupagus]' in raw:
                        lines.append((_syslog_ts(raw), raw))
            break
    out = []
    for t, msg in lines:
        ev = R.parse_line(msg)
        if ev:
            ev['t'] = t
            out.append(ev)
    out.sort(key=lambda e: -e['t'])
    return out[:limit]


def _syslog_ts(line):
    m = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
    if m:
        return int(time.mktime(time.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S')))
    m = re.match(r'^(\w{3})\s+(\d+) (\d{2}:\d{2}:\d{2})', line)
    if m:
        try:
            return int(time.mktime(time.strptime(f'{time.localtime().tm_year} {m.group(1)} {m.group(2)} {m.group(3)}',
                                                 '%Y %b %d %H:%M:%S')))
        except ValueError:
            return 0
    return 0


# -------------------------------------------------------------------- CLI

def _cli_build(ver, enable_after):
    st = {'ver': ver, 'state': 'running', 'lines': [], 't': int(time.time())}

    def log(msg):
        print(msg, flush=True)
        st['lines'] = (st['lines'] + [str(msg)])[-200:]
        appkit.write_json(APP, 'build.json', st)
    try:
        build(ver, log)
        if enable_after:
            ok, err = enable(ver, log)
            if not ok:
                raise RuntimeError(err)
        st.update(state='done', message=f'PHP {ver}: module built' + (' and protection turned on.' if enable_after else '.'))
        appkit.oplog(APP, 'build', st['message'], user='admin')
    except Exception as e:  # noqa: BLE001
        st.update(state='failed', message=f'PHP {ver}: {e}')
        appkit.oplog(APP, 'build failed', st['message'], user='admin')
    log(st['message'])
    appkit.write_json(APP, 'build.json', st)
    return 0 if st['state'] == 'done' else 1


if __name__ == '__main__':
    if len(sys.argv) >= 3 and sys.argv[1] == 'build' and re.fullmatch(r'\d\.\d', sys.argv[2]):
        sys.exit(_cli_build(sys.argv[2], '--enable' in sys.argv))
    print('usage: python -m vpapp_php_guard.engine build <php version> [--enable]')
    sys.exit(2)
