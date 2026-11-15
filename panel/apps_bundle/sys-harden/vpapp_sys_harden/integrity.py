"""Integrity check: compares what is installed with references an attacker cannot
simply re-baseline.

  panel     VortexPanel's own files against the signed release tag (git blob
            hashes, the tag signature checked with the panel's signing keys), and
            every compiled __pycache__/*.pyc against its verified source
  apps      installed Apps (plugins/<id>) against the copy shipped in the signed
            release, or the package published on the download server
  venv      the panel's Python packages against their pip RECORD hashes
  builds    VortexPanel software builds (/usr/local/vortex/<app>/<version>)
            against the package on the download server (signed catalog)
  packages  security-relevant OS packages, and the package of every running
            program, against the package manager's checksums
  backdoors known backdoor traces: CWPdoor (Control Web Panel), Ebury, forced
            library preloading in running programs
  webservers Apache, nginx, OpenLiteSpeed and Caddy behind a security fix (VortexPanel
            builds: the signed catalog and a minimum-version table; operating system
            packages: pending security updates), and known flaws without a fix
  php2shell PHP versions without the PHP2Shell fix (CVE-2026-109618/109619) and the
            published traces of the attack: log patterns, markers, dropped files,
            SSH keys of the web user, a hidden sshd in web server log folders

Results go to integrity.json; new problems become events and alerts.
"""
import base64
import glob
import hashlib
import importlib.util
import json
import marshal
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

from panel import appkit

APP = 'sys-harden'
PANEL_DIR = os.environ.get('VP_INSTALL_DIR', '/opt/vortexpanel')
CODE_ITEMS = ['panel', 'web', 'app.py', 'requirements.txt', 'install.sh', 'VERSION']
SOFT_BASE = os.environ.get('VP_SOFT_BASE', '/usr/local/vortex')
REF_MAX_AGE = 30 * 86400          # download-server references are fetched again after 30 days
REF_FMT = 2                       # 2: hard links in a package are counted (1.1.0 missed them)
SECTIONS = [
    ('panel', 'VortexPanel files', 'The panel code compared with the signed release it was installed from.'),
    ('apps', 'Installed Apps', 'App code compared with the signed release or the published package.'),
    ('venv', 'Panel Python packages', 'The libraries the panel runs on, compared with their install records.'),
    ('builds', 'VortexPanel software builds', 'Web server, PHP, database and other builds compared with the download server.'),
    ('packages', 'System packages', 'SSH, sudo, PAM, core tools and every running program compared with the package manager.'),
    ('backdoors', 'Known backdoors', 'Traces of CWPdoor (Control Web Panel), Ebury and forced library preloading.'),
    ('php2shell', 'PHP2Shell', 'PHP versions without the PHP2Shell fix, and traces of the attack (October 2026 onwards).'),
    ('webservers', 'Web servers', 'Apache, nginx, OpenLiteSpeed and Caddy versions without the latest security fixes, and known flaws that have no fix yet.'),
]

DEB_CORE = ['openssh-server', 'openssh-client', 'openssh-sftp-server', 'sudo', 'passwd', 'login', 'util-linux',
            'coreutils', 'procps', 'iproute2', 'net-tools', 'findutils', 'grep', 'sed', 'bash', 'dash', 'systemd',
            'libpam-modules', 'libpam-modules-bin', 'libpam-runtime', 'libpam0g', 'libkeyutils1', 'libc-bin', 'libc6',
            'cron', 'cronie', 'openssl', 'libssl3', 'libssl3t64', 'curl', 'wget', 'tar', 'gzip', 'psmisc', 'lsof',
            'iptables', 'nftables', 'libaudit1', 'libselinux1', 'kmod', 'mount', 'libcrypt1', 'libsystemd0', 'git']
RPM_CORE = ['openssh-server', 'openssh-clients', 'sudo', 'shadow-utils', 'passwd', 'util-linux', 'util-linux-core',
            'coreutils', 'procps-ng', 'iproute', 'net-tools', 'findutils', 'grep', 'sed', 'bash', 'systemd', 'pam',
            'keyutils-libs', 'glibc', 'cronie', 'openssl', 'openssl-libs', 'curl', 'wget', 'tar', 'gzip', 'psmisc',
            'lsof', 'iptables', 'nftables', 'audit-libs', 'libselinux', 'kmod', 'libxcrypt', 'systemd-libs', 'git']
# files a package may legitimately leave out (minimal images, path-exclude) or that the system rewrites
_SKIP_MISSING = re.compile(r'^/usr/share/(doc|man|info|locale|lintian|bug|help)/')
EBURY_FILES = ('libns2.so', 'libns5.so', 'libpw3.so', 'libpw5.so', 'libsbr.so', 'libslr.so')
LIB_DIRS = ('/lib', '/lib64', '/usr/lib', '/usr/lib64', '/lib/x86_64-linux-gnu', '/lib/aarch64-linux-gnu',
            '/usr/lib/x86_64-linux-gnu', '/usr/lib/aarch64-linux-gnu')
CWPDOOR_MARKER = b'X-Ngx-Integrity'


# ------------------------------------------------------------------ helpers

def _sh(argv, timeout=300, input_=None):
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout, input=input_)
        return r.returncode, r.stdout.decode(errors='replace'), r.stderr.decode(errors='replace')
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, '', str(e)


def _have(cmd):
    return shutil.which(cmd) is not None


def _sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def _git_blob(path):
    h = hashlib.sha1()
    h.update(b'blob %d\0' % os.path.getsize(path))
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def _item(severity, path, detail, fix=''):
    return {'severity': severity, 'path': str(path)[:400], 'detail': str(detail)[:400], 'fix': fix}


def _section(sid, status, summary, items=(), **extra):
    label, desc = next((l, d) for s, l, d in SECTIONS if s == sid)
    return dict({'id': sid, 'label': label, 'desc': desc, 'status': status, 'summary': summary,
                 'items': list(items)[:300], 'count': len(items)}, **extra)


def _family():
    if _have('dpkg-query'):
        return 'deb'
    if _have('rpm'):
        return 'rpm'
    return ''


# ------------------------------------------------------------- compiled code

def check_pyc(src, pyc):
    """'' when pyc is what compiling src gives (or Python would not load it), else the reason.
    A planted .pyc next to a clean .py is how a backdoor survives a source check."""
    try:
        data = open(pyc, 'rb').read()
    except OSError:
        return ''
    if data[:4] != importlib.util.MAGIC_NUMBER:
        return ''                       # another Python version: never loaded by this interpreter
    flags = int.from_bytes(data[4:8], 'little')
    m = re.search(r'\.opt-([12])\.pyc$', pyc)
    try:
        code = marshal.loads(data[16:])
        fname = getattr(code, 'co_filename', '') or src
        source = open(src, 'rb').read()
        want = compile(source, fname, 'exec', dont_inherit=True, optimize=int(m.group(1)) if m else 0)
    except Exception as e:  # noqa: BLE001
        return f'the compiled file cannot be read ({type(e).__name__})'
    if want == code:          # same instructions, constants, names and line table (byte layout may differ)
        return ''
    if not flags & 1:
        st = os.stat(src)
        if int.from_bytes(data[8:12], 'little') != (int(st.st_mtime) & 0xFFFFFFFF) or \
                int.from_bytes(data[12:16], 'little') != (st.st_size & 0xFFFFFFFF):
            return ''                   # stale: Python recompiles it from the source
    elif flags & 2 and data[8:16] != importlib.util.source_hash(source):
        return ''                       # checked hash that no longer matches: recompiled
    return 'compiled code does not match its source file'


# ------------------------------------------------------------------- panel

def _panel_tag():
    from panel import updater
    ver = updater.current_version()
    rd = updater.repo_dir()
    return ver, rd


def panel_reference():
    """(tag, repo, {path: (mode, blob)}, signed, note) of the installed release; raises ValueError."""
    from panel import updater
    tag, rd = _panel_tag()
    if not os.path.isdir(rd):
        raise ValueError('The release repository is not on this server, so the files cannot be compared. '
                         'Run Settings > Update once to fetch it.')
    rc, typ, _ = _sh(['git', '-C', rd, 'cat-file', '-t', f'refs/tags/{tag}'], 60)
    if rc != 0:
        raise ValueError(f'The release {tag} is not in {rd}. Run Settings > Update once to fetch it.')
    signed, note = updater.verify_tag(rd, tag)
    rc, out, err = _sh(['git', '-C', rd, 'ls-tree', '-r', '-z', '--full-tree', f'{tag}^{{commit}}', '--'] + CODE_ITEMS, 120)
    if rc != 0:
        raise ValueError(f'git could not read {tag}: {err.strip()[:200]}')
    tree = {}
    for rec in out.split('\0'):
        if not rec.strip():
            continue
        meta, path = rec.split('\t', 1)
        mode, typ, blob = meta.split()
        if typ == 'blob':
            tree[path] = (mode, blob)
    return tag, rd, tree, signed, note


def _panel_extra(tree):
    """Code files in panel/ and web/ that the release does not contain."""
    out = []
    for top in ('panel', 'web'):
        root = os.path.join(PANEL_DIR, top)
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d != '__pycache__' and not os.path.islink(os.path.join(dp, d))]
            rel_dir = os.path.relpath(dp, PANEL_DIR)
            for fn in fns:
                rel = os.path.join(rel_dir, fn)
                if rel in tree:
                    continue
                if fn.endswith(('.py', '.so', '.pth', '.js', '.html', '.sh')):
                    out.append(rel)
    return out


def check_panel():
    try:
        tag, rd, tree, signed, note = panel_reference()
    except ValueError as e:
        return _section('panel', 'unknown', str(e))
    items = []
    for rel, (mode, blob) in sorted(tree.items()):
        p = os.path.join(PANEL_DIR, rel)
        if mode == '120000':
            continue
        if not os.path.isfile(p) or os.path.islink(p):
            if rel.startswith(('panel/', 'web/', 'app.py')):
                items.append(_item('medium', rel, 'missing (it is part of the release)', 'restore'))
            continue
        if _git_blob(p) != blob:
            items.append(_item('critical', rel, f'differs from the signed release {tag}', 'restore'))
    for rel in _panel_extra(tree):
        # a file an older release shipped and a file-by-file upgrade left behind is in the
        # repository history with exactly this content; planted code never is
        rc, _, _ = _sh(['git', '-C', rd, 'cat-file', '-e', _git_blob(os.path.join(PANEL_DIR, rel))], 30)
        if rc == 0:
            items.append(_item('low', rel, f'left over from an older release (not used by {tag}; safe to remove)', 'remove'))
        else:
            sev = 'high' if rel.endswith(('.py', '.so', '.pth')) else 'medium'
            items.append(_item(sev, rel, f'not part of the release {tag} or any earlier release', 'remove'))
    pyc_bad = 0
    for rel in tree:
        if not rel.endswith('.py'):
            continue
        src = os.path.join(PANEL_DIR, rel)
        for pyc in glob.glob(os.path.join(os.path.dirname(src), '__pycache__', os.path.basename(rel)[:-3] + '.*.pyc')):
            why = check_pyc(src, pyc)
            if why:
                pyc_bad += 1
                items.append(_item('critical', os.path.relpath(pyc, PANEL_DIR), why, 'remove'))
    if not signed:
        items.insert(0, _item('high', f'release {tag}', f'the release signature could not be verified: {note}'))
    status = 'bad' if any(i['severity'] in ('critical', 'high') for i in items) else ('warn' if items else 'ok')
    summary = (f'{len(tree)} files match the signed release {tag}.' if not items
               else f'{len(items)} difference(s) from the release {tag}.')
    return _section('panel', status, summary, items, tag=tag)


def repair_panel(paths):
    """Put release files back from the signed tag, delete foreign code and bad compiled files.
    Returns (fixed, errors). The panel must be restarted afterwards."""
    tag, rd, tree, signed, note = panel_reference()
    if not signed:
        raise ValueError(f'The release {tag} is not signed by a trusted key; nothing was restored.')
    fixed, errors = [], []
    for rel in paths:
        rel = os.path.normpath(str(rel))
        if rel.startswith(('/', '..')) or not rel.split('/')[0] in ('panel', 'web', 'app.py', 'requirements.txt',
                                                                     'install.sh', 'VERSION'):
            errors.append(f'{rel}: outside the panel code')
            continue
        p = os.path.join(PANEL_DIR, rel)
        if rel in tree:
            rc = subprocess.run(['git', '-C', rd, 'cat-file', 'blob', tree[rel][1]], capture_output=True, timeout=60)
            if rc.returncode != 0:
                errors.append(f'{rel}: git could not read it')
                continue
            os.makedirs(os.path.dirname(p), exist_ok=True)
            tmp = p + '.vp-restore'
            with open(tmp, 'wb') as f:
                f.write(rc.stdout)
            os.chmod(tmp, 0o755 if tree[rel][0] == '100755' else 0o644)
            os.replace(tmp, p)
            fixed.append(rel)
        elif os.path.isfile(p) and (rel.endswith('.pyc') or rel not in tree):
            q = os.path.join(appkit.data_dir(APP), 'quarantine', time.strftime('%Y%m%d-%H%M%S'))
            os.makedirs(q, mode=0o700, exist_ok=True)
            shutil.move(p, os.path.join(q, rel.replace('/', '__')))
            fixed.append(rel)
    return fixed, errors


# -------------------------------------------------------------------- apps

def _dir_hashes(d, skip=('__pycache__',)):
    out = {}
    for dp, dns, fns in os.walk(d):
        dns[:] = [x for x in dns if x not in skip and not os.path.islink(os.path.join(dp, x))]
        for fn in fns:
            p = os.path.join(dp, fn)
            if os.path.isfile(p) and not os.path.islink(p):
                out[os.path.relpath(p, d)] = _sha256(p)
    return out


def _app_reference(aid, version):
    """{rel: sha256} of the App as released, from the signed panel release (bundle) or the
    download server; the downloaded reference is cached for REF_MAX_AGE."""
    bundle = os.path.join(PANEL_DIR, 'panel', 'apps_bundle', aid)
    try:
        bman = json.load(open(os.path.join(bundle, 'plugin.json')))
    except (OSError, ValueError):
        bman = {}
    if bman.get('version') == version:
        return _dir_hashes(bundle), 'the signed panel release'
    cache = f'ref-app-{aid}-{version}.json'
    ref = appkit.read_json(APP, cache, {})
    if ref.get('files') and time.time() - ref.get('t', 0) < REF_MAX_AGE:
        return ref['files'], 'the download server'
    from panel import softs
    tmp = tempfile.mkdtemp(prefix='vp-appref-')
    try:
        softs.fetch_panel_app(aid, version, os.path.join(tmp, 'a'))
        files = _dir_hashes(os.path.join(tmp, 'a'))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    appkit.write_json(APP, cache, {'t': int(time.time()), 'files': files})
    return files, 'the download server'


def check_apps():
    pdir = os.path.join(PANEL_DIR, 'plugins')
    try:
        names = sorted(n for n in os.listdir(pdir) if os.path.isdir(os.path.join(pdir, n)))
    except OSError:
        names = []
    if not names:
        return _section('apps', 'ok', 'No Apps are installed.')
    items, checked, unknown = [], 0, []
    for aid in names:
        d = os.path.join(pdir, aid)
        try:
            man = json.load(open(os.path.join(d, 'plugin.json')))
        except (OSError, ValueError):
            continue
        if man.get('kind') != 'app':
            continue
        try:
            ref, src = _app_reference(aid, man.get('version', ''))
        except Exception as e:  # noqa: BLE001
            unknown.append(f'{aid} {man.get("version")}: {str(e)[:120]}')
            continue
        checked += 1
        cur = _dir_hashes(d)
        for rel, h in ref.items():
            if rel not in cur:
                items.append(_item('medium', f'plugins/{aid}/{rel}', 'missing', 'reinstall'))
            elif cur[rel] != h:
                items.append(_item('critical', f'plugins/{aid}/{rel}', f'differs from {src}', 'reinstall'))
        for rel in cur:
            if rel not in ref and rel.endswith(('.py', '.so', '.pth', '.js', '.html', '.sh')):
                items.append(_item('high', f'plugins/{aid}/{rel}', f'not part of {aid} {man.get("version")}', 'reinstall'))
        for pyc in glob.glob(os.path.join(d, '**', '__pycache__', '*.pyc'), recursive=True):
            base = os.path.basename(pyc).split('.')[0] + '.py'
            src = os.path.join(os.path.dirname(os.path.dirname(pyc)), base)
            why = check_pyc(src, pyc) if os.path.exists(src) else ''
            if why:
                items.append(_item('critical', os.path.relpath(pyc, PANEL_DIR), why, 'remove'))
    status = 'bad' if any(i['severity'] in ('critical', 'high') for i in items) else ('warn' if items or unknown else 'ok')
    summary = f'{checked} App(s) checked' + (f', {len(items)} difference(s).' if items else ', all match.')
    if unknown:
        summary += ' Not checked: ' + '; '.join(unknown[:3])
    return _section('apps', status, summary, items)


# -------------------------------------------------------------------- venv

def check_venv():
    venv = os.path.join(PANEL_DIR, 'venv')
    sps = glob.glob(os.path.join(venv, 'lib', 'python3*', 'site-packages'))
    if not sps:
        return _section('venv', 'unknown', 'The panel has no Python environment at ' + venv + '.')
    items, n = [], 0
    for sp in sps:
        for rec in glob.glob(os.path.join(sp, '*.dist-info', 'RECORD')):
            try:
                lines = open(rec, encoding='utf-8', errors='replace').read().splitlines()
            except OSError:
                continue
            for line in lines:
                parts = line.rsplit(',', 2)
                if len(parts) != 3 or not parts[1].startswith('sha256='):
                    continue
                rel, h = parts[0], parts[1][7:]
                p = os.path.normpath(os.path.join(sp, rel))
                if not p.startswith(venv + '/') or not os.path.isfile(p):
                    continue
                n += 1
                got = base64.urlsafe_b64encode(hashlib.sha256(open(p, 'rb').read()).digest()).rstrip(b'=').decode()
                if got != h:
                    items.append(_item('critical', os.path.relpath(p, PANEL_DIR),
                                       f'differs from what pip installed ({os.path.basename(os.path.dirname(rec))})',
                                       'pip'))
        for pth in glob.glob(os.path.join(sp, '*.pth')):
            txt = open(pth, errors='replace').read()
            if re.search(r'^\s*import\s', txt, re.M) and not os.path.basename(pth).startswith(('distutils-precedence', '_virtualenv')):
                items.append(_item('high', os.path.relpath(pth, PANEL_DIR), 'runs code at every Python start (import line)', 'remove'))
        for pyc in glob.glob(os.path.join(sp, '**', '__pycache__', '*.pyc'), recursive=True):
            base = os.path.basename(pyc).split('.')[0] + '.py'
            src = os.path.join(os.path.dirname(os.path.dirname(pyc)), base)
            if os.path.exists(src):
                why = check_pyc(src, pyc)
                if why:
                    items.append(_item('critical', os.path.relpath(pyc, PANEL_DIR), why, 'remove'))
    status = 'bad' if items else 'ok'
    return _section('venv', status, f'{n} files checked' + (f', {len(items)} problem(s).' if items else ', all match.'), items)


# ------------------------------------------------------------------ builds

def _payload_hashes(zpath):
    """{rel: sha256 | 'link:<target>'} of a package's payload."""
    out = {}
    with zipfile.ZipFile(zpath) as z, z.open('payload.tar.xz') as px:
        with tarfile.open(fileobj=px, mode='r|xz') as tf:
            for m in tf:
                rel = os.path.normpath(m.name)
                if m.isreg():
                    h = hashlib.sha256()
                    f = tf.extractfile(m)
                    for b in iter(lambda: f.read(1 << 20), b''):
                        h.update(b)
                    out[rel] = h.hexdigest()
                elif m.issym():
                    out[rel] = 'link:' + m.linkname
                elif m.islnk():                 # a hard link: the same content as the file it names
                    tgt = out.get(os.path.normpath(m.linkname))
                    if tgt and not tgt.startswith('link:'):
                        out[rel] = tgt
    return out


def _fetch_build(app, version, target, arch):
    """Download exactly the installed package (any channel, also a withdrawn release),
    checked against the signed catalog."""
    from panel import softs
    cat = softs.refresh()
    for r in ((cat.get('apps') or {}).get(app) or {}).get('releases') or []:
        if r.get('version') == version:
            f = (r.get('files') or {}).get(f'{target}-{arch}')
            if f:
                return softs._fetch(f)
    raise ValueError(f'{app} {version} ({target}-{arch}) is not on the download server')


def build_reference(app, version, prefix, target='', arch=''):
    """{rel: hash} for an installed build: the package on the download server (signed catalog),
    cached for REF_MAX_AGE; the list recorded at install time when the server no longer has it."""
    cache = f'ref-build-{app}-{version}.json'
    ref = appkit.read_json(APP, cache, {})
    if ref.get('fmt') == REF_FMT and ref.get('files') and time.time() - ref.get('t', 0) < REF_MAX_AGE:
        return ref['files'], ref.get('source', 'the download server')
    try:
        path = _fetch_build(app, version, target, arch)
        try:
            files = _payload_hashes(path)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
        appkit.write_json(APP, cache, {'t': int(time.time()), 'fmt': REF_FMT, 'files': files, 'source': 'the download server'})
        return files, 'the download server'
    except Exception as e:  # noqa: BLE001
        local = os.path.join(prefix, '.vortex', 'files.json')
        try:
            return json.load(open(local)), 'the list recorded when it was installed'
        except (OSError, ValueError):
            raise ValueError(f'no reference ({str(e)[:120]})')


def installed_builds():
    out = []
    for man_path in glob.glob(os.path.join(SOFT_BASE, '*', '*', '.vortex', 'manifest.json')):
        try:
            man = json.load(open(man_path))
        except (OSError, ValueError):
            continue
        prefix = os.path.dirname(os.path.dirname(man_path))
        if man.get('app') and man.get('version') and prefix == os.path.join(SOFT_BASE, man['app'], man['version']):
            out.append((man['app'], man['version'], prefix, man.get('target', ''), man.get('arch', '')))
    return sorted(out)


def check_builds():
    builds = installed_builds()
    if not builds:
        return _section('builds', 'ok', 'No VortexPanel software builds are installed.')
    items, unknown, n = [], [], 0
    for app, version, prefix, target, arch in builds:
        try:
            ref, src = build_reference(app, version, prefix, target, arch)
        except ValueError as e:
            unknown.append(f'{app} {version}: {e}')
            continue
        n += 1
        for rel, h in ref.items():
            p = os.path.join(prefix, rel)
            if h.startswith('link:'):
                if os.path.islink(p) and os.readlink(p) != h[5:]:
                    items.append(_item('high', p, f'link points to {os.readlink(p)} instead of {h[5:]}', 'reinstall'))
                continue
            if not os.path.isfile(p) or os.path.islink(p):
                items.append(_item('medium', p, 'missing', 'reinstall'))
            elif _sha256(p) != h:
                items.append(_item('critical', p, f'differs from {src}', 'reinstall'))
        for dp, dns, fns in os.walk(prefix):
            dns[:] = [x for x in dns if x != '.vortex']
            for fn in fns:
                p = os.path.join(dp, fn)
                rel = os.path.relpath(p, prefix)
                if rel not in ref and os.path.isfile(p) and not os.path.islink(p):
                    try:
                        head = open(p, 'rb').read(4)
                    except OSError:
                        continue
                    if head == b'\x7fELF' or os.stat(p).st_mode & 0o111 or fn.endswith(('.so', '.php', '.py')):
                        items.append(_item('high', p, f'not part of {app} {version}', 'reinstall'))
    status = 'bad' if any(i['severity'] in ('critical', 'high') for i in items) else ('warn' if items or unknown else 'ok')
    summary = f'{n} build(s) checked' + (f', {len(items)} difference(s).' if items else ', all match.')
    if unknown:
        summary += ' Not checked: ' + '; '.join(unknown[:3])
    return _section('builds', status, summary, items)


# ---------------------------------------------------------------- packages

def _running_exes():
    out = set()
    for pid in os.listdir('/proc'):
        if pid.isdigit():
            try:
                exe = os.readlink(f'/proc/{pid}/exe')
            except OSError:
                continue
            if not exe.endswith(' (deleted)'):
                out.add(exe)
    return out


def _owners(paths, fam):
    """Packages that own these files (unowned paths are skipped)."""
    pkgs = set()
    paths = [p for p in paths if p.startswith('/') and not p.startswith(SOFT_BASE + '/')]
    for i in range(0, len(paths), 200):
        chunk = paths[i:i + 200]
        if fam == 'deb':
            # merged /usr: the package database may list /bin/x for /usr/bin/x
            alt = chunk + [p[4:] for p in chunk if p.startswith(('/usr/bin/', '/usr/sbin/', '/usr/lib/'))]
            rc, out, _ = _sh(['dpkg-query', '-S'] + alt, 120)
            for line in out.splitlines():
                if ': ' in line:
                    for pk in line.split(': ', 1)[0].split(', '):
                        pkgs.add(pk.split(':')[0].strip())
        else:
            rc, out, _ = _sh(['rpm', '-qf', '--qf', '%{NAME}\n'] + chunk, 120)
            for line in out.splitlines():
                if line and ' ' not in line:
                    pkgs.add(line.strip())
    return pkgs


def _installed_pkgs(names, fam):
    if fam == 'deb':
        rc, out, _ = _sh(['dpkg-query', '-W', '-f', '${Package} ${Status}\n'] + list(names), 60)
        return {l.split()[0] for l in out.splitlines() if l.endswith('install ok installed')}
    rc, out, _ = _sh(['rpm', '-q', '--qf', '%{NAME}\n'] + list(names), 60)
    return {l.strip() for l in out.splitlines() if l.strip() and 'not installed' not in l}


def verify_packages(pkgs, fam):
    """[(path, flags, package)] of files whose content differs from the package (config files excluded)."""
    bad = []
    pkgs = sorted(pkgs)
    for i in range(0, len(pkgs), 40):
        chunk = pkgs[i:i + 40]
        if fam == 'deb':
            rc, out, _ = _sh(['dpkg', '--verify'] + chunk, 600)
            for line in out.splitlines():
                m = re.match(r'^(\S{9}) (c| ) (/.+)$', line)
                if m and m.group(2) != 'c' and m.group(1)[2] == '5':
                    bad.append((m.group(3), 'checksum', ''))
                m2 = re.match(r'^missing\s+(c| )\s*(/.+)$', line)
                if m2 and m2.group(1) != 'c' and not _SKIP_MISSING.match(m2.group(2)):
                    bad.append((m2.group(2), 'missing', ''))
        else:
            rc, out, _ = _sh(['rpm', '-V', '--nomtime', '--nouser', '--nogroup', '--nomode'] + chunk, 600)
            for line in out.splitlines():
                m = re.match(r'^(\S{9})\s+([cdglr]?)\s*(/.+)$', line)
                if m and m.group(2) not in ('c', 'g') and m.group(1)[2] == '5':
                    bad.append((m.group(3), 'checksum', ''))
                m2 = re.match(r'^missing\s+([cdglr]?)\s*(/.+)$', line)
                if m2 and m2.group(1) not in ('c', 'g', 'd') and not _SKIP_MISSING.match(m2.group(2)):
                    bad.append((m2.group(2), 'missing', ''))
    if bad:
        own = {}
        for p, _, _ in bad:
            own[p] = sorted(_owners([p], fam))
        bad = [(p, k, ', '.join(own.get(p) or [])) for p, k, _ in bad]
    return bad


def file_matches_package(path, cache=None):
    """True: owned by a package and unchanged; False: owned and changed; None: not from a package.
    cache: a dict reused within one scan (a system update changes many files of one package)."""
    fam = _family()
    if not fam:
        return None
    owners = _owners([path], fam)
    if not owners:
        return None
    key = tuple(sorted(owners))
    if cache is not None and key in cache:
        bad = cache[key]
    else:
        bad = verify_packages(owners, fam)
        if cache is not None:
            cache[key] = bad
    real = os.path.realpath(path)
    return not any(os.path.realpath(p) == real for p, kind, _ in bad if kind == 'checksum')


def check_packages():
    fam = _family()
    if not fam:
        return _section('packages', 'unknown', 'No dpkg or rpm on this system.')
    core = _installed_pkgs(DEB_CORE if fam == 'deb' else RPM_CORE, fam)
    running = _owners(sorted(_running_exes()), fam)
    pkgs = core | running
    bad = verify_packages(pkgs, fam)
    reinstall = 'apt-get install --reinstall' if fam == 'deb' else 'dnf reinstall'
    items = []
    for path, kind, pk in bad:
        crit = re.search(r'/(s?bin|libexec|security)/|\.so(\.|$)', path)
        sev = ('critical' if crit else 'high') if kind == 'checksum' else 'medium'
        items.append(_item(sev, path, (f'differs from the package {pk}' if kind == 'checksum' else f'missing from {pk}')
                           + (f' -- {reinstall} {pk.split(",")[0]}' if pk else ''), 'package'))
    status = 'bad' if any(i['severity'] in ('critical', 'high') for i in items) else ('warn' if items else 'ok')
    return _section('packages', status, f'{len(pkgs)} packages checked ({len(running)} with running programs)'
                    + (f', {len(items)} file(s) differ.' if items else ', all files match.'), items)


# --------------------------------------------------------------- backdoors

def elf_needed(path):
    """DT_NEEDED names of an ELF shared object (64- and 32-bit, little endian)."""
    import struct
    try:
        data = open(path, 'rb').read(8 << 20)
    except OSError:
        return []
    if data[:4] != b'\x7fELF' or data[5] != 1:
        return []
    is64 = data[4] == 2
    try:
        if is64:
            phoff, = struct.unpack_from('<Q', data, 0x20)
            phentsize, phnum = struct.unpack_from('<HH', data, 0x36)
        else:
            phoff, = struct.unpack_from('<I', data, 0x1C)
            phentsize, phnum = struct.unpack_from('<HH', data, 0x2A)
        loads, dyn = [], None
        for i in range(phnum):
            o = phoff + i * phentsize
            if is64:
                ptype, _, off, vaddr, _, filesz, _, _ = struct.unpack_from('<IIQQQQQQ', data, o)
            else:
                ptype, off, vaddr, _, filesz, _, _, _ = struct.unpack_from('<IIIIIIII', data, o)
            if ptype == 1:
                loads.append((vaddr, off, filesz))
            elif ptype == 2:
                dyn = (off, filesz)
        if not dyn:
            return []
        ent = 16 if is64 else 8
        needed, strtab = [], None
        for o in range(dyn[0], dyn[0] + dyn[1], ent):
            tag, val = struct.unpack_from('<qQ' if is64 else '<iI', data, o)
            if tag == 0:
                break
            if tag == 1:
                needed.append(val)
            elif tag == 5:
                strtab = val
        if strtab is None:
            return []
        base = next((off + strtab - va for va, off, sz in loads if va <= strtab < va + sz), None)
        if base is None:
            return []
        return [data[base + n:data.index(b'\0', base + n)].decode(errors='replace') for n in needed]
    except (struct.error, ValueError, IndexError):
        return []


def _unix_sockets():
    """{inode: path} of Unix sockets (abstract names start with @)."""
    out = {}
    try:
        for line in open('/proc/net/unix').read().splitlines()[1:]:
            f = line.split()
            if len(f) >= 8:
                out[f[6]] = f[7]
    except OSError:
        pass
    return out


def _socket_owners(inodes):
    own = {}
    want = {f'socket:[{i}]' for i in inodes}
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            for fd in os.listdir(f'/proc/{pid}/fd'):
                try:
                    t = os.readlink(f'/proc/{pid}/fd/{fd}')
                except OSError:
                    continue
                if t in want:
                    own.setdefault(t[8:-1], []).append(pid)
        except OSError:
            continue
    return own


def _comm(pid):
    try:
        return open(f'/proc/{pid}/comm').read().strip()
    except OSError:
        return '?'


def _contains(path, needle, limit=512 << 20):
    try:
        with open(path, 'rb') as f:
            tail, read = b'', 0
            while read < limit:
                b = f.read(8 << 20)
                if not b:
                    return False
                if needle in tail + b:
                    return True
                tail = b[-len(needle):]
                read += len(b)
    except OSError:
        pass
    return False


PRELOAD_OK = re.compile(r'(^|/)lib(jemalloc|tcmalloc|tcmalloc_minimal|eatmydata|mimalloc)[^/]*\.so', re.I)


def check_backdoors():
    items = []
    # CWPdoor: helper socket, marker in the CWP web server or any running program
    socks = _unix_sockets()
    for ino, name in socks.items():
        if 'ngx_http_integrity_helper' in name:
            items.append(_item('critical', name, 'CWPdoor backdoor socket (a web server answers hidden X-Ngx-Integrity commands)'))
    exes = _running_exes() | {p for p in ('/usr/local/cwpsrv/bin/cwpsrv',) if os.path.exists(p)}
    for exe in sorted(exes):
        if _contains(exe, CWPDOOR_MARKER):
            items.append(_item('critical', exe, 'contains the CWPdoor marker X-Ngx-Integrity (backdoored web server)'))
    # Ebury: its library files, libkeyutils with an extra NEEDED entry, tls/ copies, fake dbus sockets
    seen = set()
    for d in LIB_DIRS:
        cand = [(os.path.join(d, n), 'file name used by the Ebury SSH backdoor') for n in EBURY_FILES]
        cand += [(p, 'libkeyutils in a tls/ folder (Ebury loads itself this way)')
                 for p in glob.glob(os.path.join(d, 'tls', 'libkeyutils.so*'))]
        for p, why in cand:
            if os.path.lexists(p) and os.path.realpath(p) not in seen:     # /lib = /usr/lib on merged-/usr systems
                seen.add(os.path.realpath(p))
                items.append(_item('critical', p, why))
    seen = set()
    for p in glob.glob('/lib*/libkeyutils.so*') + glob.glob('/usr/lib*/libkeyutils.so*') + \
            glob.glob('/lib/*-linux-gnu/libkeyutils.so*') + glob.glob('/usr/lib/*-linux-gnu/libkeyutils.so*'):
        real = os.path.realpath(p)
        if real in seen or not os.path.isfile(real):
            continue
        seen.add(real)
        extra = [n for n in elf_needed(real) if not re.match(r'^(libc|libdl|ld-linux)[.-]', n)]
        if extra:
            items.append(_item('critical', real, 'libkeyutils loads ' + ', '.join(extra) + ' (Ebury patches it this way)'))
    dbus = {i: n for i, n in socks.items() if n.startswith('@/tmp/dbus-')}
    if dbus:
        for ino, pids in _socket_owners(dbus).items():
            for pid in pids:
                c = _comm(pid)
                if c not in ('dbus-daemon', 'dbus-broker', 'dbus-launch'):
                    items.append(_item('critical', dbus[ino], f'dbus-style socket held by {c} (pid {pid}); Ebury hides this way'))
    # forced library preloading in running programs
    if os.path.exists('/etc/ld.so.preload') and open('/etc/ld.so.preload').read().strip():
        items.append(_item('critical', '/etc/ld.so.preload', 'forces a library into every program: '
                           + open('/etc/ld.so.preload').read().strip()[:200]))
    pre = {}
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            env = open(f'/proc/{pid}/environ', 'rb').read().split(b'\0')
        except OSError:
            continue
        for e in env:
            if e.startswith(b'LD_PRELOAD=') and len(e) > 11:
                pre.setdefault(e[11:].decode(errors='replace'), set()).add(_comm(pid))
    for lib, comms in pre.items():
        names = sorted(comms)
        if all(PRELOAD_OK.search(x) for x in lib.replace(':', ' ').split()):
            continue
        sev = 'critical' if {'sshd', 'sshd-session', 'nginx', 'httpd', 'apache2', 'cwpsrv', 'gunicorn', 'php-fpm'} & comms else 'high'
        items.append(_item(sev, lib, 'preloaded into ' + ', '.join(names[:6]) + (' ...' if len(names) > 6 else '')))
    status = 'bad' if items else 'ok'
    return _section('backdoors', status, 'No known backdoor traces found.' if not items
                    else f'{len(items)} backdoor trace(s) found.', items)


# -------------------------------------------------------------------- run


# --------------------------------------------------------------- PHP2Shell

P2S_FIXED = {'8.5': (8, 5, 12), '8.4': (8, 4, 27), '8.3': (8, 3, 36), '8.2': (8, 2, 35)}
P2S_MARKERS = ('PHP2SHELL_CONFIRMED', 'JACKALPOC', 'B7kQpoc618', 'sess_p2sopchain')
P2S_LOG_PATTERNS = [
    (re.compile(r'Allowed memory size of \d+ bytes exhausted.* in Unknown on line 0'), 'medium',
     'PHP ran out of memory before any script ran (the first step of PHP2Shell)'),
    (re.compile(r'Session ID is too long or contains illegal characters'), 'medium',
     'oversized session cookie (the memory-leak step of PHP2Shell)'),
    (re.compile(r'zend_mm_heap corrupted'), 'medium', 'PHP memory corruption (PHP2Shell crashes workers)'),
]
P2S_LOG_GLOBS = ['/var/log/apache2/*error*.log*', '/var/log/httpd/*error*log*', '/var/log/nginx/*error*.log*',
                 '/usr/local/lsws/logs/error.log*', '/usr/local/lsws/logs/stderr.log*', '/var/log/php*-fpm.log*',
                 '/var/log/apache2/*access*.log*', '/var/log/httpd/*access*log*', '/var/log/nginx/*access*.log*',
                 '/usr/local/lsws/logs/access.log*', '/home/*/logs/*.log', '/www/wwwlogs/*.log']
P2S_DROPPED = ['/tmp/nfs', '/tmp/collect.sh', '/var/tmp/nfs', '/var/tmp/collect.sh', '/dev/shm/nfs', '/dev/shm/collect.sh']
WEB_USERS = ('www-data', 'apache', 'nginx', 'nobody', 'lsadm', 'http')


def _tail_lines(path, limit=64 << 20):
    """Lines of the last `limit` bytes of a text log (gzip logs are skipped)."""
    if path.endswith(('.gz', '.xz', '.bz2', '.zst')):
        return []
    try:
        with open(path, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - limit))
            data = f.read()
    except OSError:
        return []
    return data.decode(errors='replace').splitlines()


def _php_binaries():
    """[(name, binary, flavor)] when the panel's own module is not there (panels before 3.11.4)."""
    out, seen = [], set()
    for b in sorted(glob.glob(os.path.join(SOFT_BASE, 'php', '*', 'bin', 'php'))):
        d = os.path.dirname(os.path.dirname(b))
        if not os.path.islink(d):
            name = 'PHP ' + '.'.join(os.path.basename(d).split('.')[:2])
            seen.add(name)
            out.append((name, b, 'vortex'))
    for b in sorted(glob.glob('/usr/bin/php[0-9]*.[0-9]*')):
        if re.search(r'/php\d+\.\d+$', b) and f'PHP {b[12:]}' not in seen:   # not a VortexPanel build's wrapper
            out.append((f'PHP {b[12:]}', b, 'os'))
    for b in sorted(glob.glob('/usr/local/lsws/lsphp*/bin/lsphp')):
        out.append((os.path.basename(os.path.dirname(os.path.dirname(b))), b, 'os'))
    return out


def _php_status_items():
    items, note = [], ''
    try:
        from panel import php2shell as P          # panel 3.11.4 and newer
        st = P.status()
        rows = st['versions']
        if not st['enabled']:
            items.append(_item('medium', 'PHP2Shell protection', 'turned off on the PHP page '
                               '(session.upload_progress stays on; CVE-2026-115560 has no fix yet)'))
        elif not st['t']:
            note = ' Protection not applied yet.'
    except Exception:  # noqa: BLE001
        rows = []
        for name, b, flavor in _php_binaries():
            rc, out, err = _sh([b, '-n', '-v'], 20)
            m = re.search(r'PHP (\d+)\.(\d+)\.(\d+)(\S*)', out)
            if not m:
                continue
            ver = tuple(int(x) for x in m.groups()[:3])
            branch = f'{ver[0]}.{ver[1]}'
            fixed = P2S_FIXED.get(branch)
            if fixed and ver >= fixed:
                stt = 'fixed'
            elif flavor == 'os' or m.group(4):
                stt = 'check'
            elif not fixed and ver < (8, 2):
                stt = 'nofix'
            else:
                stt = 'vulnerable'
            rows.append({'name': name, 'version': '.'.join(map(str, ver)) + m.group(4), 'status': stt,
                         'detail': ''})
    for r in rows:
        if r['status'] == 'vulnerable':
            items.append(_item('critical', f"{r['name']} {r['version']}", 'affected by PHP2Shell: update PHP '
                               '(App Store, or the operating system updates)'))
        elif r['status'] == 'nofix':
            items.append(_item('high', f"{r['name']} {r['version']}", 'PHP 8.1 and older have no official PHP2Shell '
                               'fix: move the websites to PHP 8.2 or newer'))
        elif r['status'] == 'check':
            items.append(_item('low', f"{r['name']} {r['version']}", 'operating system package: make sure the '
                               "distribution's PHP2Shell update is installed"))
    return items, rows, note


def check_php2shell():
    items, rows, note = _php_status_items()
    # dropped files and persistence seen in the attacks
    for p in P2S_DROPPED + glob.glob('/tmp/.c1*') + glob.glob('/var/tmp/.c1*') + glob.glob('/dev/shm/.c1*'):
        if os.path.isfile(p) and not os.path.islink(p):
            items.append(_item('critical', p, 'file name dropped by PHP2Shell attackers (bot / collection script)'))
    import pwd
    for u in WEB_USERS:
        try:
            home = pwd.getpwnam(u).pw_dir
        except KeyError:
            continue
        ak = os.path.join(home, '.ssh', 'authorized_keys')
        if os.path.isfile(ak) and os.path.getsize(ak) > 0:
            items.append(_item('critical', ak, f'SSH keys for the web user {u}: attackers add these after PHP2Shell'))
    for d in ('/var/log/apache2', '/var/log/httpd', '/var/log/nginx', '/usr/local/lsws/logs'):
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for n in names:
            p = os.path.join(d, n)
            if n.startswith('.') and n not in ('.', '..'):
                items.append(_item('high', p, 'hidden entry in a web server log folder (PHP2Shell attackers hide an sshd in .j/)'))
            elif os.path.isfile(p) and not n.endswith(('.gz', '.xz')):
                try:
                    with open(p, 'rb') as f:
                        if f.read(4) == b'\x7fELF':
                            items.append(_item('critical', p, 'a program inside a web server log folder'))
                except OSError:
                    pass
    for d in ('/var/lib/php/sessions', '/var/lib/php/session', '/tmp'):
        for p in glob.glob(os.path.join(d, 'sess_p2sopchain*')):
            items.append(_item('critical', p, 'session file named by the PHP2Shell exploit chain'))
    # log patterns and markers (the current and the previous log)
    hits = {}
    for pat in P2S_LOG_GLOBS:
        for p in sorted(glob.glob(pat)):
            if not re.search(r'(\.log|log|\.\d)$', p):
                continue
            for line in _tail_lines(p):
                for m in P2S_MARKERS:
                    if m in line:
                        hits.setdefault((p, m), [0, 'high', f'PHP2Shell exploit marker {m}'])[0] += 1
                for rx, sev, why in P2S_LOG_PATTERNS:
                    if rx.search(line):
                        hits.setdefault((p, rx.pattern), [0, sev, why])[0] += 1
    for (p, _), (n, sev, why) in sorted(hits.items()):
        items.append(_item(sev, p, f'{why}: {n} time(s)'))
    # the root exploit chained after PHP2Shell (Fragnesia, CVE-2026-46300) needs these modules
    try:
        mods = {l.split()[0] for l in open('/proc/modules')}
    except OSError:
        mods = set()
    ipsec = any(_have(x) for x in ('ipsec', 'charon', 'strongswan', 'pluto'))
    loaded = sorted(mods & {'esp4', 'esp6', 'rxrpc'})
    if loaded and not ipsec:
        items.append(_item('medium', ', '.join(loaded), 'kernel modules loaded without IPsec software: the root exploit '
                           'used after PHP2Shell (CVE-2026-46300) relies on them; install the kernel update'))
    bad = any(i['severity'] in ('critical', 'high') for i in items)
    traces = [i for i in items if i['severity'] in ('critical', 'high') and not i['path'].startswith(('PHP ', 'lsphp'))]
    fixed = sum(1 for r in rows if r['status'] == 'fixed')
    summary = (f'{fixed} of {len(rows)} PHP version(s) carry the fix' if rows else 'No PHP found') + \
              (f'; {len(traces)} trace(s) of the attack found.' if traces else '; no traces of the attack found.') + note
    return _section('php2shell', 'bad' if bad else ('warn' if items else 'ok'), summary, items)


# ------------------------------------------------------------- web servers

def _vt3(v):
    return tuple(int(x) for x in re.findall(r'\d+', v or '')[:3])


# Minimum version per track that carries the fixes for serious, published flaws. The catalog
# keeps only the newest release of a track, so its "security" flag alone can miss a server two
# releases behind (nginx 1.31.6 -> 1.31.8, where 1.31.7 was the fix). Updated with this App.
WEB_MIN_SAFE = {
    'apache2': {'2.4': ((2, 4, 71), 'CVE-2026-119618, HTTP/2 remote code execution without a login (critical, 9.8), '
                                    'and two more')},
    'nginx': {'1.31': ((1, 31, 7), 'CVE-2026-15176 and four more fixed in October 2026'),
              '1.30': ((1, 30, 6), 'CVE-2026-15176 and four more fixed in October 2026')},
}
# tracks upstream no longer fixes
WEB_EOL = {'nginx': {'1.29', '1.28', '1.27', '1.26'}, 'apache2': {'2.2'}}
WEB_APPS = {'apache2': 'Apache', 'nginx': 'nginx', 'openlitespeed': 'OpenLiteSpeed', 'caddy': 'Caddy',
            'caddy-waf': 'Caddy (WAF build)'}


def _web_builds():
    """[(app, version)] of the VortexPanel web server builds in use (not the copies kept for rollback)."""
    out = []
    try:
        from panel import softs
        for app in WEB_APPS:
            for slot, rec in (softs.installed(app) or {}).items():
                if rec.get('version'):
                    out.append((app, rec['version']))
        return out
    except Exception:  # noqa: BLE001 - panels without the engine: follow the current links
        for app in WEB_APPS:
            for link in glob.glob(os.path.join(SOFT_BASE, app, '*')):
                if os.path.islink(link):
                    out.append((app, os.path.basename(os.path.realpath(link))))
        return sorted(set(out))


def _catalog_releases(app):
    try:
        from panel import softs
        return ((softs.load() or {}).get('apps') or {}).get(app, {}).get('releases') or []
    except Exception:  # noqa: BLE001
        return []


def _apache_conf_dirs():
    return [d for d in ('/etc/apache2', '/etc/httpd') if os.path.isdir(d)]


def _apache_h2():
    """True when Apache serves HTTP/2: the module is loaded and a Protocols line offers h2/h2c."""
    loaded = False
    for ctl in ('apache2ctl', 'apachectl', 'httpd'):
        if _have(ctl):
            rc, out, err = _sh([ctl, '-M'], 30)
            if 'http2_module' in out + err:
                loaded = True
                break
    if not loaded:
        return False
    for d in _apache_conf_dirs():
        for dp, dns, fns in os.walk(d):
            dns[:] = [x for x in dns if not x.endswith('-available')]      # only what Apache loads
            for fn in fns:
                if not fn.endswith(('.conf', '.load')) and fn != 'apache2.conf':
                    continue
                try:
                    text = open(os.path.join(dp, fn), errors='replace').read()
                except OSError:
                    continue
                if re.search(r'^\s*Protocols\s+[^\n#]*\bh2c?\b', text, re.M | re.I):
                    return True
    return False


def _ols_conf():
    texts = []
    for p in ['/usr/local/lsws/conf/httpd_config.conf'] + glob.glob('/usr/local/lsws/conf/vhosts/*/vhconf.conf'):
        try:
            texts.append(open(p, errors='replace').read())
        except OSError:
            pass
    return '\n'.join(texts)


def _ols_open_issue(ver):
    """CVE-2026-119559 (no fix yet, all versions to 1.9.4): sites that require client
    certificates can be reached without one over HTTP/3."""
    if _vt3(ver) > (1, 9, 4):
        return None
    conf = _ols_conf()
    m = re.search(r'^\s*quicEnable\s+(\d)', conf, re.M)
    quic = (m.group(1) != '0') if m else True             # HTTP/3 is on unless switched off
    mtls = re.search(r'^\s*clientVerify\s+[123]\b', conf, re.M)
    if quic and mtls:
        return _item('high', f'OpenLiteSpeed {ver}', 'CVE-2026-119559 (no fix yet): a site that requires client '
                     'certificates can be reached without one over HTTP/3. Turn HTTP/3 off (quicEnable 0) until '
                     'LiteSpeed releases a fix.')
    return _item('low', f'OpenLiteSpeed {ver}', 'CVE-2026-119559 has no fix yet, but this server is not exposed: '
                 + ('no site requires client certificates' if quic else 'HTTP/3 is off'))


def _pending_security(pkgs):
    """{package: new version} of operating system security updates waiting to be installed,
    as of the last package list refresh."""
    out = {}
    if _have('apt-get'):
        rc, txt, err = _sh(['apt-get', '-s', '-o', 'Debug::NoLocking=1', 'upgrade'], 120)
        for m in re.finditer(r'^Inst (\S+) (?:\[[^\]]*\] )?\((\S+) ([^)]*)\)', txt, re.M):
            if m.group(1) in pkgs and 'security' in m.group(3).lower():
                out[m.group(1)] = m.group(2)
    elif _have('dnf'):
        rc, txt, err = _sh(['dnf', '-q', '--cacheonly', 'updateinfo', 'list', '--security', '--available'] + list(pkgs), 120)
        for line in txt.splitlines():
            f = line.split()
            if len(f) >= 3:
                name = re.sub(r'-\d.*$', '', f[-1])
                if name in pkgs:
                    out[name] = f[-1]
    return out


def _os_web():
    """[(app, binary, package, version)] of web servers from operating system packages."""
    fam = _family()
    if not fam:
        return []
    cands = {'apache2': ['/usr/sbin/apache2', '/usr/sbin/httpd'], 'nginx': ['/usr/sbin/nginx'],
             'openlitespeed': ['/usr/local/lsws/bin/openlitespeed'], 'caddy': ['/usr/bin/caddy']}
    out = []
    for app, bins in cands.items():
        for b in bins:
            if not os.path.exists(b) or os.path.realpath(b).startswith(SOFT_BASE + '/'):
                continue
            owners = _owners([b], fam)
            if not owners:
                continue
            pkg = sorted(owners)[0]
            argv = {'apache2': [b, '-v'], 'nginx': [b, '-v'], 'openlitespeed': [b, '-v'], 'caddy': [b, 'version']}[app]
            rc, o, e = _sh(argv, 20)
            m = re.search(r'(\d+\.\d+\.\d+)', o + e)
            out.append((app, b, pkg, m.group(1) if m else ''))
            break
    return out


def check_webservers():
    items, seen = [], []
    h2 = None
    for app, ver in _web_builds():
        name = WEB_APPS[app]
        seen.append(f'{name} {ver}')
        vt = _vt3(ver)
        track = '.'.join(ver.split('.')[:2]) if app not in ('caddy', 'caddy-waf') else ver.split('.')[0]
        rels = _catalog_releases(app)
        newer_sec = [r for r in rels if (r.get('track') == track or not r.get('track')) and _vt3(r['version']) > vt
                     and r.get('security') and r.get('status', 'active') == 'active']
        safe = WEB_MIN_SAFE.get(app, {}).get(track)
        target = max([r['version'] for r in newer_sec] or [''], key=_vt3) or (
            max([r['version'] for r in rels if r.get('track') == track] or [''], key=_vt3))
        if safe and vt < safe[0]:
            if app == 'apache2':
                h2 = _apache_h2() if h2 is None else h2
            sev = 'critical' if app == 'apache2' and h2 else 'high'
            items.append(_item(sev, f'{name} {ver}', f'missing the fix for {safe[1]}'
                               + (' -- HTTP/2 is on, so it is exposed' if app == 'apache2' and h2 else '')
                               + f'. Update to {target or ".".join(map(str, safe[0]))} in the App Store.', 'update'))
        elif newer_sec:
            cves = sorted({c for r in newer_sec for c in (r.get('cves') or [])})
            items.append(_item('high', f'{name} {ver}', f'{target} is a security update'
                               + (f' ({", ".join(cves[:4])}{" and more" if len(cves) > 4 else ""})' if cves else '')
                               + ': update it in the App Store.', 'update'))
        elif track in WEB_EOL.get(app, set()):
            items.append(_item('medium', f'{name} {ver}', f'{name} {track} no longer receives security fixes: '
                               'move to a supported version in the App Store.', 'update'))
        if app == 'openlitespeed':
            it = _ols_open_issue(ver)
            if it:
                items.append(it)
    os_web = _os_web()
    if os_web:
        pending = _pending_security({p for _, _, p, _ in os_web})
        for app, b, pkg, ver in os_web:
            name = WEB_APPS[app]
            seen.append(f'{name} {ver} (system package)')
            if pkg in pending:
                items.append(_item('high', f'{name} {ver} ({pkg})', f'a security update ({pending[pkg]}) is waiting: '
                                   'install the operating system updates', 'package'))
            if app == 'apache2' and _vt3(ver) < (2, 4, 71) and _vt3(ver) >= (2, 4, 55):
                h2 = _apache_h2() if h2 is None else h2
                if h2:
                    items.append(_item('medium', f'{name} {ver} ({pkg})', 'CVE-2026-119618 (HTTP/2 remote code execution) '
                                       'is fixed upstream in 2.4.71. Distributions backport the fix under their own '
                                       'version numbers: install the operating system updates, and if your distribution '
                                       'has no fix yet, set "Protocols http/1.1" to turn HTTP/2 off.', 'package'))
            if app == 'openlitespeed':
                it = _ols_open_issue(ver)
                if it:
                    items.append(it)
    if not seen:
        return _section('webservers', 'ok', 'No Apache, nginx, OpenLiteSpeed or Caddy on this server.')
    bad = any(i['severity'] in ('critical', 'high') for i in items)
    flagged = [i for i in items if i['severity'] in ('critical', 'high', 'medium')]
    summary = ', '.join(seen) + (f': {len(flagged)} problem(s).' if flagged else ': up to date.')
    return _section('webservers', 'bad' if bad else ('warn' if flagged else 'ok'), summary, items)

CHECKS = {'php2shell': check_php2shell, 'webservers': check_webservers, 'panel': check_panel, 'apps': check_apps, 'venv': check_venv, 'builds': check_builds,
          'packages': check_packages, 'backdoors': check_backdoors}


def run(only=None, on_new=None):
    """Run the checks, save integrity.json, call on_new(section, item) for problems not seen last time."""
    prev = appkit.read_json(APP, 'integrity.json', {})
    seen = {(s['id'], i['path'], i['detail']) for s in prev.get('sections', []) for i in s.get('items', [])}
    appkit.write_json(APP, 'integrity.json', dict(prev, running=True, started=int(time.time())))
    sections = []
    t0 = time.time()
    try:
        for sid, _, _ in SECTIONS:
            if only and sid not in only:
                old = next((s for s in prev.get('sections', []) if s['id'] == sid), None)
                if old:
                    sections.append(old)
                continue
            try:
                s = CHECKS[sid]()
            except Exception as e:  # noqa: BLE001
                s = _section(sid, 'unknown', f'The check failed: {type(e).__name__}: {str(e)[:200]}')
            s['t'] = int(time.time())
            sections.append(s)
            if on_new:
                for i in s['items']:
                    if (sid, i['path'], i['detail']) not in seen:
                        on_new(s, i)
    finally:
        worst = 'ok'
        for s in sections:
            if s['status'] == 'bad':
                worst = 'bad'
            elif s['status'] in ('warn', 'unknown') and worst == 'ok':
                worst = 'warn'
        res = {'t': int(time.time()), 'seconds': round(time.time() - t0, 1), 'status': worst,
               'sections': sections, 'running': False}
        appkit.write_json(APP, 'integrity.json', res)
    return res


if __name__ == '__main__':
    r = run(sys.argv[1:] or None)
    for s in r['sections']:
        print(f"{s['status']:8} {s['label']}: {s['summary']}")
        for i in s['items'][:20]:
            print(f"         [{i['severity']}] {i['path']}  {i['detail']}")
