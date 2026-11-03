"""VortexPanel software builds: install, update and roll back server software from
the VortexPanel download server (Cloudflare R2), not from the OS package sources.

    catalog   <base_url>/catalog.json + catalog.json.sig, signed with the key in
              panel/trust/softs.json. Refused when the signature does not verify or
              its serial is lower than the one already accepted (replay).
    files     <base_url>/<app>/<version>/<app>-<version>-<target>-<arch>.zip,
              checked against the SHA-256 in the signed catalog before use.
    on disk   /usr/local/vortex/<app>/<version>/        one folder per version
              /usr/local/vortex/<app>/current  (or /<track> for PHP, Python)
                                                         -> the version in use

Install / update:  download -> verify -> runtime packages -> unpack the new version
next to the old one -> scripts/install.sh -> switch the link -> scripts/activate.sh
-> scripts/check.sh. If activate or check fails, the link goes back to the previous
version, which is activated again, and the new folder is removed: an update never
leaves the server without a working version. The previous version is kept for a
one-click rollback.

It also runs on its own (the build pipeline tests every zip with it):

    python3 softs.py target
    python3 softs.py install-zip FILE.zip [--init none]
    python3 softs.py install APP VERSION | update APP [TRACK] | rollback APP [TRACK]
    python3 softs.py uninstall APP [TRACK] | status | refresh | periodic
"""
import base64
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import uuid
import tempfile
import threading
import time
import urllib.request
import zipfile

BASE = '/usr/local/vortex'
PANEL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_IN_PANEL = os.path.isfile(os.path.join(PANEL_DIR, 'app.py'))
DATA = os.path.join(PANEL_DIR, 'data', 'softs') if _IN_PANEL else '/var/lib/vortex-softs'
TRUST = os.path.join(PANEL_DIR, 'panel', 'trust', 'softs.json')
UA = 'VortexPanel-softs'
CATALOG_MAX_AGE = 6 * 3600
AUTO_SOAK = 12 * 3600


class SoftError(Exception):
    pass


def _say(log, msg):
    (log or print)(str(msg))


# --------------------------------------------------------------------- config

def trust():
    """{"base_url": "...", "keys": ["base64 Ed25519 public key", ...]}"""
    try:
        d = json.load(open(TRUST))
    except (OSError, ValueError):
        d = {}
    env = os.environ.get('VP_SOFTS_BASE_URL')
    if env:
        d['base_url'] = env
    d.setdefault('base_url', '')
    d.setdefault('keys', [])
    return d


def configured():
    t = trust()
    return bool(t['base_url'] and t['keys'])


def settings():
    s = _read(os.path.join(DATA, 'settings.json'), {})
    return {'channel': s.get('channel') if s.get('channel') in ('stable', 'beta') else 'stable',
            'auto': s.get('auto') if s.get('auto') in ('off', 'security', 'all') else 'security',
            'notify': bool(s.get('notify', True))}


def save_settings(new):
    s = settings()
    s.update({k: v for k, v in (new or {}).items() if k in s})
    _write(os.path.join(DATA, 'settings.json'), settings_clean(s))
    return settings_clean(s)


def settings_clean(s):
    return {'channel': s['channel'] if s['channel'] in ('stable', 'beta') else 'stable',
            'auto': s['auto'] if s['auto'] in ('off', 'security', 'all') else 'security', 'notify': bool(s['notify'])}


# ---------------------------------------------------------------------- target

def target():
    """(target id or '', arch). AlmaLinux / Rocky / RHEL / Oracle / CentOS Stream /
    CloudLinux N -> elN; Ubuntu 22.04/24.04 -> ubuntu22/24; Debian 12/13."""
    osr = {}
    try:
        for line in open('/etc/os-release'):
            k, _, v = line.strip().partition('=')
            osr[k] = v.strip().strip('"')
    except OSError:
        pass
    ident = osr.get('ID', '').lower()
    like = osr.get('ID_LIKE', '').lower().split()
    ver = osr.get('VERSION_ID', '')
    major = ver.split('.')[0]
    arch = os.uname().machine
    arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}.get(arch, arch)
    t = ''
    if ident == 'ubuntu' and ver in ('22.04', '24.04'):
        t = 'ubuntu' + ver[:2]
    elif ident == 'debian' and major in ('12', '13'):
        t = 'debian' + major
    elif ident in ('rhel', 'almalinux', 'rocky', 'ol', 'centos', 'cloudlinux', 'eurolinux', 'navy') \
            or ('rhel' in like and ident != 'fedora'):
        if major in ('8', '9', '10'):
            t = 'el' + major
    return t, arch


def family():
    return 'deb' if shutil.which('apt-get') else ('rpm' if (shutil.which('dnf') or shutil.which('yum')) else '')


def file_keys():
    """Catalog file keys this server can use, best first."""
    t, a = target()
    keys = []
    if t:
        keys.append(f'{t}-{a}')
    keys += [f'linux-{a}', 'linux-noarch']
    return keys


# --------------------------------------------------------------------- helpers

def _read(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write(path, data):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = f'{path}.{os.getpid()}.{threading.get_ident()}.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


class _Lock:
    """One software operation at a time on this server (any process)."""
    def __init__(self, name='ops'):
        os.makedirs(DATA, mode=0o700, exist_ok=True)
        self.path = os.path.join(DATA, f'.{name}.lock')

    def __enter__(self):
        self.fh = open(self.path, 'a')
        try:
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.fh.close()
            raise SoftError('Another software install or update is running. Try again when it has finished.')
        return self

    def __exit__(self, *a):
        fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()


def vt(v):
    return tuple(int(x) if x.isdigit() else -1 for x in re.split(r'[.+-]', str(v)) if x != '')


def _http(url, timeout=60, limit=16 << 20):
    """GET with a size cap (a catalog is a few hundred KB)."""
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise SoftError(f'{url.split("?")[0]} is larger than expected')
    return data


def _run(cmd, log=None, env=None, timeout=3600, cwd=None):
    """Run a command, streaming its output to log. A watchdog stops the whole
    process group after `timeout` seconds even when it prints nothing."""
    import signal
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace',
                         env=env, cwd=cwd, stdin=subprocess.DEVNULL, start_new_session=True)
    timed_out = []

    def kill():
        timed_out.append(1)
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(p.pid, sig)
            except OSError:
                pass
            time.sleep(3)
    w = threading.Timer(timeout, kill)
    w.daemon = True
    w.start()
    try:
        for line in p.stdout:
            _say(log, line.rstrip('\n'))
        rc = p.wait()
    finally:
        w.cancel()
    if timed_out:
        _say(log, f'stopped after {timeout // 60} minutes')
        return -9
    return rc


# --------------------------------------------------------------------- catalog

def _verify(data, sig_b64, keys):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    sig = base64.b64decode(sig_b64.strip())
    for k in keys:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(k)).verify(sig, data)
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


def refresh(force=False, log=None):
    """Fetch and verify the catalog. Keeps the last good one on any failure."""
    path = os.path.join(DATA, 'catalog.json')
    meta = _read(os.path.join(DATA, 'catalog-meta.json'), {})
    if not force and time.time() - meta.get('checked', 0) < CATALOG_MAX_AGE and os.path.exists(path):
        return load()
    t = trust()
    if not (t['base_url'] and t['keys']):
        raise SoftError('The VortexPanel download server is not configured (panel/trust/softs.json).')
    base = t['base_url'].rstrip('/')
    meta['checked'] = int(time.time())
    try:
        raw = _http(f'{base}/catalog.json?t={int(time.time()) // 300}')
        sig = _http(f'{base}/catalog.json.sig?t={int(time.time()) // 300}').decode()
        if not _verify(raw, sig, t['keys']):
            raise SoftError('the catalog signature does not verify')
        cat = json.loads(raw)
        old = load() or {}
        if int(cat.get('serial') or 0) < int(old.get('serial') or 0):
            raise SoftError(f'the catalog is older than the one already in use ({cat.get("serial")} < {old.get("serial")})')
        # the pipeline re-signs the catalog every day; an expired one means someone is
        # holding this server on an old catalog (no security updates, no withdrawals)
        if int(cat.get('expires') or 0) and int(cat['expires']) < time.time():
            raise SoftError('the catalog has expired (the download server may be serving a stale copy)')
        os.makedirs(DATA, mode=0o700, exist_ok=True)
        tmp = f'{path}.{os.getpid()}.{threading.get_ident()}.tmp'
        with open(tmp, 'wb') as f:
            f.write(raw)
        os.replace(tmp, path)
        meta.update(serial=cat.get('serial'), error='', ok=int(time.time()))
        _write(os.path.join(DATA, 'catalog-meta.json'), meta)
        _say(log, f'catalog {cat.get("serial")} verified')
        return cat
    except Exception as e:  # noqa: BLE001
        meta['error'] = str(e)[:300]
        _write(os.path.join(DATA, 'catalog-meta.json'), meta)
        _say(log, f'catalog not updated: {e}')
        cur = load()
        if cur is None:
            raise SoftError(f'Could not load the software catalog: {e}')
        return cur


def load():
    return _read(os.path.join(DATA, 'catalog.json'))


def catalog_status():
    m = _read(os.path.join(DATA, 'catalog-meta.json'), {})
    c = load() or {}
    t, a = target()
    return {'configured': configured(), 'serial': c.get('serial'), 'generated': c.get('generated', ''),
            'checked': m.get('checked', 0), 'ok': m.get('ok', 0), 'error': m.get('error', ''),
            'target': t, 'arch': a, 'supported': bool(t), 'settings': settings()}


def releases(app, cat=None, channel=None):
    """Releases of app this server can install on its channel, newest first."""
    cat = cat if cat is not None else (load() or {})
    ch = channel or settings()['channel']
    keys = file_keys()
    out = []
    for r in ((cat.get('apps') or {}).get(app) or {}).get('releases') or []:
        if r.get('status', 'active') != 'active':
            continue
        if ch == 'stable' and r.get('channel') != 'stable':
            continue
        f = next((r['files'][k] for k in keys if k in (r.get('files') or {})), None)
        if f:
            out.append(dict(r, file=f))
    out.sort(key=lambda r: vt(r['version']), reverse=True)
    return out


def tracks(app, cat=None):
    """{track: newest installable release} for app."""
    out = {}
    for r in releases(app, cat):
        out.setdefault(r['track'], r)
    return out


def apps_available(cat=None):
    cat = cat if cat is not None else (load() or {})
    return sorted(a for a in (cat.get('apps') or {}) if releases(a, cat))


def withdrawn(app, version, cat=None):
    cat = cat if cat is not None else (load() or {})
    r = next((x for x in ((cat.get('apps') or {}).get(app) or {}).get('releases') or [] if x['version'] == version), None)
    return bool(r and r.get('status') == 'withdrawn')


# ----------------------------------------------------------------------- state

def state():
    return _read(os.path.join(DATA, 'state.json'), {})


def _save_state(st):
    _write(os.path.join(DATA, 'state.json'), st)


def installed(app):
    """{slot: {version, track, prefix, prev, installed}} where slot is 'current' or a track."""
    return state().get(app) or {}


def installed_version(app, track=None):
    slots = installed(app)
    if track:
        return (slots.get(track) or slots.get('current') or {}).get('version', '')
    vs = [s['version'] for s in slots.values() if s.get('version')]
    return max(vs, key=vt) if vs else ''


def updates(cat=None):
    """[{app, slot, track, from, to, security, notes}] for every installed app."""
    out = []
    for app, slots in state().items():
        tr = tracks(app, cat)
        for slot, s in slots.items():
            new = tr.get(s.get('track'))
            if new and vt(new['version']) > vt(s['version']):
                out.append({'app': app, 'slot': slot, 'track': s['track'], 'from': s['version'], 'to': new['version'],
                            'security': bool(new.get('security')), 'notes': new.get('notes', ''),
                            'cves': new.get('cves') or [], 'released': int(new.get('released') or 0)})
            if withdrawn(app, s['version'], cat):
                out.append({'app': app, 'slot': slot, 'track': s['track'], 'from': s['version'], 'to': '',
                            'withdrawn': True, 'prev': (s.get('prev') or {}).get('version', '')})
    return out


# -------------------------------------------------------------- packages (deps)

def _pkg_installed(name):
    fam = family()
    if fam == 'deb':
        r = subprocess.run(['dpkg-query', '-W', '-f=${Status}', name], capture_output=True, text=True)
        return 'install ok installed' in r.stdout
    if fam == 'rpm':
        if subprocess.run(['rpm', '-q', name], capture_output=True).returncode == 0:
            return True
        # EL9/10 images ship curl-minimal/libcurl-minimal, which conflict with curl/libcurl:
        # the minimal variant (or any package providing the name) counts as installed
        if subprocess.run(['rpm', '-q', '--whatprovides', name], capture_output=True).returncode == 0:
            return True
        return name in ('curl', 'libcurl') and \
            subprocess.run(['rpm', '-q', name + '-minimal'], capture_output=True).returncode == 0
    return False


def _pkg_exists(name):
    fam = family()
    if fam == 'deb':
        r = subprocess.run(['apt-cache', 'policy', name], capture_output=True, text=True)
        return 'Candidate:' in r.stdout and 'Candidate: (none)' not in r.stdout
    r = subprocess.run(['dnf', '-q', 'list', '--available', '--installed', name], capture_output=True, text=True)
    return r.returncode == 0


def ensure_packages(names, repos=(), log=None):
    """Install runtime packages. 'a|b' takes the first that exists here."""
    fam = family()
    if not fam or not names:
        return
    if fam == 'rpm' and repos:
        if 'epel' in repos and not _pkg_installed('epel-release'):
            _run(['dnf', '-y', '-q', 'install', 'epel-release'], log)
        if 'crb' in repos:
            subprocess.run('dnf config-manager --set-enabled crb 2>/dev/null || dnf config-manager --set-enabled powertools 2>/dev/null',
                           shell=True, capture_output=True)
    need = []
    for spec in names:
        # package names, or rpm capabilities such as perl(Sys::Hostname) that resolve on every
        # EL version whichever package carries the module there
        alts = [x for x in str(spec).split('|') if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+_:-]*', x)
                or (family() == 'rpm' and (re.fullmatch(r'perl\([A-Za-z0-9_:]{1,80}\)', x)
                                           or re.fullmatch(r'lib[A-Za-z0-9_.+-]{1,80}\.so\.[0-9.]+\(\)\(64bit\)', x)))]
        if not alts or any(_pkg_installed(a) for a in alts):
            continue
        pick = next((a for a in alts if len(alts) == 1 or _pkg_exists(a)), alts[0])
        need.append(pick)
    if not need:
        return
    _say(log, 'Installing runtime packages: ' + ' '.join(need))
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
    if fam == 'deb':
        rc = _run(['apt-get', 'install', '-y', '--no-install-recommends', '-o', 'Dpkg::Options::=--force-confold'] + need, log, env)
        if rc != 0:
            _run(['apt-get', 'update', '-qq'], log, env)
            rc = _run(['apt-get', 'install', '-y', '--no-install-recommends'] + need, log, env)
    else:
        rc = _run(['dnf', '-y', 'install'] + need, log, env)
    if rc != 0:
        raise SoftError('Runtime packages could not be installed: ' + ' '.join(need))


def replaced_packages(man):
    """OS packages of the same software that are installed now (they would clash)."""
    fam = family()
    pats = [p.format(track=man.get('track', ''), nodot=man.get('track', '').replace('.', ''))
            for p in (man.get('replaces') or {}).get(fam, [])]
    if not pats:
        return []
    if fam == 'deb':
        r = subprocess.run(['dpkg-query', '-W', '-f=${Package} ${Status}\n'], capture_output=True, text=True)
        have = [l.split()[0] for l in r.stdout.splitlines() if 'install ok installed' in l]
    else:
        r = subprocess.run(['rpm', '-qa', '--qf', '%{NAME}\n'], capture_output=True, text=True)
        have = r.stdout.split()
    import fnmatch
    return sorted({h for h in have for p in pats if fnmatch.fnmatchcase(h, p)})


# --------------------------------------------------------------------- install

def _slot(man):
    return man['track'] if man.get('coexist') else 'current'


def _link_path(man):
    return os.path.join(BASE, man['app'], _slot(man))


def _switch(link, target_dir):
    tmp = f'{link}.{os.getpid()}.new'
    if os.path.lexists(tmp):
        os.remove(tmp)
    os.symlink(target_dir, tmp)
    os.replace(tmp, link)


_RUN = threading.local()       # VP_RUN_ID: data copies are only restored by the run that made them


def _script_env(man, prefix, current, prev, action, init):
    env = dict(os.environ)
    env['VP_RUN_ID'] = getattr(_RUN, 'id', '') or uuid.uuid4().hex
    env.update(VP_APP=man['app'], VP_VERSION=man['version'], VP_TRACK=man['track'], VP_PREFIX=prefix,
               VP_CURRENT=current, VP_PREV=prev or '', VP_ACTION=action, VP_INIT=init, VP_FAMILY=family(),
               PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
    return env


def _script(prefix, name, env, log):
    p = os.path.join(prefix, '.vortex', 'scripts', name)
    if not os.path.exists(p):
        return 0
    _say(log, f'--- {name}')
    return _run(['bash', p], log, env, timeout=1800, cwd=os.path.dirname(p))


def read_zip(path):
    with zipfile.ZipFile(path) as z:
        man = json.loads(z.read('manifest.json'))
    for k in ('app', 'version', 'track', 'target', 'arch', 'prefix', 'payload_sha256'):
        if not man.get(k):
            raise SoftError(f'the package has no {k}')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,40}', man['app']) or not re.fullmatch(r'[0-9][0-9A-Za-z.+-]{0,40}', man['version']):
        raise SoftError('the package has an invalid name or version')
    if man['prefix'] != os.path.join(BASE, man['app'], man['version']):
        raise SoftError('the package installs outside its own folder')
    if not re.fullmatch(r'[0-9]+(\.[0-9]+){0,3}', man['track']):
        raise SoftError('the package has an invalid track')
    return man


def _unpack(path, man, stage):
    """Extract a verified zip into stage/files (owned by root, no unsafe paths)."""
    with zipfile.ZipFile(path) as z:
        z.extract('payload.tar.xz', stage)
        h = hashlib.sha256()
        with open(os.path.join(stage, 'payload.tar.xz'), 'rb') as f:
            for b in iter(lambda: f.read(1 << 20), b''):
                h.update(b)
        if h.hexdigest() != man['payload_sha256']:
            raise SoftError('the package contents do not match its manifest')
        files = os.path.join(stage, 'files')
        os.mkdir(files)
        with tarfile.open(os.path.join(stage, 'payload.tar.xz')) as tf:
            for m in tf.getmembers():
                n = os.path.normpath(m.name)
                if n.startswith(('/', '..')) or m.isdev() or (m.islnk() and os.path.normpath(m.linkname).startswith(('/', '..'))):
                    raise SoftError(f'unsafe path in the package: {m.name}')
            tf.extractall(files, filter='tar') if hasattr(tarfile, 'data_filter') else tf.extractall(files)
        sd = os.path.join(files, '.vortex', 'scripts')
        os.makedirs(sd)
        for n in z.namelist():
            if n.startswith('scripts/') and not n.endswith('/'):
                dst = os.path.join(sd, os.path.basename(n))
                with open(dst, 'wb') as f:
                    f.write(z.read(n))
                os.chmod(dst, 0o755)
        with open(os.path.join(files, '.vortex', 'manifest.json'), 'w') as f:
            json.dump(man, f, indent=1)
    # whatever the archive says, every file belongs to root and nobody else can write it
    for d, dirs, fs in os.walk(files):
        for n in [d] + [os.path.join(d, x) for x in dirs + fs]:
            os.lchown(n, 0, 0)
            if not os.path.islink(n):
                mode = os.lstat(n).st_mode & 0o7777
                os.chmod(n, mode & ~0o022 & ~0o6000)
    return files


def _apt_remove_extras(pkgs):
    """Packages apt would remove besides pkgs (dependents, e.g. a metapackage or phpMyAdmin)."""
    r = subprocess.run(['apt-get', '-s', 'remove'] + pkgs, capture_output=True, text=True,
                       env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'))
    out = []
    for l in r.stdout.splitlines():
        p = l.split()
        if len(p) > 1 and p[0] == 'Remv' and p[1] not in pkgs:
            out.append(p[1])
    return out


def install_zip(path, log=None, action='install', init=None, migrate=False):
    """Install (or update to) the software in a verified zip. Returns the manifest."""
    init = init or ('systemd' if os.path.isdir('/run/systemd/system') else 'none')
    _RUN.id = uuid.uuid4().hex      # every script of this install/update (and its restore) gets this id
    man = read_zip(path)
    t, a = target()
    if man['target'] != 'linux' and (man['target'] != t or man['arch'] != a):
        raise SoftError(f'this package is for {man["target"]}-{man["arch"]}, this server is {t or "unsupported"}-{a}')
    if man['target'] == 'linux' and man['arch'] not in (a, 'noarch'):
        raise SoftError(f'this package is for {man["arch"]}, this server is {a}')
    clash = replaced_packages(man)
    if clash and not migrate:
        raise SoftError(f'{man.get("name", man["app"])} is installed from the operating system packages '
                        f'({", ".join(clash[:4])}). Use the "Use VortexPanel build" button in the App Store to move it over.')
    if clash and family() != 'deb':
        # rpm -e renames changed configuration files to .rpmsave and Remi PHP keeps its
        # pools elsewhere: a switch would lose websites. Not offered until migrated safely.
        raise SoftError('Switching from the operating system packages is available on Ubuntu and Debian. '
                        'On this system the installed packages stay in use.')
    if clash:
        extra = _apt_remove_extras(clash)
        if extra:
            raise SoftError('Removing the operating system packages would also remove: ' + ', '.join(extra[:10])
                            + '. Nothing was changed.')
    prefix = man['prefix']
    link = _link_path(man)
    prev = os.path.realpath(link) if os.path.islink(link) else ''
    if prev == prefix:
        raise SoftError(f'{man["app"]} {man["version"]} is already the version in use')
    _say(log, f'Installing {man.get("name", man["app"])} {man["version"]} ({man["target"]}-{man["arch"]})')


    # unpack next to the other versions; nothing on the system changes before this works
    root = _ensure_dir(os.path.join(BASE, man['app']))
    stage = tempfile.mkdtemp(prefix=f'.{man["app"]}-', dir=root)
    aside = ''
    try:
        files = _unpack(path, man, stage)
        if os.path.exists(prefix):
            # same version again (a reinstall, or the rollback copy): keep it until this works
            aside = f'{prefix}.aside-{os.getpid()}'
            os.rename(prefix, aside)
        os.rename(files, prefix)
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    removed_pkgs = []
    kept = []
    env = _script_env(man, prefix, link, prev, action if not migrate else 'migrate', init)
    # precheck.sh: conditions this version needs, checked while nothing on the system has
    # changed yet (e.g. Apache: PHP-FPM must exist before mod_php can be replaced)
    if _script(prefix, 'precheck.sh', env, log) != 0:
        shutil.rmtree(prefix, ignore_errors=True)
        if aside and not os.path.lexists(prefix):
            os.rename(aside, prefix)
        try:
            os.rmdir(root)
        except OSError:
            pass
        raise SoftError(f'{man.get("name", man["app"])} {man["version"]}: a required condition is not met (see above). Nothing was changed.')
    # runtime packages: a missing library would only show up at activate
    try:
        ensure_packages((man.get('run_deps') or {}).get(family(), []), man.get('rpm_repos') or [], log)
    except Exception:
        shutil.rmtree(prefix, ignore_errors=True)
        if aside and not os.path.lexists(prefix):
            os.rename(aside, prefix)
        raise
    try:
        if clash:
            # files the OS package's removal scripts could delete or reset (e.g. OpenLiteSpeed's
            # /usr/local/lsws/conf): copied first, put back exactly after the removal
            kept = _keep_copy(man, log)
            _say(log, 'Stopping and removing the operating system packages (configuration files are kept): ' + ', '.join(clash))
            if man.get('service'):
                subprocess.run(['systemctl', 'stop', man['service']], capture_output=True, timeout=120)
            removed_pkgs = clash
            rc = _run(['apt-get', 'remove', '-y', '-o', 'DPkg::Lock::Timeout=300'] + clash, log,
                      dict(os.environ, DEBIAN_FRONTEND='noninteractive'))
            if rc != 0:
                raise SoftError('the operating system packages could not be removed')
            bad = _keep_put_back(kept, log)
            if bad:
                raise SoftError('could not put back ' + ', '.join(bad) + ' after removing the packages')
        if _script(prefix, 'install.sh', env, log) != 0:
            raise SoftError('install.sh failed')
        # data safety (databases): stop the running version and copy its data before
        # the new version can upgrade it; postfail.sh puts the copy back on failure
        if prev and _script(prefix, 'preupdate.sh', env, log) != 0:
            raise SoftError('the data could not be backed up before the update (see above)')
        _switch(link, prefix)
        if _script(prefix, 'activate.sh', env, log) != 0:
            raise SoftError('the new version did not start')
        if _script(prefix, 'check.sh', env, log) != 0:
            raise SoftError('the new version failed its health check')
    except Exception as e:  # noqa: BLE001 - whatever failed, the server must get its old setup back
        msg = str(e) if isinstance(e, SoftError) else f'{type(e).__name__}: {e}'
        _say(log, f'{msg} -- going back')
        try:
            if prev:
                _script(prefix, 'postfail.sh', env, log)     # e.g. stop the new database, restore its data copy
            _restore(man, link, prev, init, log, removed_pkgs)
        finally:
            if kept:
                # after the packages are back: the files exactly as they were, then the
                # service restarted on them; a copy that could not be put back is kept
                bad = _keep_put_back(kept, log)
                if man.get('service'):
                    subprocess.run(['systemctl', 'restart', man['service']], capture_output=True, timeout=180)
                if bad:
                    _say(log, 'NOT restored: ' + ', '.join(bad) + f' -- copies are in {os.path.dirname(kept[0][1])}')
                else:
                    _keep_drop(kept)
            shutil.rmtree(prefix, ignore_errors=True)
            if aside:
                os.rename(aside, prefix)
            try:
                os.rmdir(root)            # only when empty (a failed first install)
            except OSError:
                pass
        raise SoftError(f'{man.get("name", man["app"])} {man["version"]}: {msg}. '
                        + ('The previous version is running again.' if prev else
                           'The operating system packages were reinstalled.' if removed_pkgs else 'Nothing was changed.'))
    if aside:
        shutil.rmtree(aside, ignore_errors=True)
    _keep_drop(kept)

    st = state()
    slots = st.setdefault(man['app'], {})
    old = slots.get(_slot(man)) or {}
    slots[_slot(man)] = {'version': man['version'], 'track': man['track'], 'prefix': prefix,
                         'installed': int(time.time()), 'target': f'{man["target"]}-{man["arch"]}',
                         'service': man.get('service', ''),
                         'prev': {'version': old.get('version'), 'prefix': old.get('prefix')} if old.get('version') else None}
    _save_state(st)
    _prune(man['app'], st)
    _say(log, f'{man.get("name", man["app"])} {man["version"]} is installed and running.')
    return man


def _ensure_dir(p):
    os.makedirs(p, mode=0o755, exist_ok=True)
    return p


KEEP_DIR = os.path.join(DATA, 'keep')


def _keep_copy(man, log):
    """Copy the manifest's keep_on_switch paths to DATA/keep/<run>/ (outside every tree a
    package removal could delete): [(path, copy)]. Any problem: nothing is kept, raise."""
    paths = []
    for p in man.get('keep_on_switch') or []:
        p = os.path.normpath(str(p))
        if not re.fullmatch(r'/(etc|usr/local|var/lib|opt|srv)/[A-Za-z0-9._/+-]{1,200}', p) or '..' in p.split('/'):
            raise SoftError(f'invalid keep_on_switch path in the package: {p}')
        if os.path.lexists(p):
            paths.append(p)
    if not paths:
        return []
    base = _ensure_dir(os.path.join(KEEP_DIR, getattr(_RUN, 'id', '') or uuid.uuid4().hex))
    need = 0
    for p in paths:
        r = subprocess.run(['du', '-sk', p], capture_output=True, text=True, timeout=600)
        need += int((r.stdout.split() or ['0'])[0]) * 1024
    st = os.statvfs(base)
    if st.f_bavail * st.f_frsize < need * 1.1 + 100 * 1024 * 1024:
        shutil.rmtree(base, ignore_errors=True)
        raise SoftError(f'not enough free disk space to keep a copy of {", ".join(paths)} during the switch. Nothing was changed.')
    out = []
    try:
        for n, p in enumerate(paths):
            copy = os.path.join(base, str(n))
            r = subprocess.run(['cp', '-a', p, copy], capture_output=True, text=True, timeout=3600)
            if r.returncode != 0:
                raise SoftError(f'could not copy {p} before removing the operating system packages: {r.stderr.strip()[-200:]}')
            out.append((p, copy))
            _say(log, f'kept a copy of {p}')
    except Exception:
        shutil.rmtree(base, ignore_errors=True)
        raise
    return out


def _keep_put_back(kept, log):
    """Make each kept path exactly what it was before the package removal.
    Returns the paths that could NOT be put back (their copies stay where they are)."""
    failed = []
    for p, copy in kept:
        if not os.path.lexists(copy):
            failed.append(p)
            _say(log, f'the kept copy of {p} is missing ({copy})')
            continue
        tmp = f'{p}.vortex-restore'
        try:
            os.makedirs(os.path.dirname(p), mode=0o755, exist_ok=True)   # the removal may have taken the parent too
            subprocess.run(['rm', '-rf', tmp], timeout=600, check=True)
            subprocess.run(['cp', '-a', copy, tmp], capture_output=True, text=True, timeout=3600, check=True)
            if os.path.lexists(p):
                subprocess.run(['rm', '-rf', p], timeout=600, check=True)
            os.rename(tmp, p)
            _say(log, f'{p} is as it was before the switch')
        except Exception:  # noqa: BLE001
            failed.append(p)
            _say(log, f'could not put back {p}; its copy is kept in {copy}')
    return failed


def _keep_drop(kept):
    """Remove the copies (only once every path was put back)."""
    if kept:
        shutil.rmtree(os.path.dirname(kept[0][1]), ignore_errors=True)


def _restore(man, link, prev, init, log, removed_pkgs):
    if prev and os.path.isdir(prev):
        _switch(link, prev)
        pman = _read(os.path.join(prev, '.vortex', 'manifest.json'), man)
        env = _script_env(pman, prev, link, '', 'rollback', init)
        _script(prev, 'install.sh', env, log)
        rc = _script(prev, 'activate.sh', env, log)
        if rc == 0:
            rc = _script(prev, 'check.sh', env, log)
        _say(log, f'previous version {pman.get("version")} ' + ('is running again' if rc == 0 else 'did not start -- check the service'))
    else:
        # first install / switch failed: undo whatever install.sh wrote (units, links,
        # config edits made for the switch) -- the scripts see VP_ACTION=abort
        env = _script_env(man, man['prefix'], link, '', 'abort', init)
        if os.path.isdir(man['prefix']):
            _script(man['prefix'], 'uninstall.sh', env, log)
        if os.path.islink(link):
            os.remove(link)
    if removed_pkgs:
        _say(log, 'Reinstalling the operating system packages that were removed: ' + ' '.join(removed_pkgs))
        env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
        _run((['apt-get', 'install', '-y', '-o', 'DPkg::Lock::Timeout=300', '-o', 'Dpkg::Options::=--force-confold']
              if family() == 'deb' else ['dnf', '-y', 'install']) + removed_pkgs, log, env)
        if man.get('service'):
            subprocess.run(['systemctl', 'restart', man['service']], capture_output=True, timeout=120)


def _prune(app, st):
    """Keep the version in use and the previous one of every slot."""
    keep = set()
    for s in (st.get(app) or {}).values():
        keep.add(s.get('prefix'))
        keep.add((s.get('prev') or {}).get('prefix'))
    root = os.path.join(BASE, app)
    for name in os.listdir(root):
        p = os.path.join(root, name)
        if os.path.isdir(p) and not os.path.islink(p) and not name.startswith('.') and p not in keep \
                and re.fullmatch(r'[0-9][0-9A-Za-z.+-]*', name):
            shutil.rmtree(p, ignore_errors=True)


def download(app, version, log=None, cat=None):
    """Download the right file for this server and check it against the signed catalog."""
    cat = cat if cat is not None else (load() or {})
    r = next((x for x in releases(app, cat, channel='beta') if x['version'] == version), None)
    if not r:
        raise SoftError(f'{app} {version} is not available for this server')
    return _fetch(r['file'], log), r


def _fetch(f, log=None):
    """Download one catalog file entry {key, sha256, size}; checked against the signed catalog."""
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/+-]{0,300}', f.get('key', '')) or '..' in f['key']:
        raise SoftError('invalid file name in the catalog')
    url = trust()['base_url'].rstrip('/') + '/' + f['key'].lstrip('/')
    d = _ensure_dir(os.path.join(DATA, 'downloads'))
    dest = os.path.join(d, os.path.basename(f['key']))
    _say(log, f'Downloading {os.path.basename(f["key"])} ({int(f.get("size", 0)) // 1024 // 1024} MB)')
    h = hashlib.sha256()
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    cap = int(f.get('size') or 0) + (1 << 20)
    got = 0
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest + '.part', 'wb') as out:
        while True:
            b = resp.read(1 << 20)
            if not b:
                break
            got += len(b)
            if got > cap:
                out.close()
                os.remove(dest + '.part')
                raise SoftError('the download is larger than the signed catalog says -- not installed')
            h.update(b)
            out.write(b)
    if h.hexdigest() != f['sha256']:
        os.remove(dest + '.part')
        raise SoftError('the download does not match the signed catalog (checksum) -- not installed')
    os.replace(dest + '.part', dest)
    return dest


def install(app, version, log=None, action='install', migrate=False):
    with _Lock():
        cat = refresh(log=log)
        path, rel = download(app, version, log, cat)
        try:
            man = install_zip(path, log, action=action, migrate=migrate)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
        if rel.get('notes'):
            _say(log, 'Release notes: ' + rel['notes'])
        return man


def update(app, slot=None, log=None):
    slots = installed(app)
    if not slots:
        raise SoftError(f'{app} is not installed from a VortexPanel build')
    slot = slot or next(iter(slots))
    s = slots.get(slot)
    if not s:
        raise SoftError(f'{app} {slot} is not installed')
    new = tracks(app, refresh(log=log)).get(s['track'])
    if not new or vt(new['version']) <= vt(s['version']):
        raise SoftError(f'{app} {s["version"]} is already the newest version on its track')
    return install(app, new['version'], log, action='update')


def rollback(app, slot=None, log=None, init=None):
    """Go back to the previous version kept on disk."""
    init = init or ('systemd' if os.path.isdir('/run/systemd/system') else 'none')
    with _Lock():
        st = state()
        slots = st.get(app) or {}
        slot = slot or next(iter(slots), None)
        s = slots.get(slot) if slot else None
        if not s or not (s.get('prev') or {}).get('prefix') or not os.path.isdir(s['prev']['prefix']):
            raise SoftError('No previous version is kept for this software')
        prev = s['prev']['prefix']
        man = _read(os.path.join(prev, '.vortex', 'manifest.json'))
        link = _link_path(man)
        cur = s['prefix']
        env = _script_env(man, prev, link, cur, 'rollback', init)
        _switch(link, prev)
        _script(prev, 'install.sh', env, log)
        if _script(prev, 'activate.sh', env, log) != 0 or _script(prev, 'check.sh', env, log) != 0:
            _switch(link, cur)
            cman = _read(os.path.join(cur, '.vortex', 'manifest.json'), man)
            _script(cur, 'activate.sh', _script_env(cman, cur, link, prev, 'update', init), log)
            raise SoftError(f'{man["version"]} did not start; {s["version"]} stays in use')
        slots[slot] = {'version': man['version'], 'track': man['track'], 'prefix': prev, 'installed': int(time.time()),
                       'target': s.get('target'), 'service': s.get('service', ''),
                       'prev': {'version': s['version'], 'prefix': cur}}
        _save_state(st)
        _say(log, f'{app} is back on {man["version"]}')
        return man


def uninstall(app, slot=None, log=None, init=None):
    init = init or ('systemd' if os.path.isdir('/run/systemd/system') else 'none')
    with _Lock():
        st = state()
        slots = st.get(app) or {}
        todo = [slot] if slot else list(slots)
        for sl in todo:
            s = slots.get(sl)
            if not s:
                continue
            man = _read(os.path.join(s['prefix'], '.vortex', 'manifest.json')) or \
                {'app': app, 'version': s['version'], 'track': s['track'], 'prefix': s['prefix']}
            link = os.path.join(BASE, app, sl)
            rc = _script(s['prefix'], 'uninstall.sh', _script_env(man, s['prefix'], link, '', 'uninstall', init), log)
            if rc == 3:                 # refuse(): removing it now would break something that uses it
                _save_state(st)
                raise SoftError(f'{man.get("name", app)} {s["version"]} was not removed (see the reason above).')
            if os.path.islink(link):
                os.remove(link)
            for p in (s['prefix'], (s.get('prev') or {}).get('prefix')):
                if p and p.startswith(BASE + '/') and os.path.isdir(p):
                    shutil.rmtree(p, ignore_errors=True)
            slots.pop(sl, None)
            _say(log, f'{app} {s["version"]} removed (configuration files are kept)')
        if not slots:
            st.pop(app, None)
            try:
                os.rmdir(os.path.join(BASE, app))
            except OSError:
                pass
        _save_state(st)


def pinned(app, cat=None):
    """Mirrored release files of a tool (phpMyAdmin, Adminer, Roundcube, Anubis, ffmpeg),
    newest first: [{version, track, files: {name: {url, sha256, size}}}]."""
    cat = cat if cat is not None else (load() or {})
    base = trust()['base_url'].rstrip('/')
    out = []
    for r in ((cat.get('pinned') or {}).get(app) or {}).get('releases') or []:
        if r.get('status', 'active') != 'active':
            continue
        files = {}
        for name, f in (r.get('files') or {}).items():
            key = str(f.get('key') or '')
            if re.fullmatch(r'pinned/[A-Za-z0-9._/+-]{1,300}', key) and '..' not in key and \
                    re.fullmatch(r'[0-9a-f]{64}', str(f.get('sha256') or '')):
                files[name] = {'url': f'{base}/{key}', 'sha256': f['sha256'], 'size': int(f.get('size') or 0)}
        if files:
            out.append({'version': r['version'], 'track': r.get('track', ''), 'files': files})
    out.sort(key=lambda r: vt(r['version']), reverse=True)
    return out


# ------------------------------------------------------------ panel Apps (cloud)

def panel_apps(cat=None, channel=None):
    """{app id: newest installable release} of VortexPanel Apps published in the catalog.
    A release: version, channel, status, requires_core, manifest (listing fields), file."""
    cat = cat if cat is not None else (load() or {})
    ch = channel or settings()['channel']
    out = {}
    for aid, entry in (cat.get('panel_apps') or {}).items():
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,40}', aid):
            continue
        for r in sorted(entry.get('releases') or [], key=lambda r: vt(r.get('version', '0')), reverse=True):
            if r.get('status', 'active') != 'active' or (ch == 'stable' and r.get('channel') != 'stable'):
                continue
            if isinstance(r.get('file'), dict) and r['file'].get('sha256'):
                out[aid] = r
                break
    return out


def fetch_panel_app(aid, version, dest, log=None):
    """Download a published App and unpack it into dest (plugin.json at the top).
    Regular files only; the zip's sha256 comes from the signed catalog."""
    r = panel_apps(refresh(log=log), channel='beta').get(aid)
    if not r or r['version'] != version:
        raise SoftError(f'App {aid} {version} is not in the catalog')
    path = _fetch(r['file'], log)
    try:
        shutil.rmtree(dest, ignore_errors=True)
        os.makedirs(dest, mode=0o755)
        n = size = 0
        with zipfile.ZipFile(path) as z:
            for zi in z.infolist():
                name = os.path.normpath(zi.filename)
                if zi.is_dir():
                    continue
                if name.startswith(('/', '..')) or (zi.external_attr >> 16) & 0o170000 == 0o120000:
                    raise SoftError(f'unsafe file in the App package: {zi.filename}')
                n += 1
                size += zi.file_size
                if n > 2000 or size > 64 << 20:
                    raise SoftError('the App package is too large')
                out = os.path.join(dest, name)
                os.makedirs(os.path.dirname(out), mode=0o755, exist_ok=True)
                with z.open(zi) as src, open(out, 'wb') as f:
                    shutil.copyfileobj(src, f)
                os.chmod(out, 0o644)
        man = _read(os.path.join(dest, 'plugin.json'), {})
        if man.get('id') != aid or man.get('version') != version or man.get('kind') != 'app':
            raise SoftError('the App package does not match the catalog (id/version)')
        return dest
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


# ------------------------------------------------------------- periodic check

def periodic(log=None):
    """Every 6 hours (systemd timer): new catalog, notifications, automatic updates."""
    if not configured():
        return 'not configured'
    cat = refresh(force=True, log=log)
    s = settings()
    ups = updates(cat)
    notified = _read(os.path.join(DATA, 'notified.json'), {})
    for u in ups:
        key = f"{u['app']}:{u['slot']}:{u.get('to') or 'withdrawn:' + u['from']}"
        if key in notified:
            continue
        notified[key] = int(time.time())
        if s['notify']:
            if u.get('withdrawn'):
                _notify(f'{u["app"]} {u["from"]} was withdrawn',
                        f'VortexPanel withdrew {u["app"]} {u["from"]}. Roll back in App Store'
                        + (f' (to {u["prev"]}).' if u.get('prev') else '.'))
            else:
                _notify(f'Update available: {u["app"]} {u["to"]}',
                        f'{u["app"]} {u["from"]} -> {u["to"]}' + (' (security update)' if u['security'] else '')
                        + (f'. {u["notes"][:300]}' if u.get('notes') else ''))
    _write(os.path.join(DATA, 'notified.json'), {k: v for k, v in notified.items() if time.time() - v < 90 * 86400})
    done = []
    for u in ups:
        if u.get('withdrawn') or not u.get('to'):
            continue
        # automatic installs wait AUTO_SOAK after release: a bad build is usually
        # withdrawn by then (security releases skip the beta channel)
        if time.time() - u.get('released', 0) < AUTO_SOAK:
            continue
        if s['auto'] == 'all' or (s['auto'] == 'security' and u['security']):
            try:
                update(u['app'], u['slot'], log)
                done.append(f'{u["app"]} {u["to"]}')
                _notify(f'Updated: {u["app"]} {u["to"]}', f'{u["app"]} was updated automatically from {u["from"]} to {u["to"]}.')
            except Exception as e:  # noqa: BLE001
                _notify(f'Update failed: {u["app"]} {u["to"]}', f'The automatic update of {u["app"]} to {u["to"]} failed: {e}')
    return f'{len(ups)} update(s) found' + (f', installed: {", ".join(done)}' if done else '')


def _notify(title, detail):
    log_path = os.path.join(DATA, 'events.jsonl')
    try:
        os.makedirs(DATA, mode=0o700, exist_ok=True)
        with open(log_path, 'a') as f:
            f.write(json.dumps({'t': int(time.time()), 'title': title, 'detail': detail}) + '\n')
    except OSError:
        pass
    if not _IN_PANEL:
        return
    try:
        sys.path.insert(0, PANEL_DIR) if PANEL_DIR not in sys.path else None
        from panel import alerts
        cfg = alerts.load()
        if cfg.get('enabled') and (cfg.get('rules', {}).get('updates') or {'enabled': True}).get('enabled', True):
            host = alerts.server_name()
            alerts.send(f'[{host}] {title}', detail, cfg, {'event': 'software-update', 'server': host})
    except Exception:  # noqa: BLE001
        pass


def events(limit=50):
    try:
        lines = open(os.path.join(DATA, 'events.jsonl')).read().splitlines()[-limit:]
    except OSError:
        return []
    out = []
    for l in reversed(lines):
        try:
            out.append(json.loads(l))
        except ValueError:
            pass
    return out


# ------------------------------------------------------------------------- CLI

def main(argv):
    args = argv[1:]
    cmd = args[0] if args else ''
    init = None
    if '--init' in args:
        init = args[args.index('--init') + 1]
        args = [a for i, a in enumerate(args) if a != '--init' and (i == 0 or args[i - 1] != '--init')]
    try:
        if cmd == 'target':
            print('-'.join(target()))
        elif cmd == 'install-zip':
            install_zip(args[1], init=init, migrate='--migrate' in args)
        elif cmd == 'install':
            install(args[1], args[2], migrate='--migrate' in args)
        elif cmd == 'update':
            update(args[1], args[2] if len(args) > 2 else None)
        elif cmd == 'rollback':
            rollback(args[1], args[2] if len(args) > 2 else None, init=init)
        elif cmd == 'uninstall':
            uninstall(args[1], args[2] if len(args) > 2 else None, init=init)
        elif cmd == 'status':
            print(json.dumps({'catalog': catalog_status(), 'installed': state(), 'updates': updates()}, indent=1))
        elif cmd == 'refresh':
            refresh(force=True)
        elif cmd == 'periodic':
            print(periodic())
        else:
            print(__doc__)
            return 2
    except SoftError as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
