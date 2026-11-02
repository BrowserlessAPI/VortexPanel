"""Real, installable updates for App Store software.

"Update available" is shown only when the server's own package sources offer a
newer build of a package the software is made of (apt: `apt list --upgradable`,
dnf: `dnf check-update`). Comparing with the newest upstream release was wrong:
Ubuntu keeps Python 3.12.3 and ships fixes as 3.12.3-1ubuntu0.N, so a "3.12.16"
badge could never be installed. Clicking the badge runs exactly the upgrade that
was found, for that software's packages only.

The package lists are refreshed in the background at most every 6 hours (one
worker at a time, under a file lock) and right after an install or update.
"""
import fcntl
import fnmatch
import json
import os
import re
import shutil
import subprocess
import threading
import time

PANEL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(PANEL_DIR, 'data', 'module_updates.json')
LOCK = os.path.join(PANEL_DIR, 'data', '.module_updates.lock')
MAX_AGE = 6 * 3600

# module id -> (Debian/Ubuntu package globs, RHEL-family package globs, services to restart)
PKGS = {
    'nginx':         (['nginx', 'nginx-*', 'libnginx-mod-*'], ['nginx', 'nginx-*'], ['nginx']),
    'apache2':       (['apache2', 'apache2-*', 'libapache2-mod-*'], ['httpd', 'httpd-*', 'mod_ssl'], ['apache2', 'httpd']),
    'openlitespeed': (['openlitespeed'], ['openlitespeed'], ['lsws']),
    'caddy':         (['caddy'], ['caddy'], ['caddy']),
    'mysql':         (['mysql-server*', 'mysql-client*', 'mysql-common', 'mysql-community-*'],
                      ['mysql-community-*', 'mysql-server', 'mysql'], ['mysql', 'mysqld']),
    'mariadb':       (['mariadb-*', 'libmariadb3'], ['MariaDB-*', 'mariadb', 'mariadb-*'], ['mariadb']),
    'mongodb':       (['mongodb-org*', 'mongodb-mongosh'], ['mongodb-org*', 'mongodb-mongosh'], ['mongod']),
    'postgresql':    (['postgresql', 'postgresql-[0-9]*', 'postgresql-client*', 'postgresql-common', 'postgresql-contrib*', 'libpq5'],
                      ['postgresql', 'postgresql-*', 'postgresql[0-9]*'], []),
    'php':           (['php[0-9].[0-9]*', 'php-common'], ['php', 'php-*', 'php[0-9][0-9]-php*'], []),
    'pure-ftpd':     (['pure-ftpd*'], ['pure-ftpd'], ['pure-ftpd']),
    'fail2ban':      (['fail2ban'], ['fail2ban', 'fail2ban-*'], ['fail2ban']),
    'postfix':       (['postfix', 'postfix-*'], ['postfix'], ['postfix']),
    'clamav':        (['clamav', 'clamav-*', 'libclamav*'], ['clamav', 'clamav-*', 'clamd'], []),
    'bind9':         (['bind9', 'bind9-*'], ['bind', 'bind-*'], ['named', 'bind9']),
    'nodejs':        (['nodejs'], ['nodejs'], []),
    'python':        (['python3.[0-9]', 'python3.[0-9][0-9]', 'python3.*-venv', 'python3.*-dev', 'libpython3.*',
                       'python3-pip', 'python3-venv'], ['python3', 'python3.[0-9]*', 'python3-pip', 'python3-libs'], []),
    'docker':        (['docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-buildx-plugin', 'docker-compose-plugin'],
                      ['docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-buildx-plugin', 'docker-compose-plugin'], []),
    'redis':         (['redis', 'redis-server', 'redis-tools'], ['redis'], []),
    'supervisor':    (['supervisor'], ['supervisor'], []),
    'memcached':     (['memcached'], ['memcached'], []),
}

_bg = {'running': False}


def family():
    if shutil.which('apt-get'):
        return 'deb'
    if shutil.which('dnf') or shutil.which('yum'):
        return 'rpm'
    return ''


def _run(cmd, timeout):
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', LC_ALL='C')
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, r.stdout
    except Exception:  # noqa: BLE001
        return -1, ''


def _scan_deb():
    """{package: {'old': ver, 'new': ver}} from the local package lists."""
    rc, out = _run(['apt', 'list', '--upgradable'], 120)
    pk = {}
    for line in out.splitlines():
        m = re.match(r'^([^/\s]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from:\s*([^\]]+)\]', line)
        if m:
            pk[m.group(1)] = {'new': m.group(2), 'old': m.group(3).strip()}
    return pk


def _scan_rpm():
    tool = 'dnf' if shutil.which('dnf') else 'yum'
    rc, out = _run([tool, '-q', 'check-update'], 300)
    pk = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and '.' in parts[0] and not line.startswith(' '):
            name = parts[0].rsplit('.', 1)[0]
            pk[name] = {'new': parts[1], 'old': ''}
    if pk:
        rc, out = _run(['rpm', '-q', '--qf', '%{NAME} %{VERSION}-%{RELEASE}\n'] + sorted(pk), 60)
        for line in out.splitlines():
            p = line.split()
            if len(p) == 2 and p[0] in pk:
                pk[p[0]]['old'] = p[1]
    return pk


def refresh(fetch=True):
    """Re-read what the package sources offer. fetch=False skips downloading the
    package lists (used right after an update: the lists are already fresh)."""
    fam = family()
    if not fam:
        return {}
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    with open(LOCK, 'a') as lk:
        try:
            fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return load()            # another worker is refreshing right now
        try:
            if fam == 'deb':
                if fetch:
                    _run(['apt-get', 'update', '-qq'], 600)
                pk = _scan_deb()
            else:
                pk = _scan_rpm()
            data = {'t': int(time.time()), 'family': fam, 'pkgs': pk}
            tmp = CACHE + f'.{os.getpid()}.tmp'
            with open(tmp, 'w') as f:
                json.dump(data, f)
            os.replace(tmp, CACHE)
            return data
        finally:
            fcntl.flock(lk, fcntl.LOCK_UN)


def load():
    try:
        with open(CACHE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def refresh_async(force=False):
    d = load()
    if _bg['running'] or (not force and d and time.time() - d.get('t', 0) < MAX_AGE):
        return
    _bg['running'] = True

    def go():
        try:
            refresh(fetch=True)
            try:
                from panel.routes.os_utils import panel_cache
                panel_cache.invalidate('modules_list')
            except Exception:  # noqa: BLE001
                pass
        finally:
            _bg['running'] = False
    threading.Thread(target=go, daemon=True).start()


def _globs(mod_id, fam):
    spec = PKGS.get(mod_id)
    if not spec:
        return []
    return spec[0] if fam == 'deb' else spec[1]


def _upstream(v):
    """'2:8.5.12-1+ubuntu24.04.1+deb.sury.org+1' -> '8.5.12'; '5:29.9.2-1~ubuntu' -> '29.9.2'."""
    v = v.split(':', 1)[-1]
    m = re.match(r'(\d+(?:\.\d+)*)', v)
    return m.group(1) if m else v


def for_module(mod_id, installed_ver='', data=None):
    """None, or {'packages': [...], 'version': shown version, 'security': bool}."""
    data = data if data is not None else load()
    pk = data.get('pkgs') or {}
    globs = _globs(mod_id, data.get('family'))
    if not pk or not globs:
        return None
    hits = sorted(n for n in pk if any(fnmatch.fnmatchcase(n, g) for g in globs))
    if mod_id == 'php':          # never the phpMyAdmin package, even if a glob would match it
        hits = [n for n in hits if not n.startswith('phpmyadmin')]
    if not hits:
        return None
    news = [_upstream(pk[n]['new']) for n in hits]
    track = '.'.join(installed_ver.split('.')[:2]) if installed_ver else ''
    same = [v for v in news if track and (v == track or v.startswith(track + '.'))]
    pool = same or news

    def key(v):
        return tuple(int(x) for x in re.findall(r'\d+', v)[:4])
    shown = max(pool, key=key)
    # Same upstream version, newer distribution build (Ubuntu/Debian backport fixes
    # this way): show it as a security update, not as a version change.
    security = all(_upstream(pk[n].get('old') or '') == _upstream(pk[n]['new']) for n in hits) or \
        (bool(installed_ver) and key(shown) <= key(installed_ver))
    return {'packages': hits, 'version': installed_ver if security else shown, 'security': security,
            'details': [{'name': n, 'from': pk[n].get('old', ''), 'to': pk[n]['new']} for n in hits]}


def update_command(mod_id, packages):
    """Shell command that upgrades only these packages (never installs new ones,
    never touches configuration files the admin changed)."""
    safe = [p for p in packages if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+_:-]*', p)]
    if not safe:
        return ''
    if family() == 'deb':
        return ('DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade '
                '-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold ' + ' '.join(safe))
    tool = 'dnf' if shutil.which('dnf') else 'yum'
    return f'{tool} upgrade -y ' + ' '.join(safe)


def services_after(mod_id, packages):
    """Services to restart after the upgrade (only those that are running)."""
    svcs = list(PKGS.get(mod_id, ((), (), []))[2])
    if mod_id == 'php':
        for p in packages:
            m = re.match(r'php(\d\.\d)-fpm$', p) or re.match(r'php(\d)(\d)-php-fpm$', p)
            if m:
                svcs.append(f'php{m.group(1)}-fpm' if len(m.groups()) == 1 else f'php{m.group(1)}{m.group(2)}-php-fpm')
        if 'php-fpm' in packages:
            svcs.append('php-fpm')
    if mod_id == 'postgresql':
        svcs.append('postgresql')
    if mod_id == 'redis':
        svcs += ['redis-server', 'redis']
    return svcs


def forget(packages):
    """Drop upgraded packages from the cache at once, so the badge disappears
    even before the next background refresh."""
    d = load()
    if not d:
        return
    for p in packages:
        (d.get('pkgs') or {}).pop(p, None)
    try:
        tmp = CACHE + f'.{os.getpid()}.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f)
        os.replace(tmp, CACHE)
    except OSError:
        pass
