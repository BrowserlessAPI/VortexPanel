"""Panel accounts, roles and API keys.

The main administrator lives in credentials.json (unchanged since v1, so
upgrades and the CLI keep working). Additional accounts are stored in
data/users.json and API keys in data/api_keys.json. Every write goes through
an atomic temp-file + rename, mode 0600.

Roles
  admin  - everything.
  site   - only the websites assigned to the account: their settings, SSL,
           backups, WordPress tools and their files. No terminal, cron,
           databases, App Store or panel settings (each of those runs as root).
  viewer - read-only dashboards: monitoring, bandwidth, service and site
           status. Cannot read files, logs, settings or backups.
"""
import hashlib
import json
import os
import re
import secrets
import time

DATA_DIR = '/opt/vortexpanel/data'
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
KEYS_FILE = os.path.join(DATA_DIR, 'api_keys.json')

ROLES = {
    'admin':  'Administrator - full access',
    'site':   'Site manager - only the assigned websites and their files',
    'viewer': 'Viewer - read-only monitoring and status',
}

USERNAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._@-]{2,63}$')


def _atomic_write(path, data, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f'{path}.tmp.{os.getpid()}.{secrets.token_hex(4)}'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read(path):
    for _ in range(3):
        try:
            with open(path) as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except FileNotFoundError:
            return {}
        except Exception:
            time.sleep(0.05)
    return {}


# --- Additional accounts ---------------------------------------------------------
def list_users():
    return list((_read(USERS_FILE).get('users') or []))


def save_users(users):
    _atomic_write(USERS_FILE, {'users': users})


def get_user(uid):
    for u in list_users():
        if u.get('id') == uid:
            return u
    return None


def find_user_by_name(name):
    name = (name or '').strip().lower()
    for u in list_users():
        if (u.get('username') or '').lower() == name:
            return u
    return None


def update_user(uid, changes):
    users = list_users()
    for u in users:
        if u.get('id') == uid:
            u.update(changes)
            for k, v in list(changes.items()):
                if v is None:
                    u.pop(k, None)
            save_users(users)
            return u
    return None


def public_user(u):
    return {
        'id': u.get('id'), 'username': u.get('username'), 'role': u.get('role'),
        'sites': u.get('sites') or [], 'disabled': bool(u.get('disabled')),
        'twofa': bool(u.get('totp_enabled')), 'created': u.get('created'),
        'last_login': u.get('last_login'), 'note': u.get('note', ''),
    }


# --- API keys --------------------------------------------------------------------
def _key_hash(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


def list_keys():
    return list(_read(KEYS_FILE).get('keys') or [])


def save_keys(keys):
    _atomic_write(KEYS_FILE, {'keys': keys})


def create_key(name, role, allowed_ips=None, expires_days=0):
    kid = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    token = f'vp_{kid}_{secret}'
    entry = {
        'id': kid, 'name': name, 'role': role, 'hash': _key_hash(token),
        'allowed_ips': allowed_ips or [], 'created': int(time.time()),
        'expires': int(time.time()) + int(expires_days) * 86400 if expires_days else 0,
        'last_used': 0, 'last_ip': '',
    }
    keys = list_keys()
    keys.append(entry)
    save_keys(keys)
    return token, entry


def check_key(token, ip):
    """Return the key entry for a valid token from an allowed IP, else None."""
    m = re.fullmatch(r'vp_([0-9a-f]{8})_[A-Za-z0-9_-]{20,}', token or '')
    if not m:
        return None
    keys = list_keys()
    h = _key_hash(token)
    for k in keys:
        if k.get('id') != m.group(1):
            continue
        if not secrets.compare_digest(k.get('hash', ''), h):
            return None
        if k.get('disabled'):
            return None
        if k.get('expires') and time.time() > k['expires']:
            return None
        rules = k.get('allowed_ips') or []
        if rules:
            from panel.routes.auth import _ip_matches
            if not any(_ip_matches(ip, r) for r in rules):
                return None
        # Record usage at most once a minute (avoid a write per request).
        if time.time() - (k.get('last_used') or 0) > 60 or k.get('last_ip') != ip:
            k['last_used'] = int(time.time())
            k['last_ip'] = ip
            try:
                save_keys(keys)
            except Exception:
                pass
        return k
    return None


def public_key(k):
    return {x: k.get(x) for x in ('id', 'name', 'role', 'allowed_ips', 'created',
                                   'expires', 'last_used', 'last_ip', 'disabled')}


# --- Permissions -----------------------------------------------------------------
# Read-only endpoints a viewer may call (GET only).
_VIEWER_GET = (
    '/api/dashboard', '/api/system', '/api/monitor', '/api/monitoring',
    '/api/bandwidth', '/api/services', '/api/onboarding/state', '/api/users/me',
    '/api/alerts/history', '/api/i18n',
)
_VIEWER_EXACT_GET = ('/api/websites', '/api/modules', '/api/modules/list')

# What a site manager may do inside /api/websites/<domain>/...
_SITE_WEBSITE_DENY = (
    'config',        # raw web-server config: load_module etc. run as root
    'directory',     # moving the web root could expose any path
    'deploy',        # git hooks / build commands run as root
    'composer',      # composer scripts run as root
    'nodejs',        # process manager commands run as root
    'proxy',         # reverse proxy to local services (SSRF)
    'waf',
)
_SITE_GLOBAL_GET = (
    '/api/websites/php-versions', '/api/wp/php-versions', '/api/wp/wp-versions',
    '/api/wp/db-engines', '/api/dashboard', '/api/system', '/api/users/me',
    '/api/i18n', '/api/onboarding/state',
)

_DOMAIN_RE = re.compile(r'^/api/(?:websites|wp)/([^/]+)(?:/(.*))?$')
_SITE_BACKUP_RE = re.compile(r'^/api/backups/sites/([^/]+)/(backups|run|schedule)$')


def site_roots(domains):
    """Web roots of the given sites (used to scope the file manager)."""
    roots = []
    try:
        from panel.routes.websites_core import _get_site_path
        for d in domains:
            p = _get_site_path(d)
            if p:
                roots.append(os.path.realpath(p))
    except Exception:
        pass
    seen, out = set(), []
    for r in roots:
        if r not in seen and r not in ('/', '/var', '/var/www', '/www', '/www/wwwroot',
                                       '/home', '/root', '/etc', '/opt', '/usr'):
            seen.add(r)
            out.append(r)
    return out


def _paths_in(obj, out):
    if isinstance(obj, str):
        if obj.startswith('/'):
            out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _paths_in(v, out)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _paths_in(v, out)


def _within(path, roots):
    rp = os.path.realpath(path)
    return any(rp == r or rp.startswith(r.rstrip('/') + '/') for r in roots)


def is_allowed(role, sites, method, path, args=None, body=None):
    """Role check for one request. Returns (allowed, reason)."""
    if role == 'admin':
        return True, ''
    if path.startswith('/api/auth/'):
        return True, ''
    if role == 'viewer':
        if method != 'GET':
            return False, 'Your account is read-only.'
        if path in _VIEWER_EXACT_GET or any(path == p or path.startswith(p + '/') for p in _VIEWER_GET):
            return True, ''
        return False, 'Your account does not have access to this page.'
    if role == 'site':
        sites = set(sites or [])
        if path == '/api/websites' and method == 'GET':
            return True, ''       # the response is filtered to the assigned sites
        if path == '/api/wp/sites' and method == 'GET':
            return True, ''
        if path == '/api/backups/sites' and method == 'GET':
            return True, ''
        if method == 'GET' and any(path == p or path.startswith(p + '/') for p in _SITE_GLOBAL_GET):
            return True, ''
        m = _DOMAIN_RE.match(path)
        if m and m.group(1) not in ('php-versions', 'sites', 'install', 'install-wpcli',
                                    'db-engines', 'wp-versions', 'deploy-apps', 'webroot'):
            if m.group(1) not in sites:
                return False, 'This website is not assigned to your account.'
            sub = (m.group(2) or '').split('/')[0]
            if sub in _SITE_WEBSITE_DENY:
                return False, 'Only an administrator can change this setting.'
            if path.startswith('/api/websites/') and not m.group(2) and method == 'DELETE':
                return False, 'Only an administrator can delete a website.'
            if path.startswith('/api/wp/') and method == 'DELETE' and not m.group(2):
                return False, 'Only an administrator can delete a website.'
            return True, ''
        m = _SITE_BACKUP_RE.match(path)
        if m:
            if m.group(1) in sites:
                return True, ''
            return False, 'This website is not assigned to your account.'
        if path.startswith('/api/files/'):
            if path.endswith('/remote-download'):
                return False, 'Only an administrator can download remote files.'
            roots = site_roots(sites)
            if not roots:
                return False, 'No website is assigned to your account.'
            found = []
            _paths_in(args or {}, found)
            _paths_in(body or {}, found)
            if not found:
                return False, 'A path inside your website is required.'
            for p in found:
                if not _within(p, roots):
                    return False, 'You can only open files inside your websites.'
            return True, ''
        return False, 'Your account does not have access to this page.'
    return False, 'Unknown role.'
