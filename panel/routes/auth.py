from flask import Blueprint, request, jsonify, session, g
import hashlib, os, json, secrets, time, string
from collections import defaultdict
from datetime import datetime

auth_bp = Blueprint('auth', __name__)

# --- Credential file locations --------------------------------------------------
CREDS_LOCATIONS = [
    '/opt/vortexpanel/credentials.json',
    '/opt/vortexpanel/config/credentials.json',
    '/etc/vortexpanel/credentials.json',
    '/root/.vortexpanel/credentials.json',
]
CREDS_FILE   = '/opt/vortexpanel/credentials.json'
AUDIT_FILE   = '/opt/vortexpanel/login_audit.log'
CONFIG_FILE  = '/opt/vortexpanel/config.json'
LOCKOUT_FILE = '/opt/vortexpanel/lockout.json'

# --- Argon2id (preferred) → bcrypt fallback → SHA-256 legacy -------------------
try:
    from argon2 import PasswordHasher as _PH
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
    # OWASP 2024+ recommended parameters
    _argon2 = _PH(time_cost=3, memory_cost=65536, parallelism=1)
    _ARGON2 = True
except ImportError:
    _ARGON2 = False

try:
    import bcrypt as _bcrypt
    _BCRYPT = True
except ImportError:
    _BCRYPT = False

# --- TOTP / 2FA -----------------------------------------------------------------
try:
    import pyotp as _pyotp
    _PYOTP = True
except ImportError:
    _PYOTP = False

# --- Brute-force lockout --------------------------------------------------------
_LOCKOUT_ATTEMPTS = 5     # per client address
_ACCOUNT_ATTEMPTS = 10    # per account, from any address (slow distributed guessing)
_LOCKOUT_WINDOW   = 900   # 15 minutes
_attempts = defaultdict(list)   # in-memory: ip -> [monotonic timestamps]

_LOOPBACK = ('127.0.0.1', '::1', '::ffff:127.0.0.1')

def _norm_ip(ip):
    ip = (ip or '').strip()
    if ip.startswith('::ffff:') and '.' in ip:
        ip = ip[7:]
    return ip

def _client_ip():
    """Real client address. X-Forwarded-For / X-Real-IP are only honoured
    when the TCP peer is a local reverse proxy (or VORTEX_TRUST_PROXY is set):
    gunicorn listens on the public port directly, so trusting these headers
    from anyone let a client send 'X-Forwarded-For: 127.0.0.1' to bypass the
    IP allowlist (loopback is always allowed) and rotate the header to dodge
    the brute-force lockout."""
    peer = _norm_ip(request.remote_addr) or '127.0.0.1'
    if peer in _LOOPBACK or os.environ.get('VORTEX_TRUST_PROXY'):
        real = _norm_ip(request.headers.get('X-Real-IP', ''))
        if real:
            return real
        xff = [x.strip() for x in request.headers.get('X-Forwarded-For', '').split(',') if x.strip()]
        if xff:
            # The proxy appends the address it saw: the right-most entry is
            # the only one the client cannot forge.
            return _norm_ip(xff[-1])
        fwd = request.headers.get('Forwarded', '')
        if 'for=' in fwd:
            last = fwd.split(',')[-1]
            for part in last.split(';'):
                k, _, v = part.strip().partition('=')
                if k.lower() == 'for' and v:
                    v = v.strip('"')
                    if v.startswith('['):
                        v = v[1:v.find(']')]
                    elif v.count(':') == 1:
                        v = v.split(':')[0]
                    return _norm_ip(v)
        if peer in _LOOPBACK and _looks_proxied():
            # A local reverse proxy that does not pass the client address:
            # every visitor would look like 127.0.0.1, which is always allowed
            # and shares one lockout counter. Treat it as an unknown address
            # (subject to the allowlist) instead.
            return 'proxy-unknown'
    return peer


def _looks_proxied():
    h = request.headers
    if h.get('Via') or h.get('X-Forwarded-Host') or h.get('X-Forwarded-Proto'):
        return True
    host = (request.host or '').rsplit(':', 1)[0].strip('[]').lower()
    return host not in ('127.0.0.1', 'localhost', '::1', '')

def _atomic_write_json(path, data, mode=0o600):
    """Write JSON via temp file + rename so a concurrent reader in another
    gunicorn worker never sees a truncated/empty file."""
    d = os.path.dirname(path) or '.'
    os.makedirs(d, exist_ok=True)
    tmp = f'{path}.tmp.{os.getpid()}.{secrets.token_hex(4)}'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try: os.unlink(tmp)
        except Exception: pass
        raise


def _load_lockout():
    try:
        with open(LOCKOUT_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _lock_entry(data, ip):
    """Current entry for ip with failures older than the window dropped.
    lockout.json is the source of truth shared by all gunicorn workers; the
    old per-worker in-memory list meant each of the 4 workers allowed its own
    5 attempts and reported a different 'attempts remaining'."""
    now = time.time()
    entry = data.get(ip) or {}
    locked_at = entry.get('locked_at', 0)
    if locked_at and now - locked_at >= _LOCKOUT_WINDOW:
        entry = {}
    first = entry.get('first', 0)
    if not locked_at and first and now - first >= _LOCKOUT_WINDOW:
        entry = {}
    return entry


def _is_locked(ip):
    data = _load_lockout()
    entry = _lock_entry(data, ip)
    if ip in data and not entry:
        data.pop(ip, None)
        try: _atomic_write_json(LOCKOUT_FILE, data)
        except Exception: pass
    if entry.get('count', 0) >= (_ACCOUNT_ATTEMPTS if ip.startswith('acct:') else _LOCKOUT_ATTEMPTS):
        return True
    if ip.startswith('acct:'):
        return False
    now = time.monotonic()
    _attempts[ip] = [t for t in _attempts[ip] if now - t < _LOCKOUT_WINDOW]
    return len(_attempts[ip]) >= _LOCKOUT_ATTEMPTS

def _record_fail(ip):
    if not ip.startswith('acct:'):
        _attempts[ip].append(time.monotonic())
    # Persist to file so restarts don't reset lockout
    try:
        data = _load_lockout()
        entry = _lock_entry(data, ip)
        if not entry:
            entry = {'count': 0, 'first': time.time()}
        entry['count'] = entry.get('count', 0) + 1
        limit = _ACCOUNT_ATTEMPTS if ip.startswith('acct:') else _LOCKOUT_ATTEMPTS
        if entry['count'] >= limit and not entry.get('locked_at'):
            entry['locked_at'] = time.time()
        data[ip] = entry
        # Bound the file: drop entries whose window has passed.
        data = {k: v for k, v in data.items() if k == ip or _lock_entry(data, k)}
        _atomic_write_json(LOCKOUT_FILE, data)
    except Exception:
        pass

def _clear_attempts(ip):
    _attempts[ip] = []
    try:
        data = _load_lockout()
        if ip in data:
            data.pop(ip, None)
            _atomic_write_json(LOCKOUT_FILE, data)
    except Exception:
        pass

def _attempts_remaining(ip):
    entry = _lock_entry(_load_lockout(), ip)
    now = time.monotonic()
    recent = [t for t in _attempts[ip] if now - t < _LOCKOUT_WINDOW]
    used = max(entry.get('count', 0), len(recent))
    return max(0, _LOCKOUT_ATTEMPTS - used)

# --- Password helpers -----------------------------------------------------------
def _hash_password(password: str) -> str:
    """Hash with Argon2id (preferred) → bcrypt → SHA-256 fallback."""
    if _ARGON2:
        return _argon2.hash(password)
    if _BCRYPT:
        return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt(rounds=12)).decode()
    return hashlib.sha256(password.encode()).hexdigest()

def _verify_password(password: str, stored: str) -> bool:
    """
    Verify against Argon2id, bcrypt, or legacy SHA-256.
    Migration order: Argon2id → bcrypt → SHA-256.
    """
    if not isinstance(password, str) or not isinstance(stored, str) or not stored:
        return False
    if stored.startswith('$argon2'):
        if not _ARGON2:
            return False
        try:
            _argon2.verify(stored, password)
            return True
        except (VerifyMismatchError, VerificationError, InvalidHashError, Exception):
            return False
    if stored.startswith('$2b$') or stored.startswith('$2a$'):
        if not _BCRYPT:
            return False
        try:
            return _bcrypt.checkpw(password.encode(), stored.encode())
        except Exception:
            return False
    # Legacy SHA-256 (64-char hex) - what install.sh wrote before v3.5.3;
    # upgraded to Argon2id on the next successful login.
    if len(stored) != 64:
        return False
    return secrets.compare_digest(hashlib.sha256(password.encode()).hexdigest(), stored.lower())

def _needs_upgrade(stored: str) -> bool:
    """True if stored hash should be upgraded to Argon2id."""
    return _ARGON2 and not stored.startswith('$argon2')

# --- Session fingerprint --------------------------------------------------------
def _session_fingerprint():
    """Bind session to IP + User-Agent to detect session hijacking."""
    ip = _client_ip()
    ua = request.headers.get('User-Agent', '')[:200]
    return hashlib.sha256(f'{ip}:{ua}'.encode()).hexdigest()[:16]

# --- IP allowlist ---------------------------------------------------------------
_ALWAYS_ALLOWED = {'127.0.0.1', '::1', 'localhost', '::ffff:127.0.0.1'}

def _ip_allowed(ip):
    if ip in _ALWAYS_ALLOWED:
        return True
    if ip == 'proxy-unknown':
        try:
            cfg = json.load(open(CONFIG_FILE))
            return not [x for x in cfg.get('allowed_ips', []) if str(x).strip()]
        except Exception:
            return True
    if os.environ.get('VORTEX_DISABLE_IP_CHECK'):
        return True
    try:
        cfg = json.load(open(CONFIG_FILE))
        allowed = [x.strip() for x in cfg.get('allowed_ips', []) if x.strip()]
        if not allowed:
            return True
        return any(_ip_matches(ip, a) for a in allowed)
    except Exception:
        return True


def _ip_matches(ip, rule):
    """Exact IP, legacy prefix ('203.0.113.') or CIDR ('203.0.113.0/24')."""
    ip, rule = _norm_ip(ip), rule.strip()
    if ip == rule or (rule.endswith('.') and ip.startswith(rule)):
        return True
    if '/' in rule:
        import ipaddress
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return False
    return False

# --- Sessions and accounts -------------------------------------------------------
def _clear_session():
    """session.clear() that keeps the security-entrance pass: logging out (or
    an expired session) must not turn the login page into a 404."""
    keep = session.get('entrance_ok')
    session.clear()
    if keep:
        session['entrance_ok'] = True


def _admin_account():
    creds = get_credentials()
    return {'id': 'admin', 'username': creds.get('username', 'admin'), 'role': 'admin',
            'sites': [], **{k: v for k, v in creds.items() if k not in ('id', 'role', 'sites')}}


def _get_account(uid):
    """(account dict, save function) for a session uid."""
    if not uid or uid == 'admin':
        creds = get_credentials()
        def save(changes, _c=creds):
            c = get_credentials()
            for k, v in changes.items():
                if v is None:
                    c.pop(k, None)
                else:
                    c[k] = v
            save_credentials(c)
        acct = dict(creds)
        acct.update(id='admin', role='admin', sites=[])
        acct.setdefault('username', 'admin')
        return acct, save
    from panel import users as _users
    u = _users.get_user(uid)
    if not u:
        return None, None
    return dict(u), (lambda changes, _uid=uid: _users.update_user(_uid, changes))


def _find_login_account(username):
    creds = get_credentials()
    if username and (username == creds.get('username', 'admin') or
                     (creds.get('email') and username == creds.get('email'))):
        return _get_account('admin')
    try:
        from panel import users as _users
        u = _users.find_user_by_name(username)
    except Exception:
        u = None
    if u:
        return _get_account(u['id'])
    return None, None


def _start_session(acct):
    _clear_session()
    session['user']            = acct.get('username', 'admin')
    session['uid']             = acct.get('id', 'admin')
    session['role']            = acct.get('role', 'admin')
    session['fingerprint']     = _session_fingerprint()
    session['session_version'] = acct.get('session_version', '')
    session['entrance_ok']     = True
    session.permanent          = True


def _api_key_user():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    try:
        from panel import users as _users
        k = _users.check_key(auth[7:].strip(), _client_ip())
    except Exception:
        k = None
    if not k:
        return None
    return {'uid': 'key:' + k['id'], 'username': 'api:' + (k.get('name') or k['id']),
            'role': k.get('role', 'viewer'), 'sites': k.get('sites') or [], 'via': 'api_key'}


def check_ip_and_session():
    """
    Central auth check used by every API route.
    Returns True if request is fully authenticated (session cookie or API
    key). Checks: session exists + not 2FA pending + IP allowed + fingerprint
    valid + the account still exists, is enabled and its session_version
    matches. The result is kept in flask.g.vp_user.
    """
    if g.get('vp_user'):
        return True
    ip = _client_ip()
    if request.headers.get('Authorization', '').startswith('Bearer '):
        if not _ip_allowed(ip):
            return False
        u = _api_key_user()
        if u:
            g.vp_user = u
            return True
        return False
    if 'user' not in session or session.get('2fa_pending'):
        return False
    if not _ip_allowed(ip):
        return False
    # Session fingerprint check (detects stolen cookie used from different IP/browser).
    # The request is refused; the session itself is kept for its real owner
    # (clearing it let anyone who could make one odd request through a proxy
    # sign the administrator out).
    if session.get('fingerprint') and session['fingerprint'] != _session_fingerprint():
        return False
    acct, _ = _get_account(session.get('uid', 'admin'))
    if not acct or acct.get('disabled'):
        _clear_session()
        return False
    # Password / 2FA changes rotate session_version; any session created
    # before that (other browsers, a stolen cookie) is now invalid.
    cur = acct.get('session_version', '') or ''
    if cur and session.get('session_version') != cur:
        _clear_session()
        return False
    g.vp_user = {'uid': acct.get('id', 'admin'), 'username': acct.get('username', 'admin'),
                 'role': acct.get('role', 'admin'), 'sites': acct.get('sites') or [],
                 'via': 'session'}
    return True


def require_admin():
    """None when the caller is a signed-in administrator, else an error response."""
    if not check_ip_and_session():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    if (g.vp_user or {}).get('role') != 'admin':
        return jsonify({'ok': False, 'error': 'Administrator access is required.'}), 403
    return None


# --- TOTP and backup codes --------------------------------------------------------
def _totp_step(secret, code):
    """Time step the code belongs to (window +-1), or None."""
    code = (code or '').strip()
    if not (code.isdigit() and len(code) == 6) or not _PYOTP:
        return None
    t = _pyotp.TOTP(secret)
    now = int(time.time())
    for off in (0, -1, 1):
        ts = now + off * 30
        if secrets.compare_digest(t.at(ts), code):
            return ts // 30
    return None


def _check_second_factor(acct, save, code):
    """Accept a TOTP code once (replays of the same or an older code are
    refused) or an unused backup code. Returns (ok, how)."""
    raw = (code or '').replace(' ', '').strip()
    step = _totp_step(acct.get('totp_secret', ''), raw)
    if step is not None:
        if step <= int(acct.get('totp_last_step') or 0):
            return False, 'replayed'
        save({'totp_last_step': step})
        return True, 'totp'
    norm = raw.replace('-', '').lower()
    if len(norm) == 10 and norm.isalnum():
        h = hashlib.sha256(norm.encode()).hexdigest()
        codes = list(acct.get('backup_codes') or [])
        for c in codes:
            if secrets.compare_digest(c, h):
                codes.remove(c)
                save({'backup_codes': codes})
                return True, 'backup'
    return False, 'invalid'


def _new_backup_codes():
    alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'
    plain = [''.join(secrets.choice(alphabet) for _ in range(10)) for _ in range(10)]
    shown = [c[:5] + '-' + c[5:] for c in plain]
    return shown, [hashlib.sha256(c.encode()).hexdigest() for c in plain]


def _current_session_version():
    path = find_creds_file()
    if not path:
        return ''
    try:
        with open(path) as f:
            return json.load(f).get('session_version', '') or ''
    except Exception:
        return ''

# --- Credentials ----------------------------------------------------------------
def find_creds_file():
    for p in CREDS_LOCATIONS:
        if os.path.exists(p): return p
    return None

def get_credentials():
    path = find_creds_file()
    if path:
        data = None
        for _ in range(3):
            try:
                with open(path) as f:
                    data = json.load(f)
                break
            except Exception:
                time.sleep(0.05)
        if not isinstance(data, dict):
            # The file exists but is unreadable/corrupt (or mid-write by an
            # older version). Never regenerate here: that used to silently
            # replace the admin password and drop 2FA. Fail closed instead.
            return {'username': 'admin', 'password_hash': '!unreadable'}
        if 'password' in data and 'password_hash' not in data:
            data['password_hash'] = _hash_password(data.pop('password'))
            save_credentials(data)
        return data
    # No credentials file found. NEVER fall back to a known default password
    # (the old 'admin123' constant meant a missing/unreadable creds file left
    # the panel logged-in-able by anyone). Generate a strong random password,
    # persist it hashed, and drop the plaintext next to the installer's file so
    # the operator can recover it locally. Nobody can log in without it.
    gen = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20))
    creds = {'username': 'admin', 'password_hash': _hash_password(gen)}
    save_credentials(creds)
    try:
        with open('/opt/vortexpanel/admin_password.txt', 'w') as f:
            f.write(gen + '\n')
        os.chmod('/opt/vortexpanel/admin_password.txt', 0o600)
    except Exception:
        pass
    return creds

def save_credentials(creds):
    _atomic_write_json(CREDS_FILE, creds, 0o600)

# --- Panel config ---------------------------------------------------------------
def _get_config():
    try: return json.load(open(CONFIG_FILE))
    except: return {}

def _save_config(cfg):
    _atomic_write_json(CONFIG_FILE, cfg, 0o600)

# --- Audit log ------------------------------------------------------------------
def _clean_name(name):
    name = str(name or '')
    return ''.join(c for c in name if c.isprintable() and c not in '|\r\n')[:64]


def _audit(ip, username, success, note='', known=True):
    """Append to the login audit log. A name typed into a failed login that
    matches no account is stored as a short hash, not as typed (people paste
    passwords into the username box)."""
    try:
        ts  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        tag = 'SUCCESS' if success else 'FAILED '
        name = _clean_name(username)
        if not known and name and name != '-':
            name = 'unknown#' + hashlib.sha256(name.encode()).hexdigest()[:8]
        line = f'{ts} | {tag} | {_clean_name(ip):<20} | {name:<20} | {_clean_name(note)}\n'
        fd = os.open(AUDIT_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, 'a') as f:
            f.write(line)
        if os.path.getsize(AUDIT_FILE) > 400_000:
            lines = open(AUDIT_FILE).readlines()
            with open(AUDIT_FILE, 'w') as f:
                f.writelines(lines[-1000:])
    except Exception:
        pass


def audit_event(action, detail=''):
    """Record an administrative action by the signed-in user."""
    u = g.get('vp_user') or {}
    _audit(_client_ip(), u.get('username') or session.get('user', '?'), True,
           f'{action} {detail}'.strip())


# ===============================================================================
# ROUTES
# ===============================================================================

_DUMMY = {}

def _dummy_hash():
    if 'h' not in _DUMMY:
        _DUMMY['h'] = _hash_password(secrets.token_hex(12))
    return _DUMMY['h']


def _algo():
    return 'argon2id' if _ARGON2 else ('bcrypt' if _BCRYPT else 'sha256')


@auth_bp.route('/api/auth/check')
def check_session():
    logged_in = check_ip_and_session()
    if logged_in:
        u = g.vp_user
        resp = jsonify({'ok': True, 'logged_in': True, 'username': u['username'],
                        'role': u['role'], 'sites': u['sites'], 'algo': _algo()})
    else:
        resp = jsonify({'ok': True, 'logged_in': False})
    resp.headers['Cache-Control'] = 'no-store'
    return resp


def _remove_initial_password_file():
    """The installer's plaintext password file is only needed until the first
    successful sign-in."""
    for p in ('/opt/vortexpanel/admin_password.txt',):
        try:
            if os.path.exists(p):
                os.unlink(p)
        except Exception:
            pass


@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    ip = _client_ip()

    # IP allowlist
    if not _ip_allowed(ip):
        _audit(ip, '-', False, 'IP not in allowlist')
        if ip == 'proxy-unknown':
            return jsonify({'ok': False, 'error': 'Access denied: the panel is behind a reverse proxy that does not '
                                                  'send the visitor address, so the IP allowlist cannot be checked. '
                                                  'Add "proxy_set_header X-Real-IP $remote_addr;" to the proxy, or '
                                                  'run "vortexpanel allow-ip clear" on the server.'}), 403
        return jsonify({'ok': False, 'error': 'Access denied from this IP address'}), 403

    # Brute-force check
    if _is_locked(ip):
        _audit(ip, '-', False, 'locked out')
        return jsonify({'ok': False,
                        'error': 'Too many failed attempts. Try again in 15 minutes.'}), 429

    data     = request.get_json(silent=True) or {}
    username = str(data.get('username') or '').strip()
    password = data.get('password') or ''
    if not isinstance(password, str):
        password = str(password)

    acct, save = _find_login_account(username)
    acct_key = 'acct:' + (acct.get('id') if acct else 'none')
    if acct and _is_locked(acct_key):
        _audit(ip, username, False, 'account locked out')
        return jsonify({'ok': False, 'error': 'This account is temporarily locked after too many '
                                              'failed attempts. Try again in 15 minutes, or run '
                                              '"vortexpanel unlock" on the server.'}), 429

    hash_match = bool(acct) and _verify_password(password, acct.get('password_hash', ''))
    if not acct:
        # Same work as a real check, so timing does not reveal valid names.
        _verify_password(password, _dummy_hash())

    if not hash_match or (acct and acct.get('disabled')):
        _record_fail(ip)
        if acct:
            _record_fail(acct_key)
        remaining = _attempts_remaining(ip)
        _audit(ip, username, False, 'account disabled' if acct and hash_match else
               f'{remaining} attempts remaining', known=bool(acct))
        if acct and hash_match:
            return jsonify({'ok': False, 'error': 'This account is disabled.'}), 403
        if remaining == 0:
            msg = 'Too many failed attempts. Try again in 15 minutes.'
        else:
            msg = f'Invalid credentials. {remaining} attempt{"s" if remaining!=1 else ""} remaining.'
        return jsonify({'ok': False, 'error': msg}), 401

    # Upgrade hash to Argon2id on successful login
    if _needs_upgrade(acct.get('password_hash', '')):
        try:
            save({'password_hash': _hash_password(password)})
        except Exception:
            pass

    if acct['id'] == 'admin':
        _remove_initial_password_file()

    # 2FA required?
    if acct.get('totp_enabled') and acct.get('totp_secret') and _PYOTP:
        _clear_session()
        session['2fa_pending'] = True
        session['2fa_user']    = acct.get('username', 'admin')
        session['2fa_uid']     = acct['id']
        session['entrance_ok'] = True
        session.permanent      = True
        _audit(ip, acct.get('username'), True, '2FA pending')
        return jsonify({'ok': True, 'requires_2fa': True})

    _clear_attempts(ip)
    _clear_attempts(acct_key)
    _start_session(acct)
    try:
        save({'last_login': int(time.time())})
    except Exception:
        pass
    _audit(ip, acct.get('username'), True, 'login successful')
    return jsonify({'ok': True, 'username': session['user'], 'role': session['role']})


@auth_bp.route('/api/auth/verify-2fa', methods=['POST'])
def verify_2fa():
    if not session.get('2fa_pending'):
        return jsonify({'ok': False, 'error': 'No pending 2FA verification'}), 400
    ip   = _client_ip()
    if not _ip_allowed(ip):
        return jsonify({'ok': False, 'error': 'Access denied from this IP address'}), 403
    uid = session.get('2fa_uid', 'admin')
    acct_key = 'acct:' + uid
    if _is_locked(ip) or _is_locked(acct_key):
        _clear_session()
        return jsonify({'ok': False, 'error': 'Too many failed attempts. Try again in 15 minutes.'}), 429
    code = str((request.get_json(silent=True) or {}).get('code') or '')
    acct, save = _get_account(uid)
    if not acct or not acct.get('totp_secret') or not _PYOTP:
        return jsonify({'ok': False, 'error': '2FA not configured'}), 400
    ok, how = _check_second_factor(acct, save, code)
    if not ok:
        _record_fail(ip)
        _record_fail(acct_key)
        _audit(ip, acct.get('username', '?'), False,
               'TOTP code already used' if how == 'replayed' else 'invalid 2FA code')
        if _attempts_remaining(ip) == 0:
            _clear_session()
        msg = ('This code was already used. Wait for the next code.' if how == 'replayed'
               else 'Invalid verification code')
        return jsonify({'ok': False, 'error': msg}), 401
    _clear_attempts(ip)
    _clear_attempts(acct_key)
    acct, save = _get_account(uid)
    _start_session(acct)
    try:
        save({'last_login': int(time.time())})
    except Exception:
        pass
    left = len(acct.get('backup_codes') or [])
    _audit(ip, acct.get('username'), True,
           f'backup code used ({left} left)' if how == 'backup' else '2FA verified')
    return jsonify({'ok': True, 'username': session['user'], 'role': session['role'],
                    'backup_codes_left': left if how == 'backup' else None})


@auth_bp.route('/api/auth/logout', methods=['POST'])
def logout():
    _clear_session()
    return jsonify({'ok': True})


@auth_bp.route('/api/auth/me')
def me():
    if check_ip_and_session():
        u = g.vp_user
        return jsonify({'ok': True, 'username': u['username'], 'role': u['role'], 'sites': u['sites']})
    return jsonify({'ok': False}), 401


@auth_bp.route('/api/auth/change-password', methods=['POST'])
def change_password():
    if not check_ip_and_session():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return _do_change_password(request.get_json(silent=True) or {})


def _session_account():
    if g.get('vp_user', {}).get('via') == 'api_key':
        return None, None
    return _get_account(session.get('uid', 'admin'))


def _do_change_password(d):
    """Shared by /api/auth/change-password and /api/settings/password.
    The current password is REQUIRED, so a hijacked session cannot take over
    the account permanently."""
    new_pw = d.get('new_password') or ''
    if not isinstance(new_pw, str) or len(new_pw) < 8:
        return jsonify({'ok': False, 'error': 'Password too short (min 8 characters)'}), 400
    acct, save = _session_account()
    if not acct:
        return jsonify({'ok': False, 'error': 'Sign in with a password to change it'}), 400
    old_pw = d.get('current_password') or ''
    if not old_pw:
        return jsonify({'ok': False, 'error': 'Current password is required'}), 400
    if not _verify_password(old_pw, acct.get('password_hash','')):
        return jsonify({'ok': False, 'error': 'Current password incorrect'}), 401
    ver = secrets.token_hex(8)
    save({'password_hash': _hash_password(new_pw), 'session_version': ver})
    session['session_version'] = ver
    if acct['id'] == 'admin':
        _remove_initial_password_file()
    _audit(_client_ip(), acct.get('username','?'), True, 'password changed')
    return jsonify({'ok': True, 'algo': _algo()})


@auth_bp.route('/api/auth/audit-log')
def audit_log():
    err = require_admin()
    if err:
        return err
    if not os.path.exists(AUDIT_FILE):
        return jsonify({'ok': True, 'entries': [], 'exists': False})
    try:
        lines = open(AUDIT_FILE).readlines()[-200:]
        entries = []
        for line in reversed(lines):
            parts = [p.strip() for p in line.strip().split('|')]
            if len(parts) >= 4:
                entries.append({
                    'time':     parts[0],
                    'status':   parts[1].strip(),
                    'ip':       parts[2].strip(),
                    'username': parts[3].strip(),
                    'note':     parts[4].strip() if len(parts) > 4 else '',
                })
        return jsonify({'ok': True, 'entries': entries, 'exists': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@auth_bp.route('/api/auth/2fa/setup', methods=['POST'])
def setup_2fa():
    if not check_ip_and_session():
        return jsonify({'ok': False}), 401
    if not _PYOTP:
        return jsonify({'ok': False, 'error': 'pyotp is not installed - run: vortexpanel repair'}), 400
    acct, _ = _session_account()
    if not acct:
        return jsonify({'ok': False, 'error': 'Not available for API keys'}), 400
    secret = _pyotp.random_base32()
    uri    = _pyotp.TOTP(secret).provisioning_uri(
        name=acct.get('username', 'admin'), issuer_name='VortexPanel')
    session['totp_setup_secret'] = secret
    # The QR code is drawn in the browser from 'uri'; the secret is never
    # sent to a third-party service.
    return jsonify({'ok': True, 'secret': secret, 'uri': uri})


@auth_bp.route('/api/auth/2fa/enable', methods=['POST'])
def enable_2fa():
    if not check_ip_and_session():
        return jsonify({'ok': False}), 401
    if not _PYOTP:
        return jsonify({'ok': False, 'error': 'pyotp not installed'}), 400
    secret = session.get('totp_setup_secret', '')
    if not secret:
        return jsonify({'ok': False, 'error': 'Run /setup first to generate a secret'}), 400
    code = str((request.get_json(silent=True) or {}).get('code') or '').replace(' ', '').strip()
    step = _totp_step(secret, code)
    if step is None:
        return jsonify({'ok': False, 'error': 'Invalid code - check your authenticator app'}), 401
    acct, save = _session_account()
    if not acct:
        return jsonify({'ok': False, 'error': 'Not available for API keys'}), 400
    shown, hashes = _new_backup_codes()
    ver = secrets.token_hex(8)
    save({'totp_secret': secret, 'totp_enabled': True, 'totp_last_step': step,
          'backup_codes': hashes, 'session_version': ver})
    # Other sessions of this account are signed out; this one stays.
    session['session_version'] = ver
    session.pop('totp_setup_secret', None)
    _audit(_client_ip(), acct.get('username','?'), True, '2FA enabled')
    return jsonify({'ok': True, 'backup_codes': shown})


@auth_bp.route('/api/auth/2fa/backup-codes', methods=['POST'])
def regenerate_backup_codes():
    if not check_ip_and_session():
        return jsonify({'ok': False}), 401
    acct, save = _session_account()
    if not acct or not acct.get('totp_enabled'):
        return jsonify({'ok': False, 'error': 'Two-factor authentication is not enabled'}), 400
    password = (request.get_json(silent=True) or {}).get('password', '')
    if not _verify_password(password, acct.get('password_hash', '')):
        return jsonify({'ok': False, 'error': 'Incorrect password'}), 401
    shown, hashes = _new_backup_codes()
    save({'backup_codes': hashes})
    _audit(_client_ip(), acct.get('username','?'), True, '2FA backup codes regenerated')
    return jsonify({'ok': True, 'backup_codes': shown})


@auth_bp.route('/api/auth/2fa/disable', methods=['POST'])
def disable_2fa():
    if not check_ip_and_session():
        return jsonify({'ok': False}), 401
    password = (request.get_json(silent=True) or {}).get('password', '')
    acct, save = _session_account()
    if not acct:
        return jsonify({'ok': False, 'error': 'Not available for API keys'}), 400
    if not _verify_password(password, acct.get('password_hash', '')):
        return jsonify({'ok': False, 'error': 'Incorrect password'}), 401
    ver = secrets.token_hex(8)
    save({'totp_secret': None, 'totp_enabled': None, 'totp_last_step': None,
          'backup_codes': None, 'session_version': ver})
    session['session_version'] = ver
    _audit(_client_ip(), acct.get('username','?'), True, '2FA disabled')
    return jsonify({'ok': True})


@auth_bp.route('/api/auth/2fa/status')
def twofa_status():
    if not check_ip_and_session():
        return jsonify({'ok': False}), 401
    acct, _ = _session_account()
    acct = acct or {}
    return jsonify({
        'ok':              True,
        'enabled':         bool(acct.get('totp_enabled') and acct.get('totp_secret')),
        'backup_codes_left': len(acct.get('backup_codes') or []),
        'pyotp_available': _PYOTP,
        'algo':            _algo(),
    })


@auth_bp.route('/api/auth/security-settings')
def get_security_settings():
    err = require_admin()
    if err:
        return err
    cfg = _get_config()
    return jsonify({
        'ok':           True,
        'allowed_ips':  cfg.get('allowed_ips', []),
        'session_hours':cfg.get('session_hours', 24),
        'algo':         _algo(),
    })


@auth_bp.route('/api/auth/security-settings', methods=['POST'])
def save_security_settings():
    err = require_admin()
    if err:
        return err
    d   = request.get_json(silent=True) or {}
    cfg = _get_config()
    if 'allowed_ips' in d:
        raw = d['allowed_ips']
        if isinstance(raw, str):
            raw = raw.replace(',', '\n').split('\n')
        if not isinstance(raw, list):
            return jsonify({'ok': False, 'error': 'allowed_ips must be a list'}), 400
        ips = [str(x).strip() for x in raw if str(x).strip()]
        import ipaddress
        for rule in ips:
            if rule.endswith('.') and all(p.isdigit() for p in rule[:-1].split('.')):
                continue
            try:
                ipaddress.ip_network(rule, strict=False)
            except ValueError:
                return jsonify({'ok': False, 'error': f'Invalid IP, prefix or CIDR: {rule}'}), 400
        # Refuse a list that would lock out the admin making the change.
        me = _client_ip()
        if ips and me not in _ALWAYS_ALLOWED and not any(_ip_matches(me, r) for r in ips):
            return jsonify({'ok': False, 'error': f'Your current IP ({me}) is not in this list - '
                                                  f'saving it would lock you out. Add it first.'}), 400
        cfg['allowed_ips'] = ips
    if 'session_hours' in d:
        try:
            cfg['session_hours'] = max(1, min(720, int(d['session_hours'])))
        except (TypeError, ValueError):
            return jsonify({'ok': False, 'error': 'session_hours must be a number'}), 400
    _save_config(cfg)
    return jsonify({'ok': True})
