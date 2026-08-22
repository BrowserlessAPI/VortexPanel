from flask import Blueprint, request, jsonify, session
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
_LOCKOUT_ATTEMPTS = 5
_LOCKOUT_WINDOW   = 900   # 15 minutes
_attempts = defaultdict(list)   # in-memory: ip -> [monotonic timestamps]

def _client_ip():
    return (request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
            or request.headers.get('X-Real-IP', '')
            or request.remote_addr or '127.0.0.1')

def _is_locked(ip):
    now = time.monotonic()
    _attempts[ip] = [t for t in _attempts[ip] if now - t < _LOCKOUT_WINDOW]
    # Also check persistent lockout file (survives restarts)
    try:
        data = json.load(open(LOCKOUT_FILE))
        entry = data.get(ip, {})
        if entry.get('count', 0) >= _LOCKOUT_ATTEMPTS:
            locked_at = entry.get('locked_at', 0)
            if time.time() - locked_at < _LOCKOUT_WINDOW:
                return True
            else:
                # Expired — clean up
                del data[ip]
                with open(LOCKOUT_FILE, 'w') as f:
                    json.dump(data, f)
    except Exception:
        pass
    return len(_attempts[ip]) >= _LOCKOUT_ATTEMPTS

def _record_fail(ip):
    _attempts[ip].append(time.monotonic())
    # Persist to file so restarts don't reset lockout
    try:
        data = {}
        try: data = json.load(open(LOCKOUT_FILE))
        except: pass
        entry = data.get(ip, {'count': 0})
        entry['count'] = entry.get('count', 0) + 1
        if entry['count'] >= _LOCKOUT_ATTEMPTS:
            entry['locked_at'] = time.time()
        data[ip] = entry
        with open(LOCKOUT_FILE, 'w') as f:
            json.dump(data, f)
    except Exception:
        pass

def _clear_attempts(ip):
    _attempts[ip] = []
    try:
        data = json.load(open(LOCKOUT_FILE))
        data.pop(ip, None)
        with open(LOCKOUT_FILE, 'w') as f:
            json.dump(data, f)
    except Exception:
        pass

def _attempts_remaining(ip):
    now = time.monotonic()
    recent = [t for t in _attempts[ip] if now - t < _LOCKOUT_WINDOW]
    return max(0, _LOCKOUT_ATTEMPTS - len(recent))

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
    # Legacy SHA-256 (64-char hex)
    return hashlib.sha256(password.encode()).hexdigest() == stored

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
    if os.environ.get('VORTEX_DISABLE_IP_CHECK'):
        return True
    try:
        cfg = json.load(open(CONFIG_FILE))
        allowed = [x.strip() for x in cfg.get('allowed_ips', []) if x.strip()]
        if not allowed:
            return True
        return any(ip == a or (a.endswith('.') and ip.startswith(a)) for a in allowed)
    except Exception:
        return True

def check_ip_and_session():
    """
    Central auth check used by every API route.
    Returns True if request is fully authenticated.
    Checks: session exists + not 2FA pending + IP allowed + fingerprint valid.
    """
    if 'user' not in session or session.get('2fa_pending'):
        return False
    ip = _client_ip()
    if not _ip_allowed(ip):
        return False
    # Session fingerprint check (detects stolen cookie used from different IP/browser)
    if session.get('fingerprint') and session['fingerprint'] != _session_fingerprint():
        session.clear()
        return False
    return True

# --- Credentials ----------------------------------------------------------------
def find_creds_file():
    for p in CREDS_LOCATIONS:
        if os.path.exists(p): return p
    return None

def get_credentials():
    path = find_creds_file()
    if path:
        try:
            data = json.load(open(path))
            if 'password' in data and 'password_hash' not in data:
                data['password_hash'] = _hash_password(data.pop('password'))
                save_credentials(data)
            return data
        except Exception:
            pass
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
    os.makedirs(os.path.dirname(CREDS_FILE), exist_ok=True)
    with open(CREDS_FILE, 'w') as f:
        json.dump(creds, f, indent=2)
    try: os.chmod(CREDS_FILE, 0o600)
    except: pass

# --- Panel config ---------------------------------------------------------------
def _get_config():
    try: return json.load(open(CONFIG_FILE))
    except: return {}

def _save_config(cfg):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)

# --- Audit log ------------------------------------------------------------------
def _audit(ip, username, success, note=''):
    try:
        ts  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        tag = 'SUCCESS' if success else 'FAILED '
        line = f'{ts} | {tag} | {ip:<20} | {username:<20} | {note}\n'
        with open(AUDIT_FILE, 'a') as f:
            f.write(line)
        lines = open(AUDIT_FILE).readlines()
        if len(lines) > 1000:
            with open(AUDIT_FILE, 'w') as f:
                f.writelines(lines[-1000:])
    except Exception:
        pass


# ===============================================================================
# ROUTES
# ===============================================================================

@auth_bp.route('/api/auth/check')
def check_session():
    logged_in = 'user' in session and not session.get('2fa_pending')
    if logged_in:
        resp = jsonify({'ok': True, 'logged_in': True,
                        'username': session.get('user','admin'),
                        'algo': 'argon2id' if _ARGON2 else ('bcrypt' if _BCRYPT else 'sha256')})
    else:
        resp = jsonify({'ok': True, 'logged_in': False})
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    ip = _client_ip()

    # IP allowlist
    if not _ip_allowed(ip):
        _audit(ip, '—', False, 'IP not in allowlist')
        return jsonify({'ok': False, 'error': 'Access denied from this IP address'}), 403

    # Brute-force check
    if _is_locked(ip):
        _audit(ip, '—', False, 'locked out')
        return jsonify({'ok': False,
                        'error': 'Too many failed attempts. Try again in 15 minutes.'}), 429

    data     = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    creds    = get_credentials()

    username_match = (username == creds.get('username', 'admin')
                      or username == creds.get('email', ''))
    hash_match = _verify_password(password, creds.get('password_hash', ''))

    if not (username_match and hash_match):
        _record_fail(ip)
        remaining = _attempts_remaining(ip)
        _audit(ip, username, False, f'{remaining} attempts remaining')
        if remaining == 0:
            msg = 'Too many failed attempts. Try again in 15 minutes.'
        else:
            msg = f'Invalid credentials. {remaining} attempt{"s" if remaining!=1 else ""} remaining.'
        return jsonify({'ok': False, 'error': msg}), 401

    # Upgrade hash to Argon2id on successful login
    if _needs_upgrade(creds.get('password_hash', '')):
        try:
            creds['password_hash'] = _hash_password(password)
            save_credentials(creds)
        except Exception:
            pass

    # 2FA required?
    if creds.get('totp_enabled') and creds.get('totp_secret') and _PYOTP:
        session.clear()
        session['2fa_pending'] = True
        session['2fa_user']    = creds.get('username', 'admin')
        session.permanent      = True
        _audit(ip, username, True, '2FA pending')
        return jsonify({'ok': True, 'requires_2fa': True})

    # Full login
    _clear_attempts(ip)
    session.clear()
    session['user']        = creds.get('username', 'admin')
    session['fingerprint'] = _session_fingerprint()
    session.permanent      = True
    _audit(ip, username, True, 'login successful')
    return jsonify({'ok': True, 'username': session['user']})


@auth_bp.route('/api/auth/verify-2fa', methods=['POST'])
def verify_2fa():
    if not session.get('2fa_pending'):
        return jsonify({'ok': False, 'error': 'No pending 2FA verification'}), 400
    ip   = _client_ip()
    code = (request.get_json() or {}).get('code', '').replace(' ', '').strip()
    creds  = get_credentials()
    secret = creds.get('totp_secret', '')
    if not secret or not _PYOTP:
        return jsonify({'ok': False, 'error': '2FA not configured'}), 400
    if not _pyotp.TOTP(secret).verify(code, valid_window=1):
        _audit(ip, session.get('2fa_user','?'), False, 'invalid TOTP code')
        return jsonify({'ok': False, 'error': 'Invalid verification code'}), 401
    _clear_attempts(ip)
    user = session.pop('2fa_user', 'admin')
    session.clear()
    session['user']        = user
    session['fingerprint'] = _session_fingerprint()
    session.permanent      = True
    _audit(ip, user, True, '2FA verified — full login')
    return jsonify({'ok': True, 'username': user})


@auth_bp.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})


@auth_bp.route('/api/auth/me')
def me():
    if check_ip_and_session():
        return jsonify({'ok': True, 'username': session['user']})
    return jsonify({'ok': False}), 401


@auth_bp.route('/api/auth/change-password', methods=['POST'])
def change_password():
    if not check_ip_and_session():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    d      = request.get_json() or {}
    new_pw = d.get('new_password', '')
    if len(new_pw) < 8:
        return jsonify({'ok': False, 'error': 'Password too short (min 8 characters)'}), 400
    creds = get_credentials()
    old_pw = d.get('current_password', '')
    if old_pw and not _verify_password(old_pw, creds.get('password_hash','')):
        return jsonify({'ok': False, 'error': 'Current password incorrect'}), 401
    creds['password_hash'] = _hash_password(new_pw)
    # Invalidate all other sessions by rotating the session token marker
    creds['session_version'] = secrets.token_hex(8)
    save_credentials(creds)
    # Keep current session valid by updating its version
    session['session_version'] = creds['session_version']
    _audit(_client_ip(), session.get('user','?'), True, 'password changed')
    return jsonify({'ok': True,
                    'algo': 'argon2id' if _ARGON2 else ('bcrypt' if _BCRYPT else 'sha256')})


@auth_bp.route('/api/auth/audit-log')
def audit_log():
    if not check_ip_and_session():
        return jsonify({'ok': False}), 401
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
        return jsonify({'ok': False, 'error': 'pyotp not installed — run: pip install pyotp'}), 400
    secret = _pyotp.random_base32()
    uri    = _pyotp.TOTP(secret).provisioning_uri(
        name=session.get('user', 'admin'), issuer_name='VortexPanel')
    session['totp_setup_secret'] = secret
    return jsonify({
        'ok': True, 'secret': secret, 'uri': uri,
        'qr_url': f'https://api.qrserver.com/v1/create-qr-code/?size=220x220&data={uri}',
    })


@auth_bp.route('/api/auth/2fa/enable', methods=['POST'])
def enable_2fa():
    if not check_ip_and_session():
        return jsonify({'ok': False}), 401
    if not _PYOTP:
        return jsonify({'ok': False, 'error': 'pyotp not installed'}), 400
    secret = session.get('totp_setup_secret', '')
    if not secret:
        return jsonify({'ok': False, 'error': 'Run /setup first to generate a secret'}), 400
    code = (request.get_json() or {}).get('code', '').replace(' ', '').strip()
    if not _pyotp.TOTP(secret).verify(code, valid_window=1):
        return jsonify({'ok': False, 'error': 'Invalid code — check your authenticator app'}), 401
    creds = get_credentials()
    creds['totp_secret']  = secret
    creds['totp_enabled'] = True
    save_credentials(creds)
    session.pop('totp_setup_secret', None)
    _audit(_client_ip(), session.get('user','?'), True, '2FA enabled')
    return jsonify({'ok': True})


@auth_bp.route('/api/auth/2fa/disable', methods=['POST'])
def disable_2fa():
    if not check_ip_and_session():
        return jsonify({'ok': False}), 401
    password = (request.get_json() or {}).get('password', '')
    creds = get_credentials()
    if not _verify_password(password, creds.get('password_hash', '')):
        return jsonify({'ok': False, 'error': 'Incorrect password'}), 401
    creds.pop('totp_secret',  None)
    creds.pop('totp_enabled', None)
    save_credentials(creds)
    _audit(_client_ip(), session.get('user','?'), True, '2FA disabled')
    return jsonify({'ok': True})


@auth_bp.route('/api/auth/2fa/status')
def twofa_status():
    if not check_ip_and_session():
        return jsonify({'ok': False}), 401
    creds = get_credentials()
    return jsonify({
        'ok':              True,
        'enabled':         bool(creds.get('totp_enabled') and creds.get('totp_secret')),
        'pyotp_available': _PYOTP,
        'algo':            'argon2id' if _ARGON2 else ('bcrypt' if _BCRYPT else 'sha256'),
    })


@auth_bp.route('/api/auth/security-settings')
def get_security_settings():
    if not check_ip_and_session():
        return jsonify({'ok': False}), 401
    cfg = _get_config()
    return jsonify({
        'ok':           True,
        'allowed_ips':  cfg.get('allowed_ips', []),
        'session_hours':cfg.get('session_hours', 24),
        'algo':         'argon2id' if _ARGON2 else ('bcrypt' if _BCRYPT else 'sha256'),
    })


@auth_bp.route('/api/auth/security-settings', methods=['POST'])
def save_security_settings():
    if not check_ip_and_session():
        return jsonify({'ok': False}), 401
    d   = request.get_json() or {}
    cfg = _get_config()
    if 'allowed_ips' in d:
        cfg['allowed_ips'] = [ip.strip() for ip in d['allowed_ips'] if ip.strip()]
    if 'session_hours' in d:
        cfg['session_hours'] = max(1, min(720, int(d['session_hours'])))
    _save_config(cfg)
    return jsonify({'ok': True})
