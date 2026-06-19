from flask import Blueprint, request, jsonify, session
import hashlib, os, json, secrets, string, time
from collections import defaultdict
from datetime import datetime

auth_bp = Blueprint('auth', __name__)

# ── Credential file locations ─────────────────────────────────────────────────
CREDS_LOCATIONS = [
    '/opt/vortexpanel/credentials.json',
    '/opt/vortexpanel/config/credentials.json',
    '/etc/vortexpanel/credentials.json',
    '/root/.vortexpanel/credentials.json',
]
CREDS_FILE  = '/opt/vortexpanel/credentials.json'
AUDIT_FILE  = '/opt/vortexpanel/login_audit.log'
CONFIG_FILE = '/opt/vortexpanel/config.json'

# ── bcrypt (preferred) with SHA-256 fallback ──────────────────────────────────
try:
    import bcrypt as _bcrypt
    _BCRYPT = True
except ImportError:
    _BCRYPT = False

# ── TOTP / 2FA ────────────────────────────────────────────────────────────────
try:
    import pyotp as _pyotp
    _PYOTP = True
except ImportError:
    _PYOTP = False

# ── Brute-force lockout ───────────────────────────────────────────────────────
_LOCKOUT_ATTEMPTS = 5
_LOCKOUT_WINDOW   = 900   # 15 minutes in seconds
_attempts = defaultdict(list)   # ip -> [timestamps]

def _client_ip():
    return (request.headers.get('X-Forwarded-For','').split(',')[0].strip()
            or request.headers.get('X-Real-IP','')
            or request.remote_addr
            or '127.0.0.1')

def _is_locked(ip):
    now = time.monotonic()
    _attempts[ip] = [t for t in _attempts[ip] if now - t < _LOCKOUT_WINDOW]
    return len(_attempts[ip]) >= _LOCKOUT_ATTEMPTS

def _record_fail(ip):
    _attempts[ip].append(time.monotonic())

def _clear_attempts(ip):
    _attempts[ip] = []

def _attempts_remaining(ip):
    now = time.monotonic()
    recent = [t for t in _attempts[ip] if now - t < _LOCKOUT_WINDOW]
    return max(0, _LOCKOUT_ATTEMPTS - len(recent))

# ── Password helpers ──────────────────────────────────────────────────────────
def _hash_password(password: str) -> str:
    """Hash with bcrypt (preferred) or SHA-256 fallback."""
    if _BCRYPT:
        return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt(rounds=12)).decode()
    return hashlib.sha256(password.encode()).hexdigest()

def _verify_password(password: str, stored: str) -> bool:
    """Verify against bcrypt or legacy SHA-256 hash."""
    if stored.startswith('$2b$') or stored.startswith('$2a$'):
        if not _BCRYPT:
            return False
        try:
            return _bcrypt.checkpw(password.encode(), stored.encode())
        except Exception:
            return False
    # Legacy SHA-256
    return hashlib.sha256(password.encode()).hexdigest() == stored

def _needs_upgrade(stored: str) -> bool:
    """Return True if stored hash is old SHA-256 and should be upgraded."""
    return _BCRYPT and not (stored.startswith('$2b$') or stored.startswith('$2a$'))

# ── Credentials persistence ───────────────────────────────────────────────────
def find_creds_file():
    for path in CREDS_LOCATIONS:
        if os.path.exists(path):
            return path
    return None

def get_credentials():
    path = find_creds_file()
    if path:
        try:
            data = json.load(open(path))
            # Migrate plaintext passwords from very old installs
            if 'password' in data and 'password_hash' not in data:
                data['password_hash'] = _hash_password(data['password'])
                del data['password']
                save_credentials(data)
            return data
        except Exception:
            pass
    # Bootstrap: no creds file yet
    creds = {
        'username':      'admin',
        'password_hash': hashlib.sha256(b'admin123').hexdigest()
    }
    save_credentials(creds)
    return creds

def save_credentials(creds):
    os.makedirs(os.path.dirname(CREDS_FILE), exist_ok=True)
    with open(CREDS_FILE, 'w') as f:
        json.dump(creds, f, indent=2)
    try:
        os.chmod(CREDS_FILE, 0o600)
    except Exception:
        pass

# ── Panel config (IP allowlist, etc.) ────────────────────────────────────────
def _get_config():
    try:
        return json.load(open(CONFIG_FILE))
    except Exception:
        return {}

def _save_config(cfg):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)

def _ip_allowed(ip):
    """Always allow localhost. Check allowlist only if enabled and non-empty."""
    if ip in ('127.0.0.1', '::1', 'localhost', '::ffff:127.0.0.1'):
        return True
    # Escape hatch: env var disables allowlist check
    if os.environ.get('VORTEX_DISABLE_IP_CHECK'):
        return True
    cfg = _get_config()
    allowed = [x.strip() for x in cfg.get('allowed_ips', []) if x.strip()]
    if not allowed:
        return True   # Empty list = allow all
    # Exact match or prefix match (e.g. "192.168.1." covers the subnet)
    return any(ip == a or (a.endswith('.') and ip.startswith(a)) for a in allowed)

# ── Audit log ─────────────────────────────────────────────────────────────────
def _audit(ip, username, success, note=''):
    try:
        ts  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        tag = 'SUCCESS' if success else 'FAILED '
        line = f'{ts} | {tag} | {ip:<20} | {username:<20} | {note}\n'
        with open(AUDIT_FILE, 'a') as f:
            f.write(line)
        # Rotate: keep last 1000 lines
        lines = open(AUDIT_FILE).readlines()
        if len(lines) > 1000:
            with open(AUDIT_FILE, 'w') as f:
                f.writelines(lines[-1000:])
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@auth_bp.route('/api/auth/check')
def check_session():
    if 'user' in session and not session.get('2fa_pending'):
        resp = jsonify({'ok': True, 'logged_in': True,
                        'username': session.get('user', 'admin')})
    else:
        resp = jsonify({'ok': True, 'logged_in': False})
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return resp


@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    ip = _client_ip()

    # ── IP allowlist ─────────────────────────────────────────────────────────
    if not _ip_allowed(ip):
        _audit(ip, '—', False, 'IP not in allowlist')
        return jsonify({'ok': False, 'error': 'Access denied from this IP address'}), 403

    # ── Brute-force lockout ───────────────────────────────────────────────────
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
    hash_match     = _verify_password(password, creds.get('password_hash', ''))

    if not (username_match and hash_match):
        _record_fail(ip)
        remaining = _attempts_remaining(ip)
        _audit(ip, username, False, f'{remaining} attempts remaining')
        msg = 'Invalid credentials.'
        if remaining > 0:
            msg += f' {remaining} attempt{"s" if remaining != 1 else ""} remaining.'
        else:
            msg = 'Too many failed attempts. Try again in 15 minutes.'
        return jsonify({'ok': False, 'error': msg}), 401

    # ── Upgrade SHA-256 → bcrypt on first successful login ────────────────────
    if _needs_upgrade(creds.get('password_hash', '')):
        try:
            creds['password_hash'] = _hash_password(password)
            save_credentials(creds)
        except Exception:
            pass

    # ── 2FA check ─────────────────────────────────────────────────────────────
    if creds.get('totp_enabled') and creds.get('totp_secret') and _PYOTP:
        session.clear()
        session['2fa_pending'] = True
        session['2fa_user']    = creds.get('username', 'admin')
        session.permanent      = True
        _audit(ip, username, True, '2FA pending')
        return jsonify({'ok': True, 'requires_2fa': True})

    # ── Full login ─────────────────────────────────────────────────────────────
    _clear_attempts(ip)
    session.clear()
    session['user']    = creds.get('username', 'admin')
    session.permanent  = True
    _audit(ip, username, True, 'login successful')
    return jsonify({'ok': True, 'username': session['user']})


@auth_bp.route('/api/auth/verify-2fa', methods=['POST'])
def verify_2fa():
    """Verify TOTP code after successful password check."""
    if not session.get('2fa_pending'):
        return jsonify({'ok': False, 'error': 'No pending 2FA verification'}), 400
    ip   = _client_ip()
    code = (request.get_json() or {}).get('code', '').replace(' ', '').strip()
    creds = get_credentials()
    secret = creds.get('totp_secret', '')
    if not secret or not _PYOTP:
        return jsonify({'ok': False, 'error': '2FA not configured'}), 400

    totp = _pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        _audit(ip, session.get('2fa_user', '?'), False, 'invalid TOTP code')
        return jsonify({'ok': False, 'error': 'Invalid verification code'}), 401

    _clear_attempts(ip)
    user = session.pop('2fa_user', 'admin')
    session.clear()
    session['user']   = user
    session.permanent = True
    _audit(ip, user, True, '2FA verified')
    return jsonify({'ok': True, 'username': user})


@auth_bp.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})


@auth_bp.route('/api/auth/me')
def me():
    if 'user' in session and not session.get('2fa_pending'):
        return jsonify({'ok': True, 'username': session['user']})
    return jsonify({'ok': False}), 401


@auth_bp.route('/api/auth/change-password', methods=['POST'])
def change_password():
    if 'user' not in session:
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    d      = request.get_json() or {}
    new_pw = d.get('new_password', '')
    if len(new_pw) < 8:
        return jsonify({'ok': False, 'error': 'Password too short (min 8 characters)'}), 400
    creds = get_credentials()
    creds['password_hash'] = _hash_password(new_pw)
    save_credentials(creds)
    return jsonify({'ok': True})


# ── Login audit log ───────────────────────────────────────────────────────────
@auth_bp.route('/api/auth/audit-log')
def audit_log():
    if 'user' not in session:
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


# ── 2FA setup routes ──────────────────────────────────────────────────────────
@auth_bp.route('/api/auth/2fa/setup', methods=['POST'])
def setup_2fa():
    """Generate a new TOTP secret (does NOT enable it yet — user must verify)."""
    if 'user' not in session:
        return jsonify({'ok': False}), 401
    if not _PYOTP:
        return jsonify({'ok': False, 'error': 'pyotp not installed'}), 400
    secret = _pyotp.random_base32()
    totp   = _pyotp.TOTP(secret)
    uri    = totp.provisioning_uri(
        name=session.get('user', 'admin'),
        issuer_name='VortexPanel'
    )
    # Store pending secret in session (not in creds until verified)
    session['totp_setup_secret'] = secret
    return jsonify({
        'ok':     True,
        'secret': secret,
        'uri':    uri,
        'qr_url': f'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={uri}',
    })


@auth_bp.route('/api/auth/2fa/enable', methods=['POST'])
def enable_2fa():
    """Verify TOTP code and enable 2FA."""
    if 'user' not in session:
        return jsonify({'ok': False}), 401
    if not _PYOTP:
        return jsonify({'ok': False, 'error': 'pyotp not installed'}), 400
    secret = session.get('totp_setup_secret', '')
    if not secret:
        return jsonify({'ok': False, 'error': 'Run /setup first'}), 400
    code = (request.get_json() or {}).get('code', '').replace(' ', '').strip()
    totp = _pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({'ok': False, 'error': 'Invalid code — check your authenticator app'}), 401
    creds = get_credentials()
    creds['totp_secret']  = secret
    creds['totp_enabled'] = True
    save_credentials(creds)
    session.pop('totp_setup_secret', None)
    return jsonify({'ok': True, 'message': '2FA enabled successfully'})


@auth_bp.route('/api/auth/2fa/disable', methods=['POST'])
def disable_2fa():
    """Disable 2FA (requires current password confirmation)."""
    if 'user' not in session:
        return jsonify({'ok': False}), 401
    password = (request.get_json() or {}).get('password', '')
    creds    = get_credentials()
    if not _verify_password(password, creds.get('password_hash', '')):
        return jsonify({'ok': False, 'error': 'Incorrect password'}), 401
    creds.pop('totp_secret',  None)
    creds.pop('totp_enabled', None)
    save_credentials(creds)
    return jsonify({'ok': True, 'message': '2FA disabled'})


@auth_bp.route('/api/auth/2fa/status')
def twofa_status():
    if 'user' not in session:
        return jsonify({'ok': False}), 401
    creds = get_credentials()
    return jsonify({
        'ok':           True,
        'enabled':      bool(creds.get('totp_enabled') and creds.get('totp_secret')),
        'pyotp_available': _PYOTP,
    })


# ── Security settings (IP allowlist) ─────────────────────────────────────────
@auth_bp.route('/api/auth/security-settings')
def get_security_settings():
    if 'user' not in session:
        return jsonify({'ok': False}), 401
    cfg = _get_config()
    return jsonify({
        'ok':           True,
        'allowed_ips':  cfg.get('allowed_ips', []),
        'session_hours':cfg.get('session_hours', 24),
    })


@auth_bp.route('/api/auth/security-settings', methods=['POST'])
def save_security_settings():
    if 'user' not in session:
        return jsonify({'ok': False}), 401
    d   = request.get_json() or {}
    cfg = _get_config()
    if 'allowed_ips' in d:
        ips = [ip.strip() for ip in d['allowed_ips'] if ip.strip()]
        cfg['allowed_ips'] = ips
    if 'session_hours' in d:
        cfg['session_hours'] = max(1, min(720, int(d['session_hours'])))
    _save_config(cfg)
    return jsonify({'ok': True})
