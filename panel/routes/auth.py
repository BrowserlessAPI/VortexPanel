from flask import Blueprint, request, jsonify, session
import hashlib, os, json, secrets, string

auth_bp = Blueprint('auth', __name__)

# Check all possible credential locations (old installs + new)
CREDS_LOCATIONS = [
    '/opt/vortexpanel/credentials.json',
    '/opt/vortexpanel/config/credentials.json',
    '/etc/vortexpanel/credentials.json',
    '/root/.vortexpanel/credentials.json',
]
CREDS_FILE = '/opt/vortexpanel/credentials.json'

def find_creds_file():
    for path in CREDS_LOCATIONS:
        if os.path.exists(path):
            return path
    return None

def get_credentials():
    path = find_creds_file()
    if path:
        try:
            with open(path) as f:
                data = json.load(f)
            # Normalize: support both 'password_hash' and 'password' (plain) fields
            if 'password' in data and 'password_hash' not in data:
                # Old install stored plaintext — hash it and resave
                data['password_hash'] = hashlib.sha256(data['password'].encode()).hexdigest()
                save_credentials(data)
            return data
        except Exception:
            pass
    # No creds file — create one with admin/admin123
    creds = {
        'username': 'admin',
        'password_hash': hashlib.sha256(b'admin123').hexdigest()
    }
    save_credentials(creds)
    return creds

def save_credentials(creds):
    os.makedirs(os.path.dirname(CREDS_FILE), exist_ok=True)
    with open(CREDS_FILE, 'w') as f:
        json.dump(creds, f, indent=2)


@auth_bp.route('/api/auth/check')
def check_session():
    if 'user' in session:
        resp = jsonify({'ok': True, 'logged_in': True, 'username': session.get('user','admin')})
    else:
        resp = jsonify({'ok': True, 'logged_in': False})
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return resp

@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    data     = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    creds    = get_credentials()

    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    # Accept match by username OR by email field
    username_match = (username == creds.get('username', 'admin'))
    email_match    = (username == creds.get('email', ''))
    hash_match     = (pw_hash  == creds.get('password_hash', ''))

    if (username_match or email_match) and hash_match:
        session['user']  = creds.get('username', 'admin')
        session.permanent = True
        return jsonify({'ok': True, 'username': session['user']})

    return jsonify({'ok': False, 'error': 'Invalid credentials'}), 401

@auth_bp.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})

@auth_bp.route('/api/auth/me')
def me():
    if 'user' in session:
        return jsonify({'ok': True, 'username': session['user']})
    return jsonify({'ok': False}), 401

@auth_bp.route('/api/auth/change-password', methods=['POST'])
def change_password():
    if 'user' not in session:
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    d      = request.get_json() or {}
    new_pw = d.get('new_password', '')
    if len(new_pw) < 6:
        return jsonify({'ok': False, 'error': 'Password too short (min 6 chars)'}), 400
    creds = get_credentials()
    creds['password_hash'] = hashlib.sha256(new_pw.encode()).hexdigest()
    save_credentials(creds)
    return jsonify({'ok': True})
