from flask import Blueprint, request, jsonify, session
import hashlib, os, json

auth_bp = Blueprint('auth', __name__)

CREDS_FILE = '/opt/vortexpanel/credentials.json'

def get_credentials():
    if os.path.exists(CREDS_FILE):
        with open(CREDS_FILE) as f:
            return json.load(f)
    # Default credentials if file doesn't exist
    return {"username": "admin", "password_hash": hashlib.sha256(b"admin123").hexdigest()}

@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username','').strip()
    password = data.get('password','')
    creds = get_credentials()
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    if username == creds['username'] and pw_hash == creds['password_hash']:
        session['user'] = username
        session.permanent = True
        return jsonify({'ok': True, 'username': username})
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
    data = request.get_json() or {}
    new_pw = data.get('new_password','')
    if len(new_pw) < 6:
        return jsonify({'ok': False, 'error': 'Password too short (min 6 chars)'}), 400
    creds = get_credentials()
    creds['password_hash'] = hashlib.sha256(new_pw.encode()).hexdigest()
    os.makedirs(os.path.dirname(CREDS_FILE), exist_ok=True)
    with open(CREDS_FILE, 'w') as f:
        json.dump(creds, f)
    return jsonify({'ok': True})
