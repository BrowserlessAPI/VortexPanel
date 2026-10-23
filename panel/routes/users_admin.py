"""Panel accounts (Settings > Users) and API keys (Settings > API)."""
import re
import secrets
import time
import uuid

from flask import Blueprint, jsonify, request, g

from panel import users as U
from panel.routes.auth import (require_admin, _hash_password, _audit, _client_ip,
                               get_credentials, check_ip_and_session)

users_bp = Blueprint('users_admin', __name__)


def _err(msg, code=400):
    return jsonify({'ok': False, 'error': msg}), code


def _valid_sites(sites):
    try:
        from panel.routes.websites_core import list_sites
        known = {s['domain'] for s in list_sites()}
    except Exception:
        known = set()
    out = []
    for s in sites or []:
        s = str(s).strip().lower()
        if s and (s in known or not known):
            out.append(s)
    return sorted(set(out))


@users_bp.route('/api/users/me')
def me():
    if not check_ip_and_session():
        return _err('Unauthorized', 401)
    u = g.vp_user
    return jsonify({'ok': True, 'username': u['username'], 'role': u['role'],
                    'sites': u['sites'], 'roles': U.ROLES})


@users_bp.route('/api/users')
def list_all():
    e = require_admin()
    if e:
        return e
    creds = get_credentials()
    admin = {'id': 'admin', 'username': creds.get('username', 'admin'), 'role': 'admin',
             'sites': [], 'disabled': False, 'twofa': bool(creds.get('totp_enabled')),
             'created': None, 'last_login': creds.get('last_login'), 'primary': True}
    return jsonify({'ok': True, 'users': [admin] + [U.public_user(u) for u in U.list_users()],
                    'roles': U.ROLES})


@users_bp.route('/api/users', methods=['POST'])
def create():
    e = require_admin()
    if e:
        return e
    d = request.get_json(silent=True) or {}
    name = str(d.get('username') or '').strip()
    pw = d.get('password') or ''
    role = d.get('role') or 'site'
    if not U.USERNAME_RE.match(name):
        return _err('Username: 3-64 characters, letters, digits, dot, dash, underscore or @')
    if name.lower() == get_credentials().get('username', 'admin').lower() or U.find_user_by_name(name):
        return _err('An account with this username already exists')
    if role not in U.ROLES:
        return _err('Unknown role')
    if not isinstance(pw, str) or len(pw) < 10:
        return _err('Password must be at least 10 characters')
    sites = _valid_sites(d.get('sites')) if role == 'site' else []
    if role == 'site' and not sites:
        return _err('Choose at least one website for a site manager')
    user = {'id': uuid.uuid4().hex[:12], 'username': name, 'role': role, 'sites': sites,
            'password_hash': _hash_password(pw), 'created': int(time.time()),
            'session_version': secrets.token_hex(8), 'note': str(d.get('note') or '')[:200]}
    users = U.list_users()
    users.append(user)
    U.save_users(users)
    _audit(_client_ip(), g.vp_user['username'], True, f'user {name} created ({role})')
    return jsonify({'ok': True, 'user': U.public_user(user)})


@users_bp.route('/api/users/<uid>', methods=['PUT'])
def update(uid):
    e = require_admin()
    if e:
        return e
    u = U.get_user(uid)
    if not u:
        return _err('No such user', 404)
    d = request.get_json(silent=True) or {}
    ch = {}
    if 'role' in d:
        if d['role'] not in U.ROLES:
            return _err('Unknown role')
        ch['role'] = d['role']
    role = ch.get('role', u.get('role'))
    if 'sites' in d or 'role' in d:
        ch['sites'] = _valid_sites(d.get('sites', u.get('sites'))) if role == 'site' else []
        if role == 'site' and not ch['sites']:
            return _err('Choose at least one website for a site manager')
    if 'disabled' in d:
        ch['disabled'] = bool(d['disabled'])
    if 'note' in d:
        ch['note'] = str(d['note'] or '')[:200]
    if d.get('password'):
        if len(d['password']) < 10:
            return _err('Password must be at least 10 characters')
        ch['password_hash'] = _hash_password(d['password'])
    if d.get('reset_2fa'):
        ch.update(totp_secret=None, totp_enabled=None, totp_last_step=None, backup_codes=None)
    # Any change to access signs the account out everywhere.
    ch['session_version'] = secrets.token_hex(8)
    u = U.update_user(uid, ch)
    _audit(_client_ip(), g.vp_user['username'], True,
           f'user {u["username"]} updated ({", ".join(k for k in d if k != "password") or "password"})')
    return jsonify({'ok': True, 'user': U.public_user(u)})


@users_bp.route('/api/users/<uid>', methods=['DELETE'])
def delete(uid):
    e = require_admin()
    if e:
        return e
    users = U.list_users()
    keep = [u for u in users if u.get('id') != uid]
    if len(keep) == len(users):
        return _err('No such user', 404)
    U.save_users(keep)
    gone = next(u for u in users if u.get('id') == uid)
    _audit(_client_ip(), g.vp_user['username'], True, f'user {gone["username"]} deleted')
    return jsonify({'ok': True})


# --- API keys ----------------------------------------------------------------------
@users_bp.route('/api/apikeys')
def keys_list():
    e = require_admin()
    if e:
        return e
    return jsonify({'ok': True, 'keys': [U.public_key(k) for k in U.list_keys()]})


@users_bp.route('/api/apikeys', methods=['POST'])
def keys_create():
    e = require_admin()
    if e:
        return e
    d = request.get_json(silent=True) or {}
    name = str(d.get('name') or '').strip()[:60]
    role = d.get('role') or 'viewer'
    if not name:
        return _err('Give the key a name')
    if role not in ('admin', 'viewer', 'provisioning'):
        return _err('API keys can have the admin, viewer or hosting provisioning role')
    ips = d.get('allowed_ips') or []
    if isinstance(ips, str):
        ips = re.split(r'[\s,]+', ips)
    ips = [x.strip() for x in ips if x.strip()]
    import ipaddress
    for r in ips:
        try:
            ipaddress.ip_network(r, strict=False)
        except ValueError:
            return _err(f'Invalid IP or CIDR: {r}')
    try:
        days = max(0, min(3650, int(d.get('expires_days') or 0)))
    except (TypeError, ValueError):
        return _err('expires_days must be a number')
    token, entry = U.create_key(name, role, ips, days)
    _audit(_client_ip(), g.vp_user['username'], True, f'API key {name} created ({role})')
    return jsonify({'ok': True, 'token': token, 'key': U.public_key(entry)})


@users_bp.route('/api/apikeys/<kid>', methods=['PUT'])
def keys_update(kid):
    e = require_admin()
    if e:
        return e
    d = request.get_json(silent=True) or {}
    keys = U.list_keys()
    for k in keys:
        if k.get('id') == kid:
            if 'disabled' in d:
                k['disabled'] = bool(d['disabled'])
            U.save_keys(keys)
            return jsonify({'ok': True, 'key': U.public_key(k)})
    return _err('No such key', 404)


@users_bp.route('/api/apikeys/<kid>', methods=['DELETE'])
def keys_delete(kid):
    e = require_admin()
    if e:
        return e
    keys = U.list_keys()
    keep = [k for k in keys if k.get('id') != kid]
    if len(keep) == len(keys):
        return _err('No such key', 404)
    U.save_keys(keep)
    _audit(_client_ip(), g.vp_user['username'], True, f'API key {kid} deleted')
    return jsonify({'ok': True})
