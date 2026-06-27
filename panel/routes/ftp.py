from flask import Blueprint, jsonify, request, session
import subprocess, os, re

ftp_bp = Blueprint('ftp', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.check_output(c, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except: return ''

def get_ftp_daemon():
    """Detect which FTP daemon is installed and running"""
    for daemon in ['pure-ftpd', 'proftpd', 'vsftpd']:
        if sh(f'which {daemon} 2>/dev/null'):
            status = sh(f'systemctl is-active {daemon} 2>/dev/null') or 'inactive'
            return daemon, status
    return None, 'none'

def is_ftp_installed():
    daemon, _ = get_ftp_daemon()
    return daemon is not None


@ftp_bp.route('/api/ftp/users')
def list_users_alias():
    return list_accounts()

@ftp_bp.route('/api/ftp/status')
def ftp_status():
    if not req(): return jsonify({'ok':False}), 401
    daemon, status = get_ftp_daemon()
    installed = daemon is not None

    # Get accounts count
    accounts = _list_ftp_accounts()

    return jsonify({
        'ok': True,
        'installed': installed,
        'daemon': daemon or 'none',
        'status': status,
        'accounts_count': len(accounts),
    })

def _list_ftp_accounts():
    """List FTP virtual users from all possible sources"""
    accounts = []
    seen = set()

    # Pure-FTPd virtual users
    for f in ['/etc/pure-ftpd/pureftpd.passwd', '/etc/pureftpd.passwd']:
        if os.path.exists(f):
            with open(f) as fh:
                for line in fh:
                    parts = line.strip().split(':')
                    if len(parts) >= 7 and parts[0] not in seen:
                        seen.add(parts[0])
                        accounts.append({'user': parts[0], 'home': parts[5] if len(parts)>5 else ''})

    # ProFTPD virtual users
    for f in ['/etc/proftpd/ftpd.passwd']:
        if os.path.exists(f):
            with open(f) as fh:
                for line in fh:
                    parts = line.strip().split(':')
                    if len(parts) >= 6 and parts[0] not in seen:
                        seen.add(parts[0])
                        accounts.append({'user': parts[0], 'home': parts[5]})

    # System users with FTP shell or home in webroot
    if not accounts:
        out = sh("getent passwd | awk -F: '$7 ~ /nologin|false/ && $6 ~ /www/ {print $1\":\"$6}'")
        for line in out.split('\n'):
            if ':' in line:
                user, home = line.split(':', 1)
                if user not in seen:
                    seen.add(user)
                    accounts.append({'user': user, 'home': home})

    return accounts

@ftp_bp.route('/api/ftp/accounts')
def list_accounts():
    if not req(): return jsonify({'ok':False}), 401
    if not is_ftp_installed():
        return jsonify({'ok':False, 'installed':False, 'error':'FTP daemon not installed'}), 200
    return jsonify({'ok':True, 'installed':True, 'accounts': _list_ftp_accounts()})

@ftp_bp.route('/api/ftp/accounts', methods=['POST'])
def create_account():
    if not req(): return jsonify({'ok':False}), 401
    if not is_ftp_installed():
        return jsonify({'ok':False, 'error':'Install Pure-FTPd or ProFTPD via Modules first'}), 400

    d    = request.get_json() or {}
    user = re.sub(r'[^a-zA-Z0-9_-]', '', d.get('user', ''))
    pwd  = d.get('password', '')
    home = d.get('home', f'/www/wwwroot/{user}')

    if not user: return jsonify({'ok':False, 'error':'Username required'}), 400
    if not pwd:  return jsonify({'ok':False, 'error':'Password required'}), 400
    if len(pwd) < 6: return jsonify({'ok':False, 'error':'Password must be at least 6 characters'}), 400

    os.makedirs(home, exist_ok=True)

    daemon, _ = get_ftp_daemon()

    if daemon == 'pure-ftpd':
        # Pure-FTPd virtual user
        sh(f'useradd -s /bin/false -d {home} {user} 2>/dev/null || true')
        result = sh(f'printf "%s\n%s\n" "{pwd}" "{pwd}" | pure-pw useradd {user} -u {user} -d {home} 2>&1')
        sh('pure-pw mkdb 2>/dev/null')
        sh('systemctl reload pure-ftpd 2>/dev/null || true')
    else:
        # Generic system user
        sh(f'useradd -m -d {home} -s /sbin/nologin {user} 2>/dev/null || true')
        sh(f'echo "{user}:{pwd}" | chpasswd')

    return jsonify({'ok':True, 'user':user, 'home':home})

@ftp_bp.route('/api/ftp/accounts/<user>', methods=['DELETE'])
def delete_account(user):
    if not req(): return jsonify({'ok':False}), 401
    daemon, _ = get_ftp_daemon()
    if daemon == 'pure-ftpd':
        sh(f'pure-pw userdel {user} 2>/dev/null && pure-pw mkdb 2>/dev/null')
    sh(f'userdel {user} 2>/dev/null || true')
    return jsonify({'ok':True})

@ftp_bp.route('/api/ftp/accounts/<user>/password', methods=['PUT'])
def change_password(user):
    if not req(): return jsonify({'ok':False}), 401
    pwd = (request.get_json() or {}).get('password','')
    if len(pwd) < 6: return jsonify({'ok':False,'error':'Min 6 characters'}), 400
    daemon, _ = get_ftp_daemon()
    if daemon == 'pure-ftpd':
        sh(f'printf "%s\n%s\n" "{pwd}" "{pwd}" | pure-pw passwd {user} 2>/dev/null && pure-pw mkdb 2>/dev/null')
    else:
        sh(f'echo "{user}:{pwd}" | chpasswd')
    return jsonify({'ok':True})
