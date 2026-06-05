from flask import Blueprint, jsonify, request, session
import subprocess, os, re

ftp_bp = Blueprint('ftp', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
    except: return ''

@ftp_bp.route('/api/ftp/accounts')
def list_accounts():
    if not req(): return jsonify({'ok':False}),401
    accounts = []
    # Check proftpd/vsftpd virtual users
    for f in ['/etc/proftpd/ftpd.passwd', '/etc/vsftpd/virtual_users']:
        if os.path.exists(f):
            with open(f) as fh:
                for line in fh:
                    parts = line.strip().split(':')
                    if len(parts)>=6: accounts.append({'user':parts[0],'home':parts[5]})
    return jsonify({'ok':True,'accounts':accounts})

@ftp_bp.route('/api/ftp/accounts', methods=['POST'])
def create_account():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    user = re.sub(r'[^a-zA-Z0-9_-]','',d.get('user',''))
    pwd  = d.get('password','')
    home = d.get('home',f'/www/wwwroot/{user}')
    if not user: return jsonify({'ok':False,'error':'Username required'}),400
    os.makedirs(home, exist_ok=True)
    # Add system user for FTP
    sh(f'useradd -m -d {home} -s /sbin/nologin {user} 2>/dev/null || true')
    sh(f'echo "{user}:{pwd}" | chpasswd')
    return jsonify({'ok':True,'user':user})

@ftp_bp.route('/api/ftp/accounts/<user>', methods=['DELETE'])
def delete_account(user):
    if not req(): return jsonify({'ok':False}),401
    sh(f'userdel {user} 2>/dev/null')
    return jsonify({'ok':True})

@ftp_bp.route('/api/ftp/status')
def ftp_status():
    if not req(): return jsonify({'ok':False}),401
    proftpd = sh('systemctl is-active proftpd 2>/dev/null')
    vsftpd  = sh('systemctl is-active vsftpd 2>/dev/null')
    daemon  = 'proftpd' if proftpd=='active' else ('vsftpd' if vsftpd=='active' else 'none')
    return jsonify({'ok':True,'daemon':daemon,'proftpd':proftpd,'vsftpd':vsftpd})
