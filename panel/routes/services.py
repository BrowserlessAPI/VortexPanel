from flask import Blueprint, jsonify, request, session
import subprocess

services_bp = Blueprint('services', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
    except: return ''

SERVICES = [
    {'name':'nginx',          'label':'Nginx',            'icon':'globe'},
    {'name':'apache2',        'label':'Apache2',          'icon':'dot'},
    {'name':'mysql',          'label':'MySQL',            'icon':'database'},
    {'name':'mariadb',        'label':'MariaDB',          'icon':'database'},
    {'name':'redis-server',   'label':'Redis',            'icon':'dot'},
    {'name':'memcached',      'label':'Memcached',        'icon':'hard-drive'},
    {'name':'php8.3-fpm',     'label':'PHP 8.3-FPM',      'icon':'code'},
    {'name':'php8.2-fpm',     'label':'PHP 8.2-FPM',      'icon':'code'},
    {'name':'php8.1-fpm',     'label':'PHP 8.1-FPM',      'icon':'code'},
    {'name':'postfix',        'label':'Postfix (Mail)',   'icon':'mail'},
    {'name':'dovecot',        'label':'Dovecot (IMAP)',   'icon':'mail'},
    {'name':'docker',         'label':'Docker',           'icon':'package'},
    {'name':'fail2ban',       'label':'Fail2ban',         'icon':'shield'},
    {'name':'ufw',            'label':'UFW Firewall',     'icon':'flame'},
    {'name':'bind9',          'label':'BIND9 (DNS)',      'icon':'globe'},
    {'name':'proftpd',        'label':'ProFTPD',          'icon':'folder'},
    {'name':'vsftpd',         'label':'vsftpd',           'icon':'folder'},
]

@services_bp.route('/api/services')
def list_svcs():
    if not req(): return jsonify({'ok':False}),401
    result = []
    for svc in SERVICES:
        status = sh(f"systemctl is-active {svc['name']} 2>/dev/null")
        if status:  # Only show if service exists
            enabled = sh(f"systemctl is-enabled {svc['name']} 2>/dev/null")
            result.append({**svc, 'status':status, 'enabled':enabled=='enabled'})
    return jsonify({'ok':True,'services':result})

@services_bp.route('/api/services/<name>/<action>', methods=['POST'])
def control(name, action):
    if not req(): return jsonify({'ok':False}),401
    if action not in ('start','stop','restart','reload','enable','disable'):
        return jsonify({'ok':False,'error':'Invalid action'}),400
    ok = subprocess.run(f'systemctl {action} {name}',shell=True).returncode == 0
    return jsonify({'ok':ok,'status':sh(f'systemctl is-active {name}')})
