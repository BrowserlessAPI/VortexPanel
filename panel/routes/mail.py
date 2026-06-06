from flask import Blueprint, jsonify, request, session
import subprocess, os, re

mail_bp = Blueprint('mail', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
    except: return ''

# Mail users stored in /etc/vortexpanel/mail_users (format: user@domain:password_hash)
MAIL_USERS_FILE = '/opt/vortexpanel/mail_users.txt'

@mail_bp.route('/api/mail/status')
def mail_status():
    if not req(): return jsonify({'ok':False}),401
    postfix = sh('systemctl is-active postfix')
    dovecot = sh('systemctl is-active dovecot')
    queue   = sh('mailq 2>/dev/null | tail -1')
    try: q_count = int(re.search(r'(\d+)\s+Request', queue or '0').group(1))
    except: q_count = 0
    return jsonify({'ok':True,'postfix':postfix,'dovecot':dovecot,'queue':q_count})

@mail_bp.route('/api/mail/domains')
def mail_domains():
    if not req(): return jsonify({'ok':False}),401
    raw = sh('cat /etc/postfix/virtual_mailbox_domains 2>/dev/null')
    domains = [l.strip() for l in raw.split('\n') if l.strip() and not l.startswith('#')]
    return jsonify({'ok':True,'domains':domains})

@mail_bp.route('/api/mail/domains', methods=['POST'])
def add_domain():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    domain = d.get('domain','').strip()
    if not domain: return jsonify({'ok':False,'error':'Domain required'}),400
    # Append to postfix virtual_mailbox_domains
    with open('/etc/postfix/virtual_mailbox_domains','a') as f:
        f.write(f'{domain} OK\n')
    sh('postmap /etc/postfix/virtual_mailbox_domains')
    sh('systemctl reload postfix')
    return jsonify({'ok':True})

@mail_bp.route('/api/mail/accounts')
def mail_accounts():
    if not req(): return jsonify({'ok':False}),401
    accounts = []
    for f in ['/etc/postfix/virtual_mailbox_maps', MAIL_USERS_FILE]:
        if os.path.exists(f):
            with open(f) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith('#') and '@' in line:
                        email = line.split()[0]
                        accounts.append({'email':email})
    return jsonify({'ok':True,'accounts':accounts})

@mail_bp.route('/api/mail/accounts', methods=['POST'])
def create_account():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    email    = d.get('email','').strip()
    password = d.get('password','')
    if not email or '@' not in email: return jsonify({'ok':False,'error':'Valid email required'}),400
    user, domain = email.split('@',1)
    # Create maildir
    maildir = f'/var/mail/vhosts/{domain}/{user}/'
    sh(f'mkdir -p {maildir}{{cur,new,tmp}}')
    sh(f'chown -R vmail:vmail /var/mail/vhosts/ 2>/dev/null || true')
    # Add to postfix maps
    for f in ['/etc/postfix/virtual_mailbox_maps']:
        if os.path.exists(f):
            with open(f,'a') as fh: fh.write(f'{email} {domain}/{user}/\n')
            sh(f'postmap {f}')
    # Set dovecot password
    pw_hash = sh(f'doveadm pw -s SHA512-CRYPT -p "{password}" 2>/dev/null')
    os.makedirs(os.path.dirname(MAIL_USERS_FILE), exist_ok=True)
    with open(MAIL_USERS_FILE,'a') as f: f.write(f'{email}:{pw_hash}\n')
    sh('systemctl reload postfix dovecot 2>/dev/null')
    return jsonify({'ok':True,'email':email})

@mail_bp.route('/api/mail/accounts/<path:email>', methods=['DELETE'])
def delete_account(email):
    if not req(): return jsonify({'ok':False}),401
    for f in ['/etc/postfix/virtual_mailbox_maps', MAIL_USERS_FILE]:
        if os.path.exists(f):
            with open(f) as fh: lines = fh.readlines()
            with open(f,'w') as fh:
                fh.writelines(l for l in lines if not l.startswith(email))
            if 'virtual' in f: sh(f'postmap {f}')
    sh('systemctl reload postfix dovecot 2>/dev/null')
    return jsonify({'ok':True})

@mail_bp.route('/api/mail/queue')
def mail_queue():
    if not req(): return jsonify({'ok':False}),401
    raw = sh('mailq 2>/dev/null')
    return jsonify({'ok':True,'output':raw})

@mail_bp.route('/api/mail/queue/flush', methods=['POST'])
def flush_queue():
    if not req(): return jsonify({'ok':False}),401
    sh('postqueue -f')
    return jsonify({'ok':True})

@mail_bp.route('/api/mail/dkim/<domain>')
def get_dkim(domain):
    if not req(): return jsonify({'ok':False}),401
    key_file = f'/etc/opendkim/keys/{domain}/default.txt'
    if os.path.exists(key_file):
        with open(key_file) as f: return jsonify({'ok':True,'record':f.read()})
    return jsonify({'ok':False,'error':'DKIM key not generated yet'})

@mail_bp.route('/api/mail/dkim/<domain>', methods=['POST'])
def gen_dkim(domain):
    if not req(): return jsonify({'ok':False}),401
    sh(f'mkdir -p /etc/opendkim/keys/{domain}')
    sh(f'opendkim-genkey -t -s default -d {domain} -D /etc/opendkim/keys/{domain}/')
    key_file = f'/etc/opendkim/keys/{domain}/default.txt'
    if os.path.exists(key_file):
        with open(key_file) as f: return jsonify({'ok':True,'record':f.read()})
    return jsonify({'ok':False,'error':'opendkim-genkey failed or not installed'})

@mail_bp.route('/api/mail/control', methods=['POST'])
def control_mail():
    if not req(): return jsonify({'ok': False}), 401
    d       = request.get_json() or {}
    service = d.get('service', 'postfix')   # postfix | dovecot
    action  = d.get('action', 'restart')    # start | stop | restart | reload
    if action not in ('start','stop','restart','reload','status'):
        return jsonify({'ok': False, 'error': 'Invalid action'}), 400
    svc_map = {'postfix':'postfix', 'dovecot':'dovecot'}
    svc = svc_map.get(service, service)
    out, err, rc = sh(f'systemctl {action} {svc} 2>&1', t=15)
    # Get new status
    st_out, _, _ = sh(f'systemctl is-active {svc} 2>/dev/null')
    return jsonify({'ok': rc==0 or action=='status', 'status': st_out.strip(),
                    'output': out or err, 'error': err if rc!=0 else ''})
