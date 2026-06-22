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
    domains = [l.strip().split()[0] for l in raw.split('\n') if l.strip() and not l.startswith('#')]
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
    domain_filter = request.args.get('domain','').strip()
    accounts = []
    seen = set()
    for f in ['/etc/postfix/virtual_mailbox_maps', MAIL_USERS_FILE]:
        if os.path.exists(f):
            with open(f) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith('#') and '@' in line:
                        email = line.split(':')[0].split()[0]
                        if email in seen: continue
                        if domain_filter and not email.endswith('@'+domain_filter): continue
                        seen.add(email)
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

@mail_bp.route('/api/mail/accounts/<path:email>/password', methods=['PUT'])
def reset_mail_password(email):
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    password = d.get('password','')
    if not password: return jsonify({'ok':False,'error':'Password required'}),400
    pw_hash = sh(f'doveadm pw -s SHA512-CRYPT -p "{password}" 2>/dev/null')
    if not pw_hash: return jsonify({'ok':False,'error':'Failed to hash password'}),500
    updated = False
    if os.path.exists(MAIL_USERS_FILE):
        with open(MAIL_USERS_FILE) as fh: lines = fh.readlines()
        with open(MAIL_USERS_FILE,'w') as fh:
            for line in lines:
                if line.startswith(email+':'):
                    fh.write(f'{email}:{pw_hash}\n')
                    updated = True
                else:
                    fh.write(line)
    if not updated:
        with open(MAIL_USERS_FILE,'a') as fh: fh.write(f'{email}:{pw_hash}\n')
    sh('systemctl reload dovecot 2>/dev/null')
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
    service = d.get('service', 'postfix')   # postfix | dovecot | opendkim
    action  = d.get('action', 'restart')    # start | stop | restart | reload | status
    if action not in ('start','stop','restart','reload','status'):
        return jsonify({'ok': False, 'error': 'Invalid action'}), 400
    svc_map = {'postfix':'postfix', 'dovecot':'dovecot', 'opendkim':'opendkim'}
    svc = svc_map.get(service, service)
    if action != 'status':
        sh(f'systemctl {action} {svc} 2>&1')
    st_out = sh(f'systemctl is-active {svc} 2>/dev/null')
    return jsonify({'ok': True, 'status': st_out.strip()})

VIRTUAL_ALIAS_FILE = '/etc/postfix/virtual_alias_maps'

@mail_bp.route('/api/mail/forwarding')
def list_forwarding():
    if not req(): return jsonify({'ok':False}),401
    domain = request.args.get('domain','')
    rules = []
    if os.path.exists(VIRTUAL_ALIAS_FILE):
        with open(VIRTUAL_ALIAS_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                parts = line.split(None, 1)
                if len(parts) != 2: continue
                source, dest = parts
                if domain and not source.endswith('@'+domain): continue
                rules.append({'source':source, 'destination':dest})
    return jsonify({'ok':True, 'rules':rules})

@mail_bp.route('/api/mail/forwarding', methods=['POST'])
def add_forwarding():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    source = (d.get('source') or '').strip().lower()
    dest   = (d.get('destination') or '').strip().lower()
    if not source or not dest or '@' not in source or '@' not in dest:
        return jsonify({'ok':False,'error':'Valid source and destination email addresses required'}),400
    lines = []
    if os.path.exists(VIRTUAL_ALIAS_FILE):
        with open(VIRTUAL_ALIAS_FILE) as f: lines = f.readlines()
    lines = [l for l in lines if not l.strip().startswith(source+' ') and not l.strip().startswith(source+'\t')]
    lines.append(f'{source}\t{dest}\n')
    with open(VIRTUAL_ALIAS_FILE,'w') as f: f.writelines(lines)
    sh(f'postmap {VIRTUAL_ALIAS_FILE}')
    sh('systemctl reload postfix 2>/dev/null')
    return jsonify({'ok':True})

@mail_bp.route('/api/mail/forwarding', methods=['DELETE'])
def del_forwarding():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    source = (d.get('source') or '').strip().lower()
    if not source: return jsonify({'ok':False,'error':'source required'}),400
    if os.path.exists(VIRTUAL_ALIAS_FILE):
        with open(VIRTUAL_ALIAS_FILE) as f: lines = f.readlines()
        lines = [l for l in lines if not l.strip().startswith(source+' ') and not l.strip().startswith(source+'\t')]
        with open(VIRTUAL_ALIAS_FILE,'w') as f: f.writelines(lines)
        sh(f'postmap {VIRTUAL_ALIAS_FILE}')
        sh('systemctl reload postfix 2>/dev/null')
    return jsonify({'ok':True})

@mail_bp.route('/api/mail/logs')
def mail_logs():
    if not req(): return jsonify({'ok':False}),401
    which = request.args.get('which','mail')
    try:
        lines = max(50, min(1000, int(request.args.get('lines', 200))))
    except: lines = 200
    # Support both Debian (/var/log/mail.log) and RHEL (/var/log/maillog) paths
    log_candidates = ['/var/log/mail.log', '/var/log/maillog']
    path = next((p for p in log_candidates if os.path.exists(p)), None)
    if not path:
        # Try journalctl as fallback (systemd-based distros)
        svc = 'postfix' if which == 'postfix' else 'dovecot' if which == 'dovecot' else ''
        if svc:
            out = sh(f'journalctl -u {svc} -n {lines} --no-pager 2>/dev/null')
        else:
            out = sh(f'journalctl -n {lines} --no-pager 2>/dev/null | grep -iE "postfix|dovecot|smtp|imap"')
        return jsonify({'ok':True, 'lines': out or 'No log entries found (journalctl fallback)', 'source':'journalctl'})
    grep = ''
    if which == 'postfix': grep = " | grep -i postfix"
    elif which == 'dovecot': grep = " | grep -i dovecot"
    out = sh(f'tail -n {lines} {path}{grep} 2>/dev/null')
    return jsonify({'ok':True, 'lines': out or 'No log entries found', 'source': path})
