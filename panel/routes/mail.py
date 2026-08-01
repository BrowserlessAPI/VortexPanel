from flask import Blueprint, jsonify, request, session
import subprocess, os, re

mail_bp = Blueprint('mail', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
    except: return ''

# Mail users stored in /etc/vortexpanel/mail_users (format: user@domain:password_hash)
MAIL_USERS_FILE = '/opt/vortexpanel/mail_users.txt'
# Dovecot reads its virtual users from here. The panel keeps this in sync with
# MAIL_USERS_FILE -- previously the panel only ever wrote its own file, which
# Dovecot never reads, so no virtual user could ever authenticate.
DOVECOT_USERS_FILE = '/etc/dovecot/users'
VMAIL_BASE = '/var/mail/vhosts'


def _mail_configured():
    """Whether virtual mailbox delivery has actually been set up.

    Checked by reading Postfix's live config rather than a marker file, so it
    stays honest if someone changes things by hand.
    """
    base = sh('postconf -h virtual_mailbox_base 2>/dev/null')
    transport = sh('postconf -h virtual_transport 2>/dev/null')
    return bool(base) and 'lmtp' in (transport or '').lower()


def _sync_dovecot_users():
    """Mirror the panel's user list into Dovecot's passwd-file.

    Kept as a separate step (rather than writing only Dovecot's file) so the
    panel keeps its own record even if Dovecot is reinstalled and its config
    directory is recreated from scratch.
    """
    try:
        if not os.path.exists(MAIL_USERS_FILE):
            return
        lines = []
        with open(MAIL_USERS_FILE) as f:
            for line in f:
                line = line.strip()
                if line and ':' in line and '@' in line:
                    lines.append(line)
        os.makedirs(os.path.dirname(DOVECOT_USERS_FILE), exist_ok=True)
        with open(DOVECOT_USERS_FILE, 'w') as f:
            f.write('\n'.join(lines) + ('\n' if lines else ''))
        sh(f'chown dovecot:dovecot {DOVECOT_USERS_FILE} 2>/dev/null; chmod 600 {DOVECOT_USERS_FILE}')
    except Exception:
        pass


@mail_bp.route('/api/mail/setup', methods=['POST'])
def setup_mail():
    """Configure virtual mailbox delivery end to end.

    WHY THIS EXISTS: the panel could create mail domains, accounts and
    forwarding rules, and all of that was written correctly into Postfix's
    lookup tables -- but nothing ever told Postfix to USE those tables, so no
    mail was ever actually delivered to a virtual mailbox. Postfix shipped
    with virtual_mailbox_base, virtual_uid_maps and virtual_gid_maps all
    empty, and there was no Dovecot passdb pointing at the panel's users.
    Account management worked; mail did not.

    Delivery goes Postfix -> Dovecot LMTP rather than Postfix writing maildirs
    itself. Postfix writing files directly behind Dovecot's back is the classic
    cause of "mail delivered but invisible in IMAP", because Dovecot's index
    never learns about it.
    """
    if not req(): return jsonify({'ok':False}), 401
    log = []

    # 1. vmail user owns every virtual mailbox.
    sh('getent group vmail >/dev/null 2>&1 || groupadd -g 5000 vmail')
    sh('id vmail >/dev/null 2>&1 || useradd -g vmail -u 5000 vmail '
       f'-d {VMAIL_BASE} -m -s /usr/sbin/nologin')
    os.makedirs(VMAIL_BASE, exist_ok=True)
    sh(f'chown -R vmail:vmail {VMAIL_BASE}; chmod 770 {VMAIL_BASE}')
    vuid = sh('id -u vmail') or '5000'
    vgid = sh("getent group vmail | cut -d: -f3") or '5000'
    log.append(f'vmail user ready (uid={vuid} gid={vgid})')

    # 2. Lookup tables must exist and be hashed BEFORE main.cf references them,
    #    or postfix refuses to start.
    for t in ('virtual_mailbox_domains', 'virtual_mailbox_maps', 'virtual_alias_maps'):
        p = f'/etc/postfix/{t}'
        if not os.path.exists(p):
            open(p, 'a').close()
        sh(f'postmap {p}')
    log.append('Postfix lookup tables created and hashed')

    # 3. The actual missing configuration.
    settings = [
        'virtual_mailbox_domains = hash:/etc/postfix/virtual_mailbox_domains',
        'virtual_mailbox_maps = hash:/etc/postfix/virtual_mailbox_maps',
        'virtual_alias_maps = hash:/etc/postfix/virtual_alias_maps',
        f'virtual_mailbox_base = {VMAIL_BASE}',
        f'virtual_uid_maps = static:{vuid}',
        f'virtual_gid_maps = static:{vgid}',
        'virtual_transport = lmtp:unix:private/dovecot-lmtp',
        'smtpd_sasl_type = dovecot',
        'smtpd_sasl_path = private/auth',
        'smtpd_sasl_auth_enable = yes',
        'smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination',
    ]
    for s in settings:
        sh(f'postconf -e "{s}"')
    # A virtual domain must NOT also be in mydestination -- if it is, Postfix
    # treats it as a local domain and never consults the virtual maps at all.
    mydest = sh('postconf -h mydestination') or ''
    log.append('Postfix virtual delivery configured (via Dovecot LMTP)')

    # 4. Dovecot: where mail lives, who the users are, and the two sockets
    #    Postfix needs (LMTP for delivery, auth for SASL submission).
    dovecot_conf = f"""# Managed by VortexPanel -- virtual mailbox delivery. Do not edit by hand.
mail_location = maildir:{VMAIL_BASE}/%d/%n
mail_privileged_group = vmail
mail_uid = vmail
mail_gid = vmail

passdb {{
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%u {DOVECOT_USERS_FILE}
}}
userdb {{
  driver = static
  args = uid=vmail gid=vmail home={VMAIL_BASE}/%d/%n
}}

service lmtp {{
  unix_listener /var/spool/postfix/private/dovecot-lmtp {{
    mode = 0600
    user = postfix
    group = postfix
  }}
}}

service auth {{
  unix_listener /var/spool/postfix/private/auth {{
    mode = 0660
    user = postfix
    group = postfix
  }}
}}

protocols = imap lmtp
"""
    os.makedirs('/etc/dovecot/conf.d', exist_ok=True)
    with open('/etc/dovecot/conf.d/99-vortexpanel.conf', 'w') as f:
        f.write(dovecot_conf)
    if not os.path.exists(DOVECOT_USERS_FILE):
        open(DOVECOT_USERS_FILE, 'a').close()
    _sync_dovecot_users()
    log.append('Dovecot configured (LMTP delivery + SASL auth sockets)')

    # 5. Validate before restarting -- never leave a broken mail server.
    pf_check = subprocess.run('postfix check', shell=True, capture_output=True, text=True)
    if pf_check.returncode != 0:
        return jsonify({'ok': False,
                        'error': f'Postfix config invalid, not restarting: {(pf_check.stderr or pf_check.stdout).strip()}',
                        'log': log}), 500
    dc_check = subprocess.run('doveconf -n', shell=True, capture_output=True, text=True)
    if dc_check.returncode != 0:
        return jsonify({'ok': False,
                        'error': f'Dovecot config invalid, not restarting: {(dc_check.stderr or dc_check.stdout).strip()}',
                        'log': log}), 500
    log.append('Both configs validated')

    sh('systemctl restart dovecot 2>/dev/null || service dovecot restart 2>/dev/null')
    sh('systemctl restart postfix 2>/dev/null || service postfix restart 2>/dev/null')
    log.append('Services restarted')

    warn = None
    if mydest and any(d.strip() and d.strip() not in ('localhost', '$myhostname', 'localhost.$mydomain')
                      for d in mydest.split(',')):
        warn = (f'mydestination is currently "{mydest}". Any mail domain listed there is treated as '
                'a local domain and will bypass virtual mailbox delivery entirely. Remove hosted mail '
                'domains from mydestination if they appear in it.')

    return jsonify({'ok': True, 'log': log, 'warning': warn,
                    'configured': _mail_configured()})

@mail_bp.route('/api/mail/status')
def mail_status():
    if not req(): return jsonify({'ok':False}),401
    postfix = sh('systemctl is-active postfix')
    dovecot = sh('systemctl is-active dovecot')
    queue   = sh('mailq 2>/dev/null | tail -1')
    try: q_count = int(re.search(r'(\d+)\s+Request', queue or '0').group(1))
    except: q_count = 0
    return jsonify({'ok':True,'postfix':postfix,'dovecot':dovecot,'queue':q_count,
                    'configured':_mail_configured()})

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
    if not re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', email):
        return jsonify({'ok':False,'error':'Valid email required'}),400
    user, domain = email.split('@',1)
    # Create maildir
    maildir = f'/var/mail/vhosts/{domain}/{user}/'
    sh(f'mkdir -p {maildir}cur {maildir}new {maildir}tmp')
    sh(f'chown -R vmail:vmail /var/mail/vhosts/ 2>/dev/null || true')
    # Add to postfix maps
    for f in ['/etc/postfix/virtual_mailbox_maps']:
        if os.path.exists(f):
            with open(f,'a') as fh: fh.write(f'{email} {domain}/{user}/\n')
            sh(f'postmap {f}')
    # Set dovecot password -- subprocess with an argument list instead of
    # shell string interpolation eliminates the injection entirely rather
    # than trying to escape the password correctly.
    hash_proc = subprocess.run(['doveadm', 'pw', '-s', 'SHA512-CRYPT', '-p', password],
                                capture_output=True, text=True)
    pw_hash = hash_proc.stdout.strip()
    os.makedirs(os.path.dirname(MAIL_USERS_FILE), exist_ok=True)
    with open(MAIL_USERS_FILE,'a') as f: f.write(f'{email}:{pw_hash}\n')
    # Dovecot reads its own file, not the panel's -- without this the
    # account exists on paper but cannot authenticate.
    _sync_dovecot_users()
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
    # Remove from Dovecot too -- otherwise the deleted account can still log in.
    _sync_dovecot_users()
    sh('systemctl reload postfix dovecot 2>/dev/null')
    return jsonify({'ok':True})

@mail_bp.route('/api/mail/accounts/<path:email>/password', methods=['PUT'])
def reset_mail_password(email):
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    password = d.get('password','')
    if not password: return jsonify({'ok':False,'error':'Password required'}),400
    hash_proc = subprocess.run(['doveadm', 'pw', '-s', 'SHA512-CRYPT', '-p', password],
                                capture_output=True, text=True)
    pw_hash = hash_proc.stdout.strip()
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
    # Push the new hash to Dovecot -- otherwise the old password keeps working.
    _sync_dovecot_users()
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
