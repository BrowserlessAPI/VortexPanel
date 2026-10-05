from flask import Blueprint, jsonify, request, session
import subprocess, os, re

mail_bp = Blueprint('mail', __name__)
def req(): return 'user' in session
def sh(c, timeout=60):
    """stdout of a shell command, also when it exits non-zero (check_output
    raised on rc!=0, so `systemctl is-active postfix` for a stopped service
    returned '' instead of 'inactive')."""
    try: return subprocess.run(c, shell=True, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, timeout=timeout).stdout.strip()
    except Exception: return ''

def run(args, input=None, timeout=60):
    try:
        r = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or '').strip(), (r.stderr or r.stdout or '').strip()
    except FileNotFoundError:
        return 127, '', f'{args[0]} not found'
    except subprocess.TimeoutExpired:
        return 124, '', f'{args[0]} timed out'

_DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')
_EMAIL_RE  = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')

def _valid_domain(d):
    return bool(d) and bool(_DOMAIN_RE.match(d))

def _write_private(path, text):
    """Write a file that holds password hashes: 0600 from the start, atomic."""
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f: f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

def _read_lines(path):
    if not os.path.exists(path): return []
    with open(path) as f: return f.readlines()

def _first_token(line):
    line = line.strip()
    if not line or line.startswith('#'): return ''
    return re.split(r'[\s:]', line, 1)[0].lower()

def _hash_password(password):
    rc, out, err = run(['doveadm', 'pw', '-s', 'SHA512-CRYPT', '-p', password])
    if rc != 0 or not out.startswith('{'):
        return None, ('doveadm is not installed (install dovecot)' if rc == 127 else (err or 'doveadm pw failed'))
    return out, None

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


def _dovecot_version():
    """(major, minor) of the installed Dovecot, (0, 0) when unknown."""
    rc, out, _ = run(['dovecot', '--version'], timeout=15)
    m = re.match(r'\s*(\d+)\.(\d+)', out or '')
    return (int(m.group(1)), int(m.group(2))) if (rc == 0 and m) else (0, 0)


def _dovecot_conf(ver):
    """The panel's Dovecot drop-in. Dovecot 2.4 (Debian 13, Fedora 42+, EL10)
    rejects the 2.3 syntax outright (mail_location, passdb driver/args,
    userdb args, %d/%n variables): `doveconf -n` failed and setup always
    rolled back there."""
    listeners = (
        "service lmtp {\n"
        "  unix_listener /var/spool/postfix/private/dovecot-lmtp {\n"
        "    mode = 0600\n    user = postfix\n    group = postfix\n  }\n}\n\n"
        "service auth {\n"
        "  unix_listener /var/spool/postfix/private/auth {\n"
        "    mode = 0660\n    user = postfix\n    group = postfix\n  }\n}\n\n"
        "protocols = imap lmtp\n")
    if ver >= (2, 4):
        return (
            "# Managed by VortexPanel -- virtual mailbox delivery (Dovecot 2.4 syntax). Do not edit by hand.\n"
            "mail_driver = maildir\n"
            f"mail_path = {VMAIL_BASE}/%{{user | domain}}/%{{user | username}}\n"
            f"mail_home = {VMAIL_BASE}/%{{user | domain}}/%{{user | username}}\n"
            # Debian 13's 10-mail.conf points INBOX at /var/mail/%{user} (mbox)
            "mail_inbox_path =\n"
            "mail_privileged_group = vmail\n"
            "mail_uid = vmail\n"
            "mail_gid = vmail\n\n"
            "passdb passwd-file {\n"
            f"  passwd_file_path = {DOVECOT_USERS_FILE}\n"
            "}\n"
            "userdb static {\n"
            "  fields {\n"
            "    uid = vmail\n"
            "    gid = vmail\n"
            f"    home = {VMAIL_BASE}/%{{user | domain}}/%{{user | username}}\n"
            "  }\n"
            "}\n\n" + listeners)
    return (
        "# Managed by VortexPanel -- virtual mailbox delivery. Do not edit by hand.\n"
        f"mail_location = maildir:{VMAIL_BASE}/%d/%n\n"
        "mail_privileged_group = vmail\n"
        "mail_uid = vmail\n"
        "mail_gid = vmail\n\n"
        "passdb {\n"
        "  driver = passwd-file\n"
        f"  args = scheme=SHA512-CRYPT username_format=%u {DOVECOT_USERS_FILE}\n"
        "}\n"
        "userdb {\n"
        "  driver = static\n"
        f"  args = uid=vmail gid=vmail home={VMAIL_BASE}/%d/%n\n"
        "}\n\n" + listeners)


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
        _write_private(DOVECOT_USERS_FILE, '\n'.join(lines) + ('\n' if lines else ''))
        sh(f'chown dovecot:dovecot {DOVECOT_USERS_FILE} 2>/dev/null')
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
    if not os.path.isdir('/etc/postfix') or not os.path.isdir('/etc/dovecot'):
        return jsonify({'ok':False,'error':'Postfix and Dovecot must be installed first '
                        '(postfix, dovecot-imapd and dovecot-lmtpd on Debian/Ubuntu; postfix and dovecot on RHEL)'}), 400
    main_cf = '/etc/postfix/main.cf'
    dc_file = '/etc/dovecot/conf.d/99-vortexpanel.conf'
    main_cf_backup = open(main_cf).read() if os.path.exists(main_cf) else None
    dc_backup = open(dc_file).read() if os.path.exists(dc_file) else None

    def rollback():
        # Validation failed: put both configs back so the next restart (or
        # reboot) does not come up with a broken mail server.
        try:
            if main_cf_backup is not None:
                with open(main_cf, 'w') as f: f.write(main_cf_backup)
            if dc_backup is not None:
                with open(dc_file, 'w') as f: f.write(dc_backup)
            elif os.path.exists(dc_file):
                os.unlink(dc_file)
        except OSError:
            pass

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
    #    or postfix refuses to start. The map type is Postfix's own default:
    #    Fedora 40+ / EL10 Postfix has no Berkeley DB, so 'hash:' fails there
    #    (default_database_type is lmdb).
    dbtype = (sh('postconf -h default_database_type 2>/dev/null') or 'hash').strip() or 'hash'
    if not re.fullmatch(r'[a-z0-9_]+', dbtype):
        dbtype = 'hash'
    for t in ('virtual_mailbox_domains', 'virtual_mailbox_maps', 'virtual_alias_maps'):
        p = f'/etc/postfix/{t}'
        if not os.path.exists(p):
            open(p, 'a').close()
        rc, _, err = run(['postmap', f'{dbtype}:{p}'])
        if rc != 0:
            rollback()
            return jsonify({'ok': False, 'error': f'postmap {dbtype}:{p} failed: {err}', 'log': log}), 500
    log.append(f'Postfix lookup tables created ({dbtype})')

    # 3. The actual missing configuration.
    settings = [
        f'virtual_mailbox_domains = {dbtype}:/etc/postfix/virtual_mailbox_domains',
        f'virtual_mailbox_maps = {dbtype}:/etc/postfix/virtual_mailbox_maps',
        f'virtual_alias_maps = {dbtype}:/etc/postfix/virtual_alias_maps',
        f'virtual_mailbox_base = {VMAIL_BASE}',
        f'virtual_uid_maps = static:{vuid}',
        f'virtual_gid_maps = static:{vgid}',
        'virtual_transport = lmtp:unix:private/dovecot-lmtp',
        'smtpd_sasl_type = dovecot',
        'smtpd_sasl_path = private/auth',
        'smtpd_sasl_auth_enable = yes',
        'smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination',
    ]
    # RHEL/Fedora ship inet_interfaces = localhost: Postfix never accepted mail
    # from the internet, so no hosted domain could receive anything. With
    # IPv6 disabled in the kernel, inet_protocols = all makes Postfix fail.
    if (sh('postconf -h inet_interfaces 2>/dev/null') or '').strip() in ('localhost', 'loopback-only', '127.0.0.1'):
        settings.append('inet_interfaces = all')
        log.append('inet_interfaces changed from localhost to all (receive mail from the internet)')
    if not os.path.exists('/proc/net/if_inet6') and \
            (sh('postconf -h inet_protocols 2>/dev/null') or '').strip() in ('all', 'ipv4, ipv6', 'ipv6'):
        settings.append('inet_protocols = ipv4')
        log.append('inet_protocols set to ipv4 (IPv6 is disabled on this server)')
    for st in settings:
        rc, _, err = run(['postconf', '-e', st])
        if rc != 0:
            rollback()
            return jsonify({'ok': False, 'error': f'postconf -e "{st}" failed, changes rolled back: {err}', 'log': log}), 500
    # A virtual domain must NOT also be in mydestination -- if it is, Postfix
    # treats it as a local domain and never consults the virtual maps at all.
    mydest = sh('postconf -h mydestination') or ''
    log.append('Postfix virtual delivery configured (via Dovecot LMTP)')

    # 4. Dovecot: where mail lives, who the users are, and the two sockets
    #    Postfix needs (LMTP for delivery, auth for SASL submission).
    dver = _dovecot_version()
    os.makedirs('/etc/dovecot/conf.d', exist_ok=True)
    with open(dc_file, 'w') as f:
        f.write(_dovecot_conf(dver))
    if not os.path.exists(DOVECOT_USERS_FILE):
        open(DOVECOT_USERS_FILE, 'a').close()
    _sync_dovecot_users()
    log.append('Dovecot configured (LMTP delivery + SASL auth sockets)')

    # 5. Validate before restarting -- never leave a broken mail server.
    rc, _, err = run(['postfix', 'check'])
    if rc != 0:
        rollback()
        return jsonify({'ok': False,
                        'error': f'Postfix config invalid, changes rolled back: {err}',
                        'log': log}), 500
    rc, _, err = run(['doveconf', '-n'])
    if rc != 0:
        rollback()
        return jsonify({'ok': False,
                        'error': f'Dovecot config invalid, changes rolled back: {err}',
                        'log': log}), 500
    log.append('Both configs validated')

    for svc in ('dovecot', 'postfix'):
        rc, _, err = run(['systemctl', 'restart', svc], timeout=120)
        if rc != 0:
            # Never leave the mail server down: restore and restart both.
            rollback()
            for s2 in ('dovecot', 'postfix'):
                run(['systemctl', 'restart', s2], timeout=120)
            return jsonify({'ok': False, 'error': f'{svc} failed to restart with the new configuration, '
                                                  f'the previous configuration was restored: {err}', 'log': log}), 500
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
    domain = (d.get('domain','') or '').strip().lower()
    if not domain: return jsonify({'ok':False,'error':'Domain required'}),400
    if not _valid_domain(domain): return jsonify({'ok':False,'error':'Invalid domain'}),400
    if not os.path.isdir('/etc/postfix'):
        return jsonify({'ok':False,'error':'Postfix is not installed'}),400
    path = '/etc/postfix/virtual_mailbox_domains'
    if any(_first_token(l) == domain for l in _read_lines(path)):
        return jsonify({'ok':False,'error':'Domain already exists'}),400
    # Append to postfix virtual_mailbox_domains
    with open(path,'a') as f:
        f.write(f'{domain} OK\n')
    rc, _, err = run(['postmap', path])
    if rc != 0: return jsonify({'ok':False,'error':f'postmap failed: {err}'}),500
    run(['systemctl', 'reload', 'postfix'])
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
    email = email.lower()
    if not _EMAIL_RE.match(email) or '..' in email:
        return jsonify({'ok':False,'error':'Valid email required'}),400
    if not password: return jsonify({'ok':False,'error':'Password required'}),400
    if any(_first_token(l) == email for l in _read_lines(MAIL_USERS_FILE)):
        return jsonify({'ok':False,'error':'Account already exists'}),400
    user, domain = email.split('@',1)
    # Hash first: an empty hash used to be written as "email:" (an account
    # with no usable password) whenever doveadm was missing.
    pw_hash, err = _hash_password(password)
    if not pw_hash: return jsonify({'ok':False,'error':err}),500
    # Create maildir
    maildir = os.path.join(VMAIL_BASE, domain, user)
    for sub in ('cur', 'new', 'tmp'):
        os.makedirs(os.path.join(maildir, sub), exist_ok=True)
    sh(f"chown -R vmail:vmail '{VMAIL_BASE}/{domain}' 2>/dev/null")
    # Add to postfix maps
    for f in ['/etc/postfix/virtual_mailbox_maps']:
        if os.path.exists(f):
            with open(f,'a') as fh: fh.write(f'{email} {domain}/{user}/\n')
            run(['postmap', f])
    os.makedirs(os.path.dirname(MAIL_USERS_FILE), exist_ok=True)
    _write_private(MAIL_USERS_FILE, ''.join(_read_lines(MAIL_USERS_FILE)) + f'{email}:{pw_hash}\n')
    # Dovecot reads its own file, not the panel's -- without this the
    # account exists on paper but cannot authenticate.
    _sync_dovecot_users()
    sh('systemctl reload postfix dovecot 2>/dev/null')
    return jsonify({'ok':True,'email':email})

@mail_bp.route('/api/mail/accounts/<path:email>', methods=['DELETE'])
def delete_account(email):
    if not req(): return jsonify({'ok':False}),401
    email = email.strip().lower()
    if '@' not in email: return jsonify({'ok':False,'error':'Invalid email'}),400
    for f in ['/etc/postfix/virtual_mailbox_maps', MAIL_USERS_FILE]:
        if os.path.exists(f):
            # exact match on the first field: startswith(email) also removed
            # e.g. bob@x.com.au when deleting bob@x.com
            kept = [l for l in _read_lines(f) if _first_token(l) != email]
            if f == MAIL_USERS_FILE:
                _write_private(f, ''.join(kept))
            else:
                with open(f,'w') as fh: fh.writelines(kept)
                run(['postmap', f])
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
    email = email.strip().lower()
    pw_hash, err = _hash_password(password)
    if not pw_hash: return jsonify({'ok':False,'error':err}),500
    updated = False
    out = []
    for line in _read_lines(MAIL_USERS_FILE):
        if _first_token(line) == email:
            out.append(f'{email}:{pw_hash}\n')
            updated = True
        else:
            out.append(line)
    # Do not silently create a brand-new account from a password reset.
    if not updated: return jsonify({'ok':False,'error':'Account not found'}),404
    _write_private(MAIL_USERS_FILE, ''.join(out))
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
    if not _valid_domain(domain): return jsonify({'ok':False,'error':'Invalid domain'}),400
    key_file = f'/etc/opendkim/keys/{domain}/default.txt'
    if os.path.exists(key_file):
        with open(key_file) as f: return jsonify({'ok':True,'record':f.read()})
    return jsonify({'ok':False,'error':'DKIM key not generated yet'})

@mail_bp.route('/api/mail/dkim/<domain>', methods=['POST'])
def gen_dkim(domain):
    if not req(): return jsonify({'ok':False}),401
    # domain was interpolated into a shell command unvalidated
    if not _valid_domain(domain): return jsonify({'ok':False,'error':'Invalid domain'}),400
    key_dir = f'/etc/opendkim/keys/{domain}'
    os.makedirs(key_dir, exist_ok=True)
    rc, _, err = run(['opendkim-genkey', '-t', '-s', 'default', '-d', domain, '-D', key_dir + '/'])
    if rc != 0:
        return jsonify({'ok':False,'error':'opendkim-genkey failed: ' + (err or 'not installed (install opendkim-tools / opendkim)')})
    # opendkim runs as its own user and must be able to read the private key
    run(['chown', '-R', 'opendkim:opendkim', key_dir])
    key_file = f'{key_dir}/default.txt'
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
    # Unknown names used to fall through verbatim into a shell command
    # (any service - or any shell code - could be passed here).
    svc = svc_map.get(service)
    if not svc: return jsonify({'ok': False, 'error': 'Invalid service'}), 400
    if action != 'status':
        rc, _, err = run(['systemctl', action, svc], timeout=120)
        if rc != 0:
            return jsonify({'ok': False, 'error': err or f'systemctl {action} {svc} failed',
                            'status': sh(f'systemctl is-active {svc} 2>/dev/null')})
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
    dests  = [x.strip() for x in dest.split(',') if x.strip()]
    # source may be a catch-all (@domain); destination may be a comma list.
    # Whitespace/newlines would inject extra entries into the Postfix map.
    src_ok = _EMAIL_RE.match(source) or (source.startswith('@') and _valid_domain(source[1:]))
    if not src_ok or not dests or not all(_EMAIL_RE.match(x) for x in dests):
        return jsonify({'ok':False,'error':'Valid source and destination email addresses required'}),400
    dest = ','.join(dests)
    lines = []
    if os.path.exists(VIRTUAL_ALIAS_FILE):
        with open(VIRTUAL_ALIAS_FILE) as f: lines = f.readlines()
    lines = [l for l in lines if not l.strip().startswith(source+' ') and not l.strip().startswith(source+'\t')]
    lines.append(f'{source}\t{dest}\n')
    with open(VIRTUAL_ALIAS_FILE,'w') as f: f.writelines(lines)
    rc, _, err = run(['postmap', VIRTUAL_ALIAS_FILE])
    if rc != 0: return jsonify({'ok':False,'error':f'postmap failed: {err}'}),500
    run(['systemctl', 'reload', 'postfix'])
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
