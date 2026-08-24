from flask import Blueprint, jsonify, request, session
import subprocess, re, os, json
from datetime import datetime, timedelta
from panel.routes.os_utils import get_os

security_bp = Blueprint('security', __name__)
def req(): return 'user' in session
def sh(c, t=10):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except: return '', 'timeout', 1

# --- SSH -----------------------------------------------------------------------

@security_bp.route('/api/security/status')
def security_status():
    from flask import jsonify, session
    if 'user' not in session: return jsonify({'ok':False}), 401
    import subprocess
    def check(cmd):
        try: r = subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=3); return r.returncode==0
        except: return False
    return jsonify({'ok':True,
        'fail2ban': check('systemctl is-active fail2ban'),
        'modsecurity': os.path.exists(_modsec_conf()),
        'ufw': check('ufw status | grep -q active'),
    })

@security_bp.route('/api/security/ssh')
def ssh_config():
    if not req(): return jsonify({'ok':False}), 401
    cfg = {}
    sshd = '/etc/ssh/sshd_config'
    if os.path.exists(sshd):
        with open(sshd) as f: content = f.read()
        def get_val(key, default=''):
            m = re.search(rf'^#?\s*{key}\s+(\S+)', content, re.MULTILINE|re.IGNORECASE)
            return m.group(1) if m else default
        cfg = {
            'port':           get_val('Port', '22'),
            'password_auth':  get_val('PasswordAuthentication', 'yes').lower(),
            'root_login':     get_val('PermitRootLogin', 'yes').lower(),
            'pubkey_auth':    get_val('PubkeyAuthentication', 'yes').lower(),
            'max_auth_tries': get_val('MaxAuthTries', '6'),
        }
    port_out, _, _ = sh("ss -tlnp | grep sshd | awk '{print $4}' | grep -oP ':\\K[0-9]+'")
    if port_out: cfg['active_port'] = port_out.split('\n')[0]

    # Check if any SSH keys exist for root (safe to disable password auth?)
    key_files = ['/root/.ssh/authorized_keys', '/root/.ssh/id_rsa.pub', '/root/.ssh/id_ed25519.pub']
    keys_exist = any(os.path.exists(f) and os.path.getsize(f) > 0 for f in key_files)
    cfg['keys_exist'] = keys_exist

    # List sudo users (non-root users in sudo/wheel group)
    sudo_users_out, _, _ = sh("getent group sudo wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sort -u | grep -v '^$'")
    cfg['sudo_users'] = [u for u in sudo_users_out.strip().split('\n') if u]

    return jsonify({'ok':True, 'config':cfg})


@security_bp.route('/api/security/ssh', methods=['PUT'])
def save_ssh():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    sshd = '/etc/ssh/sshd_config'
    if not os.path.exists(sshd):
        return jsonify({'ok':False,'error':'sshd_config not found'}), 404

    # Safety: refuse to disable password auth if no SSH keys exist
    if d.get('password_auth') == 'no':
        key_files = ['/root/.ssh/authorized_keys', '/root/.ssh/id_rsa.pub', '/root/.ssh/id_ed25519.pub']
        keys_exist = any(os.path.exists(f) and os.path.getsize(f) > 0 for f in key_files)
        # Also check if any sudo user has keys
        sudo_out, _, _ = sh("find /home -name authorized_keys 2>/dev/null | xargs cat 2>/dev/null | wc -l")
        sudo_keys = int(sudo_out.strip() or 0) > 0
        if not keys_exist and not sudo_keys:
            return jsonify({'ok':False,
                'error':'Cannot disable password auth: no SSH keys found. Add your public key to /root/.ssh/authorized_keys first.'}), 400

    with open(sshd) as f: content = f.read()

    def set_val(key, val, content):
        pattern = re.compile(rf'^#?\s*{key}\s+.*', re.MULTILINE|re.IGNORECASE)
        new_line = f'{key} {val}'
        if pattern.search(content): return pattern.sub(new_line, content)
        return content + f'\n{new_line}\n'

    old_port = re.search(r'^#?\s*Port\s+(\d+)', content, re.MULTILINE|re.IGNORECASE)
    old_port = old_port.group(1) if old_port else '22'

    if 'port' in d:           content = set_val('Port', d['port'], content)
    if 'password_auth' in d:  content = set_val('PasswordAuthentication', d['password_auth'], content)
    if 'root_login' in d:     content = set_val('PermitRootLogin', d['root_login'], content)
    if 'pubkey_auth' in d:    content = set_val('PubkeyAuthentication', d['pubkey_auth'], content)
    if 'max_auth_tries' in d: content = set_val('MaxAuthTries', d['max_auth_tries'], content)

    # Test config before applying
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as tf:
        tf.write(content)
        tf_path = tf.name
    test_out, test_err, rc = sh(f'sshd -t -f {tf_path} 2>&1')
    os.unlink(tf_path)
    if rc != 0:
        return jsonify({'ok':False, 'error':f'sshd config test failed: {test_out}{test_err}'}), 400

    with open(sshd,'w') as f: f.write(content)

    # Update firewall rule if port changed
    new_port = d.get('port', old_port)
    if new_port != old_port:
        sh(f'ufw allow {new_port}/tcp 2>/dev/null || firewall-cmd --add-port={new_port}/tcp --permanent 2>/dev/null')
        sh(f'ufw delete allow {old_port}/tcp 2>/dev/null || firewall-cmd --remove-port={old_port}/tcp --permanent 2>/dev/null')
        sh('firewall-cmd --reload 2>/dev/null || true')

    sh('systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null')
    return jsonify({'ok':True, 'port': new_port})


@security_bp.route('/api/security/ssh/create-user', methods=['POST'])
def create_sudo_user():
    """Create a new sudo user — must do this before disabling root login."""
    if not req(): return jsonify({'ok':False}), 401
    d        = request.get_json() or {}
    username = d.get('username','').strip().lower()
    password = d.get('password','')
    pubkey   = d.get('pubkey','').strip()

    if not username or not re.match(r'^[a-z_][a-z0-9_-]{1,30}$', username):
        return jsonify({'ok':False,'error':'Invalid username (2-31 chars, lowercase letters/numbers/-/_)'}), 400
    if not password and not pubkey:
        return jsonify({'ok':False,'error':'Password or SSH public key required'}), 400
    if len(password) < 8 and password:
        return jsonify({'ok':False,'error':'Password must be at least 8 characters'}), 400

    # Check user doesn't already exist
    out, _, rc = sh(f'id {username} 2>/dev/null')
    if rc == 0:
        return jsonify({'ok':False,'error':f'User {username} already exists'}), 409

    # Create user
    _, err, rc = sh(f'useradd -m -s /bin/bash {username} 2>&1')
    if rc != 0:
        return jsonify({'ok':False,'error':f'Failed to create user: {err}'}), 500

    # Set password
    if password:
        pw_proc = subprocess.run(['chpasswd'], input=f'{username}:{password}', text=True, capture_output=True)
        if pw_proc.returncode != 0:
            sh(f'userdel -r {username} 2>/dev/null')
            return jsonify({'ok':False,'error':f'Failed to set password: {pw_proc.stderr.strip()}'}), 500

    # Add to sudo/wheel group
    os_family, _, _ = sh('. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian')
    sudo_group = 'wheel' if any(x in os_family for x in ('rhel','fedora','centos','almalinux','rocky','ol','cloudlinux')) else 'sudo'
    sh(f'usermod -aG {sudo_group} {username} 2>/dev/null')

    # Add SSH public key
    if pubkey:
        ssh_dir = f'/home/{username}/.ssh'
        sh(f'mkdir -p {ssh_dir} && chmod 700 {ssh_dir}')
        with open(f'{ssh_dir}/authorized_keys', 'w') as f:
            f.write(pubkey + '\n')
        sh(f'chmod 600 {ssh_dir}/authorized_keys && chown -R {username}:{username} {ssh_dir}')

    return jsonify({'ok':True,'username':username,'sudo_group':sudo_group})


@security_bp.route('/api/security/ssh/add-key', methods=['POST'])
def add_ssh_key():
    """Add an SSH public key to /root/.ssh/authorized_keys."""
    if not req(): return jsonify({'ok':False}), 401
    pubkey = (request.get_json() or {}).get('pubkey','').strip()
    if not pubkey or not pubkey.startswith('ssh-'):
        return jsonify({'ok':False,'error':'Invalid public key format (must start with ssh-)'}), 400
    ssh_dir = '/root/.ssh'
    os.makedirs(ssh_dir, exist_ok=True)
    os.chmod(ssh_dir, 0o700)
    auth_file = f'{ssh_dir}/authorized_keys'
    # Check if key already exists
    existing = ''
    if os.path.exists(auth_file):
        existing = open(auth_file).read()
    if pubkey in existing:
        return jsonify({'ok':True,'message':'Key already exists'})
    with open(auth_file,'a') as f:
        f.write(('\n' if existing and not existing.endswith('\n') else '') + pubkey + '\n')
    os.chmod(auth_file, 0o600)
    return jsonify({'ok':True})

# --- Fail2ban ------------------------------------------------------------------
@security_bp.route('/api/security/fail2ban')
def fail2ban_status():
    if not req(): return jsonify({'ok':False}), 401
    out, _, rc = sh('fail2ban-client status 2>/dev/null')
    if rc != 0: return jsonify({'ok':False,'error':'Fail2ban not running','jails':[]})

    jails_raw = re.search(r'Jail list:\s*(.+)', out)
    jail_names = [j.strip() for j in jails_raw.group(1).split(',')] if jails_raw else []

    jails = []
    for jail in jail_names:
        if not jail: continue
        jout, _, _ = sh(f'fail2ban-client status {jail} 2>/dev/null')
        currently_banned = re.search(r'Currently banned:\s*(\d+)', jout)
        total_banned     = re.search(r'Total banned:\s*(\d+)', jout)
        banned_ips_m     = re.search(r'Banned IP list:\s*(.*)', jout)
        banned_ips = [ip.strip() for ip in (banned_ips_m.group(1).split() if banned_ips_m else [])]
        jails.append({
            'name':          jail,
            'currently':     int(currently_banned.group(1)) if currently_banned else 0,
            'total':         int(total_banned.group(1)) if total_banned else 0,
            'banned_ips':    banned_ips[:20],
        })
    return jsonify({'ok':True,'jails':jails})

@security_bp.route('/api/security/fail2ban/unban', methods=['POST'])
def unban_ip():
    if not req(): return jsonify({'ok':False}), 401
    d    = request.get_json() or {}
    ip   = d.get('ip','').strip()
    jail = d.get('jail','sshd')
    if not ip: return jsonify({'ok':False,'error':'IP required'}), 400
    sh(f'fail2ban-client set {jail} unbanip {ip} 2>/dev/null')
    return jsonify({'ok':True})

@security_bp.route('/api/security/fail2ban/ban', methods=['POST'])
def ban_ip():
    if not req(): return jsonify({'ok':False}), 401
    d    = request.get_json() or {}
    ip   = d.get('ip','').strip()
    jail = d.get('jail','sshd')
    if not ip: return jsonify({'ok':False,'error':'IP required'}), 400
    sh(f'fail2ban-client set {jail} banip {ip} 2>/dev/null')
    return jsonify({'ok':True})


# --- FAIL2BAN JAIL CREATION (Website Protection / Server Protection) -------------
# Previously VortexPanel could only view/ban/unban IPs on jails that already
# existed at the OS level (e.g. the default sshd jail) — there was no way to
# actually CREATE a jail from the panel, so "Website Protection" and "Server
# Protection" (matching aaPanel's Fail2ban Manager) only ever showed
# "No jails configured" with no path forward. This was a genuinely missing
# feature, not a bug in existing code.
F2B_JAIL_DIR   = '/etc/fail2ban/jail.d'
F2B_FILTER_DIR = '/etc/fail2ban/filter.d'
VORTEX_SITE_PREFIX   = 'vortex-site-'
VORTEX_SERVER_PREFIX = 'vortex-server-'

def _f2b_safe_name(name):
    return re.sub(r'[^a-zA-Z0-9_-]', '', (name or '').strip())[:60]

def _f2b_reload():
    out, err, rc = sh('fail2ban-client reload 2>&1', t=20)
    return rc == 0, (out or err)

def _parse_jail_conf(path):
    """Parse a simple INI-style jail.d config file into a dict."""
    if not os.path.exists(path): return {}
    cfg = {}
    section = None
    for line in open(path).read().splitlines():
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
            cfg[section] = {}
        elif '=' in line and section:
            k, _, v = line.partition('=')
            cfg[section][k.strip()] = v.strip()
    return cfg


@security_bp.route('/api/security/fail2ban/website-jails')
def list_website_jails():
    if not req(): return jsonify({'ok': False}), 401
    jails = []
    if os.path.isdir(F2B_JAIL_DIR):
        for fname in sorted(os.listdir(F2B_JAIL_DIR)):
            if not fname.startswith(VORTEX_SITE_PREFIX) or not fname.endswith('.conf'):
                continue
            cfg = _parse_jail_conf(os.path.join(F2B_JAIL_DIR, fname))
            for section, opts in cfg.items():
                status_out, _, _ = sh(f'fail2ban-client status {section} 2>/dev/null')
                currently = re.search(r'Currently banned:\s*(\d+)', status_out)
                jails.append({
                    'name': section,
                    'site': opts.get('_vortex_site', ''),
                    'port': opts.get('port', ''),
                    'mode': opts.get('_vortex_mode', 'anti-cc'),
                    'maxretry': opts.get('maxretry', ''),
                    'findtime': opts.get('findtime', ''),
                    'bantime': opts.get('bantime', ''),
                    'enabled': opts.get('enabled', 'true') == 'true',
                    'currently_banned': int(currently.group(1)) if currently else 0,
                })
    return jsonify({'ok': True, 'jails': jails})


@security_bp.route('/api/security/fail2ban/website-jails', methods=['POST'])
def create_website_jail():
    """Anti-CC / scan protection for a specific site's nginx access log.
    Uses fail2ban's own counting engine (maxretry within findtime) — the
    filter just needs to correctly extract the client IP from each request
    line; fail2ban handles the threshold/ban logic itself."""
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}

    site     = (d.get('site') or '').strip()
    mode     = d.get('mode', 'anti-cc')  # 'anti-cc' | 'anti-scan'
    port     = _f2b_safe_name(str(d.get('port', '80,443')).replace(',', '_')) or '80_443'
    port_val = str(d.get('port', '80,443')).strip()
    maxretry = int(d.get('maxretry', 30))
    findtime = int(d.get('findtime', 300))
    bantime  = int(d.get('bantime', 600))

    if not site:
        return jsonify({'ok': False, 'error': 'Site is required'})

    safe_site = _f2b_safe_name(site.replace('.', '_'))
    jail_name = f'{VORTEX_SITE_PREFIX}{safe_site}'
    access_log = f'/var/log/nginx/{site}.access.log'

    os.makedirs(F2B_FILTER_DIR, exist_ok=True)
    os.makedirs(F2B_JAIL_DIR, exist_ok=True)

    # Filter: matches every request line, extracting the client IP as <HOST>.
    # fail2ban's engine does the actual counting — this filter only needs to
    # reliably identify "a request happened, here's who made it".
    if mode == 'anti-scan':
        # Anti-scan: only count 4xx/404-type responses (probing for files/paths)
        failregex = r'^<HOST> -.*"(GET|POST|HEAD|PUT|DELETE|OPTIONS) [^"]*" (404|403) '
    else:
        # Anti-CC: count every request regardless of status (raw request-rate limiting)
        failregex = r'^<HOST> -.*"(GET|POST|HEAD|PUT|DELETE|OPTIONS) [^"]*" \d+ '

    filter_content = (
        f'[Definition]\n'
        f'failregex = {failregex}\n'
        f'ignoreregex =\n'
    )
    filter_path = os.path.join(F2B_FILTER_DIR, f'{jail_name}.conf')
    open(filter_path, 'w').write(filter_content)

    jail_content = (
        f'[{jail_name}]\n'
        f'enabled = true\n'
        f'port = {port_val}\n'
        f'filter = {jail_name}\n'
        f'logpath = {access_log}\n'
        f'maxretry = {maxretry}\n'
        f'findtime = {findtime}\n'
        f'bantime = {bantime}\n'
        f'backend = polling\n'
        f'action = iptables-multiport[name={safe_site}, port="{port_val}", protocol=tcp]\n'
        f'_vortex_site = {site}\n'
        f'_vortex_mode = {mode}\n'
    )
    jail_path = os.path.join(F2B_JAIL_DIR, f'{jail_name}.conf')

    if not os.path.exists(access_log):
        return jsonify({'ok': False, 'error': f'Access log not found: {access_log} — the site must exist and have received at least one request'})

    open(jail_path, 'w').write(jail_content)

    ok, output = _f2b_reload()
    if not ok:
        # Clean up on failure so we don't leave a broken jail definition behind
        try: os.remove(jail_path)
        except Exception: pass
        try: os.remove(filter_path)
        except Exception: pass
        return jsonify({'ok': False, 'error': f'fail2ban reload failed: {output[-400:]}'})

    return jsonify({'ok': True, 'jail': jail_name})


@security_bp.route('/api/security/fail2ban/website-jails/<name>', methods=['DELETE'])
def delete_website_jail(name):
    if not req(): return jsonify({'ok': False}), 401
    name = _f2b_safe_name(name)
    if not name.startswith(VORTEX_SITE_PREFIX):
        return jsonify({'ok': False, 'error': 'Invalid jail name'})
    jail_path   = os.path.join(F2B_JAIL_DIR, f'{name}.conf')
    filter_path = os.path.join(F2B_FILTER_DIR, f'{name}.conf')
    for p in (jail_path, filter_path):
        if os.path.exists(p):
            try: os.remove(p)
            except Exception: pass
    ok, output = _f2b_reload()
    return jsonify({'ok': ok, 'error': output[-400:] if not ok else ''})


@security_bp.route('/api/security/fail2ban/server-jails')
def list_server_jails():
    if not req(): return jsonify({'ok': False}), 401
    jails = []
    if os.path.isdir(F2B_JAIL_DIR):
        for fname in sorted(os.listdir(F2B_JAIL_DIR)):
            if not fname.startswith(VORTEX_SERVER_PREFIX) or not fname.endswith('.conf'):
                continue
            cfg = _parse_jail_conf(os.path.join(F2B_JAIL_DIR, fname))
            for section, opts in cfg.items():
                status_out, _, _ = sh(f'fail2ban-client status {section} 2>/dev/null')
                currently = re.search(r'Currently banned:\s*(\d+)', status_out)
                jails.append({
                    'name': section,
                    'server': opts.get('filter', ''),
                    'port': opts.get('port', ''),
                    'maxretry': opts.get('maxretry', ''),
                    'findtime': opts.get('findtime', ''),
                    'bantime': opts.get('bantime', ''),
                    'enabled': opts.get('enabled', 'true') == 'true',
                    'currently_banned': int(currently.group(1)) if currently else 0,
                })
    return jsonify({'ok': True, 'jails': jails})


# Common services and their built-in fail2ban filter name + typical log path.
# These reuse fail2ban's OWN shipped filters (no custom regex needed) — only
# the well-known, standard services are offered here to avoid generating a
# jail against a filter/log combination that doesn't actually exist.
SERVER_PROTECTION_PRESETS = {
    'sshd':     {'filter': 'sshd',     'logpath': '/var/log/auth.log',  'default_port': '22'},
    'vsftpd':   {'filter': 'vsftpd',   'logpath': '/var/log/vsftpd.log','default_port': '21'},
    'proftpd':  {'filter': 'proftpd',  'logpath': '/var/log/proftpd/proftpd.log', 'default_port': '21'},
    'postfix':  {'filter': 'postfix',  'logpath': '/var/log/mail.log',  'default_port': '25,465,587'},
    'dovecot':  {'filter': 'dovecot',  'logpath': '/var/log/mail.log',  'default_port': '110,143,993,995'},
}

@security_bp.route('/api/security/fail2ban/server-presets')
def server_presets():
    if not req(): return jsonify({'ok': False}), 401
    return jsonify({'ok': True, 'presets': [
        {'id': k, 'label': k, 'default_port': v['default_port']} for k, v in SERVER_PROTECTION_PRESETS.items()
    ]})


@security_bp.route('/api/security/fail2ban/server-jails', methods=['POST'])
def create_server_jail():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}

    server = (d.get('server') or 'sshd').strip()
    if server not in SERVER_PROTECTION_PRESETS:
        return jsonify({'ok': False, 'error': f'Unknown service "{server}" — supported: {", ".join(SERVER_PROTECTION_PRESETS)}'})

    preset   = SERVER_PROTECTION_PRESETS[server]
    port_val = str(d.get('port') or preset['default_port']).strip()
    maxretry = int(d.get('maxretry', 30))
    findtime = int(d.get('findtime', 300))
    bantime  = int(d.get('bantime', 600))

    jail_name = f'{VORTEX_SERVER_PREFIX}{server}'
    os.makedirs(F2B_JAIL_DIR, exist_ok=True)

    if not os.path.exists(preset['logpath']):
        return jsonify({'ok': False, 'error': f'Log file not found: {preset["logpath"]} — is {server} installed and has it logged anything yet?'})

    jail_content = (
        f'[{jail_name}]\n'
        f'enabled = true\n'
        f'port = {port_val}\n'
        f'filter = {preset["filter"]}\n'
        f'logpath = {preset["logpath"]}\n'
        f'maxretry = {maxretry}\n'
        f'findtime = {findtime}\n'
        f'bantime = {bantime}\n'
    )
    jail_path = os.path.join(F2B_JAIL_DIR, f'{jail_name}.conf')
    open(jail_path, 'w').write(jail_content)

    ok, output = _f2b_reload()
    if not ok:
        try: os.remove(jail_path)
        except Exception: pass
        return jsonify({'ok': False, 'error': f'fail2ban reload failed: {output[-400:]}'})

    return jsonify({'ok': True, 'jail': jail_name})


@security_bp.route('/api/security/fail2ban/server-jails/<name>', methods=['DELETE'])
def delete_server_jail(name):
    if not req(): return jsonify({'ok': False}), 401
    name = _f2b_safe_name(name)
    if not name.startswith(VORTEX_SERVER_PREFIX):
        return jsonify({'ok': False, 'error': 'Invalid jail name'})
    jail_path = os.path.join(F2B_JAIL_DIR, f'{name}.conf')
    if os.path.exists(jail_path):
        try: os.remove(jail_path)
        except Exception: pass
    ok, output = _f2b_reload()
    return jsonify({'ok': ok, 'error': output[-400:] if not ok else ''})


# --- Login attempts -------------------------------------------------------------
@security_bp.route('/api/security/login-attempts')
def login_attempts():
    if not req(): return jsonify({'ok':False}), 401
    attempts = []
    # Try different auth log locations
    for log in ['/var/log/auth.log', '/var/log/secure', '/var/log/btmp']:
        if not os.path.exists(log): continue
        if log == '/var/log/btmp':
            out, _, _ = sh('last -F -f /var/log/btmp 2>/dev/null | head -30')
        else:
            out, _, _ = sh(f'grep -i "failed\\|invalid\\|illegal" {log} 2>/dev/null | tail -50')
        if out: attempts.append({'log':log, 'content':out})
        break
    return jsonify({'ok':True,'attempts':attempts})

# --- Port scan / open ports -----------------------------------------------------
@security_bp.route('/api/security/ports')
def open_ports():
    if not req(): return jsonify({'ok':False}), 401
    out, _, _ = sh('ss -tlnp 2>/dev/null')
    return jsonify({'ok':True,'output':out})

# --- Security Score -------------------------------------------------------------
@security_bp.route('/api/security/score')
def security_score():
    if not req(): return jsonify({'ok':False}), 401
    checks = []

    # --- SSH --------------------------------------------------------------------
    sshd = '/etc/ssh/sshd_config'
    if os.path.exists(sshd):
        with open(sshd) as f: content = f.read()
        root_m = re.search(r'^PermitRootLogin\s+(\S+)', content, re.MULTILINE)
        val    = root_m.group(1).lower() if root_m else 'yes'
        checks.append({'label':'SSH Root Login Disabled',
                        'pass': val in ('no','prohibit-password','forced-commands-only'),
                        'severity':'high'})
        pw_m  = re.search(r'^PasswordAuthentication\s+(\S+)', content, re.MULTILINE)
        pval  = pw_m.group(1).lower() if pw_m else 'yes'
        checks.append({'label':'SSH Password Auth Disabled',
                        'pass': pval == 'no', 'severity':'medium'})
        port_m = re.search(r'^Port\s+(\d+)', content, re.MULTILINE)
        port   = int(port_m.group(1)) if port_m else 22
        checks.append({'label':'SSH on Non-default Port',
                        'pass': port != 22, 'severity':'low'})

    # --- Fail2ban ---------------------------------------------------------------
    f2b, _, _ = sh('systemctl is-active fail2ban 2>/dev/null')
    checks.append({'label':'Fail2ban Running',
                   'pass': f2b.strip() == 'active', 'severity':'high'})

    # --- Firewall — check both UFW and firewalld --------------------------------
    ufw, _, _  = sh('ufw status 2>/dev/null | head -1')
    fwd, _, _  = sh('firewall-cmd --state 2>/dev/null')
    fw_active  = 'active' in ufw.lower() or fwd.strip() == 'running'
    checks.append({'label':'Firewall Active (UFW or firewalld)',
                   'pass': fw_active, 'severity':'high'})

    # --- Auto security updates --------------------------------------------------
    apt_out, _, _ = sh('dpkg -l unattended-upgrades 2>/dev/null | grep -c "^ii"')
    dnf_out, _, _ = sh('dnf list installed dnf-automatic 2>/dev/null | grep -c dnf-automatic')
    auto_updates  = apt_out.strip() == '1' or dnf_out.strip() == '1'
    checks.append({'label':'Auto Security Updates Enabled',
                   'pass': auto_updates, 'severity':'medium'})

    # --- Panel security ---------------------------------------------------------
    try:
        import json as _json, hashlib as _hashlib
        creds_file = '/opt/vortexpanel/credentials.json'
        if os.path.exists(creds_file):
            creds = _json.load(open(creds_file))
            h = creds.get('password_hash','')
            # bcrypt hash starts with $2b$
            checks.append({'label':'Panel Password Uses bcrypt or Argon2id (not SHA-256)',
                           'pass': h.startswith('$2b$') or h.startswith('$2a$') or h.startswith('$argon2'),
                           'severity':'high'})
            # Default password check (admin123)
            default_sha = _hashlib.sha256(b'admin123').hexdigest()
            not_default = h != default_sha and h != _hashlib.sha256(b'admin').hexdigest()
            checks.append({'label':'Panel Default Password Changed',
                           'pass': not_default, 'severity':'critical'})
            # 2FA
            checks.append({'label':'Panel Two-Factor Authentication Enabled',
                           'pass': bool(creds.get('totp_enabled') and creds.get('totp_secret')),
                           'severity':'medium'})
    except Exception:
        pass

    # --- Secret key not default -------------------------------------------------
    checks.append({'label':'Panel Secret Key Auto-Generated (not default)',
                   'pass': os.path.exists('/opt/vortexpanel/secret.key'),
                   'severity':'high'})

    passed = sum(1 for c in checks if c['pass'])
    score  = round(passed / len(checks) * 100) if checks else 0
    return jsonify({'ok':True, 'checks':checks, 'score':score})

# --- ModSecurity ----------------------------------------------------------------

def _modsec_target():
    """Which webserver's ModSecurity is actually installed on this box,
    checked directly against disk rather than assumed. Returns 'nginx',
    'apache', or None if neither config exists yet. Every path helper and
    every endpoint below goes through this instead of a hardcoded nginx
    path, which is the root cause behind four separate broken surfaces
    found by a real user: the WAF Settings modal ('nginx service:
    inactive' on an Apache box), WAF Analytics ('not installed' despite
    a working install), the Security page WAF tab ('supports Nginx'
    only), and the App Store status badge -- all of them ultimately call
    into this same backend, and it only ever checked nginx paths."""
    if os.path.exists('/etc/nginx/modsec/modsecurity.conf'):
        return 'nginx'
    if os.path.exists('/etc/modsecurity/modsecurity.conf'):
        return 'apache'
    return None

def _modsec_conf():
    return '/etc/modsecurity/modsecurity.conf' if _modsec_target() == 'apache' else '/etc/nginx/modsec/modsecurity.conf'

def _modsec_main():
    return '/etc/modsecurity/main.conf' if _modsec_target() == 'apache' else '/etc/nginx/modsec/main.conf'

def _modsec_crs_dir():
    return '/etc/modsecurity/crs' if _modsec_target() == 'apache' else '/etc/nginx/modsec/crs'

def _modsec_custom():
    return '/etc/modsecurity/custom-rules.conf' if _modsec_target() == 'apache' else '/etc/nginx/modsec/custom-rules.conf'

def _modsec_dir():
    return '/etc/modsecurity' if _modsec_target() == 'apache' else '/etc/nginx/modsec'

def _modsec_lists_conf():
    return os.path.join(_modsec_dir(), 'vortex-lists.conf')

def _modsec_lists_json():
    return os.path.join(_modsec_dir(), 'vortex-lists.json')

def _modsec_audit():
    """Read the actual SecAuditLog path from whichever modsecurity.conf
    is active, rather than assume a shared constant -- the downloaded
    recommended conf and VortexPanel's own fallback conf could specify
    different paths, and nginx vs Apache builds may too."""
    conf = _modsec_conf()
    if os.path.exists(conf):
        try:
            m = re.search(r'SecAuditLog\s+(\S+)', open(conf).read())
            if m: return m.group(1)
        except Exception:
            pass
    return '/var/log/modsec_audit.log'

def _modsec_configtest():
    """Validate config for whichever webserver is active. Returns
    (ok, output)."""
    if _modsec_target() == 'apache':
        out, err, rc = sh('apache2ctl configtest 2>&1 || apachectl configtest 2>&1 || httpd -t 2>&1')
        return rc == 0, (out or err)
    out, err, rc = sh('nginx -t 2>&1')
    return rc == 0, (out or err)

def _modsec_reload():
    """Reload whichever webserver is active."""
    if _modsec_target() == 'apache':
        sh('systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null || service apache2 reload 2>/dev/null || apachectl graceful 2>/dev/null')
    else:
        sh('systemctl reload nginx 2>/dev/null')

MODSEC_AUDIT    = '/var/log/modsec_audit.log'  # fallback default; _modsec_audit() reads the real value at runtime

# --- WAF Blacklist / Whitelist ----------------------------------------------------
# ID ranges reserved outside OWASP CRS's 900000-999999 space so this can never
# collide with CRS or the free-text custom-rules.conf. Whitelist rules use
# ctl:ruleEngine=Off so a whitelisted request skips CRS entirely (real
# performance win, not just a "don't block" flag) — this is why the lists file
# must be Included BEFORE crs-setup.conf, not after.
_LIST_ID_BASE = {'ip_whitelist': 1050000, 'ip_blacklist': 1051000,
                  'ua_blacklist': 1052000, 'url_blacklist': 1053000}

_IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
_IPV6_RE = re.compile(r'^[0-9a-fA-F:]+(/\d{1,3})?$')

def _valid_ip(v):
    v = v.strip()
    if not v: return False
    if _IPV4_RE.match(v):
        parts = v.split('/')[0].split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    return bool(_IPV6_RE.match(v)) and ':' in v

def _modsec_str_escape(v):
    """Escape a value going inside a ModSecurity double-quoted operator
    string. Only neutralizes the string delimiter and backslash — pattern
    metacharacters (for UA/URL regex entries) are intentionally left alone
    since users are entering real regex. Newlines are stripped so a value
    can't break out onto a new config line. nginx -t is still the final
    gate before anything is ever reloaded — this is defense in depth, not
    the only check."""
    v = v.replace('\\', '\\\\').replace('"', '\\"')
    return v.replace('\r', '').replace('\n', '')

def _load_lists():
    import json
    default = {'ip_whitelist': [], 'ip_blacklist': [], 'ua_blacklist': [], 'url_blacklist': []}
    if not os.path.exists(_modsec_lists_json()):
        return default
    try:
        data = json.load(open(_modsec_lists_json()))
        for k in default:
            data.setdefault(k, [])
        return data
    except Exception:
        return default

def _save_lists_json(data):
    import json
    os.makedirs(os.path.dirname(_modsec_lists_json()), exist_ok=True)
    with open(_modsec_lists_json(), 'w') as f:
        json.dump(data, f, indent=2)

def _render_lists_conf(data):
    """Build the ModSecurity rules file from the stored lists. Rebuilt
    fully from scratch every save (not appended-to) so a removed entry
    actually disappears instead of lingering as a stale rule."""
    lines = ['# Auto-generated by VortexPanel — do not edit by hand, use the WAF Blacklist/Whitelist page',
             '# Regenerated in full on every save']

    wl = [ip.strip() for ip in data.get('ip_whitelist', []) if ip.strip()]
    if wl:
        rid = _LIST_ID_BASE['ip_whitelist'] + 1
        ip_list = ','.join(_modsec_str_escape(ip) for ip in wl)
        lines.append(
            f'SecRule REMOTE_ADDR "@ipMatch {ip_list}" '
            f'"id:{rid},phase:1,pass,nolog,ctl:ruleEngine=Off"'
        )

    for i, ip in enumerate([x.strip() for x in data.get('ip_blacklist', []) if x.strip()]):
        rid = _LIST_ID_BASE['ip_blacklist'] + i + 1
        lines.append(
            f'SecRule REMOTE_ADDR "@ipMatch {_modsec_str_escape(ip)}" '
            f'"id:{rid},phase:1,deny,status:403,log,msg:\'VortexPanel IP Blacklist\'"'
        )

    for i, ua in enumerate([x.strip() for x in data.get('ua_blacklist', []) if x.strip()]):
        rid = _LIST_ID_BASE['ua_blacklist'] + i + 1
        lines.append(
            f'SecRule REQUEST_HEADERS:User-Agent "@rx {_modsec_str_escape(ua)}" '
            f'"id:{rid},phase:1,deny,status:403,log,msg:\'VortexPanel UA Blacklist\'"'
        )

    for i, url in enumerate([x.strip() for x in data.get('url_blacklist', []) if x.strip()]):
        rid = _LIST_ID_BASE['url_blacklist'] + i + 1
        lines.append(
            f'SecRule REQUEST_URI "@rx {_modsec_str_escape(url)}" '
            f'"id:{rid},phase:1,deny,status:403,log,msg:\'VortexPanel URL Blacklist\'"'
        )

    return '\n'.join(lines) + '\n'

def _ensure_lists_included():
    """Insert the Include for vortex-lists.conf right after modsecurity.conf
    and BEFORE crs-setup.conf in main.conf, so whitelist's ruleEngine=Off can
    actually skip CRS. Idempotent — safe to call on every save.

    Apache-only exception: Apache's security2.conf already does
    IncludeOptional /etc/modsecurity/*.conf, which auto-includes
    vortex-lists.conf (and modsecurity.conf, and custom-rules.conf) on
    its own since they sit directly in that directory. Adding an
    explicit Include for it here too causes double-inclusion — the same
    rule ID gets loaded twice and Apache refuses to start. Confirmed via
    a real reproduced failure. nginx has no equivalent auto-include, so
    it genuinely needs this explicit wiring; Apache does not."""
    if _modsec_target() == 'apache':
        return
    if not os.path.exists(_modsec_main()):
        return
    main = open(_modsec_main()).read()
    include_line = f'Include {_modsec_lists_conf()}'
    if include_line in main:
        return
    base_include = f'Include {_modsec_conf()}'
    if base_include in main:
        main = main.replace(base_include, f'{base_include}\n{include_line}', 1)
    else:
        main = f'{include_line}\n{main}'
    with open(_modsec_main(), 'w') as f:
        f.write(main)

def _connector_present():
    """Whether the actual connector/module is present AND wired in for
    whichever webserver this is. nginx's connector is compiled from
    source (see the App Store install_tpl) so this checks for the real
    .so plus the nginx.conf wiring, not just a package. Apache's
    security2 module is a distro package that self-registers via
    a2enmod, so this checks it's actually enabled."""
    if _modsec_target() == 'apache':
        enabled, _, _ = sh('a2query -m security2 2>&1')
        if 'enabled' in (enabled or '').lower():
            return True
        return os.path.exists('/etc/apache2/mods-enabled/security2.load')

    so_present = any(
        os.path.exists(os.path.join(d, 'ngx_http_modsecurity_module.so'))
        for d in ['/usr/lib/nginx/modules', '/usr/lib64/nginx/modules']
    )
    wired = False
    if os.path.exists('/etc/nginx/nginx.conf'):
        try:
            wired = 'modsecurity_rules_file' in open('/etc/nginx/nginx.conf').read()
        except Exception:
            pass
    return so_present and wired

def _modsec_installed():
    """'Installed' = the core engine is actually usable, which requires
    the engine library, modsecurity.conf, AND the connector/module
    actually being loadable — checking only the first two was exactly
    the false-green pattern already fixed once for the CRS chain.
    The engine library check differs by target: nginx's connector links
    against libmodsecurity.so.3 (the v3 library), but Apache's
    libapache2-mod-security2 is a self-contained v2 module that never
    installs that library at all — confirmed via the actual install log
    (only libapache2-mod-security2 + modsecurity-crs as new packages,
    no v3 library pulled in). Checking for libmodsecurity.so.3
    unconditionally would make this always return False on a genuinely
    working Apache install."""
    if _modsec_target() == 'apache':
        engine_present = os.path.exists('/usr/lib/apache2/modules/mod_security2.so')
    else:
        engine_present = any(os.path.exists(p) for p in [
            '/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3',
            '/usr/lib64/libmodsecurity.so.3',
            '/usr/lib/aarch64-linux-gnu/libmodsecurity.so.3',
        ])
    return engine_present and os.path.exists(_modsec_conf()) and _connector_present()

def _crs_version():
    """Read CRS version from the CHANGES file or setup.conf."""
    for path in [f'{_modsec_crs_dir()}/CHANGES.md',
                 f'{_modsec_crs_dir()}/CHANGES',
                 f'{_modsec_crs_dir()}/crs-setup.conf.example']:
        if not os.path.exists(path): continue
        try:
            for line in open(path):
                m = re.search(r'(\d+\.\d+\.\d+)', line)
                if m: return m.group(1)
        except: pass
    return 'unknown'

def _paranoia_level():
    """Read current paranoia level from crs-setup.conf."""
    setup = f'{_modsec_crs_dir()}/crs-setup.conf'
    if not os.path.exists(setup): return 1
    try:
        content = open(setup).read()
        m = re.search(r'tx\.paranoia_level=(\d)', content)
        return int(m.group(1)) if m else 1
    except: return 1

def _engine_state():
    """Return engine state: On / DetectionOnly / Off."""
    if not os.path.exists(_modsec_conf()): return 'Off'
    content = open(_modsec_conf()).read()
    if 'SecRuleEngine On' in content:             return 'On'
    if 'SecRuleEngine DetectionOnly' in content:  return 'DetectionOnly'
    return 'Off'

@security_bp.route('/api/security/caddywaf')
def caddywaf_status():
    if not req(): return jsonify({'ok': False}), 401
    modules_out, _, _ = sh('caddy list-modules 2>/dev/null')
    installed = 'http.handlers.waf' in modules_out

    settings_path = '/etc/caddy/waf/panel_settings.json'
    settings = {'anomaly_threshold': 20, 'rate_limit_requests': 100, 'rate_limit_window': 10, 'rate_limit_paths': ''}
    if os.path.exists(settings_path):
        try:
            with open(settings_path) as f:
                settings.update(json.load(f))
        except Exception:
            pass

    def _count_lines(path):
        if not os.path.exists(path):
            return 0
        try:
            with open(path) as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0

    ip_count = _count_lines('/etc/caddy/waf/ip_blacklist.txt')
    dns_count = _count_lines('/etc/caddy/waf/dns_blacklist.txt')

    # Sites currently running the WAF - scan Caddy's per-site config dir
    # for the waf{} block, the same directory _find_site_config already
    # uses for Caddy sites.
    enabled_sites = []
    sites_dir = '/etc/caddy/sites'
    if os.path.isdir(sites_dir):
        for fn in os.listdir(sites_dir):
            if not fn.endswith('.conf'):
                continue
            try:
                with open(os.path.join(sites_dir, fn)) as f:
                    content = f.read()
                if 'waf {' in content or 'waf{' in content:
                    enabled_sites.append(fn[:-5])
            except Exception:
                pass

    return jsonify({
        'ok': True, 'installed': installed, 'settings': settings,
        'ip_blacklist_count': ip_count, 'dns_blacklist_count': dns_count,
        'enabled_sites': enabled_sites,
    })


@security_bp.route('/api/security/caddywaf/settings', methods=['POST'])
def caddywaf_save_settings():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}

    settings = {
        'anomaly_threshold': int(d.get('anomaly_threshold', 20)),
        'rate_limit_requests': int(d.get('rate_limit_requests', 100)),
        'rate_limit_window': int(d.get('rate_limit_window', 10)),
        'rate_limit_paths': (d.get('rate_limit_paths') or '').strip(),
    }
    os.makedirs('/etc/caddy/waf', exist_ok=True)
    with open('/etc/caddy/waf/panel_settings.json', 'w') as f:
        json.dump(settings, f)

    # Re-apply to every site currently running the WAF, so a settings
    # change actually takes effect everywhere rather than only on the
    # next fresh enable. Reuses the same real brace-matching already
    # proven for the enable/disable toggle in websites_core.py.
    from panel.routes.websites_core import _split_site_block
    updated, failed = [], []
    sites_dir = '/etc/caddy/sites'
    if os.path.isdir(sites_dir):
        for fn in os.listdir(sites_dir):
            if not fn.endswith('.conf'):
                continue
            fp = os.path.join(sites_dir, fn)
            domain = fn[:-5]
            try:
                with open(fp) as f:
                    content = f.read()
                if 'waf {' not in content and 'waf{' not in content:
                    continue
                header, inner, trailing = _split_site_block(content)
                if header is None:
                    failed.append(domain); continue
                route_start = inner.find('route {')
                if route_start == -1:
                    failed.append(domain); continue
                _, route_inner, route_trailing = _split_site_block(inner[route_start:])
                waf_start = route_inner.find('waf {')
                if waf_start == -1:
                    failed.append(domain); continue
                _, _, after_waf = _split_site_block(route_inner[waf_start:])

                rate_limit_block = ''
                if settings['rate_limit_requests'] > 0:
                    paths_line = f'\n                paths            {settings["rate_limit_paths"]}' if settings['rate_limit_paths'] else ''
                    rate_limit_block = (
                        f'\n            rate_limit {{\n'
                        f'                requests         {settings["rate_limit_requests"]}\n'
                        f'                window           {settings["rate_limit_window"]}s{paths_line}\n'
                        f'            }}'
                    )
                new_waf_block = (
                    '\n    route {\n'
                    '        waf {\n'
                    '            metrics_endpoint   /waf_metrics\n'
                    '            rule_file          /etc/caddy/waf/rules.json\n'
                    '            ip_blacklist_file  /etc/caddy/waf/ip_blacklist.txt\n'
                    '            dns_blacklist_file /etc/caddy/waf/dns_blacklist.txt\n'
                    f'            anomaly_threshold  {settings["anomaly_threshold"]}'
                    f'{rate_limit_block}\n'
                    '        }\n'
                    f'    {after_waf.lstrip("}").strip()}\n'
                    '    }\n'
                )
                new_content = header + new_waf_block + trailing

                tmp_path = fp + '.waf-test'
                with open(tmp_path, 'w') as f:
                    f.write(new_content)
                validate_out, validate_err, _ = sh(f'caddy validate --config {tmp_path} --adapter caddyfile 2>&1')
                test = validate_out + validate_err
                if 'error' in test.lower() or 'invalid' in test.lower():
                    os.remove(tmp_path)
                    failed.append(domain)
                    continue
                os.replace(tmp_path, fp)
                updated.append(domain)
            except Exception:
                failed.append(domain)

    if updated:
        sh('systemctl reload caddy 2>/dev/null')

    return jsonify({'ok': True, 'settings': settings, 'updated_sites': updated, 'failed_sites': failed})


@security_bp.route('/api/security/caddywaf/blacklist', methods=['POST'])
def caddywaf_add_blacklist():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    kind = d.get('type')  # 'ip' or 'dns'
    entry = (d.get('entry') or '').strip()
    if kind not in ('ip', 'dns') or not entry:
        return jsonify({'ok': False, 'error': 'type (ip/dns) and entry are required'}), 400

    path = f'/etc/caddy/waf/{"ip_blacklist" if kind == "ip" else "dns_blacklist"}.txt'
    os.makedirs('/etc/caddy/waf', exist_ok=True)
    existing = set()
    if os.path.exists(path):
        with open(path) as f:
            existing = {line.strip() for line in f if line.strip()}
    if entry in existing:
        return jsonify({'ok': True, 'message': 'Entry already present'})
    with open(path, 'a') as f:
        f.write(entry + '\n')
    return jsonify({'ok': True})


@security_bp.route('/api/security/caddywaf/blacklist', methods=['DELETE'])
def caddywaf_remove_blacklist():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    kind = d.get('type')
    entry = (d.get('entry') or '').strip()
    if kind not in ('ip', 'dns') or not entry:
        return jsonify({'ok': False, 'error': 'type (ip/dns) and entry are required'}), 400

    path = f'/etc/caddy/waf/{"ip_blacklist" if kind == "ip" else "dns_blacklist"}.txt'
    if not os.path.exists(path):
        return jsonify({'ok': True, 'message': 'Nothing to remove'})
    with open(path) as f:
        lines = [l for l in f if l.strip() != entry]
    with open(path, 'w') as f:
        f.writelines(lines)
    return jsonify({'ok': True})


@security_bp.route('/api/security/modsecurity')
def modsec_status():
    if not req(): return jsonify({'ok':False}), 401
    installed = _modsec_installed()
    state     = _engine_state()
    rules_out, _, _ = sh(f'find {_modsec_crs_dir()}/rules/ -name "*.conf" 2>/dev/null | wc -l')
    try:    rules_count = int(rules_out.strip() or 0)
    except: rules_count = 0

    # Custom rules
    custom_rules = ''
    if os.path.exists(_modsec_custom()):
        try: custom_rules = open(_modsec_custom()).read()
        except: pass

    # Sites with per-site overrides
    site_overrides = {}
    for conf_dir in ['/etc/nginx/vortex', '/etc/nginx/conf.d']:
        if not os.path.isdir(conf_dir): continue
        for fn in os.listdir(conf_dir):
            fp = os.path.join(conf_dir, fn)
            try:
                c = open(fp).read()
                domain = re.search(r'server_name\s+([^;]+);', c)
                if domain:
                    d = domain.group(1).strip().split()[0]
                    if 'modsecurity off' in c.lower():
                        site_overrides[d] = 'off'
                    elif 'modsecurity on' in c.lower():
                        site_overrides[d] = 'on'
            except: pass

    return jsonify({
        'ok':            True,
        'installed':     installed,
        'enabled':       state == 'On',
        'state':         state,
        'rules':         rules_count,
        'crs_version':   _crs_version() if installed else '',
        'paranoia_level':_paranoia_level() if installed else 1,
        'custom_rules':  custom_rules,
        'site_overrides':site_overrides,
        'audit_log':     os.path.exists(_modsec_audit()),
        'webserver_name': 'apache2' if _modsec_target() == 'apache' else 'nginx',
        'custom_rules_path': _modsec_custom(),
    })


@security_bp.route('/api/security/modsecurity/toggle', methods=['POST'])
def modsec_toggle():
    if not req(): return jsonify({'ok':False}), 401
    d      = request.get_json() or {}
    state  = d.get('state', 'On')     # 'On' | 'DetectionOnly' | 'Off'
    conf   = _modsec_conf()
    if not os.path.exists(conf):
        return jsonify({'ok':False,'error':'ModSecurity not installed'}), 404
    content = open(conf).read()
    # Replace any existing state
    content = re.sub(r'SecRuleEngine\s+(On|DetectionOnly|Off)',
                     f'SecRuleEngine {state}', content)
    with open(conf,'w') as f: f.write(content)
    ok, out = _modsec_configtest()
    if not ok:
        return jsonify({'ok':False,'error':f'Config error: {out}'}), 400
    _modsec_reload()
    return jsonify({'ok':True,'state':state})


@security_bp.route('/api/security/modsecurity/paranoia', methods=['POST'])
def modsec_paranoia():
    """Set OWASP CRS paranoia level (1–4)."""
    if not req(): return jsonify({'ok':False}), 401
    level = int((request.get_json() or {}).get('level', 1))
    level = max(1, min(4, level))
    setup = f'{_modsec_crs_dir()}/crs-setup.conf'
    if not os.path.exists(setup):
        return jsonify({'ok':False,'error':'CRS setup.conf not found'}), 404
    content = open(setup).read()
    # Replace or inject paranoia level
    if 'tx.paranoia_level' in content:
        content = re.sub(r'tx\.paranoia_level=\d', f'tx.paranoia_level={level}', content)
    else:
        content += f'\nSecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level={level}"\n'
    with open(setup,'w') as f: f.write(content)
    ok, _ = _modsec_configtest()
    if ok: _modsec_reload()
    return jsonify({'ok':True,'level':level})


@security_bp.route('/api/security/modsecurity/custom-rules', methods=['GET'])
def modsec_get_custom():
    if not req(): return jsonify({'ok':False}), 401
    content = ''
    if os.path.exists(_modsec_custom()):
        try: content = open(_modsec_custom()).read()
        except: pass
    return jsonify({'ok':True,'rules':content})


@security_bp.route('/api/security/modsecurity/custom-rules', methods=['POST'])
def modsec_save_custom():
    """Save custom SecRule directives."""
    if not req(): return jsonify({'ok':False}), 401
    rules = (request.get_json() or {}).get('rules', '')
    os.makedirs(_modsec_dir(), exist_ok=True)
    with open(_modsec_custom(),'w') as f: f.write(rules)
    # Ensure it's included in main.conf -- nginx only. Apache's
    # security2.conf already glob-includes every top-level .conf file in
    # /etc/modsecurity/ (confirmed: IncludeOptional /etc/modsecurity/*.conf),
    # so custom-rules.conf is already loaded without this; adding an
    # explicit Include here too caused a real, reproduced double-inclusion
    # failure ("Found another rule with the same id").
    if _modsec_target() != 'apache' and os.path.exists(_modsec_main()):
        main = open(_modsec_main()).read()
        include_line = f'Include {_modsec_custom()}'
        if include_line not in main:
            with open(_modsec_main(),'a') as f: f.write(f'\n{include_line}\n')
    ok, out = _modsec_configtest()
    if not ok:
        return jsonify({'ok':False,'error':f'Syntax error in rules: {out}'}), 400
    _modsec_reload()
    return jsonify({'ok':True})


@security_bp.route('/api/security/modsecurity/lists')
def modsec_get_lists():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, 'lists': _load_lists()})


@security_bp.route('/api/security/modsecurity/lists', methods=['POST'])
def modsec_save_lists():
    """Save IP/UA/URL blacklist+whitelist. Unlike modsec_save_custom, this
    validates against nginx -t BEFORE committing the live .conf file and
    rolls back to the previous working version on failure — a broken
    custom-rules.conf left in place after a rejected save is exactly the
    kind of silent half-state that caused the ModSecurity bug fixed last
    round, not repeating that pattern here."""
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}

    incoming = {
        'ip_whitelist': d.get('ip_whitelist', []),
        'ip_blacklist': d.get('ip_blacklist', []),
        'ua_blacklist': d.get('ua_blacklist', []),
        'url_blacklist': d.get('url_blacklist', []),
    }
    for key in ('ip_whitelist', 'ip_blacklist'):
        bad = [ip for ip in incoming[key] if ip.strip() and not _valid_ip(ip)]
        if bad:
            return jsonify({'ok':False, 'error': f'Invalid IP/CIDR in {key}: {", ".join(bad[:5])}'}), 400

    os.makedirs(_modsec_dir(), exist_ok=True)

    backup = None
    if os.path.exists(_modsec_lists_conf()):
        backup = open(_modsec_lists_conf()).read()
    main_backup = open(_modsec_main()).read() if os.path.exists(_modsec_main()) else None

    with open(_modsec_lists_conf(), 'w') as f:
        f.write(_render_lists_conf(incoming))
    _ensure_lists_included()

    ok, out = _modsec_configtest()
    if not ok:
        # Roll back both files to their pre-save state — the webserver must
        # never be left in a broken state by a rejected save.
        if backup is not None:
            with open(_modsec_lists_conf(), 'w') as f: f.write(backup)
        elif os.path.exists(_modsec_lists_conf()):
            os.remove(_modsec_lists_conf())
        if main_backup is not None:
            with open(_modsec_main(), 'w') as f: f.write(main_backup)
        return jsonify({'ok':False, 'error': f'Syntax error in generated rules: {out}'}), 400

    _save_lists_json(incoming)
    _modsec_reload()
    # Mirror the same lists to Caddy/Coraza when it's installed, so black/white
    # list edits made here apply to Caddy sites too (no-op otherwise).
    _coraza_sync()
    return jsonify({'ok':True, 'lists': incoming})


@security_bp.route('/api/security/modsecurity/audit-log')
def modsec_audit_log():
    """Return last N lines of ModSecurity audit log."""
    if not req(): return jsonify({'ok':False}), 401
    lines = int(request.args.get('lines', 100))
    if not os.path.exists(_modsec_audit()):
        return jsonify({'ok':True,'entries':[],'raw':'','exists':False})
    out, _, _ = sh(f'tail -n {min(lines, 500)} "{_modsec_audit()}" 2>/dev/null')
    entries = _parse_modsec_entries(out)
    entries.reverse()
    return jsonify({'ok':True,'entries':entries[-100:],'raw':out,'exists':True})


# --- WAF ANALYTICS ----------------------------------------------------------------
# OWASP CRS assigns rule IDs in stable, documented ranges per attack category.
# This mapping is based on that well-established convention (CRS 3.x/4.x) — I
# could not live-verify it against crs.owasp.org given this environment's
# network restrictions, so treat category labels as best-effort; the raw
# rule_id is always preserved alongside so nothing is hidden or guessed away.
CRS_CATEGORY_RANGES = [
    (911000, 911999, 'Method Enforcement'),
    (912000, 912999, 'DoS Protection'),
    (913000, 913999, 'Scanner Detection'),
    (920000, 920999, 'Protocol Enforcement'),
    (921000, 921999, 'Protocol Attack'),
    (930000, 930999, 'Path Traversal / LFI'),
    (931000, 931999, 'Remote File Inclusion'),
    (932000, 932999, 'Remote Code Execution'),
    (933000, 933999, 'PHP Injection'),
    (934000, 934999, 'Node.js Injection'),
    (941000, 941999, 'XSS'),
    (942000, 942999, 'SQL Injection'),
    (943000, 943999, 'Session Fixation'),
    (944000, 944999, 'Java Attack'),
    (949000, 949999, 'Anomaly Threshold'),
    (950000, 959999, 'Data Leakage'),
    (980000, 980999, 'Correlation'),
]

def _categorize_rule(rule_id):
    if not rule_id: return 'Other'
    try: rid = int(rule_id)
    except (ValueError, TypeError): return 'Other'
    for lo, hi, name in CRS_CATEGORY_RANGES:
        if lo <= rid <= hi: return name
    return 'Other'

def _parse_modsec_entries(raw_text):
    """Shared parser for ModSecurity audit log entries.

    IMPORTANT: section markers (--uuid-X--) announce that the FOLLOWING
    lines belong to section X, until the next marker — the marker line
    itself never contains the actual request/message data. The original
    inline parser (before this refactor) tried to regex-match request/
    message content against the marker line itself, which never matched
    anything real; this version tracks "current section" as state and
    processes each subsequent line according to it, which is how
    ModSecurity's audit log format actually works.
    """
    entries, current, section = [], {}, None
    for line in raw_text.split('\n'):
        m = re.match(r'--[a-f0-9]+-([A-Z])--', line)
        if m:
            new_section = m.group(1)
            if new_section == 'A':
                if current:
                    entries.append(current)
                current = {'raw': line}
            section = new_section
            continue

        if not current:
            continue

        if section == 'A':
            # Section A content line: [DD/Mon/YYYY:HH:MM:SS +ZZZZ] txid client-ip client-port server-ip server-port
            ts_m = re.search(r'\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})', line)
            if ts_m: current['timestamp'] = ts_m.group(1)
            ip_m = re.search(r'^\[[^\]]+\]\s+[a-f0-9]+\s+(\d+\.\d+\.\d+\.\d+)', line)
            if ip_m: current['ip'] = ip_m.group(1)
        elif section == 'B':
            req_m = re.search(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)', line)
            if req_m:
                current['method'] = req_m.group(1)
                current['uri']    = req_m.group(2)
            host_m = re.search(r'^Host:\s*(\S+)', line, re.IGNORECASE)
            if host_m: current['domain'] = host_m.group(1)
        elif section == 'H':
            msg_m = re.search(r'Message: (.+)', line)
            if msg_m and 'message' not in current:  # keep the first/primary message
                current['message'] = msg_m.group(1)[:200]
            id_m = re.search(r'\[id "(\d+)"\]', line)
            if id_m and 'rule_id' not in current:
                current['rule_id'] = id_m.group(1)
            sev_m = re.search(r'\[severity "(\w+)"\]', line)
            if sev_m and 'severity' not in current:
                current['severity'] = sev_m.group(1)
            if 'ip' not in current:
                ip_m2 = re.search(r'client:\s*(\d+\.\d+\.\d+\.\d+)|client (\d+\.\d+\.\d+\.\d+)', line)
                if ip_m2: current['ip'] = ip_m2.group(1) or ip_m2.group(2)

    if current:
        entries.append(current)
    entries = [e for e in entries if e.get('message') or e.get('uri')]
    return entries

def _entry_datetime(entry):
    """Parse ModSecurity's [DD/Mon/YYYY:HH:MM:SS timestamp into a datetime."""
    ts = entry.get('timestamp')
    if not ts: return None
    try:
        return datetime.strptime(ts, '%d/%b/%Y:%H:%M:%S')
    except (ValueError, TypeError):
        return None

@security_bp.route('/api/security/waf/stats')
def waf_stats():
    """Aggregated WAF analytics — attack categories, top IPs/URIs, and a
    timeline, built on top of the same parser as the raw audit-log view.
    Reads a capped tail of the log (not the whole file, which can be large
    on a busy server) then filters/aggregates in Python."""
    if not req(): return jsonify({'ok': False}), 401
    period = request.args.get('period', 'today')

    if not os.path.exists(_modsec_audit()):
        return jsonify({'ok': True, 'exists': False, 'total': 0,
                         'categories': [], 'top_ips': [], 'top_uris': [], 'timeline': []})

    # Cap the read — a very busy site's audit log can be huge; this covers a
    # generous window of recent activity without loading the whole file.
    out, _, _ = sh(f'tail -n 20000 "{_modsec_audit()}" 2>/dev/null', t=20)
    entries = _parse_modsec_entries(out)

    now = datetime.now()
    if period == 'today':
        cutoff = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == 'yesterday':
        cutoff = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        upper  = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == '7days':
        cutoff = now - timedelta(days=7)
    else:
        cutoff = now - timedelta(days=1)

    filtered = []
    for e in entries:
        dt = _entry_datetime(e)
        if dt is None:
            continue  # can't place it in time — exclude from period-bounded stats
        if period == 'yesterday':
            if cutoff <= dt < upper: filtered.append((dt, e))
        elif dt >= cutoff:
            filtered.append((dt, e))

    total = len(filtered)
    cat_counts, ip_counts, uri_counts = {}, {}, {}
    timeline_buckets = {}

    for dt, e in filtered:
        cat = _categorize_rule(e.get('rule_id'))
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
        if e.get('ip'):
            ip_counts[e['ip']] = ip_counts.get(e['ip'], 0) + 1
        if e.get('uri'):
            uri_counts[e['uri']] = uri_counts.get(e['uri'], 0) + 1
        # Bucket by hour for today/yesterday, by day for 7days
        bucket = dt.strftime('%H:00') if period in ('today', 'yesterday') else dt.strftime('%m/%d')
        timeline_buckets[bucket] = timeline_buckets.get(bucket, 0) + 1

    top_ips  = sorted(ip_counts.items(),  key=lambda x: -x[1])[:10]
    top_uris = sorted(uri_counts.items(), key=lambda x: -x[1])[:10]
    categories = sorted(cat_counts.items(), key=lambda x: -x[1])
    timeline = sorted(timeline_buckets.items(), key=lambda x: x[0])

    return jsonify({
        'ok': True, 'exists': True, 'period': period, 'total': total,
        'categories': [{'name': k, 'count': v} for k, v in categories],
        'top_ips':    [{'ip': k, 'count': v} for k, v in top_ips],
        'top_uris':   [{'uri': k, 'count': v} for k, v in top_uris],
        'timeline':   [{'label': k, 'count': v} for k, v in timeline],
    })


@security_bp.route('/api/security/waf/blockade-log')
def waf_blockade_log():
    """Filterable version of the raw audit log — supports search by IP,
    URI, or rule category, plus pagination for larger result sets."""
    if not req(): return jsonify({'ok': False}), 401
    if not os.path.exists(_modsec_audit()):
        return jsonify({'ok': True, 'entries': [], 'total': 0, 'exists': False})

    search   = (request.args.get('q') or '').strip().lower()
    page     = max(1, int(request.args.get('page', 1)))
    per_page = min(100, max(10, int(request.args.get('per_page', 20))))

    out, _, _ = sh(f'tail -n 20000 "{_modsec_audit()}" 2>/dev/null', t=20)
    entries = _parse_modsec_entries(out)
    for e in entries:
        e['category'] = _categorize_rule(e.get('rule_id'))
    entries.reverse()  # most recent first

    if search:
        entries = [e for e in entries if
                   search in (e.get('ip') or '').lower() or
                   search in (e.get('uri') or '').lower() or
                   search in (e.get('domain') or '').lower() or
                   search in (e.get('category') or '').lower() or
                   search in (e.get('message') or '').lower()]

    total = len(entries)
    start = (page - 1) * per_page
    page_entries = entries[start:start + per_page]

    return jsonify({'ok': True, 'exists': True, 'entries': page_entries,
                     'total': total, 'page': page, 'per_page': per_page})

@security_bp.route('/api/security/modsecurity/repair', methods=['POST'])
def modsec_repair():
    """Fix an incomplete ModSecurity install — writes modsecurity.conf if
    missing, downloads OWASP CRS if missing, and regenerates main.conf to
    correctly reflect whichever pieces end up present. This exists because
    the install script has multiple independent download steps that can
    each fail on their own (network hiccups, GitHub rate limits); previously
    a partial failure left the install stuck with no in-panel way to finish
    it short of a full uninstall/reinstall."""
    if not req(): return jsonify({'ok': False}), 401
    log = []

    if not _modsec_installed():
        return jsonify({'ok': False, 'error': 'ModSecurity engine (libmodsecurity) is not installed at all — install it from the App Store first, this repair only fixes an incomplete config.'})

    os.makedirs(_modsec_dir(), exist_ok=True)

    # 1. Fix modsecurity.conf if missing
    conf_ok = os.path.exists(_modsec_conf())
    if not conf_ok:
        log.append('modsecurity.conf missing — downloading...')
        _, err, rc = sh(
            f'wget -q https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended -O {_modsec_conf()}',
            t=20
        )
        if rc == 0 and os.path.exists(_modsec_conf()):
            content = open(_modsec_conf()).read()
            content = content.replace('SecRuleEngine DetectionOnly', 'SecRuleEngine On')
            content = content.replace('SecAuditLogParts ABIJDEFHZ', 'SecAuditLogParts ABCEFHJKZ')
            open(_modsec_conf(), 'w').write(content)
            conf_ok = True
            log.append('✓ modsecurity.conf downloaded and configured')
        else:
            # Fallback minimal config so the engine is at least usable
            open(_modsec_conf(), 'w').write(
                'SecRuleEngine On\nSecRequestBodyAccess On\n'
                'SecAuditEngine RelevantOnly\nSecAuditLog /var/log/modsec_audit.log\n'
            )
            conf_ok = True
            log.append(f'⚠ Download failed ({err[:150]}) — wrote minimal fallback config so the engine is still usable')
    else:
        log.append('✓ modsecurity.conf already present')

    # 2. Fix CRS if missing
    crs_ok = os.path.exists(f'{_modsec_crs_dir()}/crs-setup.conf')
    if not crs_ok:
        log.append('OWASP CRS missing — downloading...')
        os.makedirs(_modsec_crs_dir(), exist_ok=True)
        api_out, _, _ = sh(
            'curl -s --max-time 10 https://api.github.com/repos/coreruleset/coreruleset/releases/latest'
            ' | python3 -c "import json,sys; print(json.load(sys.stdin)[\'tag_name\'])"', t=15
        )
        tag = api_out.strip() if api_out.strip().startswith('v') else 'v4.0.0'
        _, err, rc = sh(
            f'wget -q --timeout=20 "https://github.com/coreruleset/coreruleset/archive/refs/tags/{tag}.tar.gz" -O /tmp/crs_repair.tar.gz && '
            f'tar -xzf /tmp/crs_repair.tar.gz -C {_modsec_crs_dir()} --strip-components=1 && rm -f /tmp/crs_repair.tar.gz',
            t=60
        )
        if rc == 0 and os.path.exists(f'{_modsec_crs_dir()}/crs-setup.conf.example'):
            sh(f'cp {_modsec_crs_dir()}/crs-setup.conf.example {_modsec_crs_dir()}/crs-setup.conf')
            crs_ok = True
            log.append(f'✓ OWASP CRS {tag} downloaded')
        else:
            log.append(f'⚠ CRS download failed ({err[:150]}) — engine will work but with no ruleset loaded. Try Repair again later.')
    else:
        log.append('✓ OWASP CRS already present')

    # 3. Regenerate main.conf to match reality — never reference a CRS file
    # that doesn't actually exist, or the webserver will fail to reload
    # entirely. Apache-only nuance: modsecurity.conf is already
    # auto-included by security2.conf's own glob (IncludeOptional
    # /etc/modsecurity/*.conf), so re-including it here would double-load
    # it -- confirmed via a real reproduced failure. Only CRS (in a
    # subdirectory the glob doesn't reach) genuinely needs wiring there.
    is_apache = _modsec_target() == 'apache'
    if crs_ok:
        main_conf = (('' if is_apache else f'Include {_modsec_conf()}\n') +
                     f'Include {_modsec_crs_dir()}/crs-setup.conf\n'
                     f'Include {_modsec_crs_dir()}/rules/*.conf\n')
    else:
        main_conf = '' if is_apache else f'Include {_modsec_conf()}\n'
    open(_modsec_main(), 'w').write(main_conf)
    log.append(f'main.conf regenerated ({"with" if crs_ok else "without"} CRS includes)')

    # 4. Ensure the webserver actually loads main.conf -- nginx-only step.
    # Apache's security2.conf already auto-includes /etc/modsecurity/*.conf
    # by default (confirmed by installing the package fresh and inspecting
    # it), so there is no equivalent wiring step needed there.
    if _modsec_target() != 'apache' and os.path.exists('/etc/nginx/nginx.conf'):
        nc = open('/etc/nginx/nginx.conf').read()
        if 'modsecurity_rules_file' not in nc:
            sh(f'sed -i "/^http {{/a\\    modsecurity on;\\n    modsecurity_rules_file {_modsec_main()};" /etc/nginx/nginx.conf')
            log.append('✓ Enabled modsecurity directives in nginx.conf')

    ok, out = _modsec_configtest()
    if not ok:
        return jsonify({'ok': False, 'error': f'Config test failed after repair: {out}', 'log': log})
    _modsec_reload()
    log.append('✓ webserver reloaded')

    return jsonify({'ok': True, 'conf_ok': conf_ok, 'crs_ok': crs_ok, 'log': log})


@security_bp.route('/api/security/modsecurity/update-crs', methods=['POST'])
def modsec_update_crs():
    """Pull latest OWASP CRS tarball and replace existing rules."""
    if not req(): return jsonify({'ok':False}), 401
    # Get latest CRS release tag from GitHub API
    api_out, _, rc = sh(
        'curl -s https://api.github.com/repos/coreruleset/coreruleset/releases/latest'
        ' | python3 -c "import json,sys; print(json.load(sys.stdin)[\'tag_name\'])"',
        t=15
    )
    tag = api_out.strip() if rc == 0 and api_out.strip().startswith('v') else 'v4.0.0'
    ver = tag.lstrip('v')

    reload_cmd = '(apache2ctl configtest 2>/dev/null || apachectl configtest 2>/dev/null || httpd -t 2>/dev/null) && (systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null)' \
        if _modsec_target() == 'apache' else 'nginx -t && systemctl reload nginx 2>/dev/null'
    out, err, rc = sh(
        f'wget -q https://github.com/coreruleset/coreruleset/archive/refs/tags/{tag}.tar.gz'
        f' -O /tmp/crs_update.tar.gz && '
        f'mkdir -p {_modsec_crs_dir()}_backup && '
        f'cp -r {_modsec_crs_dir()}/crs-setup.conf {_modsec_crs_dir()}_backup/ 2>/dev/null || true && '
        f'tar -xzf /tmp/crs_update.tar.gz -C {_modsec_crs_dir()} --strip-components=1 && '
        f'cp {_modsec_crs_dir()}/crs-setup.conf.example {_modsec_crs_dir()}/crs-setup.conf 2>/dev/null || true && '
        f'cp {_modsec_crs_dir()}_backup/crs-setup.conf {_modsec_crs_dir()}/crs-setup.conf 2>/dev/null || true && '
        f'{reload_cmd}',
        t=120
    )
    return jsonify({
        'ok': rc == 0,
        'version': ver,
        'output': (out + err)[-500:],
    })


@security_bp.route('/api/security/modsecurity/per-site', methods=['POST'])
def modsec_per_site():
    """Enable or disable ModSecurity for a specific site's nginx vhost.
    Apache uses a different per-vhost mechanism (IfModule blocks in a
    different config location) that hasn't been built and tested yet --
    explicitly say so rather than silently do nothing or risk an
    untested edit to an Apache vhost file."""
    if not req(): return jsonify({'ok':False}), 401
    if _modsec_target() == 'apache':
        return jsonify({'ok':False,'error':'Per-site ModSecurity override is not yet available for Apache installs (global toggle, paranoia level, custom rules, and IP/UA/URL lists all work correctly). Use the global Engine Mode toggle for now.'}), 501
    d      = request.get_json() or {}
    domain = d.get('domain', '')
    enable = d.get('enable', True)   # True = use global setting, False = disable for this site
    if not domain:
        return jsonify({'ok':False,'error':'domain required'}), 400

    for conf_dir in ['/etc/nginx/vortex', '/etc/nginx/conf.d']:
        if not os.path.isdir(conf_dir): continue
        for fn in os.listdir(conf_dir):
            fp = os.path.join(conf_dir, fn)
            try:
                content = open(fp).read()
                if domain not in content: continue
                # Remove any existing modsecurity directives for this site
                content = re.sub(r'\s*modsecurity\s+(on|off);\s*', '\n', content,
                                 flags=re.IGNORECASE)
                content = re.sub(r'\s*modsecurity_rules_file[^\n]+\n', '', content)
                if not enable:
                    # Insert modsecurity off; inside the server block
                    content = content.replace(
                        'server {',
                        'server {\n    modsecurity off;',
                        1
                    )
                with open(fp,'w') as f: f.write(content)
                out, err, rc = sh('nginx -t 2>&1')
                if rc != 0:
                    return jsonify({'ok':False,'error':f'nginx config error: {out}{err}'}), 400
                sh('systemctl reload nginx 2>/dev/null')
                return jsonify({'ok':True,'domain':domain,'enabled':enable})
            except Exception as e:
                return jsonify({'ok':False,'error':str(e)}), 500

    return jsonify({'ok':False,'error':f'No nginx config found for {domain}'}), 404

# --- Nginx Load Balancer --------------------------------------------------------
LB_CONF = '/etc/nginx/conf.d/loadbalancer.conf'

@security_bp.route('/api/security/loadbalancer')
def lb_status():
    if not req(): return jsonify({'ok':False}), 401
    if not os.path.exists(LB_CONF):
        return jsonify({'ok':True,'configured':False,'servers':[],'method':'roundrobin'})
    with open(LB_CONF) as f: content = f.read()
    # Parse only real "server <addr> [weight=N];" upstream directives.
    # Must end in ';' and exclude { } — this prevents the virtual host's
    # "server {" block declaration from being parsed as a phantom backend.
    servers = re.findall(r'^\s*server\s+([^\s;{}]+)(?:\s+weight=(\d+))?\s*;', content, re.MULTILINE)
    method = 'roundrobin'
    if 'least_conn' in content: method = 'leastconn'
    if 'ip_hash'    in content: method = 'iphash'
    server_list = [{'address':s[0],'weight':int(s[1]) if s[1] else 1} for s in servers]
    return jsonify({'ok':True,'configured':True,'servers':server_list,'method':method,'content':content})

@security_bp.route('/api/security/loadbalancer', methods=['PUT'])
def lb_save():
    if not req(): return jsonify({'ok':False}), 401
    d       = request.get_json() or {}
    servers = d.get('servers', [])  # [{address, weight}]
    method  = d.get('method', 'roundrobin')
    domain  = d.get('domain', '_')
    port    = d.get('port', '80')
    cookie_name = d.get('cookie_name', 'VORTEX_LB')
    if not servers: return jsonify({'ok':False,'error':'At least one server required'}), 400

    # Build upstream block
    method_directive = ''
    if method == 'leastconn': method_directive = '    least_conn;\n'
    if method == 'iphash':    method_directive = '    ip_hash;\n'
    if method == 'cookie':
        # Open-source nginx has no nginx-plus "sticky cookie" directive, but
        # the standard `hash` directive with `consistent` minimizes
        # redistribution when servers are added/removed — using the
        # client's existing session cookie as the hash key gives the same
        # practical session-affinity result without needing nginx-plus.
        # The backend application must already be setting this cookie
        # (e.g. PHPSESSID, JSESSIONID, or a custom session cookie name).
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', cookie_name):
            return jsonify({'ok':False,'error':'Invalid cookie name'}), 400
        method_directive = f'    hash $cookie_{cookie_name} consistent;\n'

    server_lines = '\n'.join([
        f"    server {s['address']} weight={s.get('weight',1)};"
        for s in servers if s.get('address')
    ])
    if not server_lines:
        return jsonify({'ok':False,'error':'At least one valid server address required'}), 400

    method_comment = f'cookie ({cookie_name})' if method == 'cookie' else method
    conf = f"""# VortexPanel Load Balancer — managed by VortexPanel
# Method: {method_comment}
upstream vortex_backend {{
{method_directive}{server_lines}
    keepalive 32;
}}

server {{
    listen {port};
    server_name {domain};

    access_log /var/log/nginx/lb.access.log;
    error_log  /var/log/nginx/lb.error.log;

    location / {{
        proxy_pass http://vortex_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_send_timeout    60s;
        proxy_read_timeout    60s;
        proxy_next_upstream   error timeout invalid_header http_500 http_502 http_503;
    }}
}}
"""
    os.makedirs('/etc/nginx/conf.d', exist_ok=True)

    # Back up the existing config before overwriting. If 'nginx -t' fails
    # below, we restore this so a broken config is never left on disk
    # (which would otherwise break nginx on the next restart/reload and
    # take down every site on the server).
    existed = os.path.exists(LB_CONF)
    backup = None
    if existed:
        with open(LB_CONF) as f: backup = f.read()

    with open(LB_CONF,'w') as f: f.write(conf)
    test_out, test_err, test_rc = sh('nginx -t 2>&1')
    test = (test_out + test_err)
    if test_rc != 0 or 'failed' in test.lower():
        if existed:
            with open(LB_CONF,'w') as f: f.write(backup)
        else:
            try: os.unlink(LB_CONF)
            except: pass
        return jsonify({'ok':False,'error':test}), 400
    sh('systemctl reload nginx 2>/dev/null')

    # Keep health-check's server list in sync if health checking is active,
    # so newly added/removed servers are picked up without a separate step.
    try:
        hcfg = _load_json(LB_HEALTH_CONFIG, None)
        if hcfg and hcfg.get('enabled'):
            hcfg['servers'] = [s['address'] for s in servers if s.get('address')]
            _save_json(LB_HEALTH_CONFIG, hcfg)
    except Exception:
        pass

    return jsonify({'ok':True})

@security_bp.route('/api/security/loadbalancer', methods=['DELETE'])
def lb_delete():
    if not req(): return jsonify({'ok':False}), 401
    try: os.unlink(LB_CONF)
    except: pass
    sh('systemctl reload nginx 2>/dev/null')
    return jsonify({'ok':True})


# --- Load Balancer: shared JSON helpers -----------------------------------------
def _load_json(path, default):
    try: return __import__('json').load(open(path))
    except Exception: return default

def _save_json(path, data):
    import json
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    try: os.chmod(path, 0o600)
    except Exception: pass


# --- Load Balancer: TCP / Stream -------------------------------------------------
LB_STREAM_DIR  = '/etc/nginx/stream.d'
LB_STREAM_CONF = '/etc/nginx/stream.d/vortex_tcp_lb.conf'

def _find_stream_module_so():
    """Locate ngx_stream_module.so on disk — varies by distro and nginx source."""
    candidates = [
        '/usr/lib/nginx/modules/ngx_stream_module.so',       # Debian/Ubuntu
        '/usr/lib64/nginx/modules/ngx_stream_module.so',     # RHEL/CentOS/Alma/Rocky
        '/usr/share/nginx/modules/ngx_stream_module.so',     # some RHEL builds
    ]
    for p in candidates:
        if os.path.exists(p): return p
    # last resort: find it
    out, _, _ = sh('find /usr -name "ngx_stream_module.so" 2>/dev/null | head -1')
    return out or ''

def _nginx_has_stream_module():
    """Check if nginx can use the stream module right now."""
    # 1) compiled-in (static module)
    out, _, _ = sh('nginx -V 2>&1')
    if '--with-stream' in out and '--with-stream=dynamic' not in out:
        return True
    # 2) dynamic module .so exists on disk
    if not _find_stream_module_so():
        return False
    # 3) already enabled in modules-enabled (Debian auto-symlink)
    if sh('find /etc/nginx/modules-enabled -name "*stream*" 2>/dev/null')[0]:
        return True
    # 4) load_module directive already in nginx.conf
    try:
        conf = open('/etc/nginx/nginx.conf').read()
        if re.search(r'^\s*load_module\s+.*ngx_stream_module', conf, re.MULTILINE):
            return True
    except: pass
    return False

def _ensure_stream_load_module():
    """Ensure the load_module directive for stream is in nginx.conf.
    On Debian, apt auto-creates a symlink in modules-enabled so this
    is a no-op. On RHEL-family it must be added manually."""
    conf_path = '/etc/nginx/nginx.conf'
    if not os.path.exists(conf_path):
        return False, 'nginx.conf not found'
    content = open(conf_path).read()
    # Already has load_module or modules-enabled symlink covers it
    if re.search(r'^\s*load_module\s+.*ngx_stream_module', content, re.MULTILINE):
        return True, ''
    if sh('find /etc/nginx/modules-enabled -name "*stream*" 2>/dev/null')[0]:
        return True, ''
    # Find the .so path
    so_path = _find_stream_module_so()
    if not so_path:
        return False, 'stream module .so not found after install'
    # Use relative path if under standard modules dir, absolute otherwise
    if '/modules/ngx_stream_module.so' in so_path:
        directive = 'load_module modules/ngx_stream_module.so;'
    else:
        directive = f'load_module {so_path};'
    # Insert at top of nginx.conf (before any other blocks)
    new_content = directive + '\n' + content
    with open(conf_path, 'w') as f:
        f.write(new_content)
    return True, ''

def _ensure_stream_block():
    """Add a top-level `stream { include .../stream.d/*.conf; }` block to
    nginx.conf if one doesn't already exist. Required once — TCP/stream
    load balancing cannot live inside conf.d (that's only included from
    within the http {} block)."""
    os.makedirs(LB_STREAM_DIR, exist_ok=True)
    conf_path = '/etc/nginx/nginx.conf'
    if not os.path.exists(conf_path):
        return False, 'nginx.conf not found'
    content = open(conf_path).read()
    if re.search(r'^\s*stream\s*\{', content, re.MULTILINE):
        return True, ''
    addition = f"\nstream {{\n    include {LB_STREAM_DIR}/*.conf;\n}}\n"
    with open(conf_path, 'a') as f:
        f.write(addition)
    return True, ''

@security_bp.route('/api/security/loadbalancer/tcp')
def lb_tcp_status():
    if not req(): return jsonify({'ok':False}), 401
    has_module = _nginx_has_stream_module()
    if not os.path.exists(LB_STREAM_CONF):
        return jsonify({'ok':True,'configured':False,'servers':[],'method':'roundrobin',
                        'stream_module_available':has_module})
    content = open(LB_STREAM_CONF).read()
    servers = re.findall(r'^\s*server\s+([^\s;{}]+)(?:\s+weight=(\d+))?\s*;', content, re.MULTILINE)
    method = 'roundrobin'
    if 'least_conn' in content: method = 'leastconn'
    if re.search(r'\bhash\b', content): method = 'hash'
    port_m = re.search(r'^\s*listen\s+(\d+)', content, re.MULTILINE)
    server_list = [{'address':s[0],'weight':int(s[1]) if s[1] else 1} for s in servers]
    return jsonify({'ok':True,'configured':True,'servers':server_list,'method':method,
                    'port':port_m.group(1) if port_m else '', 'stream_module_available':has_module})

@security_bp.route('/api/security/loadbalancer/tcp/install-stream', methods=['POST'])
def lb_tcp_install_stream():
    """Auto-install nginx stream module for any supported distro."""
    if not req(): return jsonify({'ok':False}), 401
    if _nginx_has_stream_module():
        return jsonify({'ok':True,'message':'Stream module already available'})

    os_info = get_os()
    family  = os_info['family']
    pkg_mgr = os_info['pkg']
    steps   = []

    # --- Step 1: install the package ---
    if family == 'debian':
        cmd = f'DEBIAN_FRONTEND=noninteractive apt-get install -y libnginx-mod-stream'
        out, err, rc = sh(cmd, t=120)
        steps.append({'cmd': cmd, 'rc': rc, 'out': out, 'err': err})
        if rc != 0:
            # Try apt update first then retry
            sh('apt-get update -qq', t=60)
            out, err, rc = sh(cmd, t=120)
            steps.append({'cmd': cmd + ' (retry after update)', 'rc': rc})
            if rc != 0:
                return jsonify({'ok':False,
                    'error':f'Failed to install libnginx-mod-stream: {err}',
                    'steps':steps}), 500

    elif family in ('rhel', 'fedora'):
        # Official nginx.org packages bundle stream in the main package.
        # The .so may already exist — just needs load_module.
        so_path = _find_stream_module_so()
        if not so_path:
            # Try installing the distro's stream module package
            pkg_name = 'nginx-mod-stream'
            cmd = f'{pkg_mgr} install -y {pkg_name}'
            out, err, rc = sh(cmd, t=120)
            steps.append({'cmd': cmd, 'rc': rc, 'out': out, 'err': err})
            if rc != 0:
                # Package doesn't exist — nginx was likely built from source
                # or from a repo that bundles everything. Check one more time.
                so_path = _find_stream_module_so()
                if not so_path:
                    return jsonify({'ok':False,
                        'error':f'Could not install stream module. '
                                f'Package "{pkg_name}" not found in repos. '
                                f'If nginx was compiled from source, rebuild with --with-stream.',
                        'steps':steps}), 500
    else:
        return jsonify({'ok':False,
            'error':f'Unsupported OS family: {family}'}), 400

    # --- Step 2: ensure load_module directive exists ---
    ok, err = _ensure_stream_load_module()
    steps.append({'action': 'ensure_load_module', 'ok': ok, 'err': err})
    if not ok:
        return jsonify({'ok':False, 'error':f'load_module failed: {err}', 'steps':steps}), 500

    # --- Step 3: test nginx config ---
    out, err, rc = sh('nginx -t 2>&1')
    steps.append({'cmd': 'nginx -t', 'rc': rc, 'out': out, 'err': err})
    if rc != 0:
        return jsonify({'ok':False,
            'error':f'nginx -t failed after install: {out} {err}',
            'steps':steps}), 500

    # --- Step 4: reload nginx ---
    sh('systemctl reload nginx', t=10)
    steps.append({'action': 'nginx reloaded'})

    return jsonify({'ok':True, 'message':'Stream module installed and loaded', 'steps':steps})

@security_bp.route('/api/security/loadbalancer/tcp', methods=['PUT'])
def lb_tcp_save():
    if not req(): return jsonify({'ok':False}), 401
    if not _nginx_has_stream_module():
        return jsonify({'ok':False,
            'error':"nginx stream module not available. Use the Install button to set it up automatically."}), 400

    d       = request.get_json() or {}
    servers = d.get('servers', [])
    method  = d.get('method', 'roundrobin')   # roundrobin | leastconn | hash (by source IP)
    port    = d.get('port', '9000')
    if not servers: return jsonify({'ok':False,'error':'At least one server required'}), 400
    try:
        port_n = int(port)
        if not (1 <= port_n <= 65535): raise ValueError()
    except ValueError:
        return jsonify({'ok':False,'error':'Invalid port'}), 400

    ok, err = _ensure_stream_block()
    if not ok: return jsonify({'ok':False,'error':err}), 500

    method_directive = ''
    if method == 'leastconn': method_directive = '    least_conn;\n'
    if method == 'hash':      method_directive = '    hash $remote_addr consistent;\n'

    server_lines = '\n'.join([
        f"    server {s['address']} weight={s.get('weight',1)};"
        for s in servers if s.get('address')
    ])
    if not server_lines:
        return jsonify({'ok':False,'error':'At least one valid server address required'}), 400

    conf = f"""# VortexPanel TCP Load Balancer — managed by VortexPanel
# Method: {method}
upstream vortex_tcp_backend {{
{method_directive}{server_lines}
}}

server {{
    listen {port_n};
    proxy_pass vortex_tcp_backend;
    proxy_timeout 10m;
    proxy_connect_timeout 5s;
    proxy_next_upstream on;
}}
"""
    os.makedirs(LB_STREAM_DIR, exist_ok=True)
    existed = os.path.exists(LB_STREAM_CONF)
    backup = open(LB_STREAM_CONF).read() if existed else None

    with open(LB_STREAM_CONF, 'w') as f: f.write(conf)
    test_out, test_err, test_rc = sh('nginx -t 2>&1')
    test = test_out + test_err
    if test_rc != 0 or 'failed' in test.lower():
        if existed:
            with open(LB_STREAM_CONF, 'w') as f: f.write(backup)
        else:
            try: os.unlink(LB_STREAM_CONF)
            except: pass
        return jsonify({'ok':False,'error':test}), 400
    sh('systemctl reload nginx 2>/dev/null')

    # Open the port in the firewall (best-effort, both UFW and firewalld)
    sh(f'ufw allow {port_n}/tcp 2>/dev/null')
    sh(f'firewall-cmd --add-port={port_n}/tcp --permanent 2>/dev/null; firewall-cmd --reload 2>/dev/null')

    return jsonify({'ok':True})

@security_bp.route('/api/security/loadbalancer/tcp', methods=['DELETE'])
def lb_tcp_delete():
    if not req(): return jsonify({'ok':False}), 401
    try: os.unlink(LB_STREAM_CONF)
    except Exception: pass
    sh('systemctl reload nginx 2>/dev/null')
    return jsonify({'ok':True})


# --- Load Balancer: Active Health Checks -----------------------------------------
LB_HEALTH_CONFIG = '/opt/vortexpanel/lb_health.json'
LB_HEALTH_STATE  = '/opt/vortexpanel/lb_health_state.json'
LB_HEALTH_LOG    = '/opt/vortexpanel/lb_health.log'
LB_HEALTH_SCRIPT = '/opt/vortexpanel/scripts/lb_healthcheck.py'
LB_HEALTH_SERVICE_FILE = '/etc/systemd/system/vortex-lb-healthcheck.service'
LB_HEALTH_SERVICE_NAME = 'vortex-lb-healthcheck'

_HEALTHCHECK_SCRIPT_BODY = '''#!/usr/bin/env python3
"""
VortexPanel Load Balancer — active health check daemon.

Open-source nginx has no built-in active health checking (that's an
nginx-plus-only feature). This script provides the same practical
result: it periodically probes each backend, and when one crosses the
configured failure threshold it comments that server out of the
upstream block, validates the new config with `nginx -t`, and reloads
nginx — then reverses the process automatically once the backend
recovers. Runs as a long-lived systemd service, not cron, so the
check interval can be sub-minute.
"""
import json, os, re, socket, subprocess, time, urllib.request

CONFIG  = "/opt/vortexpanel/lb_health.json"
STATE   = "/opt/vortexpanel/lb_health_state.json"
LOG     = "/opt/vortexpanel/lb_health.log"
LB_CONF = "/etc/nginx/conf.d/loadbalancer.conf"

def log(msg):
    try:
        with open(LOG, "a") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\\n")
        lines = open(LOG).readlines()
        if len(lines) > 500:
            with open(LOG, "w") as f:
                f.writelines(lines[-500:])
    except Exception:
        pass

def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def check_http(address, path, timeout):
    try:
        host, port = address.rsplit(":", 1)
        url = "http://" + host + ":" + port + path
        req = urllib.request.Request(url, headers={"User-Agent": "VortexPanel-HealthCheck"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 400
    except Exception:
        return False

def check_tcp(address, timeout):
    try:
        host, port = address.rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False

def rewrite_upstream(healthy_servers):
    if not os.path.exists(LB_CONF):
        return
    content = open(LB_CONF).read()
    new_lines = []
    changed = False
    for line in content.split("\\n"):
        m = re.match(r"^(\\s*)(#\\s*)?server\\s+([^\\s;{}]+)(\\s+weight=\\d+)?\\s*;.*$", line)
        if m:
            indent, was_commented, addr, weight = m.group(1), m.group(2), m.group(3), m.group(4) or ""
            is_healthy = addr in healthy_servers
            if is_healthy and was_commented:
                new_lines.append(indent + "server " + addr + weight + ";")
                changed = True
            elif not is_healthy and not was_commented:
                new_lines.append(indent + "#server " + addr + weight + "; # VortexPanel: marked unhealthy")
                changed = True
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    if not changed:
        return
    new_content = "\\n".join(new_lines)
    with open(LB_CONF, "w") as f:
        f.write(new_content)
    test = subprocess.run("nginx -t", shell=True, capture_output=True, text=True)
    if test.returncode == 0:
        subprocess.run("systemctl reload nginx", shell=True)
        log("upstream updated, healthy=" + ",".join(healthy_servers))
    else:
        with open(LB_CONF, "w") as f:
            f.write(content)
        log("nginx -t failed after health-check rewrite, rolled back: " + test.stderr[:200])

def run_once():
    cfg = load_json(CONFIG, None)
    if not cfg or not cfg.get("enabled"):
        return
    servers = cfg.get("servers", [])
    if not servers:
        return
    state = load_json(STATE, {})
    healthy = []
    for addr in servers:
        s = state.get(addr, {"fail": 0, "ok": 0, "healthy": True})
        timeout = cfg.get("timeout_seconds", 3)
        if cfg.get("protocol", "http") == "tcp":
            up = check_tcp(addr, timeout)
        else:
            up = check_http(addr, cfg.get("check_path", "/"), timeout)
        if up:
            s["ok"] += 1
            s["fail"] = 0
            if s["ok"] >= cfg.get("healthy_threshold", 2):
                if not s["healthy"]:
                    log(addr + " recovered, marking HEALTHY")
                s["healthy"] = True
        else:
            s["fail"] += 1
            s["ok"] = 0
            if s["fail"] >= cfg.get("unhealthy_threshold", 3):
                if s["healthy"]:
                    log(addr + " failed " + str(s["fail"]) + " checks, marking UNHEALTHY")
                s["healthy"] = False
        state[addr] = s
        if s["healthy"]:
            healthy.append(addr)
    save_json(STATE, state)

    if not healthy:
        # Fail open: never remove every backend from rotation even if all
        # checks fail (e.g. a network blip affecting the checker itself) —
        # a false-positive total outage is worse than serving through an
        # unconfirmed-healthy backend.
        log("WARNING: all backends report unhealthy — failing open, keeping all in rotation")
        healthy = servers

    rewrite_upstream(healthy)

def main():
    log("health check daemon started")
    while True:
        try:
            run_once()
        except Exception as e:
            log("error in check loop: " + str(e))
        cfg = load_json(CONFIG, {})
        time.sleep(max(5, cfg.get("interval_seconds", 10)))

if __name__ == "__main__":
    main()
'''

def _install_health_service():
    os.makedirs(os.path.dirname(LB_HEALTH_SCRIPT), exist_ok=True)
    with open(LB_HEALTH_SCRIPT, 'w') as f:
        f.write(_HEALTHCHECK_SCRIPT_BODY)
    os.chmod(LB_HEALTH_SCRIPT, 0o700)

    service = f"""[Unit]
Description=VortexPanel Load Balancer Active Health Check
After=network.target nginx.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {LB_HEALTH_SCRIPT}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    with open(LB_HEALTH_SERVICE_FILE, 'w') as f:
        f.write(service)
    sh('systemctl daemon-reload')

@security_bp.route('/api/security/loadbalancer/health')
def lb_health_status():
    if not req(): return jsonify({'ok':False}), 401
    cfg   = _load_json(LB_HEALTH_CONFIG, {'enabled':False,'check_path':'/','protocol':'http',
                                          'interval_seconds':10,'timeout_seconds':3,
                                          'unhealthy_threshold':3,'healthy_threshold':2,'servers':[]})
    state = _load_json(LB_HEALTH_STATE, {})
    service_active, _, _ = sh(f'systemctl is-active {LB_HEALTH_SERVICE_NAME} 2>/dev/null')
    log_tail = ''
    if os.path.exists(LB_HEALTH_LOG):
        try: log_tail = ''.join(open(LB_HEALTH_LOG).readlines()[-30:])
        except Exception: pass
    return jsonify({'ok':True, 'config':cfg, 'state':state,
                    'service_active': service_active.strip()=='active', 'log': log_tail})

@security_bp.route('/api/security/loadbalancer/health', methods=['PUT'])
def lb_health_save():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}

    # Pull current LB server list automatically so health checks always
    # match whatever's actually configured in the load balancer.
    current = _load_json(LB_HEALTH_CONFIG, {})
    lb = lb_status_data()
    servers = [s['address'] for s in lb.get('servers', [])]

    cfg = {
        'enabled':              bool(d.get('enabled', False)),
        'protocol':             d.get('protocol', 'http') if d.get('protocol') in ('http','tcp') else 'http',
        'check_path':           d.get('check_path', '/') or '/',
        'interval_seconds':     max(5, min(300, int(d.get('interval_seconds', 10)))),
        'timeout_seconds':      max(1, min(30, int(d.get('timeout_seconds', 3)))),
        'unhealthy_threshold':  max(1, min(10, int(d.get('unhealthy_threshold', 3)))),
        'healthy_threshold':    max(1, min(10, int(d.get('healthy_threshold', 2)))),
        'servers':              servers,
    }
    _save_json(LB_HEALTH_CONFIG, cfg)

    if not os.path.exists(LB_HEALTH_SCRIPT):
        _install_health_service()

    if cfg['enabled']:
        sh(f'systemctl enable {LB_HEALTH_SERVICE_NAME} 2>/dev/null')
        sh(f'systemctl restart {LB_HEALTH_SERVICE_NAME} 2>/dev/null')
    else:
        sh(f'systemctl stop {LB_HEALTH_SERVICE_NAME} 2>/dev/null')
        # Restore any servers that were commented out, since checking is now off
        if os.path.exists(LB_CONF):
            content = open(LB_CONF).read()
            restored = re.sub(r'#server ([^\s;{}]+)(\s+weight=\d+)?; # VortexPanel: marked unhealthy',
                              r'server \1\2;', content)
            if restored != content:
                with open(LB_CONF, 'w') as f: f.write(restored)
                out, err, rc = sh('nginx -t 2>&1')
                if rc == 0: sh('systemctl reload nginx 2>/dev/null')

    return jsonify({'ok':True, 'config':cfg})


def lb_status_data():
    """Internal helper — same logic as lb_status() but returns plain dict
    for reuse by other routes instead of a Flask Response."""
    if not os.path.exists(LB_CONF):
        return {'configured':False,'servers':[],'method':'roundrobin'}
    content = open(LB_CONF).read()
    servers = re.findall(r'^\s*server\s+([^\s;{}]+)(?:\s+weight=(\d+))?\s*;', content, re.MULTILINE)
    method = 'roundrobin'
    if 'least_conn' in content: method = 'leastconn'
    if 'ip_hash'    in content: method = 'iphash'
    server_list = [{'address':s[0],'weight':int(s[1]) if s[1] else 1} for s in servers]
    return {'configured':True,'servers':server_list,'method':method}
# ===============================================================================
# WAF 2.0 — Phase 1: per-site engine mode + scoped rule exceptions
# ===============================================================================
# All state lives in vortex-exceptions.json and is compiled, in full, to
# vortex-exceptions.conf on every change. The generated rules key on
# SERVER_NAME, so per-site mode and scoped exceptions work identically on
# nginx AND Apache (via ModSecurity's per-request ctl: action) without any
# vhost surgery.
import ipaddress as _ipaddr

# Reserved SecRule id space — outside CRS (900000-999999) and the
# vortex-lists.conf range (_LIST_ID_BASE, 1050000-1053999).
_EXC_SITEMODE_BASE = 1820000
_EXC_RULE_BASE     = 1830000

_HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT'}

# Protocol-integrity rules that can NEVER be excepted (request smuggling /
# splitting). Disabling these re-opens whole request-parsing attack classes,
# so the builder refuses them even with force=true.
_EXC_PROTECTED_RANGES = [(921000, 921999)]          # CRS: Protocol Attack
def _rid_in_ranges(rid, ranges):
    return any(lo <= rid <= hi for lo, hi in ranges)


def _exc_json(): return os.path.join(_modsec_dir(), 'vortex-exceptions.json')


def _exc_conf(): return os.path.join(_modsec_dir(), 'vortex-exceptions.conf')


def _load_exceptions():
    if not os.path.exists(_exc_json()):
        return {}
    try:
        data = json.load(open(_exc_json()))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_exceptions(data):
    os.makedirs(os.path.dirname(_exc_json()), exist_ok=True)
    with open(_exc_json(), 'w') as f:
        json.dump(data, f, indent=2)


def _valid_ip_or_cidr(v):
    try:
        _ipaddr.ip_network(v.strip(), strict=False)
        return True
    except ValueError:
        return False


def _valid_hostname(h):
    h = (h or '').strip().lower()
    if not h or len(h) > 253:
        return False
    return bool(re.fullmatch(
        r'(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)'
        r'(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*', h))


def _validate_exception(exc, force=False):
    """Validate + normalize ONE exception. Returns (ok, normalized_dict|error_str)."""
    url = (exc.get('url_prefix') or '').strip()
    if not url or not url.startswith('/'):
        return False, 'URL prefix must start with "/"'
    if url == '/':
        return False, 'A URL prefix of "/" disables the rule for the whole site — scope it to a real path'
    if len(url) > 512 or '\n' in url or '\r' in url:
        return False, 'URL prefix is invalid'

    methods = exc.get('methods') or []
    if not isinstance(methods, list):
        return False, 'methods must be a list'
    methods = [m.strip().upper() for m in methods if m and str(m).strip()]
    for m in methods:
        if m not in _HTTP_METHODS:
            return False, f'Unknown HTTP method: {m}'

    ips = exc.get('client_ips') or []
    if not isinstance(ips, list):
        return False, 'client_ips must be a list'
    ips = [i.strip() for i in ips if i and str(i).strip()]
    for i in ips:
        if not _valid_ip_or_cidr(i):
            return False, f'Invalid IP/CIDR: {i}'

    raw_ids = exc.get('rule_ids') or []
    if not isinstance(raw_ids, list) or not raw_ids:
        return False, 'At least one rule ID is required'
    rule_ids = []
    for r in raw_ids:
        try:
            rid = int(r)
        except (ValueError, TypeError):
            return False, f'Rule ID must be a number: {r}'
        if not (900000 <= rid <= 999999):
            return False, f'{rid} is not an OWASP CRS rule ID (expected 900000-999999)'
        if _rid_in_ranges(rid, _EXC_PROTECTED_RANGES):
            return False, f'Rule {rid} is a protected protocol-integrity rule and cannot be excepted'
        if _rid_in_ranges(rid, _EXC_ALWAYS_BLOCK_RANGES) and not force:
            return False, (f'Rule {rid} guards against SQLi/XSS. Excepting it needs an explicit '
                           f'override — resubmit with force=true if you are certain.')
        if rid not in rule_ids:
            rule_ids.append(rid)

    note = (exc.get('note') or '').strip()[:200]
    return True, {'url_prefix': url, 'methods': methods, 'client_ips': ips,
                  'rule_ids': rule_ids, 'note': note}


def _compile_exceptions_text(model):
    """PURE: turn the exceptions model into ModSecurity config text.

    IDs are assigned sequentially from the reserved range at compile time —
    they only need to be unique within this file (regenerated wholesale on
    every change), so positional assignment is safe.

    Chain semantics (important): a ModSecurity chain fires its actions only
    when EVERY link matches. Non-disruptive actions attached to the chain
    STARTER would run as soon as the starter matches, so the ctl:ruleRemoveById
    actions are attached to the LAST link instead — they then execute only
    when the full (domain + path [+ method] [+ ip]) condition is met. Phase 1
    guarantees the removal lands before CRS evaluates in phase 2.
    """
    lines = ['# Auto-generated by VortexPanel WAF — DO NOT EDIT BY HAND.',
             '# Per-site engine mode + scoped rule exceptions. Regenerated in full on every change.']
    site_id = _EXC_SITEMODE_BASE
    exc_id  = _EXC_RULE_BASE
    for domain in sorted(model.keys()):
        if not _valid_hostname(domain):
            continue
        entry = model[domain] or {}
        dom = _modsec_str_escape(domain)

        mode = (entry.get('site_mode') or 'enforce').lower()
        if mode in ('detect', 'off'):
            site_id += 1
            ctl = 'ctl:ruleEngine=DetectionOnly' if mode == 'detect' else 'ctl:ruleEngine=Off'
            lines.append(f'# {domain}: site engine mode = {mode}')
            lines.append(f'SecRule SERVER_NAME "@streq {dom}" '
                         f'"id:{site_id},phase:1,pass,nolog,{ctl}"')

        for exc in entry.get('exceptions', []):
            ok, norm = _validate_exception(exc, force=True)  # stored entries were validated on write
            if not ok:
                continue
            exc_id += 1
            ctls = ','.join(f'ctl:ruleRemoveById={rid}' for rid in norm['rule_ids'])
            links = [('SERVER_NAME', f'@streq {dom}'),
                     ('REQUEST_FILENAME', f'@beginsWith {_modsec_str_escape(norm["url_prefix"])}')]
            if norm['methods']:
                links.append(('REQUEST_METHOD', '@rx ^(' + '|'.join(norm['methods']) + ')$'))
            if norm['client_ips']:
                ipm = ','.join(_modsec_str_escape(i) for i in norm['client_ips'])
                links.append(('REMOTE_ADDR', f'@ipMatch {ipm}'))

            lines.append(f'# {domain}: skip {norm["rule_ids"]} on {norm["url_prefix"]}'
                         + (f' ({norm["note"]})' if norm['note'] else ''))
            n = len(links)
            for idx, (var, op) in enumerate(links):
                if idx == 0:
                    action = f'id:{exc_id},phase:1,pass,nolog' + (f',{ctls}' if n == 1 else ',chain')
                    lines.append(f'SecRule {var} "{op}" "{action}"')
                elif idx == n - 1:
                    lines.append(f'    SecRule {var} "{op}" "{ctls}"')
                else:
                    lines.append(f'    SecRule {var} "{op}" "chain"')
    return '\n'.join(lines) + '\n'


def _ensure_exceptions_included():
    """Wire vortex-exceptions.conf into main.conf after modsecurity.conf and
    before the CRS rules, so ctl:ruleRemoveById lands in phase 1 before CRS.
    Idempotent. Apache auto-includes /etc/modsecurity/*.conf, so (like
    vortex-lists.conf) it must NOT be explicitly included there or the rule
    IDs load twice and Apache refuses to start."""
    if _modsec_target() == 'apache':
        return
    if not os.path.exists(_modsec_main()):
        return
    main = open(_modsec_main()).read()
    include_line = f'Include {_exc_conf()}'
    if include_line in main:
        return
    base_include = f'Include {_modsec_conf()}'
    if base_include in main:
        main = main.replace(base_include, f'{base_include}\n{include_line}', 1)
    else:
        main = f'{include_line}\n{main}'
    with open(_modsec_main(), 'w') as f:
        f.write(main)


def _write_exceptions(model):
    """Compile → write conf → wire include → config-test → reload, on EVERY
    web server present on this box. nginx/Apache share one generated file
    (via _modsec_dir); Caddy gets the same text mirrored through Coraza. Each
    engine validates and rolls back independently, so a bad edit can never
    take any server down, and a Caddy-only box (no ModSecurity target) is
    handled by simply skipping the nginx/Apache half. Returns (ok, error)."""
    modsec_ok, modsec_err = True, ''
    if _modsec_target() is not None:
        os.makedirs(_modsec_dir(), exist_ok=True)
        conf_path = _exc_conf()
        prev = open(conf_path).read() if os.path.exists(conf_path) else None
        with open(conf_path, 'w') as f:
            f.write(_compile_exceptions_text(model))
        _ensure_exceptions_included()
        modsec_ok, modsec_err = _modsec_configtest()
        if not modsec_ok:
            if prev is not None:
                with open(conf_path, 'w') as f:
                    f.write(prev)
            else:
                try: os.unlink(conf_path)
                except Exception: pass
        else:
            _modsec_reload()
    caddy_ok, caddy_err = _coraza_sync()
    return _combine_engine_results(modsec_ok, modsec_err, caddy_ok, caddy_err)


def _combine_engine_results(modsec_ok, modsec_err, caddy_ok, caddy_err):
    """Fail if any PRESENT engine failed; name which one so the user can tell
    an nginx problem from a Caddy one. Because every engine regenerates
    wholesale from the stored model on every change, a one-engine failure is
    self-healing on the next successful save rather than permanent drift."""
    if not modsec_ok:
        return False, f'nginx/Apache: {modsec_err}'
    if not caddy_ok:
        return False, f'Caddy/Coraza: {caddy_err}'
    return True, ''


@security_bp.route('/api/security/waf/exceptions')
def waf_exceptions_list():
    if not req(): return jsonify({'ok': False}), 401
    model  = _load_exceptions()
    domain = request.args.get('domain', '').strip().lower()
    if domain:
        entry = model.get(domain, {})
        return jsonify({'ok': True, 'domain': domain,
                        'site_mode': entry.get('site_mode', 'enforce'),
                        'exceptions': entry.get('exceptions', [])})
    return jsonify({'ok': True, 'sites': model})


@security_bp.route('/api/security/waf/exceptions', methods=['POST'])
def waf_exceptions_add():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    domain = (d.get('domain') or '').strip().lower()
    if not _valid_hostname(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    ok, norm = _validate_exception(d, force=bool(d.get('force')))
    if not ok:
        return jsonify({'ok': False, 'error': norm}), 400
    import secrets as _secrets
    norm['id'] = 'exc_' + _secrets.token_hex(4)
    norm['note'] = norm.get('note', '')
    model = _load_exceptions()
    entry = model.setdefault(domain, {'site_mode': 'enforce', 'exceptions': []})
    entry.setdefault('exceptions', []).append(norm)
    saved_ok, err = _write_exceptions(model)
    if not saved_ok:
        return jsonify({'ok': False, 'error': f'WAF config test failed, change reverted: {err}'}), 400
    _save_exceptions(model)
    return jsonify({'ok': True, 'exception': norm})


@security_bp.route('/api/security/waf/exceptions/<exc_id>', methods=['DELETE'])
def waf_exceptions_delete(exc_id):
    if not req(): return jsonify({'ok': False}), 401
    domain = (request.args.get('domain') or '').strip().lower()
    model  = _load_exceptions()
    removed = False
    domains = [domain] if domain else list(model.keys())
    for dom in domains:
        entry = model.get(dom, {})
        before = entry.get('exceptions', [])
        after  = [e for e in before if e.get('id') != exc_id]
        if len(after) != len(before):
            entry['exceptions'] = after
            removed = True
    if not removed:
        return jsonify({'ok': False, 'error': 'Exception not found'}), 404
    saved_ok, err = _write_exceptions(model)
    if not saved_ok:
        return jsonify({'ok': False, 'error': f'WAF config test failed, change reverted: {err}'}), 400
    _save_exceptions(model)
    return jsonify({'ok': True})


@security_bp.route('/api/security/waf/site-mode', methods=['POST'])
def waf_site_mode():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    domain = (d.get('domain') or '').strip().lower()
    mode   = (d.get('mode') or '').strip().lower()
    if not _valid_hostname(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    if mode not in ('enforce', 'detect', 'off'):
        return jsonify({'ok': False, 'error': 'mode must be enforce, detect, or off'}), 400
    model = _load_exceptions()
    entry = model.setdefault(domain, {'site_mode': 'enforce', 'exceptions': []})
    entry['site_mode'] = mode
    saved_ok, err = _write_exceptions(model)
    if not saved_ok:
        return jsonify({'ok': False, 'error': f'WAF config test failed, change reverted: {err}'}), 400
    _save_exceptions(model)
    return jsonify({'ok': True, 'domain': domain, 'mode': mode})


@security_bp.route('/api/security/waf/rule-catalog')
def waf_rule_catalog():
    """CRS category ranges + which are protected / always-block, so the UI can
    label and grey-out rules in the exception picker. Also does a best-effort
    scan of the installed CRS rules for id -> msg descriptions."""
    if not req(): return jsonify({'ok': False}), 401
    categories = [{'from': lo, 'to': hi, 'name': name} for lo, hi, name in CRS_CATEGORY_RANGES]
    rules = {}
    rules_dir = f'{_modsec_crs_dir()}/rules'
    if os.path.isdir(rules_dir):
        out, _, _ = sh(f'grep -rhoE "id:[0-9]{{6}}[^\\"]*msg:\'[^\']+\'" {rules_dir} 2>/dev/null | head -500')
        for line in (out or '').split('\n'):
            m = re.search(r"id:(\d{6}).*?msg:'([^']+)'", line)
            if m:
                rules.setdefault(m.group(1), m.group(2)[:120])
    return jsonify({'ok': True, 'categories': categories, 'rules': rules,
                    'protected': [{'from': lo, 'to': hi} for lo, hi in _EXC_PROTECTED_RANGES],
                    'always_block': [{'from': lo, 'to': hi} for lo, hi in _EXC_ALWAYS_BLOCK_RANGES]})


@security_bp.route('/api/security/waf/recent-hits')
def waf_recent_hits():
    """Recent WAF interceptions from the audit log, to power 'Add exception
    from this hit'. Each hit carries the exact rule_id that fired + its path."""
    if not req(): return jsonify({'ok': False}), 401
    domain = (request.args.get('domain') or '').strip().lower()
    if not os.path.exists(_modsec_audit()):
        return jsonify({'ok': True, 'hits': [], 'exists': False})
    out, _, _ = sh(f'tail -n 400 "{_modsec_audit()}" 2>/dev/null')
    entries = _parse_modsec_entries(out)
    hits, seen = [], set()
    for e in reversed(entries):
        rid = e.get('rule_id')
        if not rid:
            continue
        dom = (e.get('domain') or '').split(':')[0].lower()
        if domain and dom != domain:
            continue
        key = (dom, e.get('uri'), e.get('method'), rid)
        if key in seen:
            continue
        seen.add(key)
        hits.append({'domain': dom, 'uri': e.get('uri', ''), 'method': e.get('method', ''),
                     'rule_id': rid, 'category': _categorize_rule(rid),
                     'message': e.get('message', ''), 'ip': e.get('ip', ''),
                     'timestamp': e.get('timestamp', '')})
        if len(hits) >= 50:
            break
    return jsonify({'ok': True, 'hits': hits, 'exists': True})


def _geo_json():  return os.path.join(_modsec_dir(), 'vortex-geo.json')


def _geo_conf():  return os.path.join(_modsec_dir(), 'vortex-geo.conf')


def _custom_json():return os.path.join(_modsec_dir(), 'vortex-custom.json')


def _custom_conf():return os.path.join(_modsec_dir(), 'vortex-custom.conf')


def _load_json_file(path, default):
    if not os.path.exists(path): return default
    try:
        d = json.load(open(path)); return d if isinstance(d, type(default)) else default
    except Exception: return default


def _geo_db_present():
    for p in ('/usr/share/GeoIP/GeoLite2-Country.mmdb', '/etc/nginx/modsec/GeoLite2-Country.mmdb',
              '/usr/share/GeoIP/GeoIP.dat'):
        if os.path.exists(p): return p
    return ''


def _validate_geo(rule):
    cc = (rule.get('country') or '').strip().upper()
    if not _ISO2_RE.match(cc):
        return False, 'country must be a 2-letter ISO code (e.g. CN, RU)'
    action = (rule.get('action') or 'block').lower()
    if action not in ('block', 'allow'):
        return False, 'action must be block or allow'
    status = str(rule.get('status') or '403')
    if status not in _WAF_STATUS_CODES:
        return False, f'status must be one of {sorted(_WAF_STATUS_CODES)}'
    return True, {'country': cc, 'action': action, 'status': status,
                  'note': (rule.get('note') or '').strip()[:120]}


def _compile_geo_text(rules):
    lines = ['# Auto-generated by VortexPanel WAF (Region). DO NOT EDIT.']
    db = _geo_db_present()
    if db:
        lines.append(f'SecGeoLookupDb {db}')
    else:
        lines.append('# WARNING: no GeoIP database found — region rules will not match until one is installed.')
    rid = _GEO_ID_BASE
    for r in rules:
        ok, n = _validate_geo(r)
        if not ok: continue
        rid += 1
        if n['action'] == 'allow':
            act = 'pass,nolog,ctl:ruleEngine=Off'
        else:
            act = f"deny,status:{n['status']},log,msg:'VortexPanel Region block {n['country']}'"
        lines.append(f'# {n["country"]}: {n["action"]}' + (f' ({n["note"]})' if n['note'] else ''))
        lines.append(f'SecRule REMOTE_ADDR "@geoLookup" "id:{rid},phase:1,pass,nolog,chain"')
        lines.append(f'    SecRule GEO:COUNTRY_CODE "@streq {n["country"]}" "{act}"')
    return '\n'.join(lines) + '\n'


def _validate_custom(rule):
    name = (rule.get('name') or '').strip()[:60]
    if not name:
        return False, 'name required'
    conds = rule.get('conditions') or []
    if not isinstance(conds, list) or not conds:
        return False, 'at least one condition required'
    norm_conds = []
    for c in conds:
        f = (c.get('field') or '').lower()
        if f not in _CUSTOM_FIELDS:
            return False, f'unknown field: {f}'
        val = (c.get('value') or '').strip()
        if not val or '\n' in val or '\r' in val or len(val) > 512:
            return False, f'invalid value for {f}'
        if f == 'ip' and not all(_valid_ip_or_cidr(x) for x in val.split(',')):
            return False, f'invalid IP/CIDR in condition: {val}'
        if f == 'method' and val.upper() not in _HTTP_METHODS:
            return False, f'invalid method: {val}'
        if f == 'country' and not _ISO2_RE.match(val.upper()):
            return False, f'invalid country code: {val}'
        norm_conds.append({'field': f, 'value': val.upper() if f in ('method', 'country') else val})
    action = (rule.get('action') or 'block').lower()
    if action not in ('block', 'allow'):
        return False, 'action must be block or allow'
    status = str(rule.get('status') or '403')
    if status not in _WAF_STATUS_CODES:
        return False, 'invalid status code'
    domain = (rule.get('domain') or '').strip().lower()
    if domain and not _valid_hostname(domain):
        return False, 'invalid domain'
    return True, {'name': name, 'conditions': norm_conds, 'action': action,
                  'status': status, 'domain': domain, 'enabled': rule.get('enabled', True)}


def _compile_custom_text(rules):
    lines = ['# Auto-generated by VortexPanel WAF (Custom Rules). DO NOT EDIT.']
    rid = _CUSTOM_ID_BASE
    needs_geo = any(c['field'] == 'country' for r in rules for c in (r.get('conditions') or []))
    db = _geo_db_present()
    if needs_geo and db:
        lines.append(f'SecGeoLookupDb {db}')
    for r in rules:
        ok, n = _validate_custom(r)
        if not ok or not n.get('enabled', True):
            continue
        rid += 1
        links = []
        if n['domain']:
            links.append(('SERVER_NAME', f'@streq {_modsec_str_escape(n["domain"])}'))
        # geoLookup must precede any GEO:COUNTRY_CODE check
        if any(c['field'] == 'country' for c in n['conditions']):
            links.append(('REMOTE_ADDR', '@geoLookup'))
        for c in n['conditions']:
            var, op = _CUSTOM_FIELDS[c['field']]
            val = _modsec_str_escape(c['value'])
            links.append((var, f'@{op} {val}'))
        if n['action'] == 'allow':
            act = 'pass,nolog,ctl:ruleEngine=Off'
        else:
            act = f"deny,status:{n['status']},log,msg:'VortexPanel Custom: {_modsec_str_escape(n['name'])}'"
        lines.append(f'# custom rule: {n["name"]} -> {n["action"]}')
        m = len(links)
        for idx, (var, op) in enumerate(links):
            if idx == 0:
                # single condition → action goes on this line; multi → starter chains
                a = f'id:{rid},phase:1,{act}' if m == 1 else f'id:{rid},phase:1,pass,nolog,chain'
                lines.append(f'SecRule {var} "{op}" "{a}"')
            elif idx == m - 1:
                lines.append(f'    SecRule {var} "{op}" "{act}"')
            else:
                lines.append(f'    SecRule {var} "{op}" "chain"')
    return '\n'.join(lines) + '\n'


def _wire_extra_include(conf_path):
    """Include an extra vortex conf into main.conf (nginx only; Apache
    auto-includes /etc/modsecurity/*.conf). Idempotent."""
    if _modsec_target() == 'apache' or not os.path.exists(_modsec_main()):
        return
    main = open(_modsec_main()).read()
    line = f'Include {conf_path}'
    if line in main:
        return
    base = f'Include {_modsec_conf()}'
    main = main.replace(base, f'{base}\n{line}', 1) if base in main else f'{line}\n{main}'
    with open(_modsec_main(), 'w') as f:
        f.write(main)


def _write_generated(conf_path, text):
    """Write a generated conf (geo/custom) to nginx/Apache if present, then
    mirror the whole model to Caddy/Coraza. Each engine configtests and rolls
    back on its own. A Caddy-only box skips the nginx/Apache half."""
    modsec_ok, modsec_err = True, ''
    if _modsec_target() is not None:
        os.makedirs(_modsec_dir(), exist_ok=True)
        prev = open(conf_path).read() if os.path.exists(conf_path) else None
        with open(conf_path, 'w') as f:
            f.write(text)
        _wire_extra_include(conf_path)
        modsec_ok, modsec_err = _modsec_configtest()
        if not modsec_ok:
            if prev is not None: open(conf_path, 'w').write(prev)
            else:
                try: os.unlink(conf_path)
                except Exception: pass
        else:
            _modsec_reload()
    caddy_ok, caddy_err = _coraza_sync()
    return _combine_engine_results(modsec_ok, modsec_err, caddy_ok, caddy_err)


@security_bp.route('/api/security/waf/geo', methods=['GET', 'POST'])
def waf_geo():
    if not req(): return jsonify({'ok': False}), 401
    rules = _load_json_file(_geo_json(), [])
    if request.method == 'GET':
        return jsonify({'ok': True, 'rules': rules, 'geoip_installed': bool(_geo_db_present())})
    ok, n = _validate_geo(request.get_json() or {})
    if not ok: return jsonify({'ok': False, 'error': n}), 400
    rules = [r for r in rules if (r.get('country') or '').upper() != n['country']]  # replace dup
    rules.append(n)
    saved, err = _write_generated(_geo_conf(), _compile_geo_text(rules))
    if not saved: return jsonify({'ok': False, 'error': f'config test failed, reverted: {err}'}), 400
    json.dump(rules, open(_geo_json(), 'w'), indent=2)
    return jsonify({'ok': True, 'rules': rules})


@security_bp.route('/api/security/waf/geo/<code>', methods=['DELETE'])
def waf_geo_delete(code):
    if not req(): return jsonify({'ok': False}), 401
    code = code.strip().upper()
    rules = [r for r in _load_json_file(_geo_json(), []) if (r.get('country') or '').upper() != code]
    saved, err = _write_generated(_geo_conf(), _compile_geo_text(rules))
    if not saved: return jsonify({'ok': False, 'error': err}), 400
    json.dump(rules, open(_geo_json(), 'w'), indent=2)
    return jsonify({'ok': True, 'rules': rules})


@security_bp.route('/api/security/waf/custom-rules-builder', methods=['GET', 'POST'])
def waf_custom_builder():
    if not req(): return jsonify({'ok': False}), 401
    rules = _load_json_file(_custom_json(), [])
    if request.method == 'GET':
        return jsonify({'ok': True, 'rules': rules})
    ok, n = _validate_custom(request.get_json() or {})
    if not ok: return jsonify({'ok': False, 'error': n}), 400
    import secrets as _s
    n['id'] = 'cr_' + _s.token_hex(4)
    rules.append(n)
    saved, err = _write_generated(_custom_conf(), _compile_custom_text(rules))
    if not saved: return jsonify({'ok': False, 'error': f'config test failed, reverted: {err}'}), 400
    json.dump(rules, open(_custom_json(), 'w'), indent=2)
    return jsonify({'ok': True, 'rule': n})


@security_bp.route('/api/security/waf/custom-rules-builder/<rid>', methods=['DELETE'])
def waf_custom_delete(rid):
    if not req(): return jsonify({'ok': False}), 401
    rules = [r for r in _load_json_file(_custom_json(), []) if r.get('id') != rid]
    saved, err = _write_generated(_custom_conf(), _compile_custom_text(rules))
    if not saved: return jsonify({'ok': False, 'error': err}), 400
    json.dump(rules, open(_custom_json(), 'w'), indent=2)
    return jsonify({'ok': True})


@security_bp.route('/api/security/waf/lists/export')
def waf_lists_export():
    if not req(): return jsonify({'ok': False}), 401
    return jsonify({'ok': True, 'lists': _load_lists()})


@security_bp.route('/api/security/waf/lists/import', methods=['POST'])
def waf_lists_import():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    incoming = d.get('lists') or {}
    mode = d.get('mode', 'merge')
    cur = _load_lists()
    for k in ('ip_whitelist', 'ip_blacklist', 'ua_blacklist', 'url_blacklist'):
        vals = [str(x).strip() for x in (incoming.get(k) or []) if str(x).strip()]
        if mode == 'replace':
            cur[k] = vals
        else:
            cur[k] = sorted(set((cur.get(k) or []) + vals))
    _save_lists_json(cur)
    modsec_ok, modsec_err = True, ''
    if _modsec_target() is not None:
        conf_path = _modsec_lists_conf()
        prev = open(conf_path).read() if os.path.exists(conf_path) else None
        open(conf_path, 'w').write(_render_lists_conf(cur))
        _ensure_lists_included()
        modsec_ok, modsec_err = _modsec_configtest()
        if not modsec_ok:
            if prev is not None: open(conf_path, 'w').write(prev)
        else:
            _modsec_reload()
    caddy_ok, caddy_err = _coraza_sync()
    ok, err = _combine_engine_results(modsec_ok, modsec_err, caddy_ok, caddy_err)
    if not ok:
        return jsonify({'ok': False, 'error': f'config test failed, reverted: {err}'}), 400
    return jsonify({'ok': True, 'lists': cur})


def _ratelimit_json(): return os.path.join(_modsec_dir(), 'vortex-ratelimit.json')


def _validate_ratelimit(r):
    name = re.sub(r'[^a-zA-Z0-9_]', '', (r.get('name') or ''))[:32]
    if not name: return False, 'name required (letters/digits/underscore)'
    url = (r.get('url') or '/').strip()
    if not url.startswith('/'): return False, 'url must start with /'
    rps_raw = r.get('rps', 10)
    try: rps = int(rps_raw)
    except (ValueError, TypeError): return False, 'rps must be a number'
    if not (1 <= rps <= 100000): return False, 'rps out of range (1-100000)'
    burst_raw = r.get('burst')
    if burst_raw in (None, ''): burst_raw = rps * 2
    try: burst = int(burst_raw)
    except (ValueError, TypeError): return False, 'burst must be a number'
    if not (0 <= burst <= 1000000): return False, 'burst out of range'
    status = str(r.get('status') or '503')
    if status not in _WAF_STATUS_CODES: return False, 'invalid status'
    domain = (r.get('domain') or '').strip().lower()
    if domain and not _valid_hostname(domain): return False, 'invalid domain'
    return True, {'name': name, 'url': url, 'rps': rps, 'burst': burst, 'status': status,
                  'domain': domain}


def _compile_ratelimit_zones(rules):
    """Generate the http-context limit_req_zone directives (safe in conf.d)."""
    lines = ['# Auto-generated by VortexPanel WAF (Rate Limit). DO NOT EDIT.',
             'limit_req_status 503;']
    seen = set()
    for r in rules:
        ok, n = _validate_ratelimit(r)
        if not ok or n['name'] in seen: continue
        seen.add(n['name'])
        lines.append(f'limit_req_zone $binary_remote_addr zone=vortex_{n["name"]}:10m rate={n["rps"]}r/s;')
    return '\n'.join(lines) + '\n'


def _ratelimit_location_snippet(n):
    """The limit_req line a site's matching location block should carry."""
    return f'limit_req zone=vortex_{n["name"]} burst={n["burst"]} nodelay;'


@security_bp.route('/api/security/waf/ratelimit', methods=['GET', 'POST'])
def waf_ratelimit():
    if not req(): return jsonify({'ok': False}), 401
    rules = _load_json_file(_ratelimit_json(), [])
    if request.method == 'GET':
        return jsonify({'ok': True, 'rules': rules})
    ok, n = _validate_ratelimit(request.get_json() or {})
    if not ok: return jsonify({'ok': False, 'error': n}), 400
    import secrets as _s
    n['id'] = 'rl_' + _s.token_hex(4)
    n['snippet'] = _ratelimit_location_snippet(n)
    rules = [r for r in rules if r.get('name') != n['name']] + [n]
    prev = open(_RATELIMIT_CONF).read() if os.path.exists(_RATELIMIT_CONF) else None
    os.makedirs('/etc/nginx/conf.d', exist_ok=True)
    open(_RATELIMIT_CONF, 'w').write(_compile_ratelimit_zones(rules))
    out, _, rc = sh('nginx -t 2>&1')
    if rc != 0:
        if prev is not None: open(_RATELIMIT_CONF, 'w').write(prev)
        else:
            try: os.unlink(_RATELIMIT_CONF)
            except Exception: pass
        return jsonify({'ok': False, 'error': f'nginx config test failed, reverted: {out}'}), 400
    sh('systemctl reload nginx 2>/dev/null')
    os.makedirs(_modsec_dir(), exist_ok=True)
    json.dump(rules, open(_ratelimit_json(), 'w'), indent=2)
    return jsonify({'ok': True, 'rules': rules})


@security_bp.route('/api/security/waf/ratelimit/<rid>', methods=['DELETE'])
def waf_ratelimit_delete(rid):
    if not req(): return jsonify({'ok': False}), 401
    rules = [r for r in _load_json_file(_ratelimit_json(), []) if r.get('id') != rid]
    if os.path.exists(_RATELIMIT_CONF):
        open(_RATELIMIT_CONF, 'w').write(_compile_ratelimit_zones(rules))
        sh('nginx -t 2>&1 && systemctl reload nginx 2>/dev/null')
    json.dump(rules, open(_ratelimit_json(), 'w'), indent=2)
    return jsonify({'ok': True, 'rules': rules})


def _aggregate_waf(entries):
    """PURE: turn parsed ModSecurity entries into dashboard aggregates."""
    from collections import Counter
    total = len(entries)
    by_ip, by_uri, by_cat, by_country, by_hour = Counter(), Counter(), Counter(), Counter(), Counter()
    for e in entries:
        ip = e.get('ip')
        if ip: by_ip[ip] += 1
        if e.get('uri'): by_uri[e['uri'][:120]] += 1
        by_cat[_categorize_rule(e.get('rule_id'))] += 1
        dt = _entry_datetime(e)
        if dt: by_hour[dt.strftime('%H')] += 1
    timeline = [{'hour': f'{h:02d}', 'count': by_hour.get(f'{h:02d}', 0)} for h in range(24)]
    return {
        'malicious': total,
        'top_attackers': [{'ip': ip, 'count': c} for ip, c in by_ip.most_common(15)],
        'top_uris':      [{'uri': u, 'count': c} for u, c in by_uri.most_common(10)],
        'categories':    [{'name': n, 'count': c} for n, c in by_cat.most_common()],
        'timeline':      timeline,
    }


@security_bp.route('/api/security/waf/overview')
def waf_overview():
    if not req(): return jsonify({'ok': False}), 401
    if not os.path.exists(_modsec_audit()):
        return jsonify({'ok': True, 'exists': False, 'malicious': 0, 'top_attackers': [],
                        'top_uris': [], 'categories': [], 'timeline': [], 'engine': _engine_state()})
    out, _, _ = sh(f'tail -n 2000 "{_modsec_audit()}" 2>/dev/null')
    agg = _aggregate_waf(_parse_modsec_entries(out))
    agg.update({'ok': True, 'exists': True, 'engine': _engine_state(),
                'paranoia': _paranoia_level() if _modsec_installed() else 0,
                'geoip_installed': bool(_geo_db_present())})
    return jsonify(agg)


def _coraza_conf_paths():
    """The four generated SecLang files Caddy's Coraza directives Include.
    Same content as the nginx/Apache copies — regenerated from the same model."""
    return {
        'lists':      os.path.join(CORAZA_DIR, 'vortex-lists.conf'),
        'geo':        os.path.join(CORAZA_DIR, 'vortex-geo.conf'),
        'custom':     os.path.join(CORAZA_DIR, 'vortex-custom.conf'),
        'exceptions': os.path.join(CORAZA_DIR, 'vortex-exceptions.conf'),
    }


def _coraza_present():
    """True only when a Caddy binary that genuinely loads coraza_waf is the
    running binary. The marker is written by the App Store build after it has
    validated the module against the new binary, so this is authoritative even
    though `caddy list-modules` cannot distinguish coraza from the old
    caddy-waf (both are http.handlers.waf)."""
    if not os.path.exists(CORAZA_MARKER):
        return False
    out, _, _ = sh('caddy list-modules 2>/dev/null')
    return 'http.handlers.waf' in out


def _coraza_directives_block():
    """The per-site coraza_waf block, identical for every site — per-site
    behaviour is already baked into the rules (keyed on SERVER_NAME), so the
    wiring never has to differ between sites. CRS itself is loaded from
    Coraza's own embedded copy via load_owasp_crs; only the VortexPanel files
    are Included from disk. Order mirrors the nginx/Apache main.conf exactly:
    lists (whitelist ruleEngine=Off first) → region/custom → exceptions
    (ctl:ruleRemoveById in phase 1) → CRS setup → CRS rules → engine on."""
    p = _coraza_conf_paths()
    return (
        '    coraza_waf {\n'
        '        load_owasp_crs\n'
        '        directives `\n'
        '        Include @coraza.conf-recommended\n'
        f'        Include {p["lists"]}\n'
        f'        Include {p["geo"]}\n'
        f'        Include {p["custom"]}\n'
        f'        Include {p["exceptions"]}\n'
        '        Include @crs-setup.conf.example\n'
        '        Include @owasp_crs/*.conf\n'
        '        SecRuleEngine On\n'
        '        `\n'
        '    }\n'
    )


def _coraza_compile_all():
    """PURE-ish: build the four files' text from the CURRENT stored model,
    reusing the exact same compile functions the nginx/Apache path uses. No
    rule logic lives here — this is only which model feeds which file."""
    return {
        'lists':      _render_lists_conf(_load_lists()),
        'geo':        _compile_geo_text(_load_json_file(_geo_json(), [])),
        'custom':     _compile_custom_text(_load_json_file(_custom_json(), [])),
        'exceptions': _compile_exceptions_text(_load_exceptions()),
    }


def _caddy_configtest():
    """Validate the whole Caddyfile against the running binary. Returns (ok, out)."""
    if not os.path.exists(CADDYFILE):
        return True, ''   # nothing to break yet
    out, err, rc = sh(f'caddy validate --config {CADDYFILE} --adapter caddyfile 2>&1')
    blob = (out or '') + (err or '')
    ok = rc == 0 and 'error' not in blob.lower() and 'invalid' not in blob.lower()
    return ok, blob


def _coraza_sync():
    """Regenerate every Caddy WAF file from the shared model, validate, and
    reload — rolling every file back on a failed validate so a bad change can
    never take Caddy's sites down. No-op (success) when Coraza isn't installed,
    so callers can invoke it unconditionally. Returns (ok, error)."""
    if not _coraza_present():
        return True, ''
    os.makedirs(CORAZA_DIR, exist_ok=True)
    paths   = _coraza_conf_paths()
    text    = _coraza_compile_all()
    backups = {}
    for key, path in paths.items():
        backups[path] = open(path).read() if os.path.exists(path) else None
        with open(path, 'w') as f:
            f.write(text[key])
    ok, out = _caddy_configtest()
    if not ok:
        for path, prev in backups.items():
            if prev is not None:
                with open(path, 'w') as f:
                    f.write(prev)
            else:
                try: os.unlink(path)
                except Exception: pass
        return False, out
    sh('systemctl reload caddy 2>/dev/null')
    return True, ''


def _split_caddy_block(content):
    """Split at the FIRST '{' and its real matching '}' via brace counting —
    the same discipline websites_core._split_site_block uses, kept local so
    this module has no import cycle. Returns (header, inner, trailing) or
    (None, None, None)."""
    start = content.find('{')
    if start == -1:
        return None, None, None
    depth = 0
    for i in range(start, len(content)):
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
            if depth == 0:
                return content[:start+1], content[start+1:i], content[i:]
    return None, None, None


def _caddyfile_has_global_block(content):
    """True if the file opens with a global options block (a bare '{' before
    any site address), rather than a site block (address then '{')."""
    stripped = re.sub(r'(?m)^\s*#.*$', '', content).strip()
    return stripped.startswith('{')


def _ensure_coraza_global_order(content):
    """PURE: guarantee `order coraza_waf first` is present in the global
    options block, adding the block if the Caddyfile has none. Idempotent."""
    if re.search(r'order\s+coraza_waf\s+first', content):
        return content
    if _caddyfile_has_global_block(content):
        header, inner, trailing = _split_caddy_block(content)
        if header is not None:
            return header + '\n    order coraza_waf first' + inner + trailing
    # No global block — prepend one.
    return '{\n    order coraza_waf first\n}\n\n' + content


def _site_has_coraza(content):
    return bool(re.search(r'\bcoraza_waf\s*\{', content))


def _wire_coraza_into_site(content):
    """PURE: insert the coraza_waf block as the first directive inside a Caddy
    site block. Returns (new_content, error). Idempotent — returns the content
    unchanged if the site already has a coraza_waf block."""
    if _site_has_coraza(content):
        return content, ''
    header, inner, trailing = _split_caddy_block(content)
    if header is None:
        return None, 'no balanced site block found'
    return header + '\n' + _coraza_directives_block() + inner + trailing, ''


def _unwire_coraza_from_site(content):
    """PURE: remove a coraza_waf { ... } block from a site config, brace-safe.
    Returns (new_content, changed)."""
    m = re.search(r'[ \t]*coraza_waf\s*\{', content)
    if not m:
        return content, False
    start = content.find('{', m.start())
    depth = 0
    for i in range(start, len(content)):
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
            if depth == 0:
                # swallow one trailing newline for tidiness
                end = i + 1
                if end < len(content) and content[end] == '\n':
                    end += 1
                return content[:m.start()] + content[end:], True
    return content, False


@security_bp.route('/api/security/waf/caddy/status')
def waf_caddy_status():
    """Whether Coraza is the live Caddy engine, which sites carry it, and
    whether Caddy's generated config currently matches the shared model."""
    if not req(): return jsonify({'ok': False}), 401
    present = _coraza_present()
    wired_sites = []
    if os.path.isdir(CADDY_SITES):
        for fn in os.listdir(CADDY_SITES):
            if not fn.endswith('.conf'): continue
            try:
                if _site_has_coraza(open(os.path.join(CADDY_SITES, fn)).read()):
                    wired_sites.append(fn[:-5])
            except Exception:
                pass
    in_sync = True
    if present:
        want = _coraza_compile_all()
        for key, path in _coraza_conf_paths().items():
            have = open(path).read() if os.path.exists(path) else ''
            if have != want[key]:
                in_sync = False
                break
    return jsonify({
        'ok': True, 'installed': present, 'engine': 'coraza',
        'wired_sites': wired_sites, 'in_sync': in_sync,
        'shares_model_with': ['nginx', 'apache'],
        'geoip_note': 'Region rules need a Coraza binary built with GeoIP support; '
                      'exceptions, per-site mode, custom rules and lists apply fully.',
    })


@security_bp.route('/api/security/waf/caddy/sync', methods=['POST'])
def waf_caddy_sync():
    """Regenerate Caddy's WAF config from the shared model on demand."""
    if not req(): return jsonify({'ok': False}), 401
    if not _coraza_present():
        return jsonify({'ok': False, 'error': 'Coraza engine is not installed — add it from the App Store (Security → Caddy WAF / Coraza).'}), 400
    ok, err = _coraza_sync()
    if not ok:
        return jsonify({'ok': False, 'error': f'Caddy config test failed, reverted: {err}'}), 400
    return jsonify({'ok': True})


@security_bp.route('/api/security/waf/caddy/site', methods=['POST'])
def waf_caddy_enable_site():
    """Turn the unified WAF on for one Caddy site: ensure the global order
    directive, wire the coraza_waf block in, sync config, validate, reload."""
    if not req(): return jsonify({'ok': False}), 401
    if not _coraza_present():
        return jsonify({'ok': False, 'error': 'Coraza engine is not installed.'}), 400
    domain = ((request.get_json() or {}).get('domain') or '').strip().lower()
    if not _valid_hostname(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    fp = os.path.join(CADDY_SITES, f'{domain}.conf')
    if not os.path.exists(fp):
        return jsonify({'ok': False, 'error': f'No Caddy site config found for {domain}'}), 404
    # Make sure the generated files exist before a site references them.
    ok, err = _coraza_sync()
    if not ok:
        return jsonify({'ok': False, 'error': f'Config sync failed, reverted: {err}'}), 400
    original = open(fp).read()
    new_site, werr = _wire_coraza_into_site(original)
    if new_site is None:
        return jsonify({'ok': False, 'error': werr}), 400
    prev_caddyfile = open(CADDYFILE).read() if os.path.exists(CADDYFILE) else None
    if prev_caddyfile is not None:
        with open(CADDYFILE, 'w') as f:
            f.write(_ensure_coraza_global_order(prev_caddyfile))
    with open(fp, 'w') as f:
        f.write(new_site)
    ok, out = _caddy_configtest()
    if not ok:
        with open(fp, 'w') as f:
            f.write(original)
        if prev_caddyfile is not None:
            with open(CADDYFILE, 'w') as f:
                f.write(prev_caddyfile)
        return jsonify({'ok': False, 'error': f'Caddy validation failed, reverted: {out}'}), 400
    sh('systemctl reload caddy 2>/dev/null')
    return jsonify({'ok': True, 'domain': domain})


@security_bp.route('/api/security/waf/caddy/site', methods=['DELETE'])
def waf_caddy_disable_site():
    if not req(): return jsonify({'ok': False}), 401
    domain = (request.args.get('domain') or '').strip().lower()
    if not _valid_hostname(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    fp = os.path.join(CADDY_SITES, f'{domain}.conf')
    if not os.path.exists(fp):
        return jsonify({'ok': False, 'error': f'No Caddy site config found for {domain}'}), 404
    original = open(fp).read()
    new_site, changed = _unwire_coraza_from_site(original)
    if not changed:
        return jsonify({'ok': True, 'message': 'Site was not running the unified WAF'})
    with open(fp, 'w') as f:
        f.write(new_site)
    ok, out = _caddy_configtest()
    if not ok:
        with open(fp, 'w') as f:
            f.write(original)
        return jsonify({'ok': False, 'error': f'Caddy validation failed, reverted: {out}'}), 400
    sh('systemctl reload caddy 2>/dev/null')
    return jsonify({'ok': True, 'domain': domain})