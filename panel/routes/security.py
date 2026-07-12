from flask import Blueprint, jsonify, request, session
import subprocess, re, os
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
        'modsecurity': check('[ -f /etc/modsecurity/modsecurity.conf ]'),
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
        _, err, rc = sh(f'echo "{username}:{password}" | chpasswd 2>&1')
        if rc != 0:
            sh(f'userdel -r {username} 2>/dev/null')
            return jsonify({'ok':False,'error':f'Failed to set password: {err}'}), 500

    # Add to sudo/wheel group
    os_family = sh('. /etc/os-release 2>/dev/null && echo $ID_LIKE || echo debian')
    sudo_group = 'wheel' if 'rhel' in os_family or 'fedora' in os_family else 'sudo'
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

MODSEC_CONF     = '/etc/nginx/modsec/modsecurity.conf'
MODSEC_MAIN     = '/etc/nginx/modsec/main.conf'
MODSEC_CRS_DIR  = '/etc/nginx/modsec/crs'
MODSEC_CUSTOM   = '/etc/nginx/modsec/custom-rules.conf'
MODSEC_AUDIT    = '/var/log/modsec_audit.log'

def _modsec_installed():
    for p in [MODSEC_CONF,
              '/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3',
              '/usr/lib64/libmodsecurity.so.3',
              '/usr/lib/aarch64-linux-gnu/libmodsecurity.so.3']:
        if os.path.exists(p): return True
    return False

def _crs_version():
    """Read CRS version from the CHANGES file or setup.conf."""
    for path in [f'{MODSEC_CRS_DIR}/CHANGES.md',
                 f'{MODSEC_CRS_DIR}/CHANGES',
                 f'{MODSEC_CRS_DIR}/crs-setup.conf.example']:
        if not os.path.exists(path): continue
        try:
            for line in open(path):
                m = re.search(r'(\d+\.\d+\.\d+)', line)
                if m: return m.group(1)
        except: pass
    return 'unknown'

def _paranoia_level():
    """Read current paranoia level from crs-setup.conf."""
    setup = f'{MODSEC_CRS_DIR}/crs-setup.conf'
    if not os.path.exists(setup): return 1
    try:
        content = open(setup).read()
        m = re.search(r'tx\.paranoia_level=(\d)', content)
        return int(m.group(1)) if m else 1
    except: return 1

def _engine_state():
    """Return engine state: On / DetectionOnly / Off."""
    if not os.path.exists(MODSEC_CONF): return 'Off'
    content = open(MODSEC_CONF).read()
    if 'SecRuleEngine On' in content:             return 'On'
    if 'SecRuleEngine DetectionOnly' in content:  return 'DetectionOnly'
    return 'Off'

@security_bp.route('/api/security/modsecurity')
def modsec_status():
    if not req(): return jsonify({'ok':False}), 401
    installed = _modsec_installed()
    state     = _engine_state()
    rules_out, _, _ = sh('find /etc/nginx/modsec/crs/rules/ -name "*.conf" 2>/dev/null | wc -l')
    try:    rules_count = int(rules_out.strip() or 0)
    except: rules_count = 0

    # Custom rules
    custom_rules = ''
    if os.path.exists(MODSEC_CUSTOM):
        try: custom_rules = open(MODSEC_CUSTOM).read()
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
        'audit_log':     os.path.exists(MODSEC_AUDIT),
    })


@security_bp.route('/api/security/modsecurity/toggle', methods=['POST'])
def modsec_toggle():
    if not req(): return jsonify({'ok':False}), 401
    d      = request.get_json() or {}
    state  = d.get('state', 'On')     # 'On' | 'DetectionOnly' | 'Off'
    conf   = MODSEC_CONF
    if not os.path.exists(conf):
        return jsonify({'ok':False,'error':'ModSecurity not installed'}), 404
    content = open(conf).read()
    # Replace any existing state
    content = re.sub(r'SecRuleEngine\s+(On|DetectionOnly|Off)',
                     f'SecRuleEngine {state}', content)
    with open(conf,'w') as f: f.write(content)
    out, err, rc = sh('nginx -t 2>&1')
    if rc != 0:
        return jsonify({'ok':False,'error':f'nginx config error: {out}{err}'}), 400
    sh('systemctl reload nginx 2>/dev/null')
    return jsonify({'ok':True,'state':state})


@security_bp.route('/api/security/modsecurity/paranoia', methods=['POST'])
def modsec_paranoia():
    """Set OWASP CRS paranoia level (1–4)."""
    if not req(): return jsonify({'ok':False}), 401
    level = int((request.get_json() or {}).get('level', 1))
    level = max(1, min(4, level))
    setup = f'{MODSEC_CRS_DIR}/crs-setup.conf'
    if not os.path.exists(setup):
        return jsonify({'ok':False,'error':'CRS setup.conf not found'}), 404
    content = open(setup).read()
    # Replace or inject paranoia level
    if 'tx.paranoia_level' in content:
        content = re.sub(r'tx\.paranoia_level=\d', f'tx.paranoia_level={level}', content)
    else:
        content += f'\nSecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level={level}"\n'
    with open(setup,'w') as f: f.write(content)
    sh('nginx -t && systemctl reload nginx 2>/dev/null')
    return jsonify({'ok':True,'level':level})


@security_bp.route('/api/security/modsecurity/custom-rules', methods=['GET'])
def modsec_get_custom():
    if not req(): return jsonify({'ok':False}), 401
    content = ''
    if os.path.exists(MODSEC_CUSTOM):
        try: content = open(MODSEC_CUSTOM).read()
        except: pass
    return jsonify({'ok':True,'rules':content})


@security_bp.route('/api/security/modsecurity/custom-rules', methods=['POST'])
def modsec_save_custom():
    """Save custom SecRule directives."""
    if not req(): return jsonify({'ok':False}), 401
    rules = (request.get_json() or {}).get('rules', '')
    os.makedirs('/etc/nginx/modsec', exist_ok=True)
    with open(MODSEC_CUSTOM,'w') as f: f.write(rules)
    # Ensure it's included in main.conf
    if os.path.exists(MODSEC_MAIN):
        main = open(MODSEC_MAIN).read()
        include_line = f'Include {MODSEC_CUSTOM}'
        if include_line not in main:
            with open(MODSEC_MAIN,'a') as f: f.write(f'\n{include_line}\n')
    out, err, rc = sh('nginx -t 2>&1')
    if rc != 0:
        return jsonify({'ok':False,'error':f'Syntax error in rules: {out}{err}'}), 400
    sh('systemctl reload nginx 2>/dev/null')
    return jsonify({'ok':True})


@security_bp.route('/api/security/modsecurity/audit-log')
def modsec_audit_log():
    """Return last N lines of ModSecurity audit log."""
    if not req(): return jsonify({'ok':False}), 401
    lines = int(request.args.get('lines', 100))
    if not os.path.exists(MODSEC_AUDIT):
        return jsonify({'ok':True,'entries':[],'raw':'','exists':False})
    out, _, _ = sh(f'tail -n {min(lines, 500)} "{MODSEC_AUDIT}" 2>/dev/null')
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

    if not os.path.exists(MODSEC_AUDIT):
        return jsonify({'ok': True, 'exists': False, 'total': 0,
                         'categories': [], 'top_ips': [], 'top_uris': [], 'timeline': []})

    # Cap the read — a very busy site's audit log can be huge; this covers a
    # generous window of recent activity without loading the whole file.
    out, _, _ = sh(f'tail -n 20000 "{MODSEC_AUDIT}" 2>/dev/null', t=20)
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
    if not os.path.exists(MODSEC_AUDIT):
        return jsonify({'ok': True, 'entries': [], 'total': 0, 'exists': False})

    search   = (request.args.get('q') or '').strip().lower()
    page     = max(1, int(request.args.get('page', 1)))
    per_page = min(100, max(10, int(request.args.get('per_page', 20))))

    out, _, _ = sh(f'tail -n 20000 "{MODSEC_AUDIT}" 2>/dev/null', t=20)
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

    out, err, rc = sh(
        f'wget -q https://github.com/coreruleset/coreruleset/archive/refs/tags/{tag}.tar.gz'
        f' -O /tmp/crs_update.tar.gz && '
        f'mkdir -p {MODSEC_CRS_DIR}_backup && '
        f'cp -r {MODSEC_CRS_DIR}/crs-setup.conf {MODSEC_CRS_DIR}_backup/ 2>/dev/null || true && '
        f'tar -xzf /tmp/crs_update.tar.gz -C {MODSEC_CRS_DIR} --strip-components=1 && '
        f'cp {MODSEC_CRS_DIR}/crs-setup.conf.example {MODSEC_CRS_DIR}/crs-setup.conf 2>/dev/null || true && '
        f'cp {MODSEC_CRS_DIR}_backup/crs-setup.conf {MODSEC_CRS_DIR}/crs-setup.conf 2>/dev/null || true && '
        f'nginx -t && systemctl reload nginx 2>/dev/null',
        t=120
    )
    return jsonify({
        'ok': rc == 0,
        'version': ver,
        'output': (out + err)[-500:],
    })


@security_bp.route('/api/security/modsecurity/per-site', methods=['POST'])
def modsec_per_site():
    """Enable or disable ModSecurity for a specific site's nginx vhost."""
    if not req(): return jsonify({'ok':False}), 401
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
