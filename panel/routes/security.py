from flask import Blueprint, jsonify, request, session
import subprocess, re, os

security_bp = Blueprint('security', __name__)
def req(): return 'user' in session
def sh(c, t=10):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except: return '', 'timeout', 1

# ── SSH ──────────────────────────────────────────────────────────────────────
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
    # Get current SSH port from ss
    port_out, _, _ = sh("ss -tlnp | grep sshd | awk '{print $4}' | grep -oP ':\\K[0-9]+'")
    if port_out: cfg['active_port'] = port_out.split('\n')[0]
    return jsonify({'ok':True, 'config':cfg})

@security_bp.route('/api/security/ssh', methods=['PUT'])
def save_ssh():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    sshd = '/etc/ssh/sshd_config'
    if not os.path.exists(sshd):
        return jsonify({'ok':False,'error':'sshd_config not found'}), 404
    with open(sshd) as f: content = f.read()

    def set_val(key, val, content):
        pattern = re.compile(rf'^#?\s*{key}\s+.*', re.MULTILINE|re.IGNORECASE)
        new_line = f'{key} {val}'
        if pattern.search(content): return pattern.sub(new_line, content)
        return content + f'\n{new_line}\n'

    if 'port' in d:           content = set_val('Port', d['port'], content)
    if 'password_auth' in d:  content = set_val('PasswordAuthentication', d['password_auth'], content)
    if 'root_login' in d:     content = set_val('PermitRootLogin', d['root_login'], content)
    if 'pubkey_auth' in d:    content = set_val('PubkeyAuthentication', d['pubkey_auth'], content)
    if 'max_auth_tries' in d: content = set_val('MaxAuthTries', d['max_auth_tries'], content)

    with open(sshd,'w') as f: f.write(content)
    sh('systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null')
    return jsonify({'ok':True})

# ── Fail2ban ─────────────────────────────────────────────────────────────────
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

# ── Login attempts ────────────────────────────────────────────────────────────
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

# ── Port scan / open ports ────────────────────────────────────────────────────
@security_bp.route('/api/security/ports')
def open_ports():
    if not req(): return jsonify({'ok':False}), 401
    out, _, _ = sh('ss -tlnp 2>/dev/null')
    return jsonify({'ok':True,'output':out})

# ── Two-Factor / basic security score ─────────────────────────────────────────
@security_bp.route('/api/security/score')
def security_score():
    if not req(): return jsonify({'ok':False}), 401
    checks = []

    # SSH root login
    sshd = '/etc/ssh/sshd_config'
    if os.path.exists(sshd):
        with open(sshd) as f: content = f.read()
        root_login = re.search(r'^PermitRootLogin\s+(\S+)', content, re.MULTILINE)
        val = root_login.group(1).lower() if root_login else 'yes'
        checks.append({'label':'SSH Root Login Disabled','pass': val in ('no','prohibit-password','forced-commands-only'),'severity':'high'})
        pw_auth = re.search(r'^PasswordAuthentication\s+(\S+)', content, re.MULTILINE)
        pval = pw_auth.group(1).lower() if pw_auth else 'yes'
        checks.append({'label':'SSH Password Auth Disabled','pass':pval=='no','severity':'medium'})
        port_m = re.search(r'^Port\s+(\d+)', content, re.MULTILINE)
        port = int(port_m.group(1)) if port_m else 22
        checks.append({'label':'SSH on Non-default Port','pass':port!=22,'severity':'low'})

    # Fail2ban running
    f2b, _, rc = sh('systemctl is-active fail2ban 2>/dev/null')
    checks.append({'label':'Fail2ban Running','pass':f2b.strip()=='active','severity':'high'})

    # UFW active
    ufw, _, _ = sh('ufw status 2>/dev/null | head -1')
    checks.append({'label':'Firewall (UFW) Active','pass':'active' in ufw.lower(),'severity':'high'})

    # Unattended upgrades
    out, _, rc = sh('dpkg -l unattended-upgrades 2>/dev/null | grep -c "^ii"')
    checks.append({'label':'Auto Security Updates Enabled','pass':out.strip()=='1','severity':'medium'})

    passed = sum(1 for c in checks if c['pass'])
    score  = round(passed / len(checks) * 100) if checks else 0
    return jsonify({'ok':True,'checks':checks,'score':score})

# ── ModSecurity ───────────────────────────────────────────────────────────────

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
    entries = []
    current = {}
    for line in out.split('\n'):
        # ModSecurity audit log section markers: --UUID-A-- through --UUID-Z--
        m = re.match(r'--[a-f0-9]+-([A-Z])--', line)
        if m:
            section = m.group(1)
            if section == 'A' and current:
                entries.append(current)
                current = {}
            if section == 'A':
                current = {'raw': line}
            elif section == 'B' and current:
                # Request line
                req_m = re.search(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)', line)
                if req_m:
                    current['method'] = req_m.group(1)
                    current['uri']    = req_m.group(2)
            elif section == 'H' and current:
                # Response / action
                msg_m = re.search(r'Message: (.+)', line)
                if msg_m: current['message'] = msg_m.group(1)[:200]
                id_m = re.search(r'\[id "(\d+)"\]', line)
                if id_m: current['rule_id'] = id_m.group(1)
                sev_m = re.search(r'\[severity "(\w+)"\]', line)
                if sev_m: current['severity'] = sev_m.group(1)
                ip_m = re.search(r'client (\d+\.\d+\.\d+\.\d+)', line)
                if ip_m: current['ip'] = ip_m.group(1)
        elif current and line:
            if 'timestamp' not in current:
                ts_m = re.search(r'\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})', line)
                if ts_m: current['timestamp'] = ts_m.group(1)
    if current: entries.append(current)
    entries = [e for e in entries if e.get('message') or e.get('uri')]
    entries.reverse()
    return jsonify({'ok':True,'entries':entries[-100:],'raw':out,'exists':True})


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

# ── Nginx Load Balancer ───────────────────────────────────────────────────────
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
    if not servers: return jsonify({'ok':False,'error':'At least one server required'}), 400

    # Build upstream block
    method_directive = ''
    if method == 'leastconn': method_directive = '    least_conn;\n'
    if method == 'iphash':    method_directive = '    ip_hash;\n'

    server_lines = '\n'.join([
        f"    server {s['address']} weight={s.get('weight',1)};"
        for s in servers if s.get('address')
    ])
    if not server_lines:
        return jsonify({'ok':False,'error':'At least one valid server address required'}), 400

    conf = f"""# VortexPanel Load Balancer — managed by VortexPanel
# Method: {method}
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
    return jsonify({'ok':True})

@security_bp.route('/api/security/loadbalancer', methods=['DELETE'])
def lb_delete():
    if not req(): return jsonify({'ok':False}), 401
    try: os.unlink(LB_CONF)
    except: pass
    sh('systemctl reload nginx 2>/dev/null')
    return jsonify({'ok':True})
