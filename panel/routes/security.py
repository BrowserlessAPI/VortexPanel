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
@security_bp.route('/api/security/modsecurity')
def modsec_status():
    if not req(): return jsonify({'ok':False}), 401
    conf = '/etc/nginx/modsec/modsecurity.conf'
    installed = os.path.exists(conf)
    enabled   = False
    if installed:
        with open(conf) as f: content = f.read()
        enabled = 'SecRuleEngine On' in content
    rules_out, _, _ = sh('find /etc/nginx/modsec/crs/rules/ -name "*.conf" 2>/dev/null | wc -l')
    try:
        rules_count = int(rules_out.strip() or 0)
    except (ValueError, AttributeError):
        rules_count = 0
    return jsonify({'ok':True,'installed':installed,'enabled':enabled,'rules':rules_count})

@security_bp.route('/api/security/modsecurity/toggle', methods=['POST'])
def modsec_toggle():
    if not req(): return jsonify({'ok':False}), 401
    enable = (request.get_json() or {}).get('enable', True)
    conf   = '/etc/nginx/modsec/modsecurity.conf'
    if not os.path.exists(conf):
        return jsonify({'ok':False,'error':'ModSecurity not installed'}), 404
    with open(conf) as f: content = f.read()
    if enable:
        content = content.replace('SecRuleEngine DetectionOnly','SecRuleEngine On')
        content = content.replace('SecRuleEngine Off','SecRuleEngine On')
    else:
        content = content.replace('SecRuleEngine On','SecRuleEngine DetectionOnly')
    with open(conf,'w') as f: f.write(content)
    sh('nginx -t && systemctl reload nginx 2>/dev/null')
    return jsonify({'ok':True,'enabled':enable})

# ── Nginx Load Balancer ───────────────────────────────────────────────────────
LB_CONF = '/etc/nginx/conf.d/loadbalancer.conf'

@security_bp.route('/api/security/loadbalancer')
def lb_status():
    if not req(): return jsonify({'ok':False}), 401
    if not os.path.exists(LB_CONF):
        return jsonify({'ok':True,'configured':False,'servers':[],'method':'roundrobin'})
    with open(LB_CONF) as f: content = f.read()
    # Parse upstream servers
    import re
    servers = re.findall(r'server\s+([^\s;]+)\s*(?:weight=(\d+))?', content)
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
        for s in servers
    ])

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
    import os
    os.makedirs('/etc/nginx/conf.d', exist_ok=True)
    with open(LB_CONF,'w') as f: f.write(conf)
    test_out, test_err, test_rc = sh('nginx -t 2>&1')
    test = (test_out + test_err)
    if test_rc != 0 or 'failed' in test.lower():
        return jsonify({'ok':False,'error':test}), 400
    sh('systemctl reload nginx 2>/dev/null')
    return jsonify({'ok':True})

@security_bp.route('/api/security/loadbalancer', methods=['DELETE'])
def lb_delete():
    if not req(): return jsonify({'ok':False}), 401
    import os
    try: os.unlink(LB_CONF)
    except: pass
    sh('systemctl reload nginx 2>/dev/null')
    return jsonify({'ok':True})
