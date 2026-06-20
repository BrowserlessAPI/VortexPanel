from flask import Blueprint, jsonify, request, session
import subprocess, os, json, re
from datetime import datetime

try:
    from panel.routes.os_utils import get_os, pkg_install, pkg_update, pkg_remove
except ImportError:
    try:
        from os_utils import get_os, pkg_install, pkg_update, pkg_remove
    except ImportError:
        def get_os(): return {'family':'debian','pkg':'apt'}
        def pkg_install(p): pass
        def pkg_update(): pass
        def pkg_remove(p): pass

settings_bp = Blueprint('settings', __name__)

def req(): return 'user' in session

def sh(cmd, t=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip()
    except: return ''

def sh3(cmd, t=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e: return '', str(e), 1

CONFIG_FILE  = '/opt/vortexpanel/config.json'
SSL_DIR      = '/opt/vortexpanel/ssl'
SSL_CONF     = '/etc/nginx/conf.d/vortexpanel-https.conf'
PANEL_PORT   = 8888

def load_config():
    if os.path.exists(CONFIG_FILE):
        try: return json.load(open(CONFIG_FILE))
        except: pass
    return {'panel_name':'VortexPanel','port':8888,'ssl_enabled':False,
            'auto_update':True,'timezone':'UTC','security_path':'',
            'panel_domain':''}

def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE,'w') as f: json.dump(cfg, f, indent=2)

# ── SSL helpers ───────────────────────────────────────────────────────────────
def _ssl_status():
    cert = os.path.join(SSL_DIR, 'panel.crt')
    key  = os.path.join(SSL_DIR, 'panel.key')
    if not os.path.exists(cert):
        return {'enabled': False, 'type': 'none'}
    # Read cert details
    out = sh(f'openssl x509 -in {cert} -noout -subject -issuer -enddate 2>/dev/null')
    cert_type = 'letsencrypt' if "Let's Encrypt" in out else 'self-signed'
    expiry_out = sh(f'openssl x509 -in {cert} -noout -enddate 2>/dev/null | cut -d= -f2')
    days_left = -1
    try:
        from datetime import timezone
        exp = datetime.strptime(expiry_out.strip(), '%b %d %H:%M:%S %Y %Z')
        days_left = (exp - datetime.utcnow()).days
    except: pass
    return {
        'enabled':   os.path.exists(SSL_CONF),
        'type':      cert_type,
        'expiry':    expiry_out.strip(),
        'days_left': days_left,
        'cert_path': cert,
        'key_path':  key,
    }

def _gen_selfsigned(domain=''):
    os.makedirs(SSL_DIR, exist_ok=True)
    cn = domain or 'VortexPanel'
    out, err, rc = sh3(
        f'openssl req -x509 -nodes -days 3650 -newkey rsa:2048 '
        f'-keyout {SSL_DIR}/panel.key -out {SSL_DIR}/panel.crt '
        f'-subj "/CN={cn}/O=VortexPanel/OU=Panel" 2>&1',
        t=30
    )
    return rc == 0, err if rc != 0 else ''

def _write_nginx_ssl(domain='', port=443):
    cfg = load_config()
    gunicorn_port = cfg.get('port', PANEL_PORT)
    server_name = domain if domain else '_'
    conf = f"""# VortexPanel HTTPS proxy — auto-generated
server {{
    listen {port} ssl;
    server_name {server_name};

    ssl_certificate     {SSL_DIR}/panel.crt;
    ssl_certificate_key {SSL_DIR}/panel.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;

    # Forward to Gunicorn
    location / {{
        proxy_pass         http://127.0.0.1:{gunicorn_port};
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_read_timeout 300;
    }}

    # WebSocket (terminal)
    location /ws {{
        proxy_pass         http://127.0.0.1:{gunicorn_port};
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
    }}
}}
"""
    os.makedirs('/etc/nginx/conf.d', exist_ok=True)
    with open(SSL_CONF, 'w') as f: f.write(conf)
    _, err, rc = sh3('nginx -t 2>&1')
    if rc != 0:
        os.unlink(SSL_CONF)
        return False, f'nginx config error: {err}'
    sh('systemctl reload nginx 2>/dev/null || service nginx reload 2>/dev/null')
    return True, ''


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@settings_bp.route('/api/settings')
def get_settings():
    if not req(): return jsonify({'ok':False}), 401
    cfg     = load_config()
    hostname = sh('hostname')
    os_info  = sh('cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2').strip('"')
    kernel   = sh('uname -r')
    ip       = sh("hostname -I 2>/dev/null | awk '{print $1}'")
    uptime   = sh("uptime -p 2>/dev/null | sed 's/up //'")
    tz       = sh("cat /etc/timezone 2>/dev/null || timedatectl show -p Timezone --value 2>/dev/null || echo UTC")
    server_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return jsonify({
        'ok': True, 'config': cfg,
        'ssl': _ssl_status(),
        'system': {
            'hostname':hostname, 'os':os_info, 'kernel':kernel,
            'ip':ip, 'uptime':uptime, 'timezone':tz.strip(),
            'server_time': server_time,
        }
    })


@settings_bp.route('/api/settings', methods=['PUT'])
def save_settings():
    if not req(): return jsonify({'ok':False}), 401
    d   = request.get_json() or {}
    cfg = load_config()
    allowed = ('panel_name','auto_update','timezone','panel_domain','security_path')
    cfg.update({k:v for k,v in d.items() if k in allowed})
    save_config(cfg)
    return jsonify({'ok':True})


@settings_bp.route('/api/settings/port', methods=['POST'])
def change_port():
    """Change the panel's listening port."""
    if not req(): return jsonify({'ok':False}), 401
    new_port = int((request.get_json() or {}).get('port', 8888))
    if not (1024 <= new_port <= 65535):
        return jsonify({'ok':False,'error':'Port must be 1024–65535'}), 400
    cfg = load_config()
    old_port = cfg.get('port', 8888)
    if new_port == old_port:
        return jsonify({'ok':True,'message':'Port unchanged'})
    # Update service config
    service_file = '/etc/systemd/system/vortexpanel.service'
    if os.path.exists(service_file):
        content = open(service_file).read()
        content = re.sub(r'--bind\s+\S+:\d+', f'--bind 0.0.0.0:{new_port}', content)
        content = re.sub(r'-b\s+\S+:\d+', f'-b 0.0.0.0:{new_port}', content)
        with open(service_file, 'w') as f: f.write(content)
        sh('systemctl daemon-reload 2>/dev/null')
    # Update firewall
    sh(f'ufw allow {new_port}/tcp 2>/dev/null; ufw delete allow {old_port}/tcp 2>/dev/null || true')
    sh(f'firewall-cmd --add-port={new_port}/tcp --permanent 2>/dev/null; firewall-cmd --remove-port={old_port}/tcp --permanent 2>/dev/null; firewall-cmd --reload 2>/dev/null || true')
    cfg['port'] = new_port
    save_config(cfg)
    sh(f'sleep 1 && systemctl restart vortexpanel 2>/dev/null &')
    return jsonify({'ok':True,'port':new_port,'message':f'Port changed to {new_port}. Panel restarting…'})


# ── SSL ────────────────────────────────────────────────────────────────────────

@settings_bp.route('/api/settings/ssl')
def ssl_status():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, **_ssl_status()})


@settings_bp.route('/api/settings/ssl/self-signed', methods=['POST'])
def ssl_self_signed():
    """Generate self-signed certificate and enable HTTPS via nginx proxy."""
    if not req(): return jsonify({'ok':False}), 401
    domain = (request.get_json() or {}).get('domain', '').strip()
    # Check nginx is installed
    if not sh('which nginx 2>/dev/null'):
        return jsonify({'ok':False,'error':'Nginx is required for HTTPS. Install it from the App Store first.'}), 400
    ok, err = _gen_selfsigned(domain)
    if not ok:
        return jsonify({'ok':False,'error':f'Certificate generation failed: {err}'}), 500
    ok2, err2 = _write_nginx_ssl(domain)
    if not ok2:
        return jsonify({'ok':False,'error':err2}), 500
    # Update firewall for port 443
    sh('ufw allow 443/tcp 2>/dev/null; firewall-cmd --add-service=https --permanent 2>/dev/null; firewall-cmd --reload 2>/dev/null || true')
    cfg = load_config()
    cfg['ssl_enabled'] = True
    if domain: cfg['panel_domain'] = domain
    save_config(cfg)
    return jsonify({'ok':True, 'type':'self-signed', 'message':'HTTPS enabled. Access panel at https://your-server-ip'})


@settings_bp.route('/api/settings/ssl/letsencrypt', methods=['POST'])
def ssl_letsencrypt():
    """Issue Let's Encrypt certificate for the panel domain."""
    if not req(): return jsonify({'ok':False}), 401
    domain = (request.get_json() or {}).get('domain','').strip()
    if not domain:
        return jsonify({'ok':False,'error':'Domain name required for Let\'s Encrypt'}), 400
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', domain):
        return jsonify({'ok':False,'error':'Invalid domain format'}), 400
    # Install certbot if needed
    sh('which certbot 2>/dev/null || apt-get install -y certbot 2>/dev/null || dnf install -y certbot 2>/dev/null')
    # Issue cert
    _, err, rc = sh3(
        f'certbot certonly --standalone --non-interactive --agree-tos '
        f'--register-unsafely-without-email -d {domain} 2>&1',
        t=120
    )
    if rc != 0:
        return jsonify({'ok':False,'error':f'Certbot failed: {err[:300]}'}), 500
    # Copy certs
    os.makedirs(SSL_DIR, exist_ok=True)
    sh(f'cp /etc/letsencrypt/live/{domain}/fullchain.pem {SSL_DIR}/panel.crt')
    sh(f'cp /etc/letsencrypt/live/{domain}/privkey.pem {SSL_DIR}/panel.key')
    ok2, err2 = _write_nginx_ssl(domain)
    if not ok2:
        return jsonify({'ok':False,'error':err2}), 500
    sh('ufw allow 443/tcp 2>/dev/null; firewall-cmd --add-service=https --permanent 2>/dev/null; firewall-cmd --reload 2>/dev/null || true')
    cfg = load_config()
    cfg['ssl_enabled'] = True
    cfg['panel_domain'] = domain
    save_config(cfg)
    return jsonify({'ok':True,'type':'letsencrypt','domain':domain,'message':f'Let\'s Encrypt cert issued for {domain}'})


@settings_bp.route('/api/settings/ssl/disable', methods=['POST'])
def ssl_disable():
    if not req(): return jsonify({'ok':False}), 401
    try: os.unlink(SSL_CONF)
    except: pass
    sh('systemctl reload nginx 2>/dev/null || true')
    cfg = load_config()
    cfg['ssl_enabled'] = False
    save_config(cfg)
    return jsonify({'ok':True})


# ── PHP Webshell Scanner ───────────────────────────────────────────────────────

WEBSHELL_PATTERNS = [
    # Classic eval-based webshells
    (r'eval\s*\(\s*base64_decode\s*\(',   'CRITICAL', 'eval(base64_decode()) — classic webshell obfuscation'),
    (r'eval\s*\(\s*gzinflate\s*\(',        'CRITICAL', 'eval(gzinflate()) — compressed payload execution'),
    (r'eval\s*\(\s*str_rot13\s*\(',        'CRITICAL', 'eval(str_rot13()) — obfuscated execution'),
    (r'eval\s*\(\s*\$[a-zA-Z_]\w*\s*\)',  'HIGH',     'eval($variable) — dynamic code execution'),
    # System command execution via user input
    (r'(?:system|exec|passthru|shell_exec|popen)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', 'CRITICAL', 'Shell exec with user input — remote command execution'),
    # PHP function code injection
    (r'preg_replace\s*\(\s*[\'"].*\/e[\'"]', 'CRITICAL', 'preg_replace /e modifier — code execution via regex'),
    (r'assert\s*\(\s*\$_(?:GET|POST|REQUEST)', 'CRITICAL', 'assert() with user input — code injection'),
    # Reverse shells
    (r'fsockopen.*(?:exec|shell_exec)',    'CRITICAL', 'fsockopen + exec — potential reverse shell'),
    (r'socket_create.*(?:exec|shell_exec)','CRITICAL', 'socket_create + exec — potential reverse shell'),
    # Dynamic function execution
    (r'\$[a-zA-Z_]\w*\s*\(\s*\$_(?:GET|POST|REQUEST)', 'HIGH', 'Dynamic function call with user input'),
    (r'call_user_func\s*\(\s*\$_(?:GET|POST|REQUEST)', 'HIGH', 'call_user_func with user input'),
    (r'create_function\s*\(',             'HIGH',     'create_function() — deprecated, often used in webshells'),
    # File write from user input
    (r'file_put_contents\s*\(\s*.*\$_(?:GET|POST|REQUEST)', 'HIGH', 'file_put_contents with user input — file upload via webshell'),
    # Heavy obfuscation markers
    (r'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}', 'MEDIUM', 'Heavy hex encoding — possible obfuscation'),
    (r'chr\(\d+\)\s*\.\s*chr\(\d+\)\s*\.\s*chr\(\d+\)', 'MEDIUM', 'chr() string assembly — obfuscation technique'),
]

@settings_bp.route('/api/settings/webshell-scan', methods=['POST'])
def webshell_scan():
    """Scan PHP files in webroot for known webshell patterns."""
    if not req(): return jsonify({'ok':False}), 401
    d     = request.get_json() or {}
    path  = d.get('path', '/www/wwwroot').strip()
    if not os.path.isdir(path):
        return jsonify({'ok':False,'error':f'Directory not found: {path}'}), 404

    findings = []
    scanned  = 0
    errors   = []
    max_files = 5000  # safety limit

    for root, dirs, files in os.walk(path):
        # Skip common safe dirs
        dirs[:] = [d for d in dirs if d not in ('node_modules','.git','.svn','vendor')]
        for fn in files:
            if not fn.endswith('.php'): continue
            if scanned >= max_files: break
            fp = os.path.join(root, fn)
            scanned += 1
            try:
                content = open(fp, 'r', errors='replace').read()
                for pattern, severity, desc in WEBSHELL_PATTERNS:
                    m = re.search(pattern, content, re.IGNORECASE)
                    if m:
                        # Get line number
                        line_no = content[:m.start()].count('\n') + 1
                        # Get snippet
                        snippet = content[max(0,m.start()-20):m.end()+40].strip().replace('\n',' ')[:120]
                        findings.append({
                            'file':     fp,
                            'line':     line_no,
                            'severity': severity,
                            'pattern':  desc,
                            'snippet':  snippet,
                        })
                        # Only report first match per file (don't spam)
                        if severity == 'CRITICAL': break
            except Exception as e:
                errors.append(str(fp))

    findings.sort(key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2}.get(x['severity'],3))
    critical = sum(1 for f in findings if f['severity']=='CRITICAL')
    high     = sum(1 for f in findings if f['severity']=='HIGH')
    medium   = sum(1 for f in findings if f['severity']=='MEDIUM')

    return jsonify({
        'ok':      True,
        'scanned': scanned,
        'total':   len(findings),
        'critical':critical,
        'high':    high,
        'medium':  medium,
        'findings':findings[:200],  # cap at 200 results
        'errors':  errors[:10],
        'path':    path,
    })


@settings_bp.route('/api/settings/webshell-scan/paths')
def webshell_scan_paths():
    """Return list of scannable paths (webroots + installed sites)."""
    if not req(): return jsonify({'ok':False}), 401
    paths = []
    for p in ['/www/wwwroot','/var/www/html','/var/www','/home','/srv/www']:
        if os.path.isdir(p): paths.append(p)
    return jsonify({'ok':True,'paths':paths})


# ── Existing routes ────────────────────────────────────────────────────────────

@settings_bp.route('/api/settings/password', methods=['POST'])
def change_password():
    if not req(): return jsonify({'ok':False}), 401
    d      = request.get_json() or {}
    new_pw = d.get('new_password','')
    if len(new_pw) < 8: return jsonify({'ok':False,'error':'Min 8 characters'}), 400
    from panel.routes.auth import CREDS_FILE, get_credentials, _hash_password
    creds = get_credentials()
    creds['password_hash'] = _hash_password(new_pw)
    import json as _json
    with open(CREDS_FILE,'w') as f: _json.dump(creds, f, indent=2)
    return jsonify({'ok':True})


@settings_bp.route('/api/settings/hostname', methods=['POST'])
def set_hostname():
    if not req(): return jsonify({'ok':False}), 401
    name = (request.get_json() or {}).get('hostname','').strip()
    if not name: return jsonify({'ok':False,'error':'Hostname required'}), 400
    sh(f'hostnamectl set-hostname {name}')
    return jsonify({'ok':True})


@settings_bp.route('/api/settings/sync-time', methods=['POST'])
def sync_time():
    if not req(): return jsonify({'ok':False}), 401
    sh('timedatectl set-ntp true 2>/dev/null || ntpdate pool.ntp.org 2>/dev/null || true')
    return jsonify({'ok':True,'time':datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')})


@settings_bp.route('/api/settings/update', methods=['POST'])
def system_update():
    if not req(): return jsonify({'ok':False}), 401
    import threading
    def do_update():
        sh('apt-get update -y && apt-get upgrade -y 2>/dev/null || dnf update -y 2>/dev/null', t=300)
    threading.Thread(target=do_update, daemon=True).start()
    return jsonify({'ok':True,'message':'System update started in background'})


@settings_bp.route('/api/settings/reboot', methods=['POST'])
def reboot():
    if not req(): return jsonify({'ok':False}), 401
    import threading
    threading.Thread(target=lambda: sh('sleep 3 && reboot'), daemon=True).start()
    return jsonify({'ok':True,'message':'Rebooting in 3 seconds...'})


@settings_bp.route('/api/settings/webroot')
def get_webroot():
    for p in ['/www/wwwroot','/var/www/html','/var/www','/srv/www']:
        if os.path.isdir(p): return jsonify({'ok':True,'path':p})
    os.makedirs('/www/wwwroot', exist_ok=True)
    return jsonify({'ok':True,'path':'/www/wwwroot'})
