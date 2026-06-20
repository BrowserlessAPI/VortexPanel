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
SERVICE_FILE = '/etc/systemd/system/vortexpanel.service'
SSL_APPLY_SCRIPT = '/opt/vortexpanel/ssl_apply.sh'
SSL_APPLY_LOG    = '/opt/vortexpanel/ssl_apply.log'
PANEL_PORT          = 8888
DEFAULT_INTERNAL_PORT = 18888   # gunicorn's loopback-only port when SSL is active

def load_config():
    if os.path.exists(CONFIG_FILE):
        try: return json.load(open(CONFIG_FILE))
        except: pass
    return {'panel_name':'VortexPanel','port':8888,'internal_port':DEFAULT_INTERNAL_PORT,
            'ssl_enabled':False,'auto_update':True,'timezone':'UTC','security_path':'',
            'panel_domain':''}

def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE,'w') as f: json.dump(cfg, f, indent=2)

# ── Gunicorn bind management ──────────────────────────────────────────────────
def _set_gunicorn_bind(host, port):
    """Rewrite the systemd unit's --bind/-b directive to host:port and restart."""
    if not os.path.exists(SERVICE_FILE):
        return False, 'systemd service file not found'
    content = open(SERVICE_FILE).read()
    target = f'{host}:{port}'
    new_content = re.sub(r'--bind\s+\S+:\d+', f'--bind {target}', content)
    new_content = re.sub(r'-b\s+\S+:\d+',     f'-b {target}',     new_content)
    if new_content == content and target not in content:
        return False, 'could not find --bind directive in service file'
    with open(SERVICE_FILE, 'w') as f: f.write(new_content)
    sh('systemctl daemon-reload 2>/dev/null')
    return True, ''

def _current_bind():
    if not os.path.exists(SERVICE_FILE): return None
    content = open(SERVICE_FILE).read()
    m = re.search(r'(?:--bind|-b)\s+(\S+):(\d+)', content)
    return (m.group(1), int(m.group(2))) if m else None

def _safe_restart_panel():
    """
    Restart vortexpanel.service from WITHIN a request handled by that very
    service. A naive '(sleep 2 && systemctl restart vortexpanel) &' is
    unsafe: that background process is still a member of vortexpanel's
    systemd cgroup, and 'systemctl restart' kills the ENTIRE cgroup —
    including the background restart command itself — partway through,
    which can leave the service down instead of restarted.

    Fix: use `systemd-run` to launch the restart command as an independent
    *transient* unit, outside vortexpanel's cgroup, so it survives the kill
    and reliably completes the restart. Falls back to setsid double-fork
    detachment if systemd-run isn't available (non-systemd or container
    environments), and finally to the naive approach as a last resort.
    """
    if sh('which systemd-run 2>/dev/null'):
        sh('systemd-run --no-block --collect --unit=vortexpanel-restart '
           '/bin/sh -c "sleep 2 && systemctl restart vortexpanel" 2>/dev/null')
    elif sh('which setsid 2>/dev/null'):
        sh('setsid sh -c "sleep 2 && systemctl restart vortexpanel" '
           '>/dev/null 2>&1 < /dev/null &')
    else:
        sh('(sleep 2 && systemctl restart vortexpanel) >/dev/null 2>&1 &')

# ── SSL helpers ───────────────────────────────────────────────────────────────
def _ssl_status():
    cert = os.path.join(SSL_DIR, 'panel.crt')
    key  = os.path.join(SSL_DIR, 'panel.key')
    cfg  = load_config()
    if not os.path.exists(cert):
        return {'enabled': False, 'type': 'none', 'port': cfg.get('port', PANEL_PORT)}
    out = sh(f'openssl x509 -in {cert} -noout -subject -issuer -enddate 2>/dev/null')
    cert_type = 'letsencrypt' if "Let's Encrypt" in out else 'self-signed'
    expiry_out = sh(f'openssl x509 -in {cert} -noout -enddate 2>/dev/null | cut -d= -f2')
    days_left = -1
    try:
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
        'port':      cfg.get('port', PANEL_PORT),   # SSL always serves on the SAME public port
    }

def _gen_selfsigned(domain=''):
    os.makedirs(SSL_DIR, exist_ok=True)
    ip = sh("hostname -I 2>/dev/null | awk '{print $1}'") or 'localhost'
    cn = domain or ip
    out, err, rc = sh3(
        f'openssl req -x509 -nodes -days 3650 -newkey rsa:2048 '
        f'-keyout {SSL_DIR}/panel.key -out {SSL_DIR}/panel.crt '
        f'-subj "/CN={cn}/O=VortexPanel/OU=Panel" '
        f'-addext "subjectAltName=DNS:{cn},IP:{ip}" 2>&1',
        t=30
    )
    return rc == 0, err if rc != 0 else ''

def _write_nginx_ssl_file(domain=''):
    """
    Write the nginx HTTPS vhost (custom port, never 443) and validate syntax
    with `nginx -t` (parse-only, doesn't bind sockets — always safe to run).
    Does NOT reload nginx here: reloading must happen only after gunicorn has
    actually released the public port, otherwise nginx's bind() races against
    the still-running old gunicorn process and silently fails while still
    reporting "reload successful" at the systemd level. The actual reload is
    performed by the atomic cutover script in _enable_https().
    """
    cfg            = load_config()
    external_port  = cfg.get('port', PANEL_PORT)
    internal_port  = cfg.get('internal_port', DEFAULT_INTERNAL_PORT)
    server_name    = domain if domain else '_'

    conf = f"""# VortexPanel HTTPS proxy — auto-generated
# Public port matches the panel's custom port setting (NOT 443) so enabling
# SSL does not expose the panel on a well-known port.
server {{
    listen {external_port} ssl;
    server_name {server_name};

    ssl_certificate     {SSL_DIR}/panel.crt;
    ssl_certificate_key {SSL_DIR}/panel.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;

    # A plain HTTP request landing on this HTTPS-only port (e.g. an old
    # bookmark, browser history, or a tab open since before SSL was enabled)
    # normally gets nginx's raw "400 Bad Request" page. Show a clear message
    # instead — we can't redirect (that would require also listening for
    # plain HTTP on this exact port, which would re-create the original bind
    # conflict this whole feature exists to avoid).
    error_page 400 = @plain_http_message;
    location @plain_http_message {{
        default_type text/html;
        return 200 '<!DOCTYPE html><html><head><meta charset="utf-8"><title>HTTPS Required</title></head><body style="font-family:-apple-system,sans-serif;text-align:center;padding:80px 20px;background:#0f1117;color:#e5e7eb"><div style="font-size:40px;margin-bottom:16px">&#128274;</div><h2 style="margin-bottom:8px">This port now requires HTTPS</h2><p style="color:#9ca3af">Please reconnect using <strong>https://</strong> instead of <strong>http://</strong> &mdash; same address, same port {external_port}.</p></body></html>';
    }}

    location / {{
        proxy_pass         http://127.0.0.1:{internal_port};
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_read_timeout 300;
    }}

    location /ws {{
        proxy_pass         http://127.0.0.1:{internal_port};
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
    return True, ''


def _run_cutover_script(script_body, unit_name='vortexpanel-ssl-apply'):
    """
    Run a multi-step bind-cutover sequence as an independent, detached
    systemd transient unit (outside vortexpanel.service's cgroup) so it
    survives stopping/restarting vortexpanel itself, and can reliably wait
    for a port to actually be released before handing it to nginx.
    """
    os.makedirs(os.path.dirname(SSL_APPLY_LOG), exist_ok=True)
    with open(SSL_APPLY_SCRIPT, 'w') as f:
        f.write(script_body)
    os.chmod(SSL_APPLY_SCRIPT, 0o700)
    if sh('which systemd-run 2>/dev/null'):
        sh(f'systemd-run --no-block --collect --unit={unit_name} '
           f'/bin/bash {SSL_APPLY_SCRIPT} 2>&1')
        return True
    elif sh('which setsid 2>/dev/null'):
        sh(f'setsid /bin/bash {SSL_APPLY_SCRIPT} >/dev/null 2>&1 < /dev/null &')
        return True
    else:
        sh(f'/bin/bash {SSL_APPLY_SCRIPT} >/dev/null 2>&1 &')
        return True


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
    """Change the panel's PUBLIC listening port (works whether HTTP or HTTPS)."""
    if not req(): return jsonify({'ok':False}), 401
    new_port = int((request.get_json() or {}).get('port', 8888))
    if not (1024 <= new_port <= 65535):
        return jsonify({'ok':False,'error':'Port must be 1024–65535'}), 400
    cfg = load_config()
    old_port = cfg.get('port', 8888)
    if new_port == old_port:
        return jsonify({'ok':True,'message':'Port unchanged'})

    internal_port = cfg.get('internal_port', DEFAULT_INTERNAL_PORT)
    if cfg.get('ssl_enabled'):
        # HTTPS active: only nginx's public listen port changes.
        # Gunicorn stays bound to loopback:internal_port — untouched.
        cfg['port'] = new_port
        save_config(cfg)
        ok, err = _write_nginx_ssl(cfg.get('panel_domain',''))
        if not ok:
            cfg['port'] = old_port; save_config(cfg)
            return jsonify({'ok':False,'error':err}), 500
    else:
        # Plain HTTP: gunicorn binds directly to the new public port.
        ok, err = _set_gunicorn_bind('0.0.0.0', new_port)
        if not ok:
            return jsonify({'ok':False,'error':err}), 500
        cfg['port'] = new_port
        save_config(cfg)
        _safe_restart_panel()

    # Update firewall: open new port, close old one
    sh(f'ufw allow {new_port}/tcp 2>/dev/null')
    sh(f'ufw delete allow {old_port}/tcp 2>/dev/null || true')
    sh(f'firewall-cmd --add-port={new_port}/tcp --permanent 2>/dev/null')
    sh(f'firewall-cmd --remove-port={old_port}/tcp --permanent 2>/dev/null')
    sh('firewall-cmd --reload 2>/dev/null || true')

    return jsonify({'ok':True,'port':new_port,
                    'message':f'Port changed to {new_port}.' + (' Panel restarting…' if not cfg.get('ssl_enabled') else '')})


# ── SSL ────────────────────────────────────────────────────────────────────────

@settings_bp.route('/api/settings/ssl')
def ssl_status():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, **_ssl_status()})


@settings_bp.route('/api/settings/ssl/apply-log')
def ssl_apply_log():
    """Tail the cutover script's log so the UI can show real progress
    instead of guessing whether the switch has completed."""
    if not req(): return jsonify({'ok':False}), 401
    if not os.path.exists(SSL_APPLY_LOG):
        return jsonify({'ok':True,'log':'','done':False})
    try:
        lines = open(SSL_APPLY_LOG).readlines()[-20:]
        log = ''.join(lines)
        done = any('Result: vortexpanel=' in l for l in lines)
        return jsonify({'ok':True,'log':log,'done':done})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)}), 500


def _enable_https(domain=''):
    """
    Shared logic: switch gunicorn to loopback-only and put nginx in front
    with TLS, serving on the SAME public port the panel already used.

    The cutover is performed by an ATOMIC external script (stop gunicorn ->
    confirm the public port is actually free -> reload nginx -> start
    gunicorn) rather than as separate fire-and-forget steps. The previous
    implementation reloaded nginx (step 2) while the OLD gunicorn process
    was still bound to the public port (it doesn't get released until the
    delayed restart in step 4 actually runs) — nginx's bind() raced against
    the still-running gunicorn and lost, every time, while still reporting
    "reload successful" because the reload signal itself was delivered fine
    even though the new listen socket silently failed to open. Confirmed via
    nginx's error log: "bind() to 0.0.0.0:8888 failed (98: Address already
    in use)" / "still could not bind()".

    Returns (ok, error_message).
    """
    cfg           = load_config()
    external_port = cfg.get('port', PANEL_PORT)
    internal_port = cfg.get('internal_port', DEFAULT_INTERNAL_PORT)
    if internal_port == external_port:
        internal_port = DEFAULT_INTERNAL_PORT if DEFAULT_INTERNAL_PORT != external_port else external_port + 1
        cfg['internal_port'] = internal_port
        save_config(cfg)

    # 1. Point gunicorn's *target* bind at loopback (text edit only — takes
    #    no effect until gunicorn is actually restarted, which happens at
    #    the right moment inside the cutover script below).
    ok, err = _set_gunicorn_bind('127.0.0.1', internal_port)
    if not ok:
        return False, f'Failed to update panel service: {err}'

    # 2. Write + syntax-check (not reload) the nginx vhost.
    ok2, err2 = _write_nginx_ssl_file(domain)
    if not ok2:
        _set_gunicorn_bind('0.0.0.0', external_port)  # roll back the unit file
        return False, err2

    # 3. Firewall: the external/custom port must stay open (it already was);
    #    the internal port is loopback-only and unreachable externally
    #    regardless of firewall state, so nothing further to open there.
    sh(f'ufw allow {external_port}/tcp 2>/dev/null')
    sh(f'firewall-cmd --add-port={external_port}/tcp --permanent 2>/dev/null; firewall-cmd --reload 2>/dev/null || true')

    # 4. Atomic cutover, run OUTSIDE vortexpanel's cgroup so it survives
    #    stopping the very service it's orchestrating:
    #      stop gunicorn -> poll until the public port is truly free
    #      -> reload nginx (now guaranteed to win the bind) -> start gunicorn
    script = f"""#!/bin/bash
exec >> {SSL_APPLY_LOG} 2>&1
echo "=== $(date -u +'%Y-%m-%d %H:%M:%S UTC') : enabling HTTPS on port {external_port} ==="
systemctl stop vortexpanel
for i in $(seq 1 20); do
  ss -tln 2>/dev/null | grep -q ":{external_port} " || break
  sleep 0.5
done
systemctl daemon-reload
if nginx -t 2>&1; then
  systemctl reload nginx 2>&1 || systemctl restart nginx 2>&1
else
  echo "nginx -t failed at cutover time — skipping reload"
fi
systemctl start vortexpanel
sleep 1
echo "Result: vortexpanel=$(systemctl is-active vortexpanel) nginx=$(systemctl is-active nginx)"
echo "Listening: $(ss -tln 2>/dev/null | grep -E ':{external_port} |:{internal_port} ')"
"""
    _run_cutover_script(script)

    cfg['ssl_enabled'] = True
    if domain: cfg['panel_domain'] = domain
    save_config(cfg)
    return True, ''


@settings_bp.route('/api/settings/ssl/self-signed', methods=['POST'])
def ssl_self_signed():
    if not req(): return jsonify({'ok':False}), 401
    domain = (request.get_json() or {}).get('domain', '').strip()
    if not sh('which nginx 2>/dev/null'):
        return jsonify({'ok':False,'error':'Nginx is required for HTTPS. Install it from the App Store first.'}), 400
    ok, err = _gen_selfsigned(domain)
    if not ok:
        return jsonify({'ok':False,'error':f'Certificate generation failed: {err}'}), 500
    ok2, err2 = _enable_https(domain)
    if not ok2:
        return jsonify({'ok':False,'error':err2}), 500
    cfg = load_config()
    return jsonify({'ok':True, 'type':'self-signed', 'port':cfg.get('port'),
                    'message':f'HTTPS enabled on port {cfg.get("port")} (same as before — no new port exposed)'})


@settings_bp.route('/api/settings/ssl/letsencrypt', methods=['POST'])
def ssl_letsencrypt():
    if not req(): return jsonify({'ok':False}), 401
    domain = (request.get_json() or {}).get('domain','').strip()
    if not domain:
        return jsonify({'ok':False,'error':'Domain name required for Let\'s Encrypt'}), 400
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', domain):
        return jsonify({'ok':False,'error':'Invalid domain format'}), 400
    if not sh('which nginx 2>/dev/null'):
        return jsonify({'ok':False,'error':'Nginx is required for HTTPS. Install it from the App Store first.'}), 400

    sh('which certbot 2>/dev/null || apt-get install -y certbot 2>/dev/null || dnf install -y certbot 2>/dev/null')

    # ACME HTTP-01 challenge always uses port 80 by spec (not configurable) —
    # this is separate from the panel's own port, and only needed momentarily
    # during issuance/renewal.
    sh('ufw allow 80/tcp 2>/dev/null; firewall-cmd --add-service=http --permanent 2>/dev/null; firewall-cmd --reload 2>/dev/null || true')

    _, err, rc = sh3(
        f'certbot certonly --standalone --non-interactive --agree-tos '
        f'--register-unsafely-without-email -d {domain} 2>&1',
        t=120
    )
    if rc != 0:
        return jsonify({'ok':False,'error':f'Certbot failed: {err[:300]}'}), 500

    os.makedirs(SSL_DIR, exist_ok=True)
    sh(f'cp /etc/letsencrypt/live/{domain}/fullchain.pem {SSL_DIR}/panel.crt')
    sh(f'cp /etc/letsencrypt/live/{domain}/privkey.pem {SSL_DIR}/panel.key')

    ok2, err2 = _enable_https(domain)
    if not ok2:
        return jsonify({'ok':False,'error':err2}), 500
    cfg = load_config()
    return jsonify({'ok':True,'type':'letsencrypt','domain':domain,'port':cfg.get('port'),
                    'message':f'Let\'s Encrypt cert issued — HTTPS active on port {cfg.get("port")}'})


@settings_bp.route('/api/settings/ssl/disable', methods=['POST'])
def ssl_disable():
    if not req(): return jsonify({'ok':False}), 401
    cfg           = load_config()
    external_port = cfg.get('port', PANEL_PORT)

    try: os.unlink(SSL_CONF)
    except: pass

    # Point gunicorn's target bind back at the public port (text edit only;
    # takes effect when the cutover script restarts it below).
    ok, err = _set_gunicorn_bind('0.0.0.0', external_port)
    if not ok:
        return jsonify({'ok':False,'error':err}), 500

    script = f"""#!/bin/bash
exec >> {SSL_APPLY_LOG} 2>&1
echo "=== $(date -u +'%Y-%m-%d %H:%M:%S UTC') : disabling HTTPS, reverting to plain HTTP on port {external_port} ==="
systemctl stop vortexpanel
nginx -t 2>&1 && (systemctl reload nginx 2>&1 || systemctl restart nginx 2>&1)
systemctl daemon-reload
systemctl start vortexpanel
sleep 1
echo "Result: vortexpanel=$(systemctl is-active vortexpanel) nginx=$(systemctl is-active nginx)"
echo "Listening: $(ss -tln 2>/dev/null | grep -E ':{external_port} ')"
"""
    _run_cutover_script(script)

    cfg['ssl_enabled'] = False
    save_config(cfg)
    return jsonify({'ok':True, 'message': 'Disabling HTTPS — reverting to plain HTTP. Reconnect at http://<ip>:'+str(external_port)+' in a few seconds.'})


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
