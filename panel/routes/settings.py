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
SERVICE_FILE = '/etc/systemd/system/vortexpanel.service'
PANEL_PORT   = 8888

def load_config():
    if os.path.exists(CONFIG_FILE):
        try: return json.load(open(CONFIG_FILE))
        except: pass
    return {'panel_name':'VortexPanel','port':8888,
            'ssl_enabled':False,'auto_update':True,'timezone':'UTC','security_path':'',
            'panel_domain':''}

def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE,'w') as f: json.dump(cfg, f, indent=2)

# --- Gunicorn bind management ---------------------------------------------------
def _set_gunicorn_bind(host, port, certfile=None, keyfile=None):
    """Rewrite the systemd unit's --bind and optional --certfile/--keyfile directives."""
    if not os.path.exists(SERVICE_FILE):
        return False, 'systemd service file not found'
    content = open(SERVICE_FILE).read()
    target = f'{host}:{port}'
    new_content = re.sub(r'--bind\s+\S+:\d+', f'--bind {target}', content)
    new_content = re.sub(r'-b\s+\S+:\d+', f'-b {target}', new_content)

    # Remove old SSL args if present
    new_content = re.sub(r'\s*--certfile\s+\S+', '', new_content)
    new_content = re.sub(r'\s*--keyfile\s+\S+', '', new_content)

    # Add SSL args if cert provided
    if certfile and keyfile:
        new_content = re.sub(
            r'(--bind\s+\S+:\d+)',
            rf'\1 --certfile {certfile} --keyfile {keyfile}',
            new_content
        )

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

# --- SSL helpers ----------------------------------------------------------------
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
        'enabled':   cfg.get('ssl_enabled', False),
        'type':      cert_type,
        'expiry':    expiry_out.strip(),
        'days_left': days_left,
        'cert_path': cert,
        'key_path':  key,
        'port':      cfg.get('port', PANEL_PORT),
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


# ===============================================================================
# ROUTES
# ===============================================================================

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

    if cfg.get('ssl_enabled'):
        # HTTPS active: update gunicorn bind with SSL certs on new port
        cert_path = f'{SSL_DIR}/panel.crt'
        key_path  = f'{SSL_DIR}/panel.key'
        ok, err = _set_gunicorn_bind('0.0.0.0', new_port, certfile=cert_path, keyfile=key_path)
        if not ok:
            return jsonify({'ok':False,'error':err}), 500
        cfg['port'] = new_port
        save_config(cfg)
        _safe_restart_panel()
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


# --- SSL -------------------------------------------------------------------------

@settings_bp.route('/api/settings/ssl')
def ssl_status():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, **_ssl_status()})


def _enable_https(domain=''):
    """Enable HTTPS directly on gunicorn. No webserver dependency."""
    cfg = load_config()
    port = cfg.get('port', PANEL_PORT)
    cert_path = f'{SSL_DIR}/panel.crt'
    key_path  = f'{SSL_DIR}/panel.key'
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        return False, 'SSL certificate files not found'
    ok, err = _set_gunicorn_bind('0.0.0.0', port, certfile=cert_path, keyfile=key_path)
    if not ok:
        return False, f'Failed to update panel service: {err}'
    cfg['ssl_enabled'] = True
    if domain: cfg['panel_domain'] = domain
    save_config(cfg)
    _safe_restart_panel()
    return True, ''


@settings_bp.route('/api/settings/ssl/self-signed', methods=['POST'])
def ssl_self_signed():
    if not req(): return jsonify({'ok':False}), 401
    domain = (request.get_json() or {}).get('domain', '').strip()
    ok, err = _gen_selfsigned(domain)
    if not ok:
        return jsonify({'ok':False,'error':f'Certificate generation failed: {err}'}), 500
    ok2, err2 = _enable_https(domain)
    if not ok2:
        return jsonify({'ok':False,'error':err2}), 500
    cfg = load_config()
    return jsonify({'ok':True, 'type':'self-signed', 'port':cfg.get('port'),
                    'message':f'HTTPS enabled on port {cfg.get("port")}'})


@settings_bp.route('/api/settings/ssl/letsencrypt', methods=['POST'])
def ssl_letsencrypt():
    if not req(): return jsonify({'ok':False}), 401
    domain = (request.get_json() or {}).get('domain','').strip()
    if not domain:
        return jsonify({'ok':False,'error':"Domain name required for Let's Encrypt"}), 400
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', domain):
        return jsonify({'ok':False,'error':'Invalid domain format'}), 400

    sh('which certbot 2>/dev/null || apt-get install -y certbot 2>/dev/null || '
       '(dnf install -y epel-release 2>/dev/null; dnf install -y certbot 2>/dev/null) || '
       '(yum install -y epel-release 2>/dev/null; yum install -y certbot 2>/dev/null)')
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
                    'message':f"Let's Encrypt cert issued. HTTPS active on port {cfg.get('port')}"})


@settings_bp.route('/api/settings/ssl/disable', methods=['POST'])
def ssl_disable():
    if not req(): return jsonify({'ok':False}), 401
    cfg  = load_config()
    port = cfg.get('port', PANEL_PORT)
    ok, err = _set_gunicorn_bind('0.0.0.0', port)
    if not ok:
        return jsonify({'ok':False,'error':err}), 500
    # Clean up old nginx SSL config if it exists
    nginx_ssl = '/etc/nginx/conf.d/vortexpanel-https.conf'
    if os.path.exists(nginx_ssl):
        os.remove(nginx_ssl)
        sh('nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true')
    cfg['ssl_enabled'] = False
    save_config(cfg)
    _safe_restart_panel()
    return jsonify({'ok':True, 'message': f'HTTPS disabled. Reconnect at http://<ip>:{port} in a few seconds.'})



# --- PHP Webshell Scanner --------------------------------------------------------

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


# --- Existing routes -------------------------------------------------------------

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


def _pending_security_packages(refresh=True):
    """Shared detection used by BOTH the check endpoint and the apply
    endpoint's post-run verification -- so 'did it actually work?' is
    answered by the same logic that decided what was pending in the
    first place, rather than by trusting an exit code."""
    os_family = sh(". /etc/os-release 2>/dev/null && echo $ID_LIKE || echo debian")
    packages = []
    if re.search(r'rhel|fedora|centos', os_family, re.I):
        if refresh: sh('dnf makecache 2>/dev/null || yum makecache 2>/dev/null', t=120)
        raw = sh('dnf updateinfo list security 2>/dev/null || yum updateinfo list security 2>/dev/null', t=60)
        for line in raw.split('\n'):
            m = re.match(r'^\S+\s+(Critical|Important|Moderate|Low)/Sec\.\s+(\S+)', line.strip())
            if m:
                packages.append({'severity': m.group(1), 'package': m.group(2)})
    else:
        if refresh: sh('apt-get update -q 2>/dev/null', t=120)
        raw = sh('apt-get -s dist-upgrade 2>/dev/null', t=60)
        for line in raw.split('\n'):
            if line.startswith('Inst') and 'security' in line.lower():
                m = re.match(r'^Inst (\S+)', line)
                if m: packages.append({'severity': 'Security', 'package': m.group(1)})
    return packages


@settings_bp.route('/api/settings/security-updates')
def check_security_updates():
    """Read-only check for PENDING security updates specifically, using
    each distro's own continuously-maintained security metadata rather
    than a hardcoded CVE/version lookup table baked into VortexPanel's
    source -- that kind of table goes stale the moment a new critical
    CVE appears that isn't in it, giving false reassurance. This defers
    entirely to apt's/dnf's own live, current security tagging instead."""
    if not req(): return jsonify({'ok':False}), 401
    packages = _pending_security_packages()
    critical = sum(1 for p in packages if p['severity'] in ('Critical', 'Important', 'Security'))
    return jsonify({'ok': True, 'total': len(packages), 'critical': critical, 'packages': packages[:50]})


@settings_bp.route('/api/settings/security-updates/apply', methods=['POST'])
def apply_security_updates():
    """Applies ONLY the packages flagged as security updates -- distinct
    from the existing /api/settings/update button, which blindly upgrades
    everything with no way to scope it. On Debian/Ubuntu this means
    passing the exact package list to --only-upgrade rather than a
    generic dist-upgrade, so nothing outside the flagged security set
    gets touched. On RHEL-family, dnf's own --security flag does this
    natively -- no need to enumerate packages ourselves there."""
    from panel.routes.job_state import save_job, load_job
    if not req(): return jsonify({'ok':False}), 401
    existing = load_job('security_update', {'running': False})
    if existing.get('running'):
        return jsonify({'ok': False, 'error': 'A security update is already in progress'}), 409

    import threading, time as _time
    def do_apply():
        save_job('security_update', {'running': True, 'done': False, 'success': None, 'output': '', 'started': _time.time()})
        os_family = sh(". /etc/os-release 2>/dev/null && echo $ID_LIKE || echo debian")
        before = _pending_security_packages()

        if re.search(r'rhel|fedora|centos', os_family, re.I):
            out, err, rc = sh3('dnf update --security -y 2>&1 || yum update --security -y 2>&1', t=600)
            combined = out or err
        else:
            pkgs = [p['package'] for p in before]
            if not pkgs:
                combined, rc = 'No pending security packages found (they may have changed since the last check — try refreshing).', 0
            else:
                # NOT --only-upgrade. That flag refuses to install any new
                # dependency, so a package whose upgrade pulls one in is
                # silently skipped while apt still exits 0 -- confirmed in
                # testing ("0 upgraded ... N not upgraded"), which is
                # exactly why packages kept reappearing as pending after a
                # reported-successful apply. Naming only already-installed
                # packages means apt resolves precisely the dependencies
                # those upgrades need and nothing unrelated.
                out, err, rc = sh3('apt-get install -y ' + ' '.join(pkgs) + ' 2>&1', t=600)
                combined = out or err

        # Verify against reality rather than trusting the exit code alone --
        # apt can exit 0 having genuinely changed nothing.
        after = _pending_security_packages()
        remaining = len(after)
        applied = max(0, len(before) - remaining)
        success = (rc == 0 and remaining == 0)

        summary = f'\n\n── Result ──\nApplied: {applied}   Still pending: {remaining}'
        if remaining:
            names = ', '.join(p['package'] for p in after[:10])
            summary += (f'\nStill pending: {names}'
                        f'\n\nThese did not upgrade. Most often that means they are held back by the '
                        f'distribution (a phased rollout, or a dependency conflict apt will not resolve '
                        f'automatically). Running "apt-get dist-upgrade" manually over SSH will show the '
                        f'specific reason for each one.')

        save_job('security_update', {'running': False, 'done': True, 'success': success,
                                      'output': combined + summary,
                                      'applied': applied, 'remaining': remaining})

    threading.Thread(target=do_apply, daemon=True).start()
    return jsonify({'ok': True, 'message': 'Applying security updates in background'})


@settings_bp.route('/api/settings/security-updates/status')
def security_update_status():
    from panel.routes.job_state import load_job
    if not req(): return jsonify({'ok':False}), 401
    state = load_job('security_update', {'running': False, 'done': False, 'success': None, 'output': '', 'started': None})
    return jsonify({'ok': True, **state})


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
