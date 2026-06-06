from flask import Blueprint, jsonify, request, session
import subprocess, os, re

caddy_bp = Blueprint('caddy', __name__)
def req(): return 'user' in session
def sh(c, t=15):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except: return '', 'timeout', 1

CADDYFILE = '/etc/caddy/Caddyfile'
CADDY_SITES_DIR = '/etc/caddy/sites'

def is_caddy_installed():
    out, _, rc = sh('which caddy 2>/dev/null')
    return rc == 0 and bool(out)

def get_webroot():
    for p in ['/www/wwwroot', '/var/www/html', '/var/www']:
        if os.path.isdir(p): return p
    os.makedirs('/www/wwwroot', exist_ok=True)
    return '/www/wwwroot'

def reload_caddy():
    sh('systemctl reload caddy 2>/dev/null || caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null')

def validate_caddy():
    out, err, rc = sh('caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1')
    return rc == 0, out + err

def list_caddy_sites():
    """Parse Caddyfile and return list of configured sites"""
    sites = []
    if not os.path.exists(CADDYFILE):
        return sites
    with open(CADDYFILE) as f:
        content = f.read()

    # Match site blocks: domain { ... }
    for m in re.finditer(r'^(\S[^\n{]*)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}', content, re.MULTILINE):
        domain_line = m.group(1).strip()
        block       = m.group(2)
        # Skip global options block
        if not domain_line or domain_line == '':
            continue
        domain = domain_line.split()[0].strip('{}').strip()
        if not domain or domain.startswith('#'):
            continue
        root_m = re.search(r'root\s+\*?\s+(\S+)', block)
        path   = root_m.group(1) if root_m else ''
        has_php    = 'php_fastcgi' in block
        has_proxy  = 'reverse_proxy' in block
        has_tls    = 'tls' in block or (not domain.startswith('localhost') and '.' in domain)
        php_ver    = ''
        if has_php:
            sock_m = re.search(r'php_fastcgi\s+unix(/[^)]+\.sock|\S+)', block)
            if sock_m:
                sock = sock_m.group(1)
                ver_m = re.search(r'php(\d+\.\d+)', sock)
                if ver_m: php_ver = ver_m.group(1)
        sites.append({
            'domain':    domain,
            'path':      path,
            'php':       php_ver or ('FPM' if has_php else 'Static'),
            'ssl':       has_tls,
            'proxy':     has_proxy,
            'type':      'php' if has_php else ('proxy' if has_proxy else 'static'),
        })
    return sites

def get_global_options():
    if not os.path.exists(CADDYFILE):
        return ''
    with open(CADDYFILE) as f:
        content = f.read()
    m = re.match(r'\{([^}]+)\}', content.strip())
    return m.group(1).strip() if m else ''

@caddy_bp.route('/api/caddy/status')
def status():
    if not req(): return jsonify({'ok':False}), 401
    installed = is_caddy_installed()
    if not installed:
        return jsonify({'ok':True, 'installed':False, 'version':'', 'status':'not installed'})
    version, _, _ = sh('caddy version 2>/dev/null | head -1')
    svc_status, _, _ = sh('systemctl is-active caddy 2>/dev/null')
    return jsonify({'ok':True, 'installed':True, 'version':version, 'status':svc_status or 'inactive'})

@caddy_bp.route('/api/caddy/sites')
def list_sites():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, 'sites':list_caddy_sites(), 'webroot':get_webroot()})

@caddy_bp.route('/api/caddy/sites', methods=['POST'])
def create_site():
    if not req(): return jsonify({'ok':False}), 401
    if not is_caddy_installed():
        return jsonify({'ok':False, 'error':'Caddy is not installed. Install it via Modules first.'}), 400

    d      = request.get_json() or {}
    domain = d.get('domain','').strip().lower()
    path   = d.get('path', f"{get_webroot()}/{domain}").strip()
    php    = d.get('php', 'none')     # '8.3', '8.2', 'none'
    stype  = d.get('type', 'static')  # static | php | proxy | nodejs
    proxy_target = d.get('proxy_target', '')

    if not domain: return jsonify({'ok':False, 'error':'Domain required'}), 400

    # Create webroot
    os.makedirs(path, exist_ok=True)
    idx = os.path.join(path, 'index.html')
    if not os.path.exists(idx):
        with open(idx,'w') as f:
            f.write(f'<!DOCTYPE html><html><body><h1>Welcome to {domain}</h1><p>Powered by Caddy + VortexPanel</p></body></html>')

    # Build Caddyfile block
    if stype == 'php' and php != 'none':
        # Find PHP-FPM socket
        sock = f'/run/php/php{php}-fpm.sock'
        for s in [f'/run/php/php{php}-fpm.sock', f'/var/run/php/php{php}-fpm.sock', f'127.0.0.1:90{php.replace(".","")[-2:]}']:
            if os.path.exists(s): sock = s; break
        site_block = f"""{domain} {{
    root * {path}
    encode gzip
    php_fastcgi unix/{sock}
    file_server
    log {{
        output file /var/log/caddy/{domain}.access.log
    }}
}}
"""
    elif stype == 'proxy' and proxy_target:
        site_block = f"""{domain} {{
    reverse_proxy {proxy_target} {{
        header_up Host {{host}}
        header_up X-Real-IP {{remote_host}}
        header_up X-Forwarded-For {{remote_host}}
    }}
    log {{
        output file /var/log/caddy/{domain}.access.log
    }}
}}
"""
    elif stype == 'nodejs' and proxy_target:
        site_block = f"""{domain} {{
    reverse_proxy localhost:{proxy_target} {{
        header_up Upgrade {{http.request.header.Upgrade}}
        header_up Connection {{http.request.header.Connection}}
    }}
    log {{
        output file /var/log/caddy/{domain}.access.log
    }}
}}
"""
    else:
        # Static site
        site_block = f"""{domain} {{
    root * {path}
    encode gzip
    file_server
    log {{
        output file /var/log/caddy/{domain}.access.log
    }}
}}
"""

    # Append to Caddyfile
    if not os.path.exists(CADDYFILE):
        with open(CADDYFILE,'w') as f:
            f.write('# VortexPanel Caddyfile\n# Caddy automatically provisions HTTPS for all domains\n\n')

    with open(CADDYFILE,'a') as f:
        f.write('\n' + site_block)

    # Validate
    ok, msg = validate_caddy()
    if not ok:
        # Rollback — remove the block we just added
        with open(CADDYFILE) as f: content = f.read()
        content = content.replace('\n' + site_block, '')
        with open(CADDYFILE,'w') as f: f.write(content)
        return jsonify({'ok':False, 'error':f'Caddyfile validation failed: {msg}'}), 400

    reload_caddy()
    return jsonify({'ok':True, 'domain':domain, 'path':path,
                   'note':'Caddy will automatically provision a free SSL certificate for this domain.'})

@caddy_bp.route('/api/caddy/sites/<domain>', methods=['DELETE'])
def delete_site(domain):
    if not req(): return jsonify({'ok':False}), 401
    if not os.path.exists(CADDYFILE):
        return jsonify({'ok':False, 'error':'Caddyfile not found'}), 404
    with open(CADDYFILE) as f: content = f.read()
    # Remove the site block for this domain
    content = re.sub(
        rf'\n{re.escape(domain)}\s*\{{[^}}]+(?:\{{[^}}]*\}}[^}}]*)*\}}\n?',
        '\n', content
    )
    with open(CADDYFILE,'w') as f: f.write(content)
    reload_caddy()
    return jsonify({'ok':True})

@caddy_bp.route('/api/caddy/sites/<domain>/config')
def get_site_config(domain):
    if not req(): return jsonify({'ok':False}), 401
    if not os.path.exists(CADDYFILE):
        return jsonify({'ok':False, 'error':'Caddyfile not found'}), 404
    with open(CADDYFILE) as f: content = f.read()
    return jsonify({'ok':True, 'content':content, 'path':CADDYFILE})

@caddy_bp.route('/api/caddy/sites/<domain>/config', methods=['PUT'])
def save_site_config(domain):
    if not req(): return jsonify({'ok':False}), 401
    content = (request.get_json() or {}).get('content','')
    backup = ''
    if os.path.exists(CADDYFILE):
        with open(CADDYFILE) as f: backup = f.read()
    with open(CADDYFILE,'w') as f: f.write(content)
    ok, msg = validate_caddy()
    if not ok:
        with open(CADDYFILE,'w') as f: f.write(backup)
        return jsonify({'ok':False, 'error':msg}), 400
    reload_caddy()
    return jsonify({'ok':True})

@caddy_bp.route('/api/caddy/caddyfile')
def get_caddyfile():
    if not req(): return jsonify({'ok':False}), 401
    if not os.path.exists(CADDYFILE):
        return jsonify({'ok':True, 'content':'', 'path':CADDYFILE})
    with open(CADDYFILE) as f: content = f.read()
    return jsonify({'ok':True, 'content':content, 'path':CADDYFILE})

@caddy_bp.route('/api/caddy/caddyfile', methods=['PUT'])
def save_caddyfile():
    if not req(): return jsonify({'ok':False}), 401
    content = (request.get_json() or {}).get('content','')
    backup = ''
    if os.path.exists(CADDYFILE):
        with open(CADDYFILE) as f: backup = f.read()
    with open(CADDYFILE,'w') as f: f.write(content)
    ok, msg = validate_caddy()
    if not ok:
        with open(CADDYFILE,'w') as f: f.write(backup)
        return jsonify({'ok':False, 'error':f'Validation failed: {msg}'}), 400
    reload_caddy()
    return jsonify({'ok':True})

@caddy_bp.route('/api/caddy/control', methods=['POST'])
def control():
    if not req(): return jsonify({'ok':False}), 401
    action = (request.get_json() or {}).get('action','status')
    if action not in ('start','stop','restart','reload'): return jsonify({'ok':False,'error':'Invalid action'}), 400
    sh(f'systemctl {action} caddy 2>/dev/null')
    status, _, _ = sh('systemctl is-active caddy 2>/dev/null')
    return jsonify({'ok':True, 'status':status or 'inactive'})

@caddy_bp.route('/api/caddy/logs')
def caddy_logs():
    if not req(): return jsonify({'ok':False}), 401
    lines = int(request.args.get('lines',100))
    out, _, _ = sh(f'journalctl -u caddy -n {lines} --no-pager 2>/dev/null')
    return jsonify({'ok':True, 'logs':out})

@caddy_bp.route('/api/caddy/sites/<domain>/ssl')
def ssl_info(domain):
    if not req(): return jsonify({'ok':False}), 401
    # Caddy stores certs in /var/lib/caddy/.local/share/caddy/certificates/
    cert_dirs = [
        f'/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/{domain}',
        f'/var/lib/caddy/.local/share/caddy/certificates/zerossl/{domain}',
        f'/root/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/{domain}',
    ]
    for d in cert_dirs:
        cert_file = os.path.join(d, f'{domain}.crt')
        if os.path.exists(cert_file):
            info, _, _ = sh(f'openssl x509 -in {cert_file} -noout -dates -subject -issuer 2>/dev/null')
            return jsonify({'ok':True, 'info':info, 'path':cert_file})
    return jsonify({'ok':True, 'info':'Certificate will be provisioned automatically when domain resolves to this server.'})
