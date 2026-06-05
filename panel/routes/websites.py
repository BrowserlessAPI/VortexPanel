from flask import Blueprint, jsonify, request, session
import os, re, subprocess

websites_bp = Blueprint('websites', __name__)
WEBROOT = '/www/wwwroot'

def req(): return 'user' in session
def sh(c, t=15):
    try: return subprocess.check_output(c, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=t).strip()
    except: return ''

def get_nginx_dirs():
    """Return available nginx config dirs"""
    candidates = [
        ('/etc/nginx/sites-available', '/etc/nginx/sites-enabled'),
        ('/etc/nginx/conf.d', '/etc/nginx/conf.d'),
        ('/usr/local/nginx/conf/vhosts', '/usr/local/nginx/conf/vhosts'),
        ('/www/server/panel/vhost/nginx', '/www/server/panel/vhost/nginx'),
    ]
    for avail, enabled in candidates:
        if os.path.isdir(avail):
            return avail, enabled
    # None found — create the standard ones
    os.makedirs('/etc/nginx/sites-available', exist_ok=True)
    os.makedirs('/etc/nginx/sites-enabled', exist_ok=True)
    return '/etc/nginx/sites-available', '/etc/nginx/sites-enabled'

def get_webroot():
    for p in [WEBROOT, '/var/www/html', '/var/www', '/srv/www']:
        if os.path.isdir(p): return p
    os.makedirs(WEBROOT, exist_ok=True)
    return WEBROOT

def reload_nginx():
    # Try different nginx reload methods
    for cmd in ['systemctl reload nginx', 'nginx -s reload', 'service nginx reload']:
        if sh(f'{cmd} 2>/dev/null') is not None:
            break

def list_sites():
    sites = []
    avail, enabled = get_nginx_dirs()
    try:
        for f in os.listdir(avail):
            fp = os.path.join(avail, f)
            if not os.path.isfile(fp): continue
            try:
                with open(fp) as fh: content = fh.read()
            except: continue
            domains = re.findall(r'server_name\s+([^;]+);', content)
            domain = domains[0].strip().split()[0] if domains else f.replace('.conf','')
            ssl    = 'ssl_certificate' in content
            php_m  = re.search(r'fastcgi_pass.*php(\d+[\.\d]*).*fpm', content)
            php_v  = php_m.group(1) if php_m else 'Static'
            enabled_path = os.path.join(enabled, f)
            is_enabled = os.path.exists(enabled_path) or avail == enabled
            path_m = re.search(r'root\s+([^;]+);', content)
            path   = path_m.group(1).strip() if path_m else f'{get_webroot()}/{domain}'
            sites.append({'domain':domain,'ssl':ssl,'php':php_v,'enabled':is_enabled,'path':path,'conf_file':f})
    except: pass
    return sites

@websites_bp.route('/api/websites')
def get_sites():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, 'sites':list_sites(), 'webroot':get_webroot()})

@websites_bp.route('/api/websites', methods=['POST'])
def create_site():
    if not req(): return jsonify({'ok':False}), 401
    d      = request.get_json() or {}
    domain = d.get('domain','').strip().lower()
    path   = d.get('path', f'{get_webroot()}/{domain}').strip()
    php    = d.get('php','8.3')
    if not domain: return jsonify({'ok':False,'error':'Domain required'}), 400

    # Create webroot
    os.makedirs(path, exist_ok=True)
    idx = os.path.join(path, 'index.html')
    if not os.path.exists(idx):
        with open(idx,'w') as f:
            f.write(f'<!DOCTYPE html><html><body><h1>Welcome to {domain}</h1><p>VortexPanel — site created successfully.</p></body></html>')

    avail, enabled_dir = get_nginx_dirs()

    # Build nginx config
    php_sock = f'/run/php/php{php}-fpm.sock'
    # Check alternative socket paths
    for sock in [f'/run/php/php{php}-fpm.sock', f'/var/run/php/php{php}-fpm.sock',
                 f'/tmp/php{php}-fpm.sock', f'/run/php-fpm/php{php}-fpm.sock']:
        if os.path.exists(sock):
            php_sock = sock
            break

    fastcgi = f"""
    location ~ \\.php$ {{
        include fastcgi_params;
        fastcgi_pass unix:{php_sock};
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_index index.php;
    }}""" if php != 'Static' else ''

    conf = f"""server {{
    listen 80;
    server_name {domain} www.{domain};
    root {path};
    index index.php index.html index.htm;

    access_log /var/log/nginx/{domain}.access.log;
    error_log  /var/log/nginx/{domain}.error.log;

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}
    {fastcgi}
    location ~ /\\.ht {{
        deny all;
    }}
}}
"""
    conf_file = f'{domain}.conf'
    conf_path = os.path.join(avail, conf_file)
    enabled_path = os.path.join(enabled_dir, conf_file)

    try:
        with open(conf_path, 'w') as f: f.write(conf)
        # Create symlink if sites-available != sites-enabled
        if avail != enabled_dir and not os.path.exists(enabled_path):
            os.symlink(conf_path, enabled_path)
        # Test nginx config
        test = sh('nginx -t 2>&1')
        if 'failed' in test.lower():
            return jsonify({'ok':False, 'error':f'Nginx config test failed: {test}'}), 400
        reload_nginx()
        return jsonify({'ok':True, 'domain':domain, 'path':path})
    except Exception as e:
        return jsonify({'ok':False, 'error':str(e)}), 500

@websites_bp.route('/api/websites/<domain>', methods=['DELETE'])
def delete_site(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, enabled_dir = get_nginx_dirs()
    for d in [avail, enabled_dir]:
        for f in [f'{domain}.conf', domain]:
            p = os.path.join(d, f)
            try: os.unlink(p)
            except: pass
    reload_nginx()
    return jsonify({'ok':True})

@websites_bp.route('/api/websites/<domain>/ssl', methods=['POST'])
def issue_ssl(domain):
    if not req(): return jsonify({'ok':False}), 401
    email = (request.get_json() or {}).get('email', f'admin@{domain}')
    out   = sh(f'certbot --nginx -d {domain} -d www.{domain} --non-interactive --agree-tos -m {email} 2>&1', t=120)
    ok    = 'Congratulations' in out or 'Certificate not yet due' in out
    return jsonify({'ok':ok, 'output':out[-500:]})

@websites_bp.route('/api/websites/<domain>/config')
def get_config(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if os.path.exists(fp):
        with open(fp) as f: return jsonify({'ok':True, 'content':f.read(), 'path':fp})
    return jsonify({'ok':False, 'error':'Config not found'}), 404

@websites_bp.route('/api/websites/<domain>/config', methods=['PUT'])
def save_config(domain):
    if not req(): return jsonify({'ok':False}), 401
    content = (request.get_json() or {}).get('content','')
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if os.path.exists(fp):
        with open(fp,'w') as f: f.write(content)
        reload_nginx()
        return jsonify({'ok':True})
    return jsonify({'ok':False, 'error':'Not found'}), 404

@websites_bp.route('/api/websites/webroot')
def webroot():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, 'path':get_webroot()})

@websites_bp.route('/api/websites/<domain>/ssl/letsencrypt', methods=['POST'])
def letsencrypt_ssl(domain):
    if not req(): return jsonify({'ok':False}), 401
    d     = request.get_json() or {}
    email = d.get('email', f'admin@{domain}')
    # Try certbot
    certbot = sh('which certbot 2>/dev/null')
    if not certbot:
        out = sh('apt-get install -y certbot python3-certbot-nginx 2>&1', t=120)
    out = sh(f'certbot --nginx -d {domain} -d www.{domain} --non-interactive --agree-tos -m {email} 2>&1', t=120)
    ok = 'Congratulations' in out or 'Certificate not yet due' in out or 'Successfully' in out
    return jsonify({'ok':ok, 'output':out[-800:]})

@websites_bp.route('/api/websites/<domain>/ssl/manual', methods=['POST'])
def manual_ssl(domain):
    if not req(): return jsonify({'ok':False}), 401
    d    = request.get_json() or {}
    key  = d.get('key','').strip()
    cert = d.get('cert','').strip()
    if not key or not cert:
        return jsonify({'ok':False,'error':'Private key and certificate are required'}), 400

    ssl_dir = f'/etc/nginx/ssl/{domain}'
    os.makedirs(ssl_dir, exist_ok=True)

    key_path  = f'{ssl_dir}/privkey.pem'
    cert_path = f'{ssl_dir}/fullchain.pem'
    with open(key_path,  'w') as f: f.write(key)
    with open(cert_path, 'w') as f: f.write(cert)
    os.chmod(key_path, 0o600)

    # Update nginx config to add SSL
    avail, _ = get_nginx_dirs()
    conf_path = os.path.join(avail, f'{domain}.conf')
    if os.path.exists(conf_path):
        with open(conf_path) as f: content = f.read()
        # Add ssl server block if not already there
        if 'ssl_certificate' not in content:
            ssl_block = f"""
server {{
    listen 443 ssl;
    server_name {domain} www.{domain};
    root {re.search(r'root\s+([^;]+);', content).group(1).strip() if re.search(r'root\s+([^;]+);', content) else '/www/wwwroot/'+domain};
    index index.php index.html;

    ssl_certificate     {cert_path};
    ssl_certificate_key {key_path};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}
}}
"""
            content += ssl_block
            # Add redirect from http to https
            http_old = 'listen 80;\n    server_name ' + domain
            http_new = 'listen 80;\n    server_name ' + domain + '\n    return 301 https://$host$request_uri;'
            content = content.replace(http_old, http_new)
            with open(conf_path,'w') as f: f.write(content)

    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower():
        return jsonify({'ok':False,'error':f'Nginx config error: {test}'}), 400
    reload_nginx()
    return jsonify({'ok':True, 'key_path':key_path, 'cert_path':cert_path})

@websites_bp.route('/api/websites/<domain>/ssl/info')
def ssl_info(domain):
    if not req(): return jsonify({'ok':False}), 401
    cert_path = f'/etc/nginx/ssl/{domain}/fullchain.pem'
    # Also check certbot path
    for p in [cert_path, f'/etc/letsencrypt/live/{domain}/fullchain.pem']:
        if os.path.exists(p):
            info = sh(f'openssl x509 -in {p} -noout -dates -subject -issuer 2>/dev/null')
            expiry = sh(f'openssl x509 -in {p} -noout -enddate 2>/dev/null')
            return jsonify({'ok':True,'info':info,'expiry':expiry,'path':p})
    return jsonify({'ok':False,'error':'No SSL certificate installed'})
