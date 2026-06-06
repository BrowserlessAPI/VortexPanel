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

# ── REVERSE PROXY ─────────────────────────────────────────────────────────────
@websites_bp.route('/api/websites/<domain>/proxy', methods=['GET'])
def get_proxies(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    proxies = []
    if os.path.exists(fp):
        with open(fp) as f: content = f.read()
        for m in re.finditer(r'#VP_PROXY:([^\n]+)\n.*?location\s+(\S+)\s*\{[^}]*proxy_pass\s+([^;]+);', content, re.DOTALL):
            proxies.append({'name':m.group(1).strip(),'path':m.group(2),'target':m.group(3).strip()})
    return jsonify({'ok':True,'proxies':proxies})

@websites_bp.route('/api/websites/<domain>/proxy', methods=['POST'])
def add_proxy(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    name   = d.get('name', f'proxy_{domain[:6]}')
    path   = d.get('path', '/')
    target = d.get('target','').strip()
    sent_domain = d.get('sent_domain','$host')
    if not target: return jsonify({'ok':False,'error':'Target URL required'}), 400

    proxy_block = f"""
#VP_PROXY:{name}
location {path} {{
    proxy_pass {target};
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host {sent_domain};
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_cache_bypass $http_upgrade;
}}
"""
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site config not found'}), 404
    with open(fp) as f: content = f.read()
    # Insert before closing brace of first server block
    content = re.sub(r'(}\s*)$', proxy_block + r'\1', content, count=1)
    with open(fp,'w') as f: f.write(content)
    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower():
        return jsonify({'ok':False,'error':f'Nginx config error: {test}'}), 400
    reload_nginx()
    return jsonify({'ok':True})

@websites_bp.route('/api/websites/<domain>/proxy/<name>', methods=['DELETE'])
def del_proxy(domain, name):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Not found'}), 404
    with open(fp) as f: content = f.read()
    # Remove the proxy block
    content = re.sub(rf'\n#VP_PROXY:{re.escape(name)}\nlocation[^{{]+\{{[^}}]+\}}\n', '\n', content)
    with open(fp,'w') as f: f.write(content)
    reload_nginx()
    return jsonify({'ok':True})

# ── REDIRECT ──────────────────────────────────────────────────────────────────
@websites_bp.route('/api/websites/<domain>/redirect', methods=['POST'])
def set_redirect(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    target  = d.get('target','').strip()
    mode    = d.get('mode','301')
    keep_uri= d.get('keep_uri', True)
    if not target: return jsonify({'ok':False,'error':'Target URL required'}), 400

    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site not found'}), 404

    uri_part = '$request_uri' if keep_uri else ''
    redir_line = f'return {mode} {target}{uri_part};'

    with open(fp) as f: content = f.read()
    # Replace existing redirect or add to server block
    if re.search(r'#VP_REDIRECT', content):
        content = re.sub(r'#VP_REDIRECT\n\s*return [^\n]+;', f'#VP_REDIRECT\n    {redir_line}', content)
    else:
        content = re.sub(r'(server\s*\{[^\n]*\n)', rf'\1    #VP_REDIRECT\n    {redir_line}\n', content, count=1)
    with open(fp,'w') as f: f.write(content)
    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower():
        return jsonify({'ok':False,'error':test}), 400
    reload_nginx()
    return jsonify({'ok':True})

@websites_bp.route('/api/websites/<domain>/redirect', methods=['DELETE'])
def del_redirect(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Not found'}), 404
    with open(fp) as f: content = f.read()
    content = re.sub(r'\s*#VP_REDIRECT\n\s*return [^\n]+;\n', '\n', content)
    with open(fp,'w') as f: f.write(content)
    reload_nginx(); return jsonify({'ok':True})

# ── PHP VERSION PER DOMAIN ────────────────────────────────────────────────────
@websites_bp.route('/api/websites/<domain>/php', methods=['PUT'])
def set_php_version(domain):
    if not req(): return jsonify({'ok':False}), 401
    ver = (request.get_json() or {}).get('version','8.3')
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site not found'}), 404

    with open(fp) as f: content = f.read()
    # Find correct socket path
    sock = f'/run/php/php{ver}-fpm.sock'
    for s in [f'/run/php/php{ver}-fpm.sock',f'/var/run/php/php{ver}-fpm.sock',f'/tmp/php{ver}-fpm.sock']:
        if os.path.exists(s): sock = s; break
    # Replace existing fastcgi_pass
    content = re.sub(r'fastcgi_pass\s+unix:[^;]+;', f'fastcgi_pass unix:{sock};', content)
    with open(fp,'w') as f: f.write(content)
    reload_nginx(); return jsonify({'ok':True,'sock':sock})

# ── MAINTENANCE MODE ──────────────────────────────────────────────────────────
MAINTENANCE_HTML = '''<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Under Maintenance</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d0f14;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh}}
.box{{text-align:center;padding:48px 40px;background:#1f2230;border:1px solid #1e2235;border-radius:16px;max-width:480px;width:90%}}
.logo{{width:64px;height:64px;background:linear-gradient(135deg,#5865f2,#06b6d4);border-radius:16px;display:flex;align-items:center;justify-content:center;font-size:28px;margin:0 auto 20px}}
h1{{font-size:24px;font-weight:700;margin-bottom:12px}}
p{{color:#94a3b8;font-size:15px;line-height:1.6}}
.badge{{display:inline-block;background:rgba(245,158,11,.12);color:#f59e0b;border:1px solid rgba(245,158,11,.2);padding:6px 18px;border-radius:20px;font-size:13px;font-weight:600;margin-top:20px}}
</style></head>
<body><div class="box">
<div class="logo">⚡</div>
<h1>Under Maintenance</h1>
<p>{message}</p>
<div class="badge">🔧 We\'ll be back shortly</div>
</div></body></html>'''

@websites_bp.route('/api/websites/<domain>/maintenance', methods=['POST'])
def set_maintenance(domain):
    if not req(): return jsonify({'ok':False}), 401
    d       = request.get_json() or {}
    enable  = d.get('enable', True)
    message = d.get('message', 'We are currently performing scheduled maintenance. Please check back soon.')

    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site not found'}), 404

    # Write maintenance HTML file
    webroot_m = re.search(r'root\s+([^;]+);', open(fp).read())
    webroot = webroot_m.group(1).strip() if webroot_m else f'/www/wwwroot/{domain}'
    maint_file = f'{webroot}/maintenance.html'

    if enable:
        with open(maint_file,'w') as f:
            f.write(MAINTENANCE_HTML.format(message=message))
        with open(fp) as f: content = f.read()
        if '#VP_MAINTENANCE' not in content:
            maint_block = f'''
    #VP_MAINTENANCE
    set $maintenance 1;
    if ($remote_addr = "127.0.0.1") {{ set $maintenance 0; }}
    if ($maintenance = 1) {{
        return 503;
    }}
    error_page 503 /maintenance.html;
    location = /maintenance.html {{
        root {webroot};
        internal;
    }}
'''
            content = re.sub(r'(server\s*\{[^\n]*\n)', r'\1' + maint_block, content, count=1)
            with open(fp,'w') as f: f.write(content)
    else:
        with open(fp) as f: content = f.read()
        content = re.sub(r'\s*#VP_MAINTENANCE.*?(?=\n\s*location|\n\s*})', '', content, flags=re.DOTALL)
        with open(fp,'w') as f: f.write(content)
        try: os.unlink(maint_file)
        except: pass

    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower(): return jsonify({'ok':False,'error':test}), 400
    reload_nginx()
    return jsonify({'ok':True,'enabled':enable})

@websites_bp.route('/api/websites/<domain>/maintenance')
def get_maintenance(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':True,'enabled':False})
    with open(fp) as f: content = f.read()
    return jsonify({'ok':True,'enabled':'#VP_MAINTENANCE' in content})

# ── NODE.JS HOSTING ───────────────────────────────────────────────────────────
@websites_bp.route('/api/websites/<domain>/nodejs', methods=['POST'])
def setup_nodejs(domain):
    if not req(): return jsonify({'ok':False}), 401
    d       = request.get_json() or {}
    port    = d.get('port', '3000')
    app_path = d.get('app_path', f'/www/wwwroot/{domain}')
    startup = d.get('startup', 'index.js')
    enable  = d.get('enable', True)

    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site not found'}), 404

    if enable:
        # Install PM2 if not present
        if not sh('which pm2 2>/dev/null'):
            sh('npm install -g pm2 2>/dev/null', t=60)

        # Update nginx config to proxy to Node
        with open(fp) as f: content = f.read()
        # Replace PHP fastcgi with proxy_pass
        node_location = f'''    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_cache_bypass $http_upgrade;
    }}
    #VP_NODEJS:{port}'''
        # Remove existing location / and PHP fastcgi
        content = re.sub(r'location\s+/\s*\{[^}]+\}', '', content)
        content = re.sub(r'location\s+~\s+\\.php\$[^}]+\}', '', content, flags=re.DOTALL)
        content = re.sub(r'(}\s*)$', '    ' + node_location + '\n' + r'\1', content, count=1)
        with open(fp,'w') as f: f.write(content)

        # Start app with PM2
        pm2_name = domain.replace('.','_')
        sh(f'cd {app_path} && pm2 start {startup} --name {pm2_name} 2>/dev/null || pm2 restart {pm2_name} 2>/dev/null')
        sh('pm2 save 2>/dev/null')
    else:
        # Stop PM2 app
        pm2_name = domain.replace('.','_')
        sh(f'pm2 stop {pm2_name} 2>/dev/null')
        # Remove nodejs marker from config
        with open(fp) as f: content = f.read()
        content = re.sub(r'\s*#VP_NODEJS:\d+', '', content)
        with open(fp,'w') as f: f.write(content)

    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower(): return jsonify({'ok':False,'error':test}), 400
    reload_nginx()
    return jsonify({'ok':True,'port':port})

@websites_bp.route('/api/websites/<domain>/nodejs')
def get_nodejs(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':True,'enabled':False})
    with open(fp) as f: content = f.read()
    m = re.search(r'#VP_NODEJS:(\d+)', content)
    return jsonify({'ok':True,'enabled':bool(m),'port':m.group(1) if m else ''})

# ── ONE-CLICK DEPLOY ──────────────────────────────────────────────────────────
DEPLOY_APPS = {
    'wordpress': {
        'name':'WordPress','version':'6.7.2','icon':'https://s.w.org/style/images/about/WordPress-logotype-standard.png',
        'desc':'The world\'s most popular CMS. Powers 43% of the web.',
        'url':'https://wordpress.org/latest.tar.gz','dir':'wordpress',
        'cmd':'''wget -q https://wordpress.org/latest.tar.gz -O /tmp/wp.tar.gz && \
tar -xzf /tmp/wp.tar.gz -C {path}/ --strip-components=1 && \
cp {path}/wp-config-sample.php {path}/wp-config.php && \
chown -R www-data:www-data {path}/ 2>/dev/null || true''',
    },
    'drupal': {
        'name':'Drupal','version':'11.1','icon':'https://www.drupal.org/files/druplicon-small.png',
        'desc':'Enterprise-grade CMS trusted by governments & Fortune 500.',
        'cmd':'''wget -q https://ftp.drupal.org/files/projects/drupal-11.1.0.tar.gz -O /tmp/drupal.tar.gz && \
tar -xzf /tmp/drupal.tar.gz -C {path}/ --strip-components=1 && \
chown -R www-data:www-data {path}/ 2>/dev/null || true''',
    },
    'joomla': {
        'name':'Joomla','version':'5.2','icon':'https://www.joomla.org/images/joomla_logo_black.png',
        'desc':'Flexible CMS for complex websites and web applications.',
        'cmd':'''wget -q https://github.com/joomla/joomla-cms/releases/download/5.2.6/Joomla_5.2.6-Stable-Full_Package.tar.gz -O /tmp/joomla.tar.gz && \
tar -xzf /tmp/joomla.tar.gz -C {path}/ && \
chown -R www-data:www-data {path}/ 2>/dev/null || true''',
    },
    'laravel': {
        'name':'Laravel','version':'11.x','icon':'https://laravel.com/img/logomark.min.svg',
        'desc':'The PHP framework for web artisans. Elegant, expressive syntax.',
        'cmd':'''which composer 2>/dev/null || curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer && \
composer create-project laravel/laravel {path} --prefer-dist -q && \
chown -R www-data:www-data {path}/ 2>/dev/null || true''',
    },
    'opencart': {
        'name':'OpenCart','version':'4.1.0','icon':'https://www.opencart.com/application/view/image/icon/opencart-logo.png',
        'desc':'Open source ecommerce solution — easy to use, feature-rich.',
        'cmd':'''wget -q https://github.com/opencart/opencart/releases/download/4.1.0.3/opencart-4.1.0.3.zip -O /tmp/oc.zip && \
apt-get install -y unzip -qq && \
unzip -q /tmp/oc.zip -d /tmp/oc_extract/ && \
cp -r /tmp/oc_extract/upload/. {path}/ && \
chown -R www-data:www-data {path}/ 2>/dev/null || true''',
    },
}

@websites_bp.route('/api/websites/deploy-apps')
def deploy_apps():
    if not req(): return jsonify({'ok':False}), 401
    apps = [{**{k:v for k,v in a.items() if k!='cmd'}, 'id':aid} for aid,a in DEPLOY_APPS.items()]
    return jsonify({'ok':True,'apps':apps})

@websites_bp.route('/api/websites/<domain>/deploy', methods=['POST'])
def deploy_app(domain):
    if not req(): return jsonify({'ok':False}), 401
    d      = request.get_json() or {}
    app_id = d.get('app','wordpress')
    app    = DEPLOY_APPS.get(app_id)
    if not app: return jsonify({'ok':False,'error':'Unknown app'}), 404

    # Get site path
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    path = f'{get_webroot()}/{domain}'
    if os.path.exists(fp):
        with open(fp) as f: content = f.read()
        m = re.search(r'root\s+([^;]+);', content)
        if m: path = m.group(1).strip()

    os.makedirs(path, exist_ok=True)
    cmd = app['cmd'].replace('{path}', path)
    out = sh(f'DEBIAN_FRONTEND=noninteractive {cmd} 2>&1', t=300)
    ok  = os.path.exists(path) and len(os.listdir(path)) > 2
    return jsonify({'ok':ok, 'output':out[-500:], 'path':path})
