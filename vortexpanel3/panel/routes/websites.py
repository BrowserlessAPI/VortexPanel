from flask import Blueprint, jsonify, request, session
import os, re, subprocess

websites_bp = Blueprint('websites', __name__)
NGINX_SITES = '/etc/nginx/sites-available'
NGINX_ENABLED = '/etc/nginx/sites-enabled'
WEBROOT = '/www/wwwroot'

def req(): return 'user' in session
def sh(c,t=15):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL,timeout=t).strip()
    except: return ''

def list_sites():
    sites = []
    conf_dir = NGINX_SITES if os.path.isdir(NGINX_SITES) else '/etc/nginx/conf.d'
    try:
        for f in os.listdir(conf_dir):
            if not f.endswith('.conf') and conf_dir == '/etc/nginx/conf.d': continue
            fp = os.path.join(conf_dir, f)
            try:
                with open(fp) as fh: content = fh.read()
            except: continue
            domains = re.findall(r'server_name\s+([^;]+);', content)
            domain = domains[0].strip().split()[0] if domains else f.replace('.conf','')
            ssl = 'ssl_certificate' in content
            php_match = re.search(r'fastcgi_pass.*php(\d+[\.\d]*).*fpm', content)
            php_ver = php_match.group(1) if php_match else 'Static'
            enabled = os.path.exists(os.path.join(NGINX_ENABLED, f))
            path_match = re.search(r'root\s+([^;]+);', content)
            path = path_match.group(1).strip() if path_match else f'{WEBROOT}/{domain}'
            sites.append({'domain':domain,'ssl':ssl,'php':php_ver,'enabled':enabled,'path':path,'conf_file':f})
    except: pass
    return sites

@websites_bp.route('/api/websites')
def get_sites():
    if not req(): return jsonify({'ok':False}),401
    return jsonify({'ok':True,'sites':list_sites()})

@websites_bp.route('/api/websites', methods=['POST'])
def create_site():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    domain = d.get('domain','').strip()
    path   = d.get('path', f'{WEBROOT}/{domain}').strip()
    php    = d.get('php','8.3')
    ssl    = d.get('ssl', False)
    if not domain: return jsonify({'ok':False,'error':'Domain required'}),400

    os.makedirs(path, exist_ok=True)
    # Write default index.html
    idx = os.path.join(path, 'index.html')
    if not os.path.exists(idx):
        with open(idx,'w') as f:
            f.write(f'<h1>Welcome to {domain}</h1>')

    php_sock = f'/run/php/php{php}-fpm.sock' if php != 'Static' else None
    fastcgi_block = f"""
    location ~ \\.php$ {{
        include fastcgi_params;
        fastcgi_pass unix:{php_sock};
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }}""" if php_sock else ''

    conf = f"""server {{
    listen 80;
    server_name {domain} www.{domain};
    root {path};
    index index.php index.html index.htm;

    access_log /var/log/nginx/{domain}.access.log;
    error_log  /var/log/nginx/{domain}.error.log;
    {fastcgi_block}
    location / {{
        try_files $uri $uri/ =404;
    }}
}}
"""
    conf_path = f'/etc/nginx/sites-available/{domain}.conf'
    enabled_path = f'/etc/nginx/sites-enabled/{domain}.conf'
    try:
        with open(conf_path,'w') as f: f.write(conf)
        if not os.path.exists(enabled_path):
            os.symlink(conf_path, enabled_path)
        sh('nginx -t && systemctl reload nginx')
        return jsonify({'ok':True,'domain':domain})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)}),500

@websites_bp.route('/api/websites/<domain>', methods=['DELETE'])
def delete_site(domain):
    if not req(): return jsonify({'ok':False}),401
    for d in [NGINX_SITES, NGINX_ENABLED, '/etc/nginx/conf.d']:
        for f in [f'{d}/{domain}.conf', f'{d}/{domain}']:
            try: os.unlink(f)
            except: pass
    sh('nginx -t && systemctl reload nginx')
    return jsonify({'ok':True})

@websites_bp.route('/api/websites/<domain>/ssl', methods=['POST'])
def issue_ssl(domain):
    if not req(): return jsonify({'ok':False}),401
    email = (request.get_json() or {}).get('email','admin@'+domain)
    ok, out = True, sh(f'certbot --nginx -d {domain} -d www.{domain} --non-interactive --agree-tos -m {email}', t=120)
    return jsonify({'ok':ok,'output':out})

@websites_bp.route('/api/websites/<domain>/config')
def get_config(domain):
    if not req(): return jsonify({'ok':False}),401
    for d in [NGINX_SITES, '/etc/nginx/conf.d']:
        fp = f'{d}/{domain}.conf'
        if os.path.exists(fp):
            with open(fp) as f: return jsonify({'ok':True,'content':f.read(),'path':fp})
    return jsonify({'ok':False,'error':'Config not found'}),404

@websites_bp.route('/api/websites/<domain>/config', methods=['PUT'])
def save_config(domain):
    if not req(): return jsonify({'ok':False}),401
    content = (request.get_json() or {}).get('content','')
    for d in [NGINX_SITES, '/etc/nginx/conf.d']:
        fp = f'{d}/{domain}.conf'
        if os.path.exists(fp):
            with open(fp,'w') as f: f.write(content)
            ok = sh('nginx -t') ; sh('systemctl reload nginx')
            return jsonify({'ok':True})
    return jsonify({'ok':False,'error':'Not found'}),404
