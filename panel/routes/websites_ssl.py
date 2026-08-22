import os, re, json
from flask import jsonify, request

try:
    from panel.routes.websites_core import websites_bp, req, sh, get_nginx_dirs, reload_nginx, pkg_install, CF_CONFIG_FILE
except ImportError:
    from websites_core import websites_bp, req, sh, get_nginx_dirs, reload_nginx, pkg_install, CF_CONFIG_FILE


# --- CLOUDFLARE HELPERS ----------------------------------------------------------
def _cf_load_token():
    try:
        with open(CF_CONFIG_FILE) as fp:
            cfg = json.load(fp).get('cloudflare', {})
        return cfg.get('api_token')
    except Exception:
        return None


def _cf_api(url, token):
    import urllib.request, urllib.error
    req_obj = urllib.request.Request(url)
    req_obj.add_header('Authorization', f'Bearer {token}')
    req_obj.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req_obj, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {}


def cf_check_proxied(domain):
    """Returns (token, True/False/None). None = no CF token or zone not found -> fallback to HTTP-01."""
    token = _cf_load_token()
    if not token:
        return None, None

    # find root domain (last two labels) for zone lookup
    parts = domain.split('.')
    root = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

    zones = _cf_api(f'https://api.cloudflare.com/client/v4/zones?name={root}', token)
    results = zones.get('result') or []
    if not results:
        return token, None
    zone_id = results[0]['id']

    recs = _cf_api(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?per_page=100', token)
    records = recs.get('result') or []

    proxied = False
    found = False
    for r in records:
        name = r.get('name', '')
        if name == domain or name == f'www.{domain}':
            found = True
            if r.get('proxied'):
                proxied = True

    if not found:
        return token, None
    return token, proxied


def _ensure_dns_cloudflare_plugin():
    out = sh('certbot plugins 2>/dev/null')
    if 'dns-cloudflare' in out or 'dns_cloudflare' in out:
        return True
    pkg = pkg_install('python3-certbot-dns-cloudflare')
    sh(pkg, t=180)
    out = sh('certbot plugins 2>/dev/null')
    return 'dns-cloudflare' in out or 'dns_cloudflare' in out


def _write_cf_credentials(domain, token):
    cred_dir = '/etc/letsencrypt/cloudflare'
    os.makedirs(cred_dir, exist_ok=True)
    cred_path = f'{cred_dir}/{domain}.ini'
    with open(cred_path, 'w') as fp:
        fp.write(f'dns_cloudflare_api_token = {token}\n')
    os.chmod(cred_path, 0o600)
    return cred_path


def _inject_ssl_block(domain, cert_path, key_path):
    """Add ssl server block + http->https redirect to nginx vhost, reusing manual_ssl's pattern."""
    avail, _ = get_nginx_dirs()
    conf_path = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(conf_path):
        return False
    with open(conf_path) as fp:
        content = fp.read()
    if 'ssl_certificate' in content:
        return True  # already has SSL block
    root_match = re.search(r'root\s+([^;]+);', content)
    root_dir = root_match.group(1).strip() if root_match else '/www/wwwroot/' + domain
    ssl_block = f"""
server {{
    listen 443 ssl;
    server_name {domain} www.{domain};
    root {root_dir};
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
    http_old = 'listen 80;\n    server_name ' + domain
    http_new = 'listen 80;\n    server_name ' + domain + '\n    return 301 https://$host$request_uri;'
    content = content.replace(http_old, http_new)
    with open(conf_path, 'w') as fp:
        fp.write(content)
    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower():
        return False
    reload_nginx()
    return True


def _d_args(domain):
    """certbot -d args. Add www. ONLY for apex (2-label) domains -- a
    www.<subdomain> almost never has a DNS record and would fail the whole
    certificate request for a subdomain like blog.example.com."""
    return f'-d {domain}' + (f' -d www.{domain}' if domain.count('.') == 1 else '')


def _issue_cert(domain, email):
    """Auto-detect HTTP-01 vs DNS-01 (Cloudflare) and issue cert. Returns (ok, output, method)."""
    token, proxied = cf_check_proxied(domain)

    if token and proxied:
        # DNS-01 via Cloudflare
        if not _ensure_dns_cloudflare_plugin():
            out = sh(f'certbot --nginx {_d_args(domain)} --non-interactive --agree-tos -m {email} 2>&1', t=120)
            ok = 'Congratulations' in out or 'Certificate not yet due' in out or 'Successfully' in out
            return ok, out, 'http (dns-plugin install failed, fallback)'

        cred_path = _write_cf_credentials(domain, token)
        out = sh(
            f'certbot certonly --dns-cloudflare --dns-cloudflare-credentials {cred_path} '
            f'--dns-cloudflare-propagation-seconds 30 '
            f'{_d_args(domain)} --non-interactive --agree-tos -m {email} 2>&1',
            t=180
        )
        ok = 'Congratulations' in out or 'Certificate not yet due' in out or 'Successfully' in out
        if ok:
            cert_path = f'/etc/letsencrypt/live/{domain}/fullchain.pem'
            key_path  = f'/etc/letsencrypt/live/{domain}/privkey.pem'
            if not _inject_ssl_block(domain, cert_path, key_path):
                ok = False
                out += '\n[VortexPanel] Cert issued but nginx config update/test failed.'
        return ok, out, 'dns-cloudflare'

    # HTTP-01 (default / not proxied / no token)
    out = sh(f'certbot --nginx {_d_args(domain)} --non-interactive --agree-tos -m {email} 2>&1', t=120)
    ok = 'Congratulations' in out or 'Certificate not yet due' in out or 'Successfully' in out
    return ok, out, 'http'


# --- ROUTES ----------------------------------------------------------------------
@websites_bp.route('/api/websites/<domain>/ssl', methods=['POST'])
def issue_ssl(domain):
    if not req(): return jsonify({'ok':False}), 401
    email = (request.get_json() or {}).get('email', f'admin@{domain}')
    ok, out, method = _issue_cert(domain, email)
    return jsonify({'ok':ok, 'output':out[-800:], 'method':method})


@websites_bp.route('/api/websites/<domain>/ssl/letsencrypt', methods=['POST'])
def letsencrypt_ssl(domain):
    if not req(): return jsonify({'ok':False}), 401
    d     = request.get_json() or {}
    email = d.get('email', f'admin@{domain}')
    certbot = sh('which certbot 2>/dev/null')
    if not certbot:
        sh(pkg_install('certbot python3-certbot-nginx'), t=120)
    ok, out, method = _issue_cert(domain, email)
    return jsonify({'ok':ok, 'output':out[-800:], 'method':method})


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
            root_m = re.search(r'root\s+([^;]+);', content)
            root_dir = root_m.group(1).strip() if root_m else '/www/wwwroot/'+domain
            ssl_block = f"""
server {{
    listen 443 ssl;
    server_name {domain} www.{domain};
    root {root_dir};
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

