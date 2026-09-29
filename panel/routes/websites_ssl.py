import os, re, json
from datetime import datetime
from flask import jsonify, request

try:
    from panel.routes.websites_core import (websites_bp, req, sh, get_nginx_dirs, reload_nginx, pkg_install,
        CF_CONFIG_FILE, is_valid_domain, nginx_server_blocks, _nginx_apply, SSL_BEGIN, SSL_END, SSL_REDIRECT_TAG)
except ImportError:
    from websites_core import (websites_bp, req, sh, get_nginx_dirs, reload_nginx, pkg_install,
        CF_CONFIG_FILE, is_valid_domain, nginx_server_blocks, _nginx_apply, SSL_BEGIN, SSL_END, SSL_REDIRECT_TAG)


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


_SSL_LINE = re.compile(r'^[ \t]*(listen[^;]*\b443\b[^;]*;|ssl_[a-z_]+\s[^;]*;|include\s+/etc/letsencrypt/[^;]*;|'
                       r'http2\s+on;|http3\s+on;|quic_[a-z_]+\s[^;]*;|add_header\s+Alt-Svc[^;]*;)[^\n]*\n', re.M)
_HTTPS_REDIRECT = re.compile(r'^[ \t]*return\s+30[12]\s+https://[^;]*;[^\n]*\n', re.M)
# Repairs the server_name line corrupted by the old redirect injection:
#   server_name a.com\n    return 301 https://$host$request_uri; www.a.com;
_CORRUPT_SN = re.compile(r'(server_name[^;\n]*)\n[ \t]*return 301 https://\$host\$request_uri;([^\n]*;)')


def _nginx_conf_path(domain):
    avail, _ = get_nginx_dirs()
    return os.path.join(avail, f'{domain}.conf')


def nginx_add_ssl(content, domain, cert_path, key_path):
    """Return content with HTTPS enabled: the site's port-80 server block is
    cloned into a `listen 443 ssl` block (keeping PHP/locations/rewrites, so
    PHP sites keep working over HTTPS) and the port-80 block gets a redirect.
    Both additions carry markers so Disable SSL can remove them exactly."""
    content = _CORRUPT_SN.sub(r'\1\2', content)
    blocks = nginx_server_blocks(content)
    http = None
    for s_, e_ in blocks:
        b = content[s_:e_]
        if re.search(r'listen[^;]*\b443\b', b) or 'ssl_certificate' in b:
            return None  # SSL already configured
        if re.search(r'^\s*listen[^;]*\b80\b', b, re.M) and 'managed by Certbot' not in b:
            http = (s_, e_); break
    if not http and blocks:
        http = blocks[0]
    if not http:
        return None
    s_, e_ = http
    block = content[s_:e_]
    ssl = re.sub(r'^([ \t]*)listen([^;]*)\b80\b([^;]*);', r'\1listen\g<2>443 ssl\3;', block, flags=re.M)
    ssl = re.sub(r'^[ \t]*return\s+30[12]\s+https://[^\n]*\n', '', ssl, flags=re.M)
    m = re.search(r'\n([ \t]*)server_name[^;]*;[^\n]*', ssl)
    ind = m.group(1) if m else '    '
    ssl_lines = (f'\n{ind}ssl_certificate     {cert_path};\n{ind}ssl_certificate_key {key_path};\n'
                 f'{ind}ssl_protocols       TLSv1.2 TLSv1.3;\n{ind}ssl_ciphers         HIGH:!aNULL:!MD5;')
    pos = m.end() if m else ssl.index('{') + 1
    ssl = ssl[:pos] + ssl_lines + ssl[pos:]
    redirect_block = block
    if m:
        m2 = re.search(r'\n([ \t]*)server_name[^;]*;[^\n]*', block)
        redirect_block = (block[:m2.end()] + f'\n{m2.group(1)}return 301 https://$host$request_uri; {SSL_REDIRECT_TAG}'
                          + block[m2.end():])
    return (content[:s_] + redirect_block + content[e_:].rstrip('\n') +
            f'\n\n{SSL_BEGIN}\n{ssl}\n{SSL_END}\n')


def nginx_remove_ssl(content):
    """Return content with HTTPS removed, handling the three shapes a site
    can be in: VortexPanel marker blocks, the older unmarked VortexPanel
    format, and certbot --nginx edits ('# managed by Certbot')."""
    content = _CORRUPT_SN.sub(r'\1\2', content)
    # 1. VortexPanel-marked 443 block + tagged redirect
    content = re.sub(r'\n*' + re.escape(SSL_BEGIN) + r'.*?' + re.escape(SSL_END) + r'[^\n]*\n?', '\n', content, flags=re.S)
    content = re.sub(r'^[^\n]*' + re.escape(SSL_REDIRECT_TAG) + r'[^\n]*\n', '', content, flags=re.M)
    blocks = nginx_server_blocks(content)
    info = []
    for s_, e_ in blocks:
        b = content[s_:e_]
        is_ssl = bool(re.search(r'listen[^;]*\b443\b', b) or 'ssl_certificate' in b)
        certbot_redirect = ('managed by Certbot' in b and re.search(r'return\s+404', b)
                            and not re.search(r'^\s*(root|location|proxy_pass|fastcgi_pass)\b', b, re.M))
        has80 = bool(re.search(r'^\s*listen[^;]*\b80\b', b, re.M))
        info.append((s_, e_, is_ssl, bool(certbot_redirect), has80))
    content_blocks = [x for x in info if not x[3]]
    plain_http = [x for x in content_blocks if x[4] and not x[2]]
    listen80 = []
    out, last = [], 0
    for s_, e_, is_ssl, cb_redirect, has80 in info:
        b = content[s_:e_]
        if cb_redirect:
            listen80 += re.findall(r'^[ \t]*listen[^;]*\b80\b[^;]*;', b, re.M)
            out.append(content[last:s_]); last = e_
            continue
        if is_ssl and plain_http:
            # a separate HTTP block already serves the site: drop the HTTPS copy
            out.append(content[last:s_]); last = e_
            continue
        if is_ssl:
            # certbot style: HTTPS lives in the only content block - strip it back to HTTP
            b = re.sub(r'^[^\n]*# managed by Certbot[^\n]*\n', '', b, flags=re.M)
            b = _SSL_LINE.sub('', b)
            if not re.search(r'^\s*listen[^;]*\b80\b', b, re.M):
                lines = [l.strip() for l in listen80] or ['listen 80;']
                m = re.search(r'\n([ \t]*)\S', b)
                ind = m.group(1) if m else '    '
                b = b.replace('{', '{\n' + '\n'.join(ind + l for l in lines), 1)
        b = _HTTPS_REDIRECT.sub('', b)
        out.append(content[last:s_]); out.append(b); last = e_
    out.append(content[last:])
    # certbot redirect blocks can appear before the content block was seen;
    # if so the listen lines were collected too late - handle by a second pass
    result = ''.join(out)
    if listen80:
        for s_, e_ in nginx_server_blocks(result):
            b = result[s_:e_]
            if not re.search(r'^\s*listen[^;]*\b80\b', b, re.M):
                m = re.search(r'\n([ \t]*)\S', b)
                ind = m.group(1) if m else '    '
                nb = b.replace('{', '{\n' + '\n'.join(ind + l.strip() for l in listen80), 1)
                result = result[:s_] + nb + result[e_:]
                break
    return re.sub(r'\n{3,}', '\n\n', result)


def _inject_ssl_block(domain, cert_path, key_path):
    """Enable HTTPS on a site's nginx vhost with an already-issued cert."""
    conf_path = _nginx_conf_path(domain)
    if not os.path.exists(conf_path):
        return False
    with open(conf_path) as fp:
        content = fp.read()
    new = nginx_add_ssl(content, domain, cert_path, key_path)
    if new is None:
        return True  # already has SSL
    ok, _ = _nginx_apply(conf_path, new)
    return ok


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

    # Update nginx config to add SSL (validated with nginx -t, restored on failure)
    conf_path = _nginx_conf_path(domain)
    if os.path.exists(conf_path):
        with open(conf_path) as f: content = f.read()
        new = nginx_add_ssl(content, domain, cert_path, key_path)
        if new is not None:
            ok, err = _nginx_apply(conf_path, new)
            if not ok:
                return jsonify({'ok':False,'error':err}), 400
        else:
            reload_nginx()  # SSL block already present - pick up the new cert files
    return jsonify({'ok':True, 'key_path':key_path, 'cert_path':cert_path})


@websites_bp.route('/api/websites/<domain>/ssl/info')
def ssl_info(domain):
    if not req(): return jsonify({'ok':False}), 401
    if not is_valid_domain(domain):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400
    conf_path = _nginx_conf_path(domain)
    if os.path.exists(conf_path):
        with open(conf_path) as f:
            if 'ssl_certificate' not in f.read():
                # cert files may still be on disk after Disable SSL - the site isn't using them
                return jsonify({'ok':False,'error':'SSL is not enabled for this site'})
    cert_path = f'/etc/nginx/ssl/{domain}/fullchain.pem'
    # Also check certbot path
    for p in [cert_path, f'/etc/letsencrypt/live/{domain}/fullchain.pem']:
        if os.path.exists(p):
            info = sh(f'openssl x509 -in {p} -noout -dates -subject -issuer 2>/dev/null')
            expiry = sh(f'openssl x509 -in {p} -noout -enddate 2>/dev/null')
            # Structured fields for the SSL tab's summary banner, parsed from
            # the same openssl output rather than a second subprocess call -
            # the raw `info` text is still returned as-is for anyone who
            # wants it, this just saves the frontend from doing its own
            # regex-on-shell-output parsing.
            issuer_m = re.search(r'issuer=.*?O\s*=\s*([^,\n]+)', info)
            brand = issuer_m.group(1).strip() if issuer_m else (
                'Let\'s Encrypt' if 'letsencrypt' in p else 'Custom')
            not_after = None
            if expiry.startswith('notAfter='):
                try:
                    not_after = datetime.strptime(expiry[9:].strip(), '%b %d %H:%M:%S %Y %Z')
                except Exception:
                    pass
            days_left = (not_after - datetime.utcnow()).days if not_after else None
            return jsonify({
                'ok': True, 'info': info, 'expiry': expiry, 'path': p,
                'brand': brand, 'domain': domain,
                'expires_on': not_after.strftime('%Y-%m-%d') if not_after else '',
                'days_left': days_left,
            })
    return jsonify({'ok':False,'error':'No SSL certificate installed'})


@websites_bp.route('/api/websites/<domain>/ssl/disable', methods=['POST'])
def disable_ssl(domain):
    """Turn HTTPS off for a site: removes the 443 server block / certbot edits
    and the http->https redirect, validated with nginx -t (restored on
    failure). Certificate files are left on disk so SSL can be re-enabled."""
    if not req(): return jsonify({'ok':False}), 401
    if not is_valid_domain(domain):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400
    conf_path = _nginx_conf_path(domain)
    if not os.path.exists(conf_path):
        return jsonify({'ok':False,'error':'Disable SSL is currently supported for nginx sites only'}), 400
    with open(conf_path) as f:
        content = f.read()
    if 'ssl_certificate' not in content and not re.search(r'listen[^;]*\b443\b', content):
        return jsonify({'ok':True,'message':'SSL was not enabled for this site'})
    new = nginx_remove_ssl(content)
    if 'ssl_certificate' in new or re.search(r'listen[^;]*\b443\b', new):
        return jsonify({'ok':False,'error':'Could not safely remove SSL from this config automatically - edit it in the Config tab'}), 400
    ok, err = _nginx_apply(conf_path, new)
    if not ok:
        return jsonify({'ok':False,'error':err}), 500
    return jsonify({'ok':True})
