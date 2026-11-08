import os, re, json, shlex, subprocess, tempfile
from datetime import datetime
from flask import jsonify, request

try:
    from panel.routes import os_utils as _ou
except ImportError:
    import os_utils as _ou

try:
    from panel.routes.websites_core import (websites_bp, req, sh, get_nginx_dirs, reload_nginx, pkg_install,
        CF_CONFIG_FILE, is_valid_domain, nginx_server_blocks, _nginx_apply, SSL_BEGIN, SSL_END, SSL_REDIRECT_TAG,
        _find_site_config, apache_apply, apache_layout, get_os, apache_edit_site)
except ImportError:
    from websites_core import (websites_bp, req, sh, get_nginx_dirs, reload_nginx, pkg_install,
        CF_CONFIG_FILE, is_valid_domain, nginx_server_blocks, _nginx_apply, SSL_BEGIN, SSL_END, SSL_REDIRECT_TAG,
        _find_site_config, apache_apply, apache_layout, get_os, apache_edit_site)


def _run_out(cmd, t=120):
    """Run a command and return its output even when it fails -- certbot's
    error text is the only explanation the user gets (the shared sh() helper
    returns '' on a non-zero exit, so failed requests showed no reason)."""
    import subprocess
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return f'[VortexPanel] The certificate request did not finish within {t} seconds.'
    except Exception as e:
        return f'[VortexPanel] Could not run certbot: {e}'


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

    # Find the zone by walking up the labels: the old "last two labels"
    # guess never found zones such as example.co.uk.
    parts = domain.split('.')
    results = []
    for i in range(0, max(len(parts) - 1, 1)):
        cand = '.'.join(parts[i:])
        zones = _cf_api(f'https://api.cloudflare.com/client/v4/zones?name={cand}', token)
        results = zones.get('result') or []
        if results:
            break
    if not results:
        return token, None
    zone_id = results[0]['id']

    # Query the two names directly -- listing only the first 100 records
    # missed them in larger zones.
    records = []
    for name in (domain, f'www.{domain}'):
        recs = _cf_api(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={name}', token)
        records += recs.get('result') or []

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
    # created 0600 from the start (was world-readable until the chmod)
    fd = os.open(cred_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as fp:
        fp.write(f'dns_cloudflare_api_token = {token}\n')
    os.chmod(cred_path, 0o600)
    return cred_path


_EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')


def _reload_hook(ws):
    """certonly (DNS-01) installs nothing, so a renewed certificate was never
    loaded by the web server: it kept serving the old one until it expired.
    The deploy hook is stored in the renewal config and runs on every renewal."""
    cmd = ('systemctl reload apache2 2>/dev/null || systemctl reload httpd' if ws == 'apache'
           else 'systemctl reload nginx')
    return '--deploy-hook ' + shlex.quote(cmd)


_SSL_LINE = re.compile(r'^[ \t]*(listen[^;]*\b443\b[^;]*;|ssl_[a-z_]+\s[^;]*;|include\s+/etc/letsencrypt/[^;]*;|'
                       r'http2\s+on;|http3\s+on;|quic_[a-z_]+\s[^;]*;|add_header\s+Alt-Svc[^;]*;)[^\n]*\n', re.M)
_HTTPS_REDIRECT = re.compile(r'^[ \t]*return\s+30[12]\s+https://[^;]*;[^\n]*\n', re.M)
# Repairs the server_name line corrupted by the old redirect injection:
#   server_name a.com\n    return 301 https://$host$request_uri; www.a.com;
_CORRUPT_SN = re.compile(r'(server_name[^;\n]*)\n[ \t]*return 301 https://\$host\$request_uri;([^\n]*;)')


def _nginx_conf_path(domain):
    avail, _ = get_nginx_dirs()
    return os.path.join(avail, f'{domain}.conf')


# http -> https, except the certificate validation paths: providers that check a file over
# plain HTTP (DigiCert, ZeroSSL, Sectigo) may not follow a redirect to https
NGINX_REDIRECT = ('if ($request_uri !~ "^/\\.well-known/(acme-challenge|pki-validation)/") '
                  '{ return 301 https://$host$request_uri; }')


def nginx_exempt_validation(content):
    """Older VortexPanel redirects sent validation files to https too: keep them on http."""
    return re.sub(r'^([ \t]*)return 301 https://\$host\$request_uri;\s*' + re.escape(SSL_REDIRECT_TAG) + r'[^\n]*',
                  lambda m: f'{m.group(1)}{NGINX_REDIRECT} {SSL_REDIRECT_TAG}', content, flags=re.M)


def apache_exempt_validation(content):
    if A_REDIR_BEGIN not in content or 'pki-validation' in content:
        return content
    return re.sub(r'^([ \t]*)RewriteCond %\{HTTPS\} off\n',
                  lambda m: m.group(0) + f'{m.group(1)}RewriteCond %{{REQUEST_URI}} !^/\\.well-known/(acme-challenge|pki-validation)/\n',
                  content, count=1, flags=re.M)


def nginx_add_ssl(content, domain, cert_path, key_path):
    """Return content with HTTPS enabled: the site's port-80 server block is
    cloned into a `listen 443 ssl` block (keeping PHP/locations/rewrites, so
    PHP sites keep working over HTTPS) and the port-80 block gets a redirect.
    Both additions carry markers so Disable SSL can remove them exactly."""
    content = _CORRUPT_SN.sub(r'\1\2', content)
    blocks = nginx_server_blocks(content)
    # SSL already configured in ANY block (the loop below stops at the first
    # port-80 block, so a 443 block after it was missed and every certificate
    # upload/renewal added another copy of the HTTPS server block).
    if any(re.search(r'listen[^;]*\b443\b', content[a:b]) or 'ssl_certificate' in content[a:b] for a, b in blocks):
        return None
    http = None
    for s_, e_ in blocks:
        b = content[s_:e_]
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
        redirect_block = (block[:m2.end()] + f'\n{m2.group(1)}{NGINX_REDIRECT} {SSL_REDIRECT_TAG}'
                          + block[m2.end():])
    return (content[:s_] + redirect_block + content[e_:].rstrip('\n') +
            f'\n\n{SSL_BEGIN}\n{ssl}\n{SSL_END}\n')


def nginx_dedupe_ssl(content):
    """Repair vhosts damaged by the duplicate-HTTPS-block bug (fixed in
    3.7.0): keep the first VortexPanel SSL block and one redirect line."""
    pat = re.compile(r'\n*' + re.escape(SSL_BEGIN) + r'.*?' + re.escape(SSL_END) + r'[^\n]*\n?', re.S)
    found = list(pat.finditer(content))
    for m in reversed(found[1:]):
        content = content[:m.start()] + '\n' + content[m.end():]
    out, seen = [], False
    for line in content.split('\n'):
        if SSL_REDIRECT_TAG in line:
            if seen:
                continue
            seen = True
        elif line.strip() == '}' or line.lstrip().startswith('server {'):
            seen = False
        out.append(line)
    return '\n'.join(out)


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


# --- Apache SSL --------------------------------------------------------------------
# Apache comments must be on their own line, so the markers are whole lines.
A_SSL_BEGIN = '# VORTEX-SSL-BEGIN'
A_SSL_END = '# VORTEX-SSL-END'
A_REDIR_BEGIN = '# VORTEX-SSL-REDIRECT-BEGIN'
A_REDIR_END = '# VORTEX-SSL-REDIRECT-END'
_A_VHOST = re.compile(r'<VirtualHost\s+[^>]*>.*?</VirtualHost>', re.S | re.I)
# The three lines certbot --apache adds to the port-80 vhost
_A_CERTBOT_REDIR = re.compile(r'\n[ \t]*RewriteEngine on\n(?:[ \t]*RewriteCond %\{SERVER_NAME\} =[^\n]*\n)+[ \t]*RewriteRule \^ https://%\{SERVER_NAME\}[^\n]*', re.I)


def _apache_enable_ssl_module():
    if apache_layout() == 'debian':
        sh('a2enmod ssl rewrite 2>/dev/null', t=30)
    elif not os.path.exists('/etc/httpd/conf.d/ssl.conf'):
        sh(pkg_install('mod_ssl') + ' 2>/dev/null', t=180)


def apache_add_ssl(content, cert_path, key_path):
    """Return content with a :443 copy of the site's port-80 vhost (same
    DocumentRoot, PHP handler, etc.) plus an http->https redirect, each
    between marker lines so Disable SSL can remove exactly what was added.
    Returns None when the config already has SSL."""
    if 'SSLCertificateFile' in content or A_SSL_BEGIN in content:
        return None
    m = None
    for mm in _A_VHOST.finditer(content):
        if ':80>' in mm.group(0).split('\n', 1)[0] or ':80 ' in mm.group(0).split('\n', 1)[0]:
            m = mm; break
    m = m or _A_VHOST.search(content)
    if not m:
        return None
    block = m.group(0)
    ssl = re.sub(r'^<VirtualHost\s+[^>]*>', '<VirtualHost *:443>', block, count=1, flags=re.I)
    # `ServerName example.com:80` copied into the :443 vhost would make
    # Apache build self-referential URLs as http://...:80
    ssl = re.sub(r'^([ \t]*ServerName[ \t]+[^\s:]+):80\b', r'\1', ssl, flags=re.M)
    sn = re.search(r'\n([ \t]*)ServerName[^\n]*', ssl)
    ind = sn.group(1) if sn else '    '
    ssl_lines = (f'\n{ind}SSLEngine on\n{ind}SSLCertificateFile {cert_path}\n{ind}SSLCertificateKeyFile {key_path}\n'
                 f'{ind}SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1')
    pos = sn.end() if sn else ssl.index('>') + 1
    ssl = ssl[:pos] + ssl_lines + ssl[pos:]
    redirect = (f'\n{ind}{A_REDIR_BEGIN}\n{ind}RewriteEngine On\n{ind}RewriteCond %{{HTTPS}} off\n'
                f'{ind}RewriteCond %{{REQUEST_URI}} !^/\\.well-known/(acme-challenge|pki-validation)/\n'
                f'{ind}RewriteRule ^ https://%{{HTTP_HOST}}%{{REQUEST_URI}} [R=301,L]\n{ind}{A_REDIR_END}')
    sn80 = re.search(r'\n[ \t]*ServerName[^\n]*', block)
    p80 = sn80.end() if sn80 else block.index('>') + 1
    block80 = block[:p80] + redirect + block[p80:]
    return (content[:m.start()] + block80 + content[m.end():].rstrip('\n') +
            f'\n\n{A_SSL_BEGIN}\n{ssl}\n{A_SSL_END}\n')


def apache_remove_ssl(content):
    content = re.sub(r'\n?[ \t]*' + re.escape(A_SSL_BEGIN) + r'.*?' + re.escape(A_SSL_END) + r'[^\n]*', '', content, flags=re.S)
    content = re.sub(r'\n[ \t]*' + re.escape(A_REDIR_BEGIN) + r'.*?' + re.escape(A_REDIR_END) + r'[^\n]*', '', content, flags=re.S)
    content = _A_CERTBOT_REDIR.sub('', content)
    return re.sub(r'\n{3,}', '\n\n', content).rstrip('\n') + '\n'


def _apache_inject_ssl(domain, cert_path, key_path):
    fp, ws = _find_site_config(domain)
    if ws != 'apache':
        return False, 'Apache config for this site not found'
    with open(fp) as f:
        content = f.read()
    new = apache_add_ssl(content, cert_path, key_path)
    if new is None:
        # already has SSL: point every SSLCertificate(Key)File of the site and
        # its certbot companion at the given files
        def repoint(c):
            c = re.sub(r'(^[ \t]*SSLCertificateFile\s+)\S+', lambda m: m.group(1) + cert_path, c, flags=re.M)
            c = apache_exempt_validation(c)
            return re.sub(r'(^[ \t]*SSLCertificateKeyFile\s+)\S+', lambda m: m.group(1) + key_path, c, flags=re.M)
        return apache_edit_site(fp, repoint)
    _apache_enable_ssl_module()
    return apache_apply(fp, new)


def _ensure_certbot(ws):
    plugin = {'apache': 'python3-certbot-apache', 'nginx': 'python3-certbot-nginx'}.get(ws, '')
    have_certbot = bool(sh('command -v certbot 2>/dev/null'))
    have_plugin = (not plugin) or ('apache' in sh('certbot plugins 2>/dev/null') if ws == 'apache'
                                   else 'nginx' in sh('certbot plugins 2>/dev/null'))
    if have_certbot and have_plugin:
        _enable_renewal()
        return
    pkgs = ('certbot ' + plugin).strip()
    if get_os().get('family') == 'rhel':
        # epel-release exists only on Alma/Rocky/CentOS/CloudLinux; RHEL and
        # Oracle Linux need their own EPEL route (Fedora ships certbot itself)
        sh(_ou.ensure_epel_cmd(), t=300)
    sh(pkg_install(pkgs) + ' 2>&1', t=300)
    _enable_renewal()


def _enable_renewal():
    """EPEL ships certbot-renew.timer disabled: without this every
    certificate issued on the RHEL family silently expired after 90 days."""
    try:
        _ou.certbot_enable_renewal()
    except Exception:
        pass


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
    if not is_valid_domain(domain):
        return False, 'Invalid domain', 'none'
    email = (email or '').strip() or f'admin@{domain}'
    if not _EMAIL_RE.match(email):
        return False, 'Enter a valid e-mail address for Let\'s Encrypt', 'none'
    email = shlex.quote(email)
    ws = _find_site_config(domain)[1] or 'nginx'
    if ws == 'caddy':
        return True, ('Caddy obtains and renews HTTPS certificates for this site automatically, as soon as '
                      f'{domain} points to this server. Nothing else to do.'), 'caddy-automatic'
    if ws == 'openlitespeed':
        return False, ('Let\'s Encrypt from the Websites page is not available for OpenLiteSpeed sites yet -- '
                       'use the OpenLiteSpeed WebAdmin console (port 7080) or upload a certificate in the Config tab.'), 'unsupported'
    token, proxied = cf_check_proxied(domain)
    if ws == 'nginx':
        _ensure_certbot('nginx')
    if ws == 'apache':
        _ensure_certbot('apache')
        if token and proxied and _ensure_dns_cloudflare_plugin():
            cred_path = _write_cf_credentials(domain, token)
            out = _run_out(f'certbot certonly --dns-cloudflare --dns-cloudflare-credentials {cred_path} '
                     f'--dns-cloudflare-propagation-seconds 30 {_d_args(domain)} {_reload_hook("apache")} --non-interactive --agree-tos -m {email} 2>&1', t=180)
            ok = 'Congratulations' in out or 'Certificate not yet due' in out or 'Successfully' in out
            if ok:
                ok2, err = _apache_inject_ssl(domain, f'/etc/letsencrypt/live/{domain}/fullchain.pem',
                                              f'/etc/letsencrypt/live/{domain}/privkey.pem')
                if not ok2:
                    ok = False
                    out += '\n[VortexPanel] Certificate issued but the Apache config update failed: ' + err
            return ok, out, 'dns-cloudflare'
        out = _run_out(f'certbot --apache {_d_args(domain)} --redirect --non-interactive --agree-tos -m {email} 2>&1', t=180)
        ok = 'Congratulations' in out or 'Certificate not yet due' in out or 'Successfully' in out
        return ok, out, 'http'

    if token and proxied:
        # DNS-01 via Cloudflare
        if not _ensure_dns_cloudflare_plugin():
            out = _run_out(f'certbot --nginx {_d_args(domain)} --non-interactive --agree-tos -m {email} 2>&1', t=120)
            ok = 'Congratulations' in out or 'Certificate not yet due' in out or 'Successfully' in out
            return ok, out, 'http (dns-plugin install failed, fallback)'

        cred_path = _write_cf_credentials(domain, token)
        out = _run_out(
            f'certbot certonly --dns-cloudflare --dns-cloudflare-credentials {cred_path} '
            f'--dns-cloudflare-propagation-seconds 30 '
            f'{_d_args(domain)} {_reload_hook("nginx")} --non-interactive --agree-tos -m {email} 2>&1',
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
    out = _run_out(f'certbot --nginx {_d_args(domain)} --non-interactive --agree-tos -m {email} 2>&1', t=120)
    ok = 'Congratulations' in out or 'Certificate not yet due' in out or 'Successfully' in out
    return ok, out, 'http'


def _validate_cert_pair(cert, key):
    """Return an error string unless `cert` is a PEM certificate (chain) and
    `key` the matching private key. Previously anything was written over the
    live cert files; when the site already had SSL only a reload followed,
    which nginx refused -- and the next nginx restart failed for every site."""
    if '-----BEGIN CERTIFICATE-----' not in cert:
        return 'The certificate must be in PEM format (-----BEGIN CERTIFICATE-----)'
    if 'PRIVATE KEY-----' not in key:
        return 'The private key must be in PEM format (-----BEGIN ... PRIVATE KEY-----)'
    tmpdir = tempfile.mkdtemp(prefix='vp-ssl-')
    try:
        cp, kp = os.path.join(tmpdir, 'c.pem'), os.path.join(tmpdir, 'k.pem')
        _write_secret(cp, cert + '\n', 0o600)
        _write_secret(kp, key + '\n', 0o600)
        def run(args):
            try:
                r = subprocess.run(args, capture_output=True, text=True, timeout=20)
                return r.returncode, r.stdout
            except Exception as e:
                return 1, str(e)
        rc, cpub = run(['openssl', 'x509', '-in', cp, '-noout', '-pubkey'])
        if rc != 0 or 'PUBLIC KEY' not in cpub:
            return 'The certificate could not be parsed by openssl'
        rc, kpub = run(['openssl', 'pkey', '-in', kp, '-pubout'])
        if rc != 0 or 'PUBLIC KEY' not in kpub:
            return 'The private key could not be parsed (encrypted keys are not supported)'
        if cpub.strip() != kpub.strip():
            return 'The private key does not match the certificate'
        rc, _ = run(['openssl', 'x509', '-in', cp, '-noout', '-checkend', '0'])
        if rc != 0:
            return 'The certificate has already expired'
        return ''
    finally:
        import shutil as _sh
        _sh.rmtree(tmpdir, ignore_errors=True)


def _write_secret(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'w') as f:
        f.write(data)
    os.chmod(path, mode)


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
    ok, out, method = _issue_cert(domain, email)
    return jsonify({'ok':ok, 'output':out[-800:], 'method':method})


@websites_bp.route('/api/websites/<domain>/ssl/manual', methods=['POST'])
def manual_ssl(domain):
    """Own certificate: certificate + private key (+ CA bundle), or a .pfx/.p12 file.
    Checked first (key matches, covers the website, chain, expiry); installed in its
    own folder so the previous certificate stays available for Switch back."""
    if not req(): return jsonify({'ok':False}), 401
    if not is_valid_domain(domain):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400
    ws = _find_site_config(domain)[1]
    if ws not in ('nginx', 'apache'):
        return jsonify({'ok': False, 'error': f'Installing your own certificate is available for nginx and Apache websites '
                                              f'({domain} is served by {ws or "an unknown web server"}).'}), 400
    d = request.get_json() or {}
    cert, key = d.get('cert', ''), d.get('key', '')
    if d.get('pfx'):
        cert, key, err = pfx_to_pem(d.get('pfx', ''), d.get('pfx_password', ''))
        if err:
            return jsonify({'ok': False, 'error': err}), 400
    if cert and not (key or '').strip():
        # bought elsewhere with a CSR made by this panel: its key is on this server
        try:
            from panel import ssl_orders as _so
            key = _so.key_for_cert(cert)
        except Exception:
            key = ''
    cert, chk = prepare_cert(domain, cert, key, d.get('chain', ''))
    if chk.get('error'):
        return jsonify({'ok': False, 'error': chk['error'], 'check': chk}), 400
    if d.get('check_only'):
        return jsonify({'ok': True, 'check': chk})
    resp = install_manual_cert(domain, cert, key, subdir='own', source='own')
    body = resp[0] if isinstance(resp, tuple) else resp
    data = body.get_json() or {}
    data['check'] = chk
    return jsonify(data), (resp[1] if isinstance(resp, tuple) else 200)


def _openssl(args, data=None, t=20):
    try:
        r = subprocess.run(['openssl'] + args, input=data, capture_output=True, timeout=t)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return 1, b'', str(e).encode()


def pfx_to_pem(b64, password):
    """A .pfx / .p12 file (base64) -> (certificate chain PEM, key PEM, error)."""
    import base64
    try:
        raw = base64.b64decode(b64, validate=False)
    except Exception:
        return '', '', 'The .pfx file could not be read'
    if not raw or len(raw) > 200_000:
        return '', '', 'The .pfx file is empty or too large'
    tmpdir = tempfile.mkdtemp(prefix='vp-pfx-')
    try:
        pf, pw = os.path.join(tmpdir, 'in.pfx'), os.path.join(tmpdir, 'pw')
        _write_secret(pf, '', 0o600)
        with open(pf, 'wb') as f:
            f.write(raw)
        _write_secret(pw, password or '', 0o600)
        out = {}
        for what, extra in (('cert', ['-nokeys']), ('key', ['-nocerts', '-nodes'])):
            for legacy in ([], ['-legacy']):     # old .pfx files use RC2/3DES (OpenSSL 3: -legacy)
                rc, o, e = _openssl(['pkcs12', '-in', pf, '-passin', f'file:{pw}'] + extra + legacy)
                if rc == 0:
                    out[what] = o.decode(errors='replace')
                    break
            if what not in out:
                return '', '', 'The .pfx password is wrong, or the file is damaged'
        # keep only the PEM blocks (drop "Bag Attributes" lines)
        certs = re.findall(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', out['cert'], re.S)
        keym = re.search(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----.+?-----END (?:RSA |EC )?PRIVATE KEY-----', out['key'], re.S)
        if not certs or not keym:
            return '', '', 'The .pfx file holds no certificate or no private key'
        return '\n'.join(certs), keym.group(0), ''
    finally:
        import shutil as _shu
        _shu.rmtree(tmpdir, ignore_errors=True)


def cert_details(pem):
    """Names, issuer and expiry of the first certificate in `pem`."""
    rc, o, e = _openssl(['x509', '-noout', '-subject', '-issuer', '-enddate', '-ext', 'subjectAltName',
                         '-nameopt', 'utf8,sep_comma_plus'], pem.encode())
    if rc != 0:
        rc, o, e = _openssl(['x509', '-noout', '-subject', '-issuer', '-enddate', '-text'], pem.encode())
    txt = o.decode(errors='replace')
    names = re.findall(r'DNS:([^,\s]+)', txt)
    cn = re.search(r'subject=.*?CN\s*=\s*([^,\n]+)', txt)
    if cn and cn.group(1).strip() not in names:
        names.insert(0, cn.group(1).strip())
    org = re.search(r'issuer=.*?O\s*=\s*([^,\n]+)', txt)
    icn = re.search(r'issuer=.*?CN\s*=\s*([^,\n]+)', txt)
    end = re.search(r'notAfter=(.+)', txt)
    not_after, days = '', None
    if end:
        try:
            dt = datetime.strptime(end.group(1).strip(), '%b %d %H:%M:%S %Y %Z')
            not_after, days = dt.strftime('%Y-%m-%d'), (dt - datetime.utcnow()).days
        except ValueError:
            pass
    return {'names': names, 'issuer': (org.group(1).strip() if org else ''),
            'issuer_cn': (icn.group(1).strip() if icn else ''), 'expires_on': not_after, 'days_left': days}


def covers(names, host):
    host = host.lower()
    for n in names:
        n = n.lower()
        if n == host or (n.startswith('*.') and host.count('.') == n.count('.') and host.endswith(n[1:])):
            return True
    return False


def _complete_chain(leaf_and_chain):
    """(pem, complete): the certificate plus any intermediates fetched from the address
    in the certificate (Authority Information Access) when they are missing."""
    def verify(pem):
        tmpdir = tempfile.mkdtemp(prefix='vp-chain-')
        try:
            blocks = re.findall(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', pem, re.S)
            lf, ch = os.path.join(tmpdir, 'leaf.pem'), os.path.join(tmpdir, 'chain.pem')
            with open(lf, 'w') as f: f.write(blocks[0] + '\n')
            args = ['verify', '-purpose', 'sslserver']
            if len(blocks) > 1:
                with open(ch, 'w') as f: f.write('\n'.join(blocks[1:]) + '\n')
                args += ['-untrusted', ch]
            rc, o, e = _openssl(args + [lf])
            return rc == 0
        finally:
            import shutil as _shu
            _shu.rmtree(tmpdir, ignore_errors=True)
    pem = leaf_and_chain
    if verify(pem):
        return pem, True
    for _ in range(3):              # follow at most three missing links
        last = re.findall(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', pem, re.S)[-1]
        rc, o, e = _openssl(['x509', '-noout', '-text'], last.encode())
        m = re.search(r'CA Issuers - URI:(http://\S+)', o.decode(errors='replace'))
        if not m:
            break
        try:
            r = subprocess.run(['curl', '-fsSL', '--max-time', '10', m.group(1)], capture_output=True, timeout=15)
        except Exception:
            break
        if r.returncode != 0 or not r.stdout:
            break
        data = r.stdout
        if b'-----BEGIN CERTIFICATE-----' not in data:
            rc, o, e = _openssl(['x509', '-inform', 'DER', '-outform', 'PEM'], data)
            if rc != 0:
                break
            data = o
        pem = pem.rstrip() + '\n' + data.decode(errors='replace').strip()
        if verify(pem):
            return pem, True
    return leaf_and_chain, False


def prepare_cert(domain, cert, key, chain=''):
    """Check an own certificate before anything changes.
    Returns (certificate with chain, check dict); check['error'] blocks the install."""
    cert = (cert or '').strip()
    chain = (chain or '').strip()
    if chain and chain not in cert:
        cert = cert + '\n' + chain
    chk = {'key_matches': False, 'covers': [], 'missing': [], 'chain_complete': False}
    if not cert or not (key or '').strip():
        chk['error'] = 'The certificate and the private key are both needed'
        return cert, chk
    err = _validate_cert_pair(cert, (key or '').strip())
    if err:
        chk['error'] = err
        return cert, chk
    chk['key_matches'] = True
    det = cert_details(cert)
    chk.update(det)
    hosts = [domain] + ([f'www.{domain}'] if domain.count('.') == 1 else [])
    chk['covers'] = [h for h in hosts if covers(det['names'], h)]
    chk['missing'] = [h for h in hosts if h not in chk['covers']]
    if domain not in chk['covers']:
        chk['error'] = (f'This certificate is for {", ".join(det["names"][:4]) or "other names"}, not for {domain}. '
                        'Installing it would show a security warning to every visitor.')
        return cert, chk
    cert, chk['chain_complete'] = _complete_chain(cert)
    return cert, chk


def _vhost_cert_paths(domain):
    """(cert, key) the website uses now, or ('', '')."""
    fp, ws = _find_site_config(domain)
    if not fp or not os.path.exists(fp):
        return '', ''
    content = open(fp).read()
    if ws == 'apache':
        companion = fp[:-5] + '-le-ssl.conf'
        if os.path.exists(companion):
            content += open(companion).read()
        c = re.search(r'^\s*SSLCertificateFile\s+"?([^"\s]+)', content, re.M)
        k = re.search(r'^\s*SSLCertificateKeyFile\s+"?([^"\s]+)', content, re.M)
    else:
        c = re.search(r'^[ \t]*ssl_certificate\s+([^;\s]+)\s*;', content, re.M)
        k = re.search(r'^[ \t]*ssl_certificate_key\s+([^;\s]+)\s*;', content, re.M)
    return (c.group(1) if c else ''), (k.group(1) if k else '')


def _ssl_dir(domain, ws=None):
    ws = ws or _find_site_config(domain)[1] or 'nginx'
    # nginx keeps its historical location; other servers must not get an
    # /etc/nginx tree created on a server without nginx.
    return f'/etc/nginx/ssl/{domain}' if ws == 'nginx' else f'/etc/ssl/vortexpanel/{domain}'


def _remember_previous(domain, new_cert_path):
    """Keep a note of the certificate the website used until now (Switch back)."""
    cur, curkey = _vhost_cert_paths(domain)
    if not cur or cur == new_cert_path or not os.path.exists(cur) or not os.path.exists(curkey):
        return
    try:
        det = cert_details(open(cur).read())
    except OSError:
        return
    meta = {'cert': cur, 'key': curkey, 'issuer': det.get('issuer') or det.get('issuer_cn'),
            'names': det.get('names', [])[:6], 'expires_on': det.get('expires_on'), 'saved': int(datetime.utcnow().timestamp())}
    d = _ssl_dir(domain)
    os.makedirs(d, mode=0o700, exist_ok=True)
    with open(f'{d}/previous.json', 'w') as f:
        json.dump(meta, f)


def install_manual_cert(domain, cert, key, subdir='', source=''):
    """Validate and install a certificate + key for a site (Upload SSL, and
    the SSL step of Website Import). Returns a Flask response tuple/object.
    subdir: a folder of its own under the site's SSL folder ('own', 'business'), so a
    certificate renewed automatically into the main folder does not overwrite it."""
    key  = (key or '').strip()
    cert = (cert or '').strip()
    if not key or not cert:
        return jsonify({'ok':False,'error':'Private key and certificate are required'}), 400

    if not is_valid_domain(domain):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400
    if subdir and not re.fullmatch(r'[a-z]{1,16}', subdir):
        return jsonify({'ok':False,'error':'Invalid folder'}), 400
    verr = _validate_cert_pair(cert, key)
    if verr:
        return jsonify({'ok':False,'error':verr}), 400
    site_ws = _find_site_config(domain)[1] or 'nginx'
    ssl_dir = _ssl_dir(domain, site_ws) + (f'/{subdir}' if subdir else '')
    os.makedirs(ssl_dir, mode=0o700, exist_ok=True)

    key_path  = f'{ssl_dir}/privkey.pem'
    cert_path = f'{ssl_dir}/fullchain.pem'
    _remember_previous(domain, cert_path)
    # write next to the live files first, swap only after the web server accepted them
    _write_secret(key_path, key + '\n', 0o600)
    _write_secret(cert_path, cert + '\n', 0o644)
    if source:
        with open(f'{ssl_dir}/source.json', 'w') as f:
            json.dump({'source': source, 'installed': int(datetime.utcnow().timestamp())}, f)

    ok, err = point_site_to(domain, cert_path, key_path)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok':True, 'key_path':key_path, 'cert_path':cert_path})


def point_site_to(domain, cert_path, key_path):
    """Make the website use these certificate files (web server config checked before the
    reload, restored when refused). Returns (ok, error)."""
    ws = _find_site_config(domain)[1]
    if ws == 'apache':
        return _apache_inject_ssl(domain, cert_path, key_path)
    if ws in ('openlitespeed', 'caddy'):
        return False, (f'Installing a certificate here is supported for nginx and Apache sites. For this {ws} site, '
                       f'the files were saved to {cert_path} and {key_path} -- reference them in the Config tab.')
    # Update nginx config to add SSL (validated with nginx -t, restored on failure)
    conf_path = _nginx_conf_path(domain)
    if not os.path.exists(conf_path):
        return True, ''
    with open(conf_path) as f: content = f.read()
    fixed = nginx_exempt_validation(nginx_dedupe_ssl(content))
    if fixed != content:
        ok, err = _nginx_apply(conf_path, fixed)
        if ok:
            content = fixed
    new = nginx_add_ssl(content, domain, cert_path, key_path)
    if new is None:
        # SSL already configured (possibly with a Let's Encrypt path):
        # point it at the new files -- previously the upload was
        # reported as installed while the old certificate kept being served
        new = re.sub(r'(^[ \t]*ssl_certificate\s+)[^;]+;', lambda m: m.group(1) + cert_path + ';', content, flags=re.M)
        new = re.sub(r'(^[ \t]*ssl_certificate_key\s+)[^;]+;', lambda m: m.group(1) + key_path + ';', new, flags=re.M)
        if new == content:
            reload_nginx()
            return True, ''
    return _nginx_apply(conf_path, new)


def previous_cert(domain):
    """The certificate the website used before the current one, if its files are still valid."""
    try:
        meta = json.load(open(f'{_ssl_dir(domain)}/previous.json'))
    except (OSError, ValueError):
        return None
    cur, _ = _vhost_cert_paths(domain)
    if meta.get('cert') == cur or not os.path.exists(meta.get('cert', '')) or not os.path.exists(meta.get('key', '')):
        return None
    try:
        det = cert_details(open(meta['cert']).read())
    except OSError:
        return None
    if det.get('days_left') is not None and det['days_left'] < 0:
        return None
    meta.update(expires_on=det.get('expires_on'), days_left=det.get('days_left'))
    return meta


@websites_bp.route('/api/websites/<domain>/ssl/switch-back', methods=['POST'])
def ssl_switch_back(domain):
    if not req(): return jsonify({'ok':False}), 401
    if not is_valid_domain(domain):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400
    prev = previous_cert(domain)
    if not prev:
        return jsonify({'ok': False, 'error': 'There is no earlier certificate to switch back to'}), 400
    err = _validate_cert_pair(open(prev['cert']).read(), open(prev['key']).read())
    if err:
        return jsonify({'ok': False, 'error': 'The earlier certificate can no longer be used: ' + err}), 400
    cur_cert, _ = _vhost_cert_paths(domain)
    _remember_previous(domain, prev['cert'])     # the current one becomes the "previous"
    ok, err = point_site_to(domain, prev['cert'], prev['key'])
    if not ok:
        return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok': True, 'message': f'Switched back to the {prev.get("issuer") or "earlier"} certificate'})


@websites_bp.route('/api/websites/<domain>/ssl/info')
def ssl_info(domain):
    if not req(): return jsonify({'ok':False}), 401
    if not is_valid_domain(domain):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400
    fp, ws = _find_site_config(domain)
    candidates = [f'/etc/nginx/ssl/{domain}/fullchain.pem', f'/etc/letsencrypt/live/{domain}/fullchain.pem',
                  f'/etc/ssl/vortexpanel/{domain}/fullchain.pem']
    if ws == 'nginx' and os.path.exists(fp):
        with open(fp) as f:
            ncontent = f.read()
        if 'ssl_certificate' not in ncontent:
            # cert files may still be on disk after Disable SSL - the site isn't using them
            return jsonify({'ok':False,'error':'SSL is not enabled for this site'})
        # report the certificate the vhost actually uses first
        candidates = re.findall(r'^[ \t]*ssl_certificate\s+([^;\s]+)\s*;', ncontent, re.M) + candidates
    elif ws == 'apache':
        content = open(fp).read()
        companion = fp[:-5] + '-le-ssl.conf'
        enabled_companion = os.path.exists(companion) and (apache_layout() != 'debian' or
                            os.path.exists('/etc/apache2/sites-enabled/' + os.path.basename(companion)))
        if enabled_companion:
            content += open(companion).read()
        certs = re.findall(r'^\s*SSLCertificateFile\s+"?([^"\s]+)', content, re.M)
        if not certs:
            return jsonify({'ok':False,'error':'SSL is not enabled for this site'})
        candidates = certs + candidates
    elif ws == 'caddy':
        return jsonify({'ok':False,'error':'Caddy manages this site\'s certificate automatically (stored under /var/lib/caddy)'})
    for p in candidates:
        if os.path.exists(p):
            info = sh(f'openssl x509 -in {shlex.quote(p)} -noout -dates -subject -issuer 2>/dev/null')
            expiry = sh(f'openssl x509 -in {shlex.quote(p)} -noout -enddate 2>/dev/null')
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
            try:
                from panel.routes.acme import acme_info
                acme = acme_info(domain)
            except Exception:
                acme = None
            src = ''
            try:
                src = json.load(open(os.path.join(os.path.dirname(p), 'source.json'))).get('source', '')
            except (OSError, ValueError):
                pass
            try:
                from panel import ssl_orders as _so
                order = _so.installed_order(domain, p)
            except Exception:
                order = None
            return jsonify({
                'ok': True, 'info': info, 'expiry': expiry, 'path': p, 'acme': acme,
                'source': src, 'previous': previous_cert(domain), 'order': order,
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
    try:
        from panel.routes.acme import remove_site_cert
        remove_site_cert(domain)   # stop DNS-API renewals of a certificate that is no longer used
    except Exception:
        pass
    fp, ws = _find_site_config(domain)
    if ws == 'apache':
        with open(fp) as f: content = f.read()
        companion = fp[:-5] + '-le-ssl.conf'
        new = apache_remove_ssl(content)
        if 'SSLCertificateFile' in new:
            return jsonify({'ok':False,'error':'Could not safely remove SSL from this config automatically - edit it in the Config tab'}), 400
        undo = None
        if os.path.exists(companion):
            if apache_layout() == 'debian':
                if os.path.exists('/etc/apache2/sites-enabled/' + os.path.basename(companion)):
                    sh(f'a2dissite {shlex.quote(os.path.basename(companion))} 2>/dev/null')
                    undo = lambda: sh(f'a2ensite {shlex.quote(os.path.basename(companion))} 2>/dev/null')
            else:
                os.rename(companion, companion + '.disabled')
                undo = lambda: os.rename(companion + '.disabled', companion)
        ok, err = apache_apply(fp, new)
        if not ok:
            if undo:
                undo()   # keep HTTPS working exactly as before
            return jsonify({'ok':False,'error':err}), 500
        sh('systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null')
        return jsonify({'ok':True})
    if ws in ('caddy', 'openlitespeed'):
        return jsonify({'ok':False,'error':f'Disable SSL is supported for nginx and Apache sites ({domain} is served by {ws})'}), 400
    conf_path = _nginx_conf_path(domain)
    if not os.path.exists(conf_path):
        return jsonify({'ok':False,'error':'No config found for this site'}), 404
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
