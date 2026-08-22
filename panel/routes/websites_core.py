from flask import Blueprint, jsonify, request, session
import os, re, subprocess
from datetime import datetime
import json, time

try:
    from panel.routes.os_utils import get_os, pkg_install, pkg_update, pkg_remove
except ImportError:
    try:
        from os_utils import get_os, pkg_install, pkg_update, pkg_remove
    except ImportError:
        def get_os(): return {'family':'debian','pkg':'apt','id':'ubuntu','codename':'noble'}
        def pkg_install(p, f=''): return f'DEBIAN_FRONTEND=noninteractive apt-get install -y {f} {p}'
        def pkg_update(): return 'apt-get update -qq'
        def pkg_remove(p): return f'apt-get remove -y --purge {p} && apt-get autoremove -y'


websites_bp = Blueprint('websites', __name__)
WEBROOT = '/www/wwwroot'
CF_CONFIG_FILE = '/opt/vortexpanel/cdn_config.json'
INTEGRITY_DIR = '/opt/vortexpanel/integrity'

# Default ownership for newly created site directories so PHP/Node processes
# (running as this user) can write configs, uploads, caches, etc.
WEB_USER  = 'www-data'
WEB_GROUP = 'www-data'


def req(): return 'user' in session


def sh(c, t=15):
    try: return subprocess.check_output(c, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=t).strip()
    except: return ''


def get_nginx_dirs():
    """Return VortexPanel-managed nginx vhost directory"""
    vortex_dir = '/etc/nginx/vortex'
    os.makedirs(vortex_dir, exist_ok=True)
    # Find nginx.conf - check multiple paths for different distros
    nginx_conf_paths = [
        '/etc/nginx/nginx.conf',
        '/usr/local/nginx/conf/nginx.conf',
    ]
    nginx_conf = next((p for p in nginx_conf_paths if os.path.exists(p)), '/etc/nginx/nginx.conf')
    if os.path.exists(nginx_conf):
        with open(nginx_conf) as f: nc = f.read()
        if 'vortex' not in nc:
            import subprocess as _sp
            _sp.run("sed -i 's|include /etc/nginx/conf.d/\\*.conf;|include /etc/nginx/conf.d/*.conf;\\n    include /etc/nginx/vortex/*.conf;|' " + nginx_conf, shell=True)
    return vortex_dir, vortex_dir


import re as _re_dom
def is_valid_domain(domain):
    """Reject anything that isn't a plain hostname before it reaches a shell
    command or a filesystem path. Allows letters, digits, dots and hyphens
    only (labels 1-63 chars, total <=253, no leading/trailing dot or hyphen).
    This blocks shell metacharacters, whitespace, slashes and path-traversal
    sequences (`;`, `|`, `$(...)`, backticks, spaces, `../`, …) that would
    otherwise be interpolated into the ~120 shell commands and vhost/DB paths
    that thread the domain through — including domains parsed from imported
    cPanel/aaPanel/Hestia archives (untrusted second-order input).
    """
    domain = (domain or '').strip().lower()
    if not domain or len(domain) > 253:
        return False
    return bool(_re_dom.fullmatch(
        r'(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)'
        r'(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*', domain))

def get_webroot():
    for p in [WEBROOT, '/var/www/html', '/var/www', '/srv/www', '/usr/share/nginx/html']:
        if os.path.isdir(p): return p
    os.makedirs(WEBROOT, exist_ok=True)
    return WEBROOT


def reload_nginx():
    for cmd in ['systemctl reload nginx', 'nginx -s reload', 'service nginx reload', 'systemctl reload nginx.service']:
        out = sh(f'{cmd} 2>/dev/null; echo $?')
        if out.strip() == '0': break


def ensure_web_ownership(path):
    """Ensure a site directory (and its contents) are owned by the web server
    user/group so PHP-FPM / Node processes can read & write files (configs,
    uploads, sessions, caches, etc). Safe to call multiple times."""
    try:
        sh(f'chown -R {WEB_USER}:{WEB_GROUP} "{path}" 2>/dev/null', t=60)
    except Exception:
        pass


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
            ssl_days = None
            if ssl:
                for cp in [f'/etc/nginx/ssl/{domain}/fullchain.pem', f'/etc/letsencrypt/live/{domain}/fullchain.pem']:
                    if os.path.exists(cp):
                        end_str = sh(f'openssl x509 -in {cp} -noout -enddate 2>/dev/null')
                        if end_str.startswith('notAfter='):
                            try:
                                end_dt = datetime.strptime(end_str[9:].strip(), '%b %d %H:%M:%S %Y %Z')
                                ssl_days = (end_dt - datetime.utcnow()).days
                            except: pass
                        break
            sites.append({'domain':domain,'ssl':ssl,'ssl_days':ssl_days,'php':php_v,'enabled':is_enabled,'path':path,'conf_file':f})
    except: pass
    return sites


def _get_site_path(domain):
    for s in list_sites():
        if s['domain'] == domain:
            return s['path']
    return os.path.join(get_webroot(), domain)


@websites_bp.route('/api/websites/php-versions')
def get_php_versions():
    if not req(): return jsonify({'ok':False}), 401
    versions = []
    for v in ['8.5','8.4','8.3','8.2','8.1','8.0','7.4','7.3','7.2']:
        import shutil
        if shutil.which(f'php{v}'):
            sock = f'/run/php/php{v}-fpm.sock'
            active = os.path.exists(sock)
            versions.append({'version':v,'active':active,'sock':sock})
    return jsonify({'ok':True,'versions':versions})


@websites_bp.route('/api/websites')
def get_sites():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, 'sites':list_sites(), 'webroot':get_webroot()})


def create_site_core(domain, path=None, php='8.3'):
    """Core site-creation logic -- shared by the normal create_site() route AND
    the website-import feature (cPanel/aaPanel/Hestia), so both paths always
    produce identical, correct vhosts with zero risk of drift between them.
    Returns (ok: bool, result: dict) -- result has 'domain'/'path' on success or
    'error' on failure.

    Detects and supports whichever webserver is actually installed (nginx,
    Apache, OpenLiteSpeed, Caddy) rather than unconditionally writing an
    nginx config -- confirmed as a real, severe bug via GitHub issue #14:
    OpenLiteSpeed users creating a site through the normal flow got an
    nginx config file OLS never reads at all, with no OLS vhost ever
    created for the site. Reuses the existing, working multi-webserver
    vhost logic from wp_toolkit.py instead of duplicating it.
    """
    domain = (domain or '').strip().lower()
    path = (path or f'{get_webroot()}/{domain}').strip()
    if not domain:
        return False, {'error': 'Domain required'}
    if not is_valid_domain(domain):
        return False, {'error': 'Invalid domain name'}

    os.makedirs(path, exist_ok=True)
    idx = os.path.join(path, 'index.html')
    if not os.path.exists(idx):
        with open(idx, 'w') as f:
            f.write(f'<!DOCTYPE html><html><body><h1>Welcome to {domain}</h1><p>VortexPanel — site created successfully.</p></body></html>')

    ensure_web_ownership(path)

    from panel.routes.wp_toolkit import _write_vhost, _detect_webserver
    webserver = _detect_webserver()
    if not webserver:
        return False, {'error': 'No web server is installed. Install Nginx, Apache2, OpenLiteSpeed, or Caddy from the App Store first.'}

    ok, result = _write_vhost(domain, path, php, webserver)
    if not ok:
        return False, {'error': result}
    return True, {'domain': domain, 'path': path, 'webserver': webserver}


@websites_bp.route('/api/websites', methods=['POST'])
def create_site():
    if not req(): return jsonify({'ok':False}), 401
    d      = request.get_json() or {}
    domain = d.get('domain','').strip().lower()
    path   = d.get('path', f'{get_webroot()}/{domain}').strip()
    php    = d.get('php','8.3')
    if not domain: return jsonify({'ok':False,'error':'Domain required'}), 400

    ok, result = create_site_core(domain, path, php)
    if not ok:
        return jsonify({'ok': False, **result}), 400 if 'Domain' in result.get('error','') else 500

    warnings = []

    # The frontend's new-site form has sent createDb/createFtp all along --
    # confirmed neither was ever read here, so checking the box silently
    # did nothing. Both are best-effort: if either fails, the site itself
    # still gets created successfully, and the failure is reported as a
    # warning rather than aborting the whole request.
    if d.get('createDb'):
        try:
            from panel.routes.databases import mysql_cmd, _sql_escape
            db_name = re.sub(r'[^a-zA-Z0-9_]', '_', domain.replace('.', '_'))[:32]
            db_user = ('u_' + re.sub(r'[^a-zA-Z0-9_]', '', domain.split('.')[0]))[:16]
            db_pass = subprocess.run(
                ['openssl', 'rand', '-base64', '16'], capture_output=True, text=True
            ).stdout.strip().replace('/', '_').replace('+', '-')[:20]
            _, err = mysql_cmd(f'CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;')
            if err:
                warnings.append(f'Database not created: {err}')
            else:
                mysql_cmd(f"CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{_sql_escape(db_pass)}';")
                mysql_cmd(f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'localhost'; FLUSH PRIVILEGES;")
                result['db_name'] = db_name
                result['db_user'] = db_user
                result['db_pass'] = db_pass
        except Exception as e:
            warnings.append(f'Database not created: {e}')

    if d.get('createFtp'):
        try:
            from panel.routes.ftp import is_ftp_installed, get_ftp_daemon
            if not is_ftp_installed():
                warnings.append('FTP account not created: no FTP server (Pure-FTPd/ProFTPD) is installed — install one from the App Store first')
            else:
                ftp_user = re.sub(r'[^a-zA-Z0-9_-]', '', domain.split('.')[0])[:16] + '_' + re.sub(r'[^a-zA-Z0-9_]', '', domain.split('.')[-1])[:8]
                ftp_pass = subprocess.run(
                    ['openssl', 'rand', '-base64', '16'], capture_output=True, text=True
                ).stdout.strip().replace('/', '_').replace('+', '-')[:20]
                daemon, _ = get_ftp_daemon()
                if not daemon:
                    warnings.append('FTP account not created: no FTP daemon is currently running')
                else:
                    os.makedirs(path, exist_ok=True)
                    if daemon == 'pure-ftpd':
                        subprocess.run(['useradd', '-s', '/bin/false', '-d', path, ftp_user], capture_output=True)
                        subprocess.run(['pure-pw', 'useradd', ftp_user, '-u', ftp_user, '-d', path],
                                        input=f'{ftp_pass}\n{ftp_pass}\n', text=True, capture_output=True)
                        subprocess.run(['pure-pw', 'mkdb'], capture_output=True)
                        subprocess.run(['systemctl', 'reload', 'pure-ftpd'], capture_output=True)
                    else:
                        subprocess.run(['useradd', '-m', '-d', path, '-s', '/sbin/nologin', ftp_user], capture_output=True)
                        subprocess.run(['chpasswd'], input=f'{ftp_user}:{ftp_pass}', text=True, capture_output=True)
                    result['ftp_user'] = ftp_user
                    result['ftp_pass'] = ftp_pass
        except Exception as e:
            warnings.append(f'FTP account not created: {e}')

    if warnings:
        result['warnings'] = warnings
    return jsonify({'ok': True, **result})


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


def _find_site_config(domain):
    """Locate a site's real config file regardless of which webserver it
    was created under. Returns (path, webserver) or (None, None).

    Previously get_config()/save_config() only ever checked nginx's path
    (/etc/nginx/vortex/{domain}.conf) - confirmed via GitHub issue #14 that
    this meant OpenLiteSpeed sites (config at a completely different path
    and format) always hit a 404, and Apache/Caddy sites had the identical
    problem despite not being reported yet.
    """
    candidates = [
        (os.path.join('/etc/nginx/vortex', f'{domain}.conf'), 'nginx'),
        (os.path.join('/etc/apache2/sites-available', f'{domain}.conf'), 'apache'),
        (os.path.join(f'/usr/local/lsws/conf/vhosts/{domain}', 'vhconf.conf'), 'openlitespeed'),
        (os.path.join('/etc/caddy/sites', f'{domain}.conf'), 'caddy'),
    ]
    for path, ws in candidates:
        if os.path.exists(path):
            return path, ws
    return None, None


def _split_site_block(content):
    """Split a Caddy site config into (header, inner_content, trailing) by
    finding the FIRST '{' and its matching closing '}' via real brace
    counting - a naive regex can't handle this correctly since the site's
    own directives already contain nested braces (@notStatic{...},
    @blocked{...}), and matching the wrong closing brace would silently
    corrupt the config. Returns (None, None, None) if no balanced block found.
    """
    start = content.find('{')
    if start == -1:
        return None, None, None
    depth = 0
    for i in range(start, len(content)):
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
            if depth == 0:
                return content[:start+1], content[start+1:i], content[i:]
    return None, None, None


@websites_bp.route('/api/websites/<domain>/waf', methods=['POST'])
def enable_caddy_waf(domain):
    if not req(): return jsonify({'ok': False}), 401
    fp, webserver = _find_site_config(domain)
    if not fp:
        return jsonify({'ok': False, 'error': f'No config found for {domain}'}), 404
    if webserver != 'caddy':
        return jsonify({'ok': False, 'error': 'The Caddy WAF only applies to sites served by Caddy'}), 400

    # Verify the WAF module is genuinely loadable by the CURRENT Caddy
    # binary, not just that the caddy-waf app-store entry was clicked at
    # some point - the module only exists if Caddy was actually rebuilt
    # with it, matching the same real-verification discipline already
    # applied to ModSecurity's connector.
    modules = sh('caddy list-modules 2>/dev/null')
    if 'http.handlers.waf' not in modules:
        return jsonify({'ok': False, 'error': 'caddy-waf is not installed — install it from the App Store first (Security category)'}), 400

    with open(fp) as f:
        content = f.read()
    if 'waf {' in content or 'waf{' in content:
        return jsonify({'ok': True, 'message': 'WAF already enabled for this site'})

    header, inner, trailing = _split_site_block(content)
    if header is None:
        return jsonify({'ok': False, 'error': 'Could not parse this site\'s config — no balanced site block found'}), 400

    waf_block = (
        '\n    route {\n'
        '        waf {\n'
        '            metrics_endpoint   /waf_metrics\n'
        '            rule_file          /etc/caddy/waf/rules.json\n'
        '            ip_blacklist_file  /etc/caddy/waf/ip_blacklist.txt\n'
        '            dns_blacklist_file /etc/caddy/waf/dns_blacklist.txt\n'
        '        }\n'
        f'    {inner.strip()}\n'
        '    }\n'
    )
    new_content = header + waf_block + trailing

    # Write to a temp file for validation rather than relying on process
    # substitution, which is not portable across every shell VortexPanel
    # might invoke this under.
    tmp_path = fp + '.waf-test'
    with open(tmp_path, 'w') as f:
        f.write(new_content)
    test = sh(f'caddy validate --config {tmp_path} --adapter caddyfile 2>&1')
    if 'error' in test.lower() or 'invalid' in test.lower():
        os.remove(tmp_path)
        return jsonify({'ok': False, 'error': f'Resulting config failed validation, WAF not enabled: {test[:300]}'}), 400

    os.replace(tmp_path, fp)
    sh('systemctl reload caddy 2>/dev/null')
    return jsonify({'ok': True})


@websites_bp.route('/api/websites/<domain>/waf', methods=['DELETE'])
def disable_caddy_waf(domain):
    if not req(): return jsonify({'ok': False}), 401
    fp, webserver = _find_site_config(domain)
    if not fp:
        return jsonify({'ok': False, 'error': f'No config found for {domain}'}), 404
    if webserver != 'caddy':
        return jsonify({'ok': False, 'error': 'The Caddy WAF only applies to sites served by Caddy'}), 400

    with open(fp) as f:
        content = f.read()
    if 'waf {' not in content and 'waf{' not in content:
        return jsonify({'ok': True, 'message': 'WAF was not enabled for this site'})

    header, inner, trailing = _split_site_block(content)
    if header is None:
        return jsonify({'ok': False, 'error': 'Could not parse this site\'s config'}), 400

    # The inner content is currently "route { waf {...} <original> }" -
    # find that inner route block and pull the original directives back out
    # from underneath it, dropping the route/waf wrapper entirely.
    route_start = inner.find('route {')
    if route_start == -1:
        return jsonify({'ok': False, 'error': 'Expected a route{} block containing the WAF but did not find one'}), 400
    _, route_inner, route_trailing = _split_site_block(inner[route_start:])
    # route_inner is "waf {...}\n    <original directives>" - strip the waf{} sub-block
    waf_start = route_inner.find('waf {')
    if waf_start == -1:
        return jsonify({'ok': False, 'error': 'Could not locate the waf{} block to remove'}), 400
    _, _, after_waf = _split_site_block(route_inner[waf_start:])
    original_directives = after_waf.lstrip('}').strip()

    new_content = header + '\n    ' + original_directives + '\n' + trailing

    tmp_path = fp + '.waf-test'
    with open(tmp_path, 'w') as f:
        f.write(new_content)
    test = sh(f'caddy validate --config {tmp_path} --adapter caddyfile 2>&1')
    if 'error' in test.lower() or 'invalid' in test.lower():
        os.remove(tmp_path)
        return jsonify({'ok': False, 'error': f'Resulting config failed validation, WAF not removed: {test[:300]}'}), 400

    os.replace(tmp_path, fp)
    sh('systemctl reload caddy 2>/dev/null')
    return jsonify({'ok': True})


@websites_bp.route('/api/websites/<domain>/config')
def get_config(domain):
    if not req(): return jsonify({'ok':False}), 401
    fp, webserver = _find_site_config(domain)
    if fp:
        with open(fp) as f: return jsonify({'ok':True, 'content':f.read(), 'path':fp, 'webserver':webserver})
    return jsonify({'ok':False, 'error':f'No config found for {domain} under any supported web server (nginx, Apache, OpenLiteSpeed, Caddy)'}), 404


@websites_bp.route('/api/websites/<domain>/config', methods=['PUT'])
def save_config(domain):
    if not req(): return jsonify({'ok':False}), 401
    content = (request.get_json() or {}).get('content','')
    fp, webserver = _find_site_config(domain)
    if not fp:
        return jsonify({'ok':False, 'error':f'No config found for {domain} under any supported web server'}), 404
    with open(fp,'w') as f: f.write(content)
    if webserver == 'nginx':
        test = sh('nginx -t 2>&1')
        if 'failed' in test.lower():
            return jsonify({'ok':False, 'error':f'Nginx config test failed: {test}'}), 400
        reload_nginx()
    elif webserver == 'apache':
        test = sh('apache2ctl configtest 2>&1')
        if 'syntax error' in test.lower():
            return jsonify({'ok':False, 'error':f'Apache config test failed: {test}'}), 400
        sh('systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null')
    elif webserver == 'openlitespeed':
        sh('kill -USR1 $(cat /tmp/lshttpd.pid 2>/dev/null) 2>/dev/null || systemctl reload lsws 2>/dev/null')
    elif webserver == 'caddy':
        sh('systemctl reload caddy 2>/dev/null')
    return jsonify({'ok':True})


@websites_bp.route('/api/websites/webroot')
def webroot():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, 'path':get_webroot()})


# --- DOMAIN MANAGER -------------------------------------------------------------
@websites_bp.route('/api/websites/<domain>/domains')
def get_domains(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':True,'domains':[]})
    with open(fp) as f: content = f.read()
    m = re.search(r'server_name\s+([^;]+);', content)
    domains = []
    if m:
        for d in m.group(1).strip().split():
            port = '80'
            if ':' in d:
                parts = d.rsplit(':',1); d=parts[0]; port=parts[1]
            domains.append({'domain':d,'port':port})
    return jsonify({'ok':True,'domains':domains})


@websites_bp.route('/api/websites/<domain>/domains', methods=['POST'])
def add_domain_binding(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    new_domain = d.get('domain','').strip()
    if not new_domain: return jsonify({'ok':False,'error':'Domain required'}), 400
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site not found'}), 404
    with open(fp) as f: content = f.read()
    content = re.sub(r'(server_name\s+)([^;]+)(;)',
        lambda m2: m2.group(1)+m2.group(2).strip()+' '+new_domain+m2.group(3), content, count=1)
    with open(fp,'w') as f: f.write(content)
    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower(): return jsonify({'ok':False,'error':test}), 400
    reload_nginx()
    return jsonify({'ok':True})


@websites_bp.route('/api/websites/<domain>/domains/<target>', methods=['DELETE'])
def remove_domain_binding(domain, target):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Not found'}), 404
    with open(fp) as f: content = f.read()
    content = re.sub(r'\s+'+re.escape(target), '', content)
    with open(fp,'w') as f: f.write(content)
    reload_nginx()
    return jsonify({'ok':True})


# --- PHP VERSIONS FOR DOMAIN ----------------------------------------------------
@websites_bp.route('/api/websites/<domain>/php-versions')
def get_php_versions_for_domain(domain):
    if not req(): return jsonify({'ok':False}), 401
    versions = []
    for v in ['8.4','8.3','8.2','8.1','8.0','7.4','7.3','7.2']:
        binary = f'/usr/bin/php{v}'
        if os.path.exists(binary):
            status = sh(f'systemctl is-active php{v}-fpm 2>/dev/null') or 'inactive'
            versions.append({'version':v,'binary':binary,'sock':f'/run/php/php{v}-fpm.sock','status':status})
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    current = 'static'
    if os.path.exists(fp):
        with open(fp) as f: content = f.read()
        m = re.search(r'fastcgi_pass.*?php([\d.]+).*?fpm', content)
        if m: current = m.group(1)
    return jsonify({'ok':True,'versions':versions,'current':current})


# --- PHP VERSION PER DOMAIN (set) -----------------------------------------------
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


# --- DIRECTORY ------------------------------------------------------------------
DIRECTORY_INI_MARKER = '; Added by VortexPanel Directory Protection (Anti-XSS / open_basedir)'

@websites_bp.route('/api/websites/<domain>/directory')
def get_directory(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    conf_path = os.path.join(avail, f'{domain}.conf')
    root_path = get_webroot() + '/' + domain
    accesslog_off = False
    if os.path.exists(conf_path):
        with open(conf_path) as f: content = f.read()
        m = re.search(r'root\s+([^;]+);', content)
        if m: root_path = m.group(1).strip()
        accesslog_off = bool(re.search(r'access_log\s+off\s*;', content))
    ini_path = os.path.join(root_path, '.user.ini')
    antixss = False
    if os.path.exists(ini_path):
        try:
            antixss = 'open_basedir' in open(ini_path).read()
        except Exception:
            pass
    return jsonify({'ok':True,'path':root_path, 'antixss':antixss, 'accesslog': not accesslog_off})


@websites_bp.route('/api/websites/<domain>/directory', methods=['PUT'])
def set_directory(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    new_path = d.get('path','').strip()
    if not new_path: return jsonify({'ok':False,'error':'Path required'})
    avail, _ = get_nginx_dirs()
    conf_path = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(conf_path):
        return jsonify({'ok':False,'error':'Config not found'})
    with open(conf_path) as f: content = f.read()
    content = re.sub(r'root\s+[^;]+;', f'root {new_path};', content)
    os.makedirs(new_path, exist_ok=True)
    ensure_web_ownership(new_path)
    with open(conf_path,'w') as f: f.write(content)
    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower():
        return jsonify({'ok':False,'error':test})
    reload_nginx()
    return jsonify({'ok':True})


@websites_bp.route('/api/websites/<domain>/directory/antixss', methods=['POST'])
def set_directory_antixss(domain):
    """Anti-XSS / 'Base directory limit' (aaPanel's naming for PHP's
    open_basedir). Implemented via a per-directory .user.ini file rather
    than editing the shared PHP-FPM pool config -- every site on this
    server currently shares one pool per PHP version (confirmed: nginx
    vhosts all point at /run/php/php{version}-fpm.sock, not a per-site
    socket), so writing open_basedir into that shared pool would restrict
    every other site running the same PHP version too. .user.ini is
    PHP's own directory-scoped mechanism and only affects this site."""
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    enabled = bool(d.get('enabled', False))

    avail, _ = get_nginx_dirs()
    conf_path = os.path.join(avail, f'{domain}.conf')
    root_path = get_webroot() + '/' + domain
    if os.path.exists(conf_path):
        with open(conf_path) as f: content = f.read()
        m = re.search(r'root\s+([^;]+);', content)
        if m: root_path = m.group(1).strip()

    if not os.path.isdir(root_path):
        return jsonify({'ok':False, 'error': f'Site directory not found: {root_path}'}), 404

    ini_path = os.path.join(root_path, '.user.ini')

    if enabled:
        directive = f'open_basedir = "{root_path}/:/tmp/:/var/tmp/:/proc/:/dev/urandom"'
        try:
            with open(ini_path, 'w') as f:
                f.write(f'{DIRECTORY_INI_MARKER}\n{directive}\n')
            ensure_web_ownership(ini_path)
        except Exception as e:
            return jsonify({'ok':False, 'error': f'Could not write .user.ini: {e}'}), 500
    else:
        if os.path.exists(ini_path):
            try:
                existing = open(ini_path).read()
            except Exception as e:
                return jsonify({'ok':False, 'error': str(e)}), 500
            if DIRECTORY_INI_MARKER not in existing:
                # A .user.ini exists but wasn't created by this feature --
                # don't blindly delete a file the site owner added for
                # unrelated reasons.
                return jsonify({'ok':False, 'error': '.user.ini exists with content not managed by VortexPanel — remove it manually if you want to disable this'}), 400
            try:
                os.remove(ini_path)
            except Exception as e:
                return jsonify({'ok':False, 'error': str(e)}), 500

    return jsonify({'ok':True, 'enabled':enabled,
                     'note':"PHP re-reads .user.ini every ~5 minutes by default (user_ini.cache_ttl) — restart PHP-FPM for this site's version to apply immediately"})


@websites_bp.route('/api/websites/<domain>/directory/accesslog', methods=['POST'])
def set_directory_accesslog(domain):
    """Toggle this site's nginx access_log on/off. Note: Fail2ban's
    website anti-CC/anti-scan jails (Security -> Fail2ban) tail this
    exact log file -- disabling it here will silently stop those jails
    from seeing any traffic for this site."""
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    enabled = bool(d.get('enabled', True))

    avail, _ = get_nginx_dirs()
    conf_path = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(conf_path):
        return jsonify({'ok':False,'error':'Config not found'}), 404

    with open(conf_path) as f: original = f.read()
    real_log_path = f'/var/log/nginx/{domain}.access.log'
    if enabled:
        content = re.sub(r'access_log\s+[^;]+;', f'access_log {real_log_path};', original)
    else:
        content = re.sub(r'access_log\s+[^;]+;', 'access_log off;', original)

    with open(conf_path, 'w') as f: f.write(content)
    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower():
        with open(conf_path, 'w') as f: f.write(original)  # roll back — never leave nginx broken
        return jsonify({'ok':False, 'error': test}), 500
    reload_nginx()

    warning = None
    if not enabled:
        safe_site = re.sub(r'[^a-zA-Z0-9_-]', '', domain.replace('.', '_'))[:60]
        jail_conf = f'/etc/fail2ban/jail.d/vortex-site-{safe_site}.conf'
        if os.path.exists(jail_conf):
            warning = 'This site has an active Fail2ban protection jail that reads this log — disabling it will stop that jail from detecting new traffic.'

    return jsonify({'ok':True, 'enabled':enabled, 'warning':warning})


# --- LOGS -----------------------------------------------------------------------
@websites_bp.route('/api/websites/<domain>/logs')
def get_site_logs(domain):
    if not req(): return jsonify({'ok':False}), 401
    access_log = f'/var/log/nginx/{domain}.access.log'
    error_log  = f'/var/log/nginx/{domain}.error.log'
    def read_log(p):
        if not os.path.exists(p): return 'Log file not found'
        return sh(f'tail -100 {p}') or 'Empty log'
    return jsonify({'ok':True,
        'access': read_log(access_log), 'access_path': access_log,
        'error':  read_log(error_log),  'error_path':  error_log})


# --- DISK USAGE -------------------------------------------------------------------
@websites_bp.route('/api/websites/<domain>/disk-usage')
def get_site_disk_usage(domain):
    """Lazy on-demand disk usage — not called on the main list to avoid slow page loads
    on servers with many/large sites. Frontend calls this when the drawer opens."""
    if not req(): return jsonify({'ok':False}), 401
    path = _get_site_path(domain)
    if not path or not os.path.isdir(path):
        return jsonify({'ok':False,'error':'Site directory not found'})
    # du -sh with a timeout — large sites (node_modules, media) can be slow
    out = sh(f'du -sh {path} 2>/dev/null | cut -f1', t=20)
    size_human = out.strip() if out else 'Unknown'
    # Also get byte count for sorting/comparison if needed later
    out_bytes = sh(f'du -sb {path} 2>/dev/null | cut -f1', t=20)
    try:
        size_bytes = int(out_bytes.strip())
    except (ValueError, AttributeError):
        size_bytes = 0
    # File + folder counts (fast, no size calc)
    file_count = sh(f'find {path} -type f 2>/dev/null | wc -l', t=15)
    dir_count  = sh(f'find {path} -type d 2>/dev/null | wc -l', t=15)
    return jsonify({
        'ok': True, 'domain': domain, 'path': path,
        'size_human': size_human, 'size_bytes': size_bytes,
        'file_count': int(file_count.strip() or 0),
        'dir_count':  int(dir_count.strip() or 0),
    })


