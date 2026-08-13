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
    """Core site-creation logic — shared by the normal create_site() route AND
    the website-import feature (cPanel/aaPanel/Hestia), so both paths always
    produce identical, correct nginx vhosts with zero risk of drift between them.
    Returns (ok: bool, result: dict) — result has 'domain'/'path' on success or
    'error' on failure."""
    domain = (domain or '').strip().lower()
    path = (path or f'{get_webroot()}/{domain}').strip()
    if not domain:
        return False, {'error': 'Domain required'}

    # Create webroot
    os.makedirs(path, exist_ok=True)
    idx = os.path.join(path, 'index.html')
    if not os.path.exists(idx):
        with open(idx, 'w') as f:
            f.write(f'<!DOCTYPE html><html><body><h1>Welcome to {domain}</h1><p>VortexPanel — site created successfully.</p></body></html>')

    ensure_web_ownership(path)

    avail, enabled_dir = get_nginx_dirs()

    php_sock = f'/run/php/php{php}-fpm.sock'
    for sock in [f'/run/php/php{php}-fpm.sock', f'/var/run/php/php{php}-fpm.sock',
                 f'/tmp/php{php}-fpm.sock', f'/run/php-fpm/php{php}-fpm.sock',
                 f'/run/php-fpm/www.sock', f'/var/run/php-fpm/www.sock']:
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
        if avail != enabled_dir and not os.path.exists(enabled_path):
            os.symlink(conf_path, enabled_path)
        test = sh('nginx -t 2>&1')
        if 'failed' in test.lower():
            return False, {'error': f'Nginx config test failed: {test}'}
        reload_nginx()
        return True, {'domain': domain, 'path': path}
    except Exception as e:
        return False, {'error': str(e)}


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


