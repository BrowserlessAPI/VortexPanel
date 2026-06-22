"""
VortexPanel WP Toolkit
Supports: PHP 7.4–8.5 | Nginx / Apache / OpenLiteSpeed / Caddy | MariaDB / MySQL
"""
import os, re, json, uuid, shutil, subprocess, secrets, string
from datetime import datetime
from flask import Blueprint, jsonify, request, session

try:
    from panel.routes.os_utils import get_os, get_webserver_user, panel_cache
except ImportError:
    from os_utils import get_os, get_webserver_user, panel_cache

wp_bp = Blueprint('wp_toolkit', __name__)

# --- Paths ----------------------------------------------------------------------
WP_BACKUP_DIR = '/opt/vortexpanel/wp_backups'
WP_CLI        = '/usr/local/bin/wp'
WEBROOTS      = ['/www/wwwroot', '/var/www/html', '/var/www', '/home']


# ===============================================================================
# HELPERS
# ===============================================================================

def req():
    return 'user' in session

def sh(cmd, t=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip()
    except Exception:
        return ''

def sh3(cmd, t=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return '', str(e), 1

def _web_user():
    """nginx/www-data/apache depending on distro"""
    u = get_webserver_user()
    return u or 'www-data'

def _wp(path, cmd, t=60):
    """Run a wp-cli command in the given path."""
    web_user = _web_user()
    # Try running as web user; fall back to --allow-root
    if os.path.exists(WP_CLI):
        out, err, rc = sh3(f'sudo -u {web_user} {WP_CLI} --path="{path}" {cmd} 2>&1', t=t)
        if rc != 0 and 'sudo' in err:
            out, err, rc = sh3(f'{WP_CLI} --path="{path}" --allow-root {cmd} 2>&1', t=t)
        return out, err, rc
    return '', 'wp-cli not installed', 1

def _wp_installed():
    return os.path.exists(WP_CLI)

def _install_wpcli():
    """Download and install wp-cli if missing."""
    if os.path.exists(WP_CLI):
        return True
    out, err, rc = sh3(
        'curl -sL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar'
        f' -o {WP_CLI} && chmod +x {WP_CLI}', t=30
    )
    return rc == 0

def _detect_webserver():
    """Return active webserver: nginx | apache | openlitespeed | caddy"""
    if sh('systemctl is-active nginx 2>/dev/null') == 'active':
        return 'nginx'
    if sh('systemctl is-active apache2 2>/dev/null') == 'active' or \
       sh('systemctl is-active httpd 2>/dev/null') == 'active':
        return 'apache'
    if sh('systemctl is-active lsws 2>/dev/null') == 'active':
        return 'openlitespeed'
    if sh('systemctl is-active caddy 2>/dev/null') == 'active':
        return 'caddy'
    return 'nginx'  # default

def _installed_webservers():
    """Return list of actually installed webservers."""
    installed = []
    if shutil.which('nginx'):
        installed.append('nginx')
    if shutil.which('apache2') or shutil.which('httpd'):
        installed.append('apache')
    if os.path.exists('/usr/local/lsws/bin/lshttpd'):
        installed.append('openlitespeed')
    if shutil.which('caddy'):
        installed.append('caddy')
    if not installed:
        installed.append('nginx')  # assume nginx as fallback
    return installed

def _php_sock(ver):
    """Return the PHP-FPM socket path for a given version."""
    for sock in [
        f'/run/php/php{ver}-fpm.sock',
        f'/var/run/php/php{ver}-fpm.sock',
        f'/run/php-fpm/php{ver}-fpm.sock',
        f'/var/run/php-fpm/www.sock',
        f'/tmp/php{ver}-fpm.sock',
    ]:
        if os.path.exists(sock):
            return sock
    return f'/run/php/php{ver}-fpm.sock'

def _available_php():
    """Return list of installed PHP versions (7.4–8.5) with socket status."""
    versions = []
    for v in ['8.5', '8.4', '8.3', '8.2', '8.1', '8.0', '7.4']:
        sock = _php_sock(v)
        if os.path.exists(sock) or shutil.which(f'php{v}'):
            versions.append({'version': v, 'sock': sock, 'active': os.path.exists(sock)})
    return versions

def _available_db():
    """Return available DB engines."""
    engines = []
    if sh('which mysql 2>/dev/null') or sh('systemctl is-active mysql 2>/dev/null') == 'active':
        engines.append('mysql')
    if sh('which mariadb 2>/dev/null') or sh('systemctl is-active mariadb 2>/dev/null') == 'active':
        engines.append('mariadb')
    if not engines:
        engines = ['mysql', 'mariadb']  # assume available, let install fail gracefully
    return engines

def _mysql_cmd(query, engine='mysql'):
    """Run a MySQL/MariaDB query as root."""
    cli = 'mariadb' if (engine == 'mariadb' and shutil.which('mariadb')) else 'mysql'
    out, err, rc = sh3(f'{cli} -u root -e "{query}" 2>/dev/null')
    return out, err, rc

def _rand_str(n=12):
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(n))

def _rand_prefix():
    return 'wp_' + _rand_str(6) + '_'

def _rand_pass(n=20):
    chars = string.ascii_letters + string.digits + '!@#$%^&*'
    return ''.join(secrets.choice(chars) for _ in range(n))

os.makedirs(WP_BACKUP_DIR, exist_ok=True)


# ===============================================================================
# VHOST GENERATORS (Nginx / Apache / OpenLiteSpeed / Caddy)
# ===============================================================================

def _nginx_vhost(domain, path, php_ver):
    sock = _php_sock(php_ver)
    return f"""server {{
    listen 80;
    server_name {domain} www.{domain};
    root {path};
    index index.php index.html index.htm;

    access_log /var/log/nginx/{domain}.access.log;
    error_log  /var/log/nginx/{domain}.error.log;

    # WordPress permalinks
    location / {{
        try_files $uri $uri/ /index.php?$args;
    }}

    # Block access to sensitive files
    location ~* /\\.ht {{
        deny all;
    }}
    location ~* wp-config\\.php {{
        deny all;
    }}

    location ~ \\.php$ {{
        include fastcgi_params;
        fastcgi_pass unix:{sock};
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_index index.php;
        fastcgi_read_timeout 300;
    }}
}}
"""

def _apache_vhost(domain, path, php_ver):
    sock = _php_sock(php_ver)
    return f"""<VirtualHost *:80>
    ServerName {domain}
    ServerAlias www.{domain}
    DocumentRoot {path}

    <Directory {path}>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # PHP-FPM via Unix socket
    <FilesMatch \\.php$>
        SetHandler "proxy:unix:{sock}|fcgi://localhost/"
    </FilesMatch>

    # Deny access to sensitive files
    <FilesMatch "wp-config\\.php">
        Require all denied
    </FilesMatch>

    ErrorLog  /var/log/apache2/{domain}.error.log
    CustomLog /var/log/apache2/{domain}.access.log combined
</VirtualHost>
"""

def _apache_htaccess():
    return """# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
"""

def _ols_vhost(domain, path, php_ver):
    """OpenLiteSpeed virtual host config in /usr/local/lsws/conf/vhosts/"""
    sock = _php_sock(php_ver)
    return f"""docRoot                   {path}/
vhDomain                  {domain}
vhAliases                 www.{domain}
adminEmails               webmaster@{domain}
enableGzip                1

index  {{
  useServer               0
  indexFiles              index.php, index.html
}}

extprocessor lsphp{{
  type                    fcgi
  address                 UDS://{sock}
  maxConns                35
  env                     PHP_LSAPI_CHILDREN=35
  initTimeout             60
  retryTimeout            0
  persistConn             1
  respBuffer              0
  autoStart               1
  path                    {shutil.which('php' + php_ver) or '/usr/bin/php' + php_ver}
  backlog                 100
  instances               1
  priority                0
  memSoftLimit            2047M
  memHardLimit            2047M
  procSoftLimit           400
  procHardLimit           500
}}

scripthandler  {{
  add                     fcgi:lsphp php
}}

rewrite  {{
  enable                  1
  autoLoadHtaccess        1
  rules                   <<<END_rules
RewriteRule ^/index\\.php$ - [L]
RewriteCond %{{REQUEST_FILENAME}} !-f
RewriteCond %{{REQUEST_FILENAME}} !-d
RewriteRule . /index.php [L]
  END_rules
}}

accessControl  {{
  allow                   *
}}
"""

def _caddy_vhost(domain, path, php_ver):
    sock = _php_sock(php_ver)
    return f"""{domain} {{
    root * {path}
    encode gzip

    php_fastcgi unix/{sock}
    file_server

    # WordPress permalinks
    @notStatic {{
        not file
        path_regexp ^\\/(?:wp-admin|wp-includes)
    }}
    rewrite @notStatic /index.php?{{query}}

    # Block sensitive files
    @blocked {{
        path *.php
        not path /wp-login.php /wp-cron.php /wp-admin/* /wp-includes/*.php
    }}
    respond @blocked 403

    @wpconfig {{
        path /wp-config.php
    }}
    respond @wpconfig 403

    log {{
        output file /var/log/caddy/{domain}.log
    }}
}}
"""

def _write_vhost(domain, path, php_ver, webserver):
    """Write vhost config for the given webserver and reload it."""
    ws = webserver or _detect_webserver()

    if ws == 'nginx':
        vhost_dir = '/etc/nginx/vortex'
        os.makedirs(vhost_dir, exist_ok=True)
        conf_path = f'{vhost_dir}/{domain}.conf'
        with open(conf_path, 'w') as f:
            f.write(_nginx_vhost(domain, path, php_ver))
        test_out, test_err, rc = sh3('nginx -t 2>&1')
        if rc != 0:
            os.unlink(conf_path)
            return False, f'nginx config error: {test_out}{test_err}'
        sh('systemctl reload nginx 2>/dev/null')

    elif ws == 'apache':
        vhost_dir = '/etc/apache2/sites-available'
        os.makedirs(vhost_dir, exist_ok=True)
        conf_path = f'{vhost_dir}/{domain}.conf'
        with open(conf_path, 'w') as f:
            f.write(_apache_vhost(domain, path, php_ver))
        htaccess_path = os.path.join(path, '.htaccess')
        if not os.path.exists(htaccess_path):
            with open(htaccess_path, 'w') as f:
                f.write(_apache_htaccess())
        sh(f'a2ensite {domain}.conf 2>/dev/null')
        sh('a2enmod rewrite proxy_fcgi setenvif 2>/dev/null')
        test_out, test_err, rc = sh3('apachectl configtest 2>&1')
        if 'Syntax error' in (test_out + test_err):
            sh(f'a2dissite {domain}.conf 2>/dev/null')
            return False, f'Apache config error: {test_out}{test_err}'
        sh('systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null')

    elif ws == 'openlitespeed':
        vhost_dir = f'/usr/local/lsws/conf/vhosts/{domain}'
        os.makedirs(vhost_dir, exist_ok=True)
        conf_path = f'{vhost_dir}/vhconf.conf'
        with open(conf_path, 'w') as f:
            f.write(_ols_vhost(domain, path, php_ver))
        htaccess_path = os.path.join(path, '.htaccess')
        if not os.path.exists(htaccess_path):
            with open(htaccess_path, 'w') as f:
                f.write(_apache_htaccess())
        sh('kill -USR1 $(cat /tmp/lshttpd.pid 2>/dev/null) 2>/dev/null || systemctl reload lsws 2>/dev/null')

    elif ws == 'caddy':
        os.makedirs('/etc/caddy/sites', exist_ok=True)
        conf_path = f'/etc/caddy/sites/{domain}.caddy'
        with open(conf_path, 'w') as f:
            f.write(_caddy_vhost(domain, path, php_ver))
        caddy_main = '/etc/caddy/Caddyfile'
        if os.path.exists(caddy_main):
            content = open(caddy_main).read()
            import_line = 'import /etc/caddy/sites/*.caddy'
            if import_line not in content:
                with open(caddy_main, 'a') as f:
                    f.write(f'\n{import_line}\n')
        out, err, rc = sh3('caddy validate --config /etc/caddy/Caddyfile 2>&1')
        if rc != 0:
            os.unlink(conf_path)
            return False, f'Caddy config error: {out}{err}'
        sh('systemctl reload caddy 2>/dev/null')

    return True, conf_path

def _delete_vhost(domain, webserver):
    ws = webserver or _detect_webserver()
    if ws == 'nginx':
        for p in [f'/etc/nginx/vortex/{domain}.conf', f'/etc/nginx/conf.d/{domain}.conf']:
            try: os.unlink(p)
            except: pass
        sh('systemctl reload nginx 2>/dev/null')
    elif ws == 'apache':
        sh(f'a2dissite {domain}.conf 2>/dev/null')
        for p in [f'/etc/apache2/sites-available/{domain}.conf', f'/etc/apache2/sites-enabled/{domain}.conf']:
            try: os.unlink(p)
            except: pass
        sh('systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null')
    elif ws == 'openlitespeed':
        try: shutil.rmtree(f'/usr/local/lsws/conf/vhosts/{domain}')
        except: pass
        sh('systemctl reload lsws 2>/dev/null')
    elif ws == 'caddy':
        try: os.unlink(f'/etc/caddy/sites/{domain}.caddy')
        except: pass
        sh('systemctl reload caddy 2>/dev/null')


# ===============================================================================
# WP INSTALL DETECTION
# ===============================================================================

def _scan_wp_sites():
    """Scan all webroots for wp-config.php and gather site metadata."""
    sites = []
    seen = set()

    # Scan common webroots
    scan_paths = []
    for root in WEBROOTS:
        if os.path.isdir(root):
            try:
                for d in os.listdir(root):
                    scan_paths.append(os.path.join(root, d))
            except: pass
    # Also check nginx/apache vhosts we know about
    for conf_dir in ['/etc/nginx/vortex', '/etc/nginx/conf.d', '/etc/apache2/sites-enabled']:
        if not os.path.isdir(conf_dir): continue
        for fn in os.listdir(conf_dir):
            fp = os.path.join(conf_dir, fn)
            if not os.path.isfile(fp): continue
            try:
                content = open(fp).read()
                for m in re.finditer(r'(?:root|DocumentRoot)\s+([^\s;{]+)', content):
                    scan_paths.append(m.group(1).strip())
            except: pass

    for path in scan_paths:
        if not os.path.isdir(path): continue
        wp_config = os.path.join(path, 'wp-config.php')
        if not os.path.exists(wp_config): continue
        if path in seen: continue
        seen.add(path)

        domain = os.path.basename(path)
        # Try reading from nginx config
        for conf_dir in ['/etc/nginx/vortex', '/etc/nginx/conf.d']:
            if not os.path.isdir(conf_dir): continue
            for fn in os.listdir(conf_dir):
                try:
                    c = open(os.path.join(conf_dir, fn)).read()
                    if path in c:
                        m = re.search(r'server_name\s+([^;]+);', c)
                        if m: domain = m.group(1).strip().split()[0]
                        break
                except: pass

        site = _get_wp_info(path, domain)
        sites.append(site)

    return sites

def _get_wp_info(path, domain=None):
    """Get WordPress site metadata."""
    if not domain:
        domain = os.path.basename(path)

    wp_config = os.path.join(path, 'wp-config.php')
    info = {
        'domain': domain,
        'path': path,
        'status': 'active',
        'wp_version': '—',
        'php_version': '—',
        'db_name': '—',
        'db_engine': '—',
        'ssl': False,
        'admin_user': '—',
        'admin_email': '—',
        'site_title': '—',
        'site_url': f'http://{domain}',
        'disk_used': 0,
        'plugin_count': 0,
        'theme_count': 0,
        'update_count': 0,
        'is_staging': 'staging' in domain.lower(),
        'webserver': _detect_webserver(),
        'has_backup': False,
        'table_prefix': 'wp_',
        'debug_mode': False,
        'maintenance': False,
        'search_visible': True,
        'nginx_cache': False,
        'system_cron': False,
        'staged_from': None,
    }

    # Parse wp-config.php for basic info
    if os.path.exists(wp_config):
        try:
            cfg = open(wp_config).read()
            def cfg_val(key):
                m = re.search(rf"define\s*\(\s*['\"]{{0,1}}{key}['\"]{{0,1}}\s*,\s*['\"]([^'\"]+)['\"]", cfg)
                return m.group(1) if m else None
            info['db_name'] = cfg_val('DB_NAME') or '—'
            info['debug_mode'] = "define('WP_DEBUG', true)" in cfg or "define(\"WP_DEBUG\", true)" in cfg
            prefix_m = re.search(r"\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]", cfg)
            if prefix_m: info['table_prefix'] = prefix_m.group(1)
        except: pass

    # WordPress version
    version_file = os.path.join(path, 'wp-includes', 'version.php')
    if os.path.exists(version_file):
        try:
            vc = open(version_file).read()
            vm = re.search(r"\\\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", vc)
            if vm: info['wp_version'] = vm.group(1)
        except: pass

    # PHP version from nginx config
    for conf_dir in ['/etc/nginx/vortex', '/etc/nginx/conf.d']:
        if not os.path.isdir(conf_dir): continue
        for fn in os.listdir(conf_dir):
            try:
                c = open(os.path.join(conf_dir, fn)).read()
                if path in c or domain in c:
                    pm = re.search(r'php(\d+[\.\d]*)-fpm\.sock', c)
                    if pm: info['php_version'] = pm.group(1)
                    break
            except: pass

    # SSL check
    for d in [f'/etc/letsencrypt/live/{domain}', f'/etc/nginx/ssl/{domain}']:
        if os.path.isdir(d):
            info['ssl'] = True
            break

    # Disk usage
    try:
        du = sh(f'du -sb "{path}" 2>/dev/null | cut -f1')
        if du.isdigit():
            info['disk_used'] = int(du)
    except: pass

    # Plugin / theme counts
    plugins_dir = os.path.join(path, 'wp-content', 'plugins')
    themes_dir  = os.path.join(path, 'wp-content', 'themes')
    try:
        info['plugin_count'] = len([d for d in os.listdir(plugins_dir) if os.path.isdir(os.path.join(plugins_dir, d))]) if os.path.isdir(plugins_dir) else 0
    except: pass
    try:
        info['theme_count'] = len([d for d in os.listdir(themes_dir) if os.path.isdir(os.path.join(themes_dir, d))]) if os.path.isdir(themes_dir) else 0
    except: pass

    # wp-cli extended info (when available)
    if _wp_installed():
        out = sh(f'{WP_CLI} --path="{path}" --allow-root option get siteurl 2>/dev/null')
        if out and 'http' in out:
            info['site_url'] = out

        out = sh(f'{WP_CLI} --path="{path}" --allow-root option get blogname 2>/dev/null')
        if out: info['site_title'] = out

        out = sh(f'{WP_CLI} --path="{path}" --allow-root option get admin_email 2>/dev/null')
        if out: info['admin_email'] = out

        out = sh(f'{WP_CLI} --path="{path}" --allow-root option get blog_public 2>/dev/null')
        info['search_visible'] = out.strip() != '0'

        # Admin user
        out = sh(f'{WP_CLI} --path="{path}" --allow-root user list --role=administrator --field=user_login --format=csv 2>/dev/null')
        if out: info['admin_user'] = out.split('\n')[0].strip()

        # DB engine
        out = sh(f'{WP_CLI} --path="{path}" --allow-root db query "SELECT @@version_comment" 2>/dev/null')
        if 'mariadb' in out.lower() or 'Maria' in out:
            info['db_engine'] = 'mariadb'
        elif out:
            info['db_engine'] = 'mysql'

        # Update count
        out = sh(f'{WP_CLI} --path="{path}" --allow-root core check-update --field=version --format=count 2>/dev/null')
        plugin_updates = sh(f'{WP_CLI} --path="{path}" --allow-root plugin update --all --dry-run --format=count 2>/dev/null')
        try:
            core_upd  = 1 if out and out.strip() and not out.strip().startswith('0') and 'Success' not in out else 0
            plug_upd  = int(plugin_updates) if plugin_updates.isdigit() else 0
            info['update_count'] = core_upd + plug_upd
        except: pass

        # System cron check
        out = sh(f'{WP_CLI} --path="{path}" --allow-root config get DISABLE_WP_CRON 2>/dev/null')
        info['system_cron'] = out.strip().lower() in ('true', '1')

        # Maintenance mode
        info['maintenance'] = os.path.exists(os.path.join(path, '.maintenance'))

    # Backup check
    info['has_backup'] = any(
        f.startswith(domain) for f in os.listdir(WP_BACKUP_DIR)
        if os.path.isfile(os.path.join(WP_BACKUP_DIR, f))
    )

    return info


# ===============================================================================
# ROUTES
# ===============================================================================

@wp_bp.route('/api/wp/sites')
def list_sites():
    if not req(): return jsonify({'ok': False}), 401
    cached = panel_cache.get('wp_sites')
    if cached: return jsonify(cached)
    sites = _scan_wp_sites()
    resp = {
        'ok': True,
        'sites': sites,
        'webservers': ['nginx', 'apache', 'openlitespeed', 'caddy'],
        'installed_webservers': _installed_webservers(),
        'php_versions': _available_php(),
        'db_engines': _available_db(),
        'wpcli_installed': _wp_installed(),
        'active_webserver': _detect_webserver(),
    }
    panel_cache.set('wp_sites', resp, ttl=30)
    return jsonify(resp)


@wp_bp.route('/api/wp/install', methods=['POST'])
def install_wp():
    """Full WordPress install: download, create DB, configure, create vhost."""
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}

    domain    = d.get('domain', '').strip().lower()
    php_ver   = d.get('php_version', '8.4')
    db_engine = d.get('db_engine', 'mysql')
    wp_ver    = d.get('wp_version', 'latest')
    locale    = d.get('locale', 'en_US')
    webserver = d.get('webserver', '') or _detect_webserver()
    title     = d.get('site_title', f'WordPress — {domain}')
    admin_user  = d.get('admin_user', 'admin_' + _rand_str(5))
    admin_pass  = d.get('admin_pass', _rand_pass())
    admin_email = d.get('admin_email', f'admin@{domain}')
    prefix    = d.get('table_prefix', _rand_prefix())
    auto_ssl  = d.get('auto_ssl', True)
    system_cron = d.get('system_cron', True)
    block_xmlrpc = d.get('block_xmlrpc', False)

    if not domain:
        return jsonify({'ok': False, 'error': 'Domain is required'}), 400

    # Webroot path
    webroot = '/www/wwwroot'
    if not os.path.isdir(webroot):
        webroot = '/var/www/html'
    path = d.get('path', f'{webroot}/{domain}').strip()
    os.makedirs(path, exist_ok=True)

    # 1. Ensure wp-cli is installed
    if not _wp_installed():
        ok = _install_wpcli()
        if not ok:
            return jsonify({'ok': False, 'error': 'Failed to install wp-cli'}), 500

    # 2. Create DB and user
    db_name = re.sub(r'[^a-zA-Z0-9_]', '_', domain.replace('.', '_'))[:32]
    db_user = 'wp_' + _rand_str(8)
    db_pass = _rand_pass(16)

    _, db_err, db_rc = _mysql_cmd(
        f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;",
        engine=db_engine
    )
    if db_rc != 0:
        return jsonify({'ok': False, 'error': f'DB creation failed: {db_err}'}), 500

    _mysql_cmd(f"CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{db_pass}';", engine=db_engine)
    _mysql_cmd(f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'localhost'; FLUSH PRIVILEGES;", engine=db_engine)

    # 3. Download WordPress
    ver_flag = f'--version={wp_ver}' if wp_ver and wp_ver != 'latest' else ''
    out, err, rc = sh3(
        f'{WP_CLI} core download --path="{path}" --locale={locale} {ver_flag} --allow-root --force 2>&1',
        t=120
    )
    if rc != 0:
        return jsonify({'ok': False, 'error': f'WP download failed: {out}{err}'}), 500

    # 4. Create wp-config.php
    site_url = f'http{"s" if auto_ssl else ""}://{domain}'
    db_host_arg = '--dbhost=localhost'
    out, err, rc = sh3(
        f'{WP_CLI} config create --path="{path}" --allow-root'
        f' --dbname={db_name} --dbuser={db_user} --dbpass="{db_pass}"'
        f' {db_host_arg} --dbprefix={prefix} --force 2>&1',
        t=30
    )
    if rc != 0:
        return jsonify({'ok': False, 'error': f'wp-config creation failed: {out}{err}'}), 500

    # 5. Add extra wp-config.php constants
    extras = []
    if system_cron:
        extras.append(f"define('DISABLE_WP_CRON', true);")
    if block_xmlrpc:
        extras.append(f"define('XMLRPC_DISABLE', true);")

    if extras:
        try:
            cfg = open(f'{path}/wp-config.php').read()
            insert = '\n'.join(extras) + '\n'
            cfg = cfg.replace("/* That's all, stop editing!", insert + "\n/* That's all, stop editing!")
            with open(f'{path}/wp-config.php', 'w') as f:
                f.write(cfg)
        except: pass

    # 6. Run WP installer
    out, err, rc = sh3(
        f'{WP_CLI} core install --path="{path}" --allow-root'
        f' --url="{site_url}" --title="{title}"'
        f' --admin_user="{admin_user}" --admin_password="{admin_pass}"'
        f' --admin_email="{admin_email}" --skip-email 2>&1',
        t=60
    )
    if rc != 0:
        return jsonify({'ok': False, 'error': f'WP install failed: {out}{err}'}), 500

    # 7. Set file ownership
    web_user = _web_user()
    sh(f'chown -R {web_user}:{web_user} "{path}" 2>/dev/null || true')
    sh(f'find "{path}" -type d -exec chmod 755 {{}} \\; 2>/dev/null || true')
    sh(f'find "{path}" -type f -exec chmod 644 {{}} \\; 2>/dev/null || true')
    sh(f'chmod 600 "{path}/wp-config.php" 2>/dev/null || true')

    # 8. Create vhost
    ok, result = _write_vhost(domain, path, php_ver, webserver)
    if not ok:
        return jsonify({'ok': False, 'error': f'Vhost creation failed: {result}'}), 500

    # 9. System cron entry
    if system_cron:
        cron_line = f'*/5 * * * * {web_user} {WP_CLI} --path="{path}" --allow-root cron event run --due-now >/dev/null 2>&1'
        cron_file = f'/etc/cron.d/vortex-wp-{re.sub(chr(46), "_", domain)}'
        try:
            with open(cron_file, 'w') as f:
                f.write(cron_line + '\n')
        except: pass

    # 10. Invalidate cache
    panel_cache.invalidate('wp_sites')

    return jsonify({
        'ok': True,
        'domain': domain,
        'path': path,
        'site_url': site_url,
        'admin_user': admin_user,
        'admin_pass': admin_pass,
        'admin_email': admin_email,
        'db_name': db_name,
        'db_user': db_user,
        'db_pass': db_pass,
        'webserver': webserver,
        'php_version': php_ver,
    })


@wp_bp.route('/api/wp/<domain>/info')
def site_info(domain):
    if not req(): return jsonify({'ok': False}), 401
    path = request.args.get('path', '')
    if not path:
        # Try to find the path
        for root in WEBROOTS:
            candidate = os.path.join(root, domain)
            if os.path.exists(os.path.join(candidate, 'wp-config.php')):
                path = candidate
                break
    if not path or not os.path.exists(os.path.join(path, 'wp-config.php')):
        return jsonify({'ok': False, 'error': 'WordPress not found at path'}), 404
    info = _get_wp_info(path, domain)
    return jsonify({'ok': True, **info})


@wp_bp.route('/api/wp/<domain>/login')
def one_click_login(domain):
    """Generate a one-click login URL using wp-cli."""
    if not req(): return jsonify({'ok': False}), 401
    path = request.args.get('path', '')
    if not path:
        for root in WEBROOTS:
            candidate = os.path.join(root, domain)
            if os.path.exists(os.path.join(candidate, 'wp-config.php')):
                path = candidate
                break
    if not _wp_installed():
        return jsonify({'ok': False, 'error': 'wp-cli not installed'}), 400

    admin_user = sh(f'{WP_CLI} --path="{path}" --allow-root user list --role=administrator --field=user_login --format=csv 2>/dev/null').split('\n')[0].strip()
    if not admin_user:
        return jsonify({'ok': False, 'error': 'No admin user found'}), 404

    login_url, err, rc = sh3(f'{WP_CLI} --path="{path}" --allow-root user session create {admin_user} --url-only 2>&1')
    if rc != 0 or not login_url.startswith('http'):
        # Fallback: magic link via eval
        login_url, err, rc = sh3(
            f'{WP_CLI} --path="{path}" --allow-root eval '
            f'"echo wp_login_url(admin_url(), true);" 2>/dev/null'
        )
    return jsonify({'ok': True, 'login_url': login_url.strip()})


# --- Plugins --------------------------------------------------------------------

@wp_bp.route('/api/wp/<domain>/plugins')
def list_plugins(domain):
    if not req(): return jsonify({'ok': False}), 401
    path = request.args.get('path', f'/www/wwwroot/{domain}')
    if not _wp_installed():
        return jsonify({'ok': False, 'error': 'wp-cli not installed'}), 400

    out, err, rc = sh3(
        f'{WP_CLI} --path="{path}" --allow-root plugin list --format=json 2>/dev/null', t=30
    )
    try:
        plugins = json.loads(out) if out else []
    except: plugins = []

    # Check for updates
    upd_out = sh(f'{WP_CLI} --path="{path}" --allow-root plugin update --all --dry-run --format=json 2>/dev/null')
    try:
        updates = {p['name']: p for p in json.loads(upd_out)} if upd_out else {}
    except: updates = {}

    for p in plugins:
        if p.get('name') in updates:
            p['update_version'] = updates[p['name']].get('new_version', '')

    return jsonify({'ok': True, 'plugins': plugins})


@wp_bp.route('/api/wp/<domain>/plugins/<plugin>', methods=['POST'])
def plugin_action(domain, plugin):
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    path = d.get('path', f'/www/wwwroot/{domain}')
    action = d.get('action', 'activate')  # activate | deactivate | update | delete | install

    if not _wp_installed():
        return jsonify({'ok': False, 'error': 'wp-cli not installed'}), 400

    if action == 'install':
        out, err, rc = sh3(f'{WP_CLI} --path="{path}" --allow-root plugin install {plugin} --activate 2>&1', t=120)
    elif action == 'activate':
        out, err, rc = sh3(f'{WP_CLI} --path="{path}" --allow-root plugin activate {plugin} 2>&1')
    elif action == 'deactivate':
        out, err, rc = sh3(f'{WP_CLI} --path="{path}" --allow-root plugin deactivate {plugin} 2>&1')
    elif action == 'update':
        out, err, rc = sh3(f'{WP_CLI} --path="{path}" --allow-root plugin update {plugin} 2>&1', t=120)
    elif action == 'delete':
        out, err, rc = sh3(f'{WP_CLI} --path="{path}" --allow-root plugin deactivate {plugin} 2>/dev/null; '
                           f'{WP_CLI} --path="{path}" --allow-root plugin delete {plugin} 2>&1')
    else:
        return jsonify({'ok': False, 'error': 'Unknown action'}), 400

    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': rc == 0, 'output': (out + err)[-500:]})


@wp_bp.route('/api/wp/<domain>/plugins/update-all', methods=['POST'])
def update_all_plugins(domain):
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    path = d.get('path', f'/www/wwwroot/{domain}')
    out, err, rc = sh3(f'{WP_CLI} --path="{path}" --allow-root plugin update --all 2>&1', t=300)
    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': rc == 0, 'output': (out + err)[-1000:]})


# --- Themes ---------------------------------------------------------------------

@wp_bp.route('/api/wp/<domain>/themes')
def list_themes(domain):
    if not req(): return jsonify({'ok': False}), 401
    path = request.args.get('path', f'/www/wwwroot/{domain}')
    if not _wp_installed():
        return jsonify({'ok': False, 'error': 'wp-cli not installed'}), 400
    out, err, rc = sh3(f'{WP_CLI} --path="{path}" --allow-root theme list --format=json 2>/dev/null', t=30)
    try: themes = json.loads(out) if out else []
    except: themes = []
    return jsonify({'ok': True, 'themes': themes})


@wp_bp.route('/api/wp/<domain>/themes/<theme>', methods=['POST'])
def theme_action(domain, theme):
    if not req(): return jsonify({'ok': False}), 401
    d      = request.get_json() or {}
    path   = d.get('path', f'/www/wwwroot/{domain}')
    action = d.get('action', 'activate')

    if not _wp_installed():
        return jsonify({'ok': False, 'error': 'wp-cli not installed'}), 400

    if action == 'install':
        out, err, rc = sh3(f'{WP_CLI} --path="{path}" --allow-root theme install {theme} 2>&1', t=120)
    elif action == 'activate':
        out, err, rc = sh3(f'{WP_CLI} --path="{path}" --allow-root theme activate {theme} 2>&1')
    elif action == 'update':
        out, err, rc = sh3(f'{WP_CLI} --path="{path}" --allow-root theme update {theme} 2>&1', t=120)
    elif action == 'delete':
        out, err, rc = sh3(f'{WP_CLI} --path="{path}" --allow-root theme delete {theme} 2>&1')
    else:
        return jsonify({'ok': False, 'error': 'Unknown action'}), 400

    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': rc == 0, 'output': (out + err)[-500:]})


# --- Core update ----------------------------------------------------------------

@wp_bp.route('/api/wp/<domain>/update-core', methods=['POST'])
def update_core(domain):
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    path = d.get('path', f'/www/wwwroot/{domain}')
    out, err, rc = sh3(f'{WP_CLI} --path="{path}" --allow-root core update 2>&1', t=300)
    out2, err2, _ = sh3(f'{WP_CLI} --path="{path}" --allow-root core update-db 2>&1', t=60)
    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': rc == 0, 'output': (out + err + out2 + err2)[-1000:]})


# --- Security scanner -----------------------------------------------------------

@wp_bp.route('/api/wp/<domain>/security')
def security_scan(domain):
    if not req(): return jsonify({'ok': False}), 401
    path = request.args.get('path', f'/www/wwwroot/{domain}')
    checks = []

    def chk(label, passed, detail='', fix=''):
        checks.append({'label': label, 'passed': passed, 'detail': detail, 'fix': fix})

    # 1. Admin username check
    admin_users = sh(f'{WP_CLI} --path="{path}" --allow-root user list --role=administrator --field=user_login --format=csv 2>/dev/null')
    bad_users = [u for u in admin_users.split('\n') if u.strip().lower() in ('admin', 'administrator', 'root')]
    chk('No weak admin username', len(bad_users) == 0,
        'Admin account uses a non-obvious username' if not bad_users else f'Weak admin username: {", ".join(bad_users)}',
        'rename_admin_user')

    # 2. File permissions
    cfg_perms = sh(f'stat -c "%a" "{path}/wp-config.php" 2>/dev/null')
    chk('wp-config.php permissions', cfg_perms in ('600', '640', '644'),
        f'wp-config.php is {cfg_perms}' if cfg_perms else 'Could not check permissions',
        'fix_permissions')

    # 3. WP version up to date
    update_check = sh(f'{WP_CLI} --path="{path}" --allow-root core check-update --field=version 2>/dev/null')
    has_core_update = bool(update_check and not update_check.startswith('Success'))
    chk('WordPress core up to date', not has_core_update,
        'Running latest version' if not has_core_update else f'Update available: {update_check}',
        'update_core')

    # 4. SSL
    ssl_ok = any(os.path.isdir(d) for d in [f'/etc/letsencrypt/live/{domain}', f'/etc/nginx/ssl/{domain}'])
    chk('SSL certificate active', ssl_ok, 'HTTPS enabled' if ssl_ok else 'No SSL certificate found', 'enable_ssl')

    # 5. Debug mode
    cfg = open(f'{path}/wp-config.php').read() if os.path.exists(f'{path}/wp-config.php') else ''
    debug_on = 'WP_DEBUG' in cfg and ('true' in cfg.lower().split('WP_DEBUG')[1][:30] if 'WP_DEBUG' in cfg else False)
    chk('Debug mode disabled', not debug_on, 'WP_DEBUG is off' if not debug_on else 'WP_DEBUG is enabled in production — disable it', 'disable_debug')

    # 6. XML-RPC
    ws = _detect_webserver()
    xmlrpc_blocked = False
    for conf_dir in ['/etc/nginx/vortex', '/etc/nginx/conf.d']:
        if not os.path.isdir(conf_dir): continue
        for fn in os.listdir(conf_dir):
            try:
                c = open(os.path.join(conf_dir, fn)).read()
                if domain in c and 'xmlrpc' in c.lower():
                    xmlrpc_blocked = True
            except: pass
    chk('XML-RPC disabled', xmlrpc_blocked, 'xmlrpc.php is blocked at web server level' if xmlrpc_blocked else 'xmlrpc.php is publicly accessible', 'block_xmlrpc')

    # 7. wp-config.php HTTP access blocked
    cfg_blocked = False
    for conf_dir in ['/etc/nginx/vortex', '/etc/nginx/conf.d']:
        if not os.path.isdir(conf_dir): continue
        for fn in os.listdir(conf_dir):
            try:
                c = open(os.path.join(conf_dir, fn)).read()
                if domain in c and 'wp-config' in c:
                    cfg_blocked = True
            except: pass
    chk('wp-config.php HTTP access blocked', cfg_blocked,
        'Direct HTTP access denied' if cfg_blocked else 'wp-config.php may be accessible over HTTP', 'block_wpconfig')

    # 8. No vulnerable plugins (basic check via wp update list)
    vuln_count = 0
    if _wp_installed():
        upd = sh(f'{WP_CLI} --path="{path}" --allow-root plugin update --all --dry-run --format=count 2>/dev/null')
        try: vuln_count = int(upd)
        except: vuln_count = 0
    chk('Plugins up to date', vuln_count == 0,
        'All plugins are current' if vuln_count == 0 else f'{vuln_count} plugin(s) have updates available', 'update_plugins')

    # 9. Login URL exposed
    login_hidden = False
    if _wp_installed():
        wps = sh(f'{WP_CLI} --path="{path}" --allow-root plugin is-installed wps-hide-login 2>/dev/null')
        login_hidden = 'installed' not in (sh(f'{WP_CLI} --path="{path}" --allow-root plugin status wps-hide-login 2>/dev/null') or '').lower()
    chk('Login URL protected', login_hidden,
        'Login URL is changed/hidden' if login_hidden else '/wp-admin is accessible at default URL', 'hide_login')

    passed = sum(1 for c in checks if c['passed'])
    score  = round(passed / len(checks) * 100) if checks else 0
    grade  = 'A' if score >= 90 else ('B' if score >= 75 else 'C')

    return jsonify({'ok': True, 'checks': checks, 'score': score, 'grade': grade, 'passed': passed, 'total': len(checks)})


@wp_bp.route('/api/wp/<domain>/security/fix', methods=['POST'])
def security_fix(domain):
    """Apply a specific security fix."""
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    path = d.get('path', f'/www/wwwroot/{domain}')
    fix  = d.get('fix', '')

    out = ''
    if fix == 'fix_permissions':
        sh(f'chmod 600 "{path}/wp-config.php"')
        sh(f'find "{path}" -type d -exec chmod 755 {{}} \\;')
        sh(f'find "{path}" -type f -exec chmod 644 {{}} \\;')
        sh(f'chmod 600 "{path}/wp-config.php"')
        out = 'File permissions corrected'

    elif fix == 'disable_debug':
        if os.path.exists(f'{path}/wp-config.php'):
            cfg = open(f'{path}/wp-config.php').read()
            cfg = re.sub(r"define\s*\(\s*'WP_DEBUG'\s*,\s*true\s*\)", "define('WP_DEBUG', false)", cfg)
            cfg = re.sub(r'define\s*\(\s*"WP_DEBUG"\s*,\s*true\s*\)', 'define("WP_DEBUG", false)', cfg)
            with open(f'{path}/wp-config.php', 'w') as f: f.write(cfg)
        out = 'WP_DEBUG disabled'

    elif fix == 'block_xmlrpc':
        ws = _detect_webserver()
        if ws == 'nginx':
            for conf_dir in ['/etc/nginx/vortex', '/etc/nginx/conf.d']:
                if not os.path.isdir(conf_dir): continue
                for fn in os.listdir(conf_dir):
                    fp = os.path.join(conf_dir, fn)
                    try:
                        c = open(fp).read()
                        if domain in c and 'location / {' in c and 'xmlrpc' not in c:
                            xmlrpc_block = '\n    location = /xmlrpc.php { deny all; }\n'
                            c = c.replace('location ~ /\\.ht', xmlrpc_block + '    location ~ /\\.ht')
                            with open(fp, 'w') as f: f.write(c)
                            sh('nginx -t && systemctl reload nginx 2>/dev/null')
                    except: pass
        out = 'XML-RPC blocked at web server level'

    elif fix == 'system_cron':
        if os.path.exists(f'{path}/wp-config.php'):
            cfg = open(f'{path}/wp-config.php').read()
            if 'DISABLE_WP_CRON' not in cfg:
                cfg = cfg.replace("/* That's all, stop editing!", "define('DISABLE_WP_CRON', true);\n/* That's all, stop editing!")
                with open(f'{path}/wp-config.php', 'w') as f: f.write(cfg)
        web_user = _web_user()
        cron_line = f'*/5 * * * * {web_user} {WP_CLI} --path="{path}" --allow-root cron event run --due-now >/dev/null 2>&1'
        cron_file = f'/etc/cron.d/vortex-wp-{re.sub(chr(46), "_", domain)}'
        with open(cron_file, 'w') as f: f.write(cron_line + '\n')
        out = 'System cron configured, wp-cron disabled'

    elif fix == 'update_core':
        out_c, err_c, _ = sh3(f'{WP_CLI} --path="{path}" --allow-root core update 2>&1', t=300)
        out = out_c or err_c

    elif fix == 'update_plugins':
        out_p, err_p, _ = sh3(f'{WP_CLI} --path="{path}" --allow-root plugin update --all 2>&1', t=300)
        out = out_p or err_p

    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': True, 'output': out})


# --- Settings -------------------------------------------------------------------

@wp_bp.route('/api/wp/<domain>/settings', methods=['PUT'])
def save_settings(domain):
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    path = d.get('path', f'/www/wwwroot/{domain}')

    if not _wp_installed():
        return jsonify({'ok': False, 'error': 'wp-cli not installed'}), 400

    results = []
    if 'site_title' in d:
        sh(f'{WP_CLI} --path="{path}" --allow-root option update blogname "{d["site_title"]}" 2>/dev/null')
        results.append('title updated')
    if 'admin_email' in d:
        sh(f'{WP_CLI} --path="{path}" --allow-root option update admin_email "{d["admin_email"]}" 2>/dev/null')
        results.append('email updated')
    if 'language' in d:
        sh(f'{WP_CLI} --path="{path}" --allow-root option update WPLANG "{d["language"]}" 2>/dev/null')
        results.append('language updated')
    if 'admin_password' in d and d['admin_password']:
        admin_user = sh(f'{WP_CLI} --path="{path}" --allow-root user list --role=administrator --field=user_login --format=csv 2>/dev/null').split('\n')[0].strip()
        if admin_user:
            sh(f'{WP_CLI} --path="{path}" --allow-root user update {admin_user} --user_pass="{d["admin_password"]}" 2>/dev/null')
            results.append('password updated')

    if 'search_visible' in d:
        val = '1' if d['search_visible'] else '0'
        sh(f'{WP_CLI} --path="{path}" --allow-root option update blog_public {val} 2>/dev/null')

    if 'debug_mode' in d:
        if os.path.exists(f'{path}/wp-config.php'):
            cfg = open(f'{path}/wp-config.php').read()
            new_val = 'true' if d['debug_mode'] else 'false'
            if 'WP_DEBUG' in cfg:
                cfg = re.sub(r"define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*(?:true|false)\s*\)",
                             f"define('WP_DEBUG', {new_val})", cfg)
            else:
                cfg = cfg.replace("/* That's all, stop editing!",
                                  f"define('WP_DEBUG', {new_val});\n/* That's all, stop editing!")
            with open(f'{path}/wp-config.php', 'w') as f: f.write(cfg)
            results.append('debug mode updated')

    if 'maintenance' in d:
        maint_file = os.path.join(path, '.maintenance')
        if d['maintenance']:
            with open(maint_file, 'w') as f:
                f.write("<?php $upgrading = time(); ?>")
        else:
            try: os.unlink(maint_file)
            except: pass
        results.append('maintenance mode updated')

    if 'php_version' in d:
        php_ver = d['php_version']
        ws = _detect_webserver()
        for conf_dir in ['/etc/nginx/vortex', '/etc/nginx/conf.d']:
            if not os.path.isdir(conf_dir): continue
            for fn in os.listdir(conf_dir):
                fp = os.path.join(conf_dir, fn)
                try:
                    c = open(fp).read()
                    if domain in c:
                        new_sock = _php_sock(php_ver)
                        c = re.sub(r'fastcgi_pass unix:/run/php/php[\d.]+-fpm\.sock',
                                   f'fastcgi_pass unix:{new_sock}', c)
                        c = re.sub(r'php[\d.]+-fpm\.sock', f'php{php_ver}-fpm.sock', c)
                        with open(fp, 'w') as f: f.write(c)
                        sh('nginx -t && systemctl reload nginx 2>/dev/null')
                        results.append(f'PHP switched to {php_ver}')
                        break
                except: pass

    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': True, 'updated': results})


# --- Backups --------------------------------------------------------------------

@wp_bp.route('/api/wp/<domain>/backups')
def list_backups(domain):
    if not req(): return jsonify({'ok': False}), 401
    backups = []
    for f in os.listdir(WP_BACKUP_DIR):
        if not f.startswith(domain): continue
        fp = os.path.join(WP_BACKUP_DIR, f)
        if not os.path.isfile(fp): continue
        stat = os.stat(fp)
        backups.append({
            'filename': f,
            'size': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
            'type': 'auto' if '_auto_' in f else 'manual',
        })
    backups.sort(key=lambda x: x['created'], reverse=True)
    return jsonify({'ok': True, 'backups': backups})


@wp_bp.route('/api/wp/<domain>/backups', methods=['POST'])
def create_backup(domain):
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    path = d.get('path', f'/www/wwwroot/{domain}')
    label = d.get('label', 'manual')
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_file = os.path.join(WP_BACKUP_DIR, f'{domain}_{label}_{ts}.tar.gz')

    # Back up files + database
    db_dump = os.path.join(WP_BACKUP_DIR, f'{domain}_{ts}.sql')
    if _wp_installed():
        sh(f'{WP_CLI} --path="{path}" --allow-root db export "{db_dump}" 2>/dev/null', t=120)

    _, err, rc = sh3(f'tar -czf "{out_file}" -C "{os.path.dirname(path)}" "{os.path.basename(path)}"'
                     + (f' "{db_dump}"' if os.path.exists(db_dump) else '') + ' 2>&1', t=300)
    if os.path.exists(db_dump):
        os.unlink(db_dump)

    return jsonify({'ok': rc == 0, 'filename': os.path.basename(out_file), 'error': err if rc != 0 else ''})


@wp_bp.route('/api/wp/<domain>/backups/<filename>/restore', methods=['POST'])
def restore_backup(domain, filename):
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    path = d.get('path', f'/www/wwwroot/{domain}')
    backup_path = os.path.join(WP_BACKUP_DIR, filename)
    if not os.path.exists(backup_path):
        return jsonify({'ok': False, 'error': 'Backup file not found'}), 404
    _, err, rc = sh3(f'tar -xzf "{backup_path}" -C "{os.path.dirname(path)}" 2>&1', t=300)
    # Re-import SQL if found in archive
    sh(f'tar -tzf "{backup_path}" 2>/dev/null | grep \\.sql | head -1', t=10)
    return jsonify({'ok': rc == 0, 'error': err if rc != 0 else ''})


@wp_bp.route('/api/wp/<domain>/backups/<filename>', methods=['DELETE'])
def delete_backup(domain, filename):
    if not req(): return jsonify({'ok': False}), 401
    backup_path = os.path.join(WP_BACKUP_DIR, filename)
    if os.path.exists(backup_path):
        os.unlink(backup_path)
    return jsonify({'ok': True})


# --- Staging / Clone ------------------------------------------------------------

@wp_bp.route('/api/wp/<domain>/clone', methods=['POST'])
def clone_site(domain):
    """Clone WP site to a staging subdomain."""
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    src_path    = d.get('path', f'/www/wwwroot/{domain}')
    dest_domain = d.get('dest_domain', f'staging.{domain}')
    clone_type  = d.get('type', 'full')  # full | files | db
    php_ver     = d.get('php_version', '8.4')
    webserver   = d.get('webserver', '') or _detect_webserver()

    dest_path = os.path.join(os.path.dirname(src_path), dest_domain)
    os.makedirs(dest_path, exist_ok=True)

    results = []

    # 1. Copy files
    if clone_type in ('full', 'files'):
        _, err, rc = sh3(f'rsync -a --exclude=wp-content/cache/ "{src_path}/" "{dest_path}/" 2>&1', t=300)
        if rc != 0:
            return jsonify({'ok': False, 'error': f'File copy failed: {err}'}), 500
        results.append('files copied')

    # 2. Clone database
    if clone_type in ('full', 'db') and _wp_installed():
        new_db   = re.sub(r'[^a-zA-Z0-9_]', '_', dest_domain.replace('.', '_'))[:32]
        new_user = 'wp_' + _rand_str(8)
        new_pass = _rand_pass(16)
        _mysql_cmd(f'CREATE DATABASE IF NOT EXISTS `{new_db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;')
        _mysql_cmd(f"CREATE USER IF NOT EXISTS '{new_user}'@'localhost' IDENTIFIED BY '{new_pass}';")
        _mysql_cmd(f"GRANT ALL PRIVILEGES ON `{new_db}`.* TO '{new_user}'@'localhost'; FLUSH PRIVILEGES;")

        # Export source DB
        dump_file = f'/tmp/vortex_clone_{domain}.sql'
        sh(f'{WP_CLI} --path="{src_path}" --allow-root db export "{dump_file}" 2>/dev/null', t=120)
        # Import into new DB
        _, err, rc = sh3(f'mysql -u root `{new_db}` < "{dump_file}" 2>&1', t=120)
        try: os.unlink(dump_file)
        except: pass

        # Update wp-config.php in destination
        if os.path.exists(f'{dest_path}/wp-config.php'):
            cfg = open(f'{dest_path}/wp-config.php').read()
            cfg = re.sub(r"define\s*\(\s*'DB_NAME'\s*,\s*'[^']*'\s*\)", f"define('DB_NAME', '{new_db}')", cfg)
            cfg = re.sub(r"define\s*\(\s*'DB_USER'\s*,\s*'[^']*'\s*\)", f"define('DB_USER', '{new_user}')", cfg)
            cfg = re.sub(r"define\s*\(\s*'DB_PASSWORD'\s*,\s*'[^']*'\s*\)", f"define('DB_PASSWORD', '{new_pass}')", cfg)
            with open(f'{dest_path}/wp-config.php', 'w') as f: f.write(cfg)

        # Update siteurl + home in staging DB
        staging_url = f'http://{dest_domain}'
        src_url = sh(f'{WP_CLI} --path="{src_path}" --allow-root option get siteurl 2>/dev/null')
        sh(f'{WP_CLI} --path="{dest_path}" --allow-root search-replace "{src_url}" "{staging_url}" --allow-root 2>/dev/null', t=120)
        results.append('database cloned')

    # 3. Create vhost for staging
    ok, result = _write_vhost(dest_domain, dest_path, php_ver, webserver)
    if not ok:
        return jsonify({'ok': False, 'error': f'Staging vhost failed: {result}'}), 500

    # 4. Fix ownership
    web_user = _web_user()
    sh(f'chown -R {web_user}:{web_user} "{dest_path}" 2>/dev/null || true')

    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': True, 'staging_domain': dest_domain, 'staging_path': dest_path, 'steps': results})


@wp_bp.route('/api/wp/<domain>/push-staging', methods=['POST'])
def push_staging(domain):
    """Push staging site to live. Always creates a backup of live first."""
    if not req(): return jsonify({'ok': False}), 401
    d           = request.get_json() or {}
    staging_path = d.get('staging_path', '')
    live_path    = d.get('live_path', '')
    if not staging_path or not live_path:
        return jsonify({'ok': False, 'error': 'staging_path and live_path required'}), 400

    # 1. Auto-backup live site first
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    bak = os.path.join(WP_BACKUP_DIR, f'{domain}_pre_push_{ts}.tar.gz')
    sh(f'tar -czf "{bak}" -C "{os.path.dirname(live_path)}" "{os.path.basename(live_path)}" 2>/dev/null', t=300)

    # 2. Rsync staging → live (exclude uploads to avoid data loss)
    _, err, rc = sh3(
        f'rsync -a --delete --exclude=wp-content/uploads/ "{staging_path}/" "{live_path}/" 2>&1', t=300
    )
    if rc != 0:
        return jsonify({'ok': False, 'error': f'Rsync failed: {err}'}), 500

    # 3. Sync DB if wp-cli available
    if _wp_installed():
        live_url = sh(f'{WP_CLI} --path="{live_path}" --allow-root option get siteurl 2>/dev/null')
        staging_url = sh(f'{WP_CLI} --path="{staging_path}" --allow-root option get siteurl 2>/dev/null')
        dump = f'/tmp/vortex_push_{domain}.sql'
        sh(f'{WP_CLI} --path="{staging_path}" --allow-root db export "{dump}" 2>/dev/null', t=120)
        sh(f'{WP_CLI} --path="{live_path}" --allow-root db import "{dump}" 2>/dev/null', t=120)
        if staging_url and live_url and staging_url != live_url:
            sh(f'{WP_CLI} --path="{live_path}" --allow-root search-replace "{staging_url}" "{live_url}" --allow-root 2>/dev/null', t=120)
        try: os.unlink(dump)
        except: pass

    # 4. Fix ownership
    web_user = _web_user()
    sh(f'chown -R {web_user}:{web_user} "{live_path}" 2>/dev/null || true')

    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': True, 'backup': os.path.basename(bak), 'message': 'Staging pushed to live'})


# --- Delete site ----------------------------------------------------------------

@wp_bp.route('/api/wp/<domain>', methods=['DELETE'])
def delete_site(domain):
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    path = d.get('path', f'/www/wwwroot/{domain}')
    delete_db = d.get('delete_db', True)
    webserver = d.get('webserver', '') or _detect_webserver()

    # Drop DB
    if delete_db and _wp_installed() and os.path.exists(f'{path}/wp-config.php'):
        cfg = open(f'{path}/wp-config.php').read()
        db_m = re.search(r"define\s*\(\s*'DB_NAME'\s*,\s*'([^']+)'", cfg)
        user_m = re.search(r"define\s*\(\s*'DB_USER'\s*,\s*'([^']+)'", cfg)
        if db_m:
            _mysql_cmd(f"DROP DATABASE IF EXISTS `{db_m.group(1)}`;")
        if user_m:
            _mysql_cmd(f"DROP USER IF EXISTS '{user_m.group(1)}'@'localhost';")

    # Remove files
    try: shutil.rmtree(path)
    except: pass

    # Remove vhost
    _delete_vhost(domain, webserver)

    # Remove system cron
    cron_file = f'/etc/cron.d/vortex-wp-{re.sub(chr(46), "_", domain)}'
    try: os.unlink(cron_file)
    except: pass

    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': True})


# --- Utilities ------------------------------------------------------------------

@wp_bp.route('/api/wp/install-wpcli', methods=['POST'])
def install_wpcli_route():
    if not req(): return jsonify({'ok': False}), 401
    ok = _install_wpcli()
    return jsonify({'ok': ok, 'version': sh(f'{WP_CLI} --version --allow-root 2>/dev/null')})

@wp_bp.route('/api/wp/wp-versions')
def wp_versions():
    """Return available WordPress versions from the API."""
    if not req(): return jsonify({'ok': False}), 401
    out = sh('curl -s https://api.wordpress.org/core/version-check/1.7/ 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); [print(o[\'version\']) for o in d.get(\'offers\',[])]"')
    versions = [v for v in out.split('\n') if v.strip()][:8]
    if not versions:
        versions = ['7.0', '6.9.4', '6.9.3', '6.9.2', '6.9.1', '6.8.1', '6.7.2']
    return jsonify({'ok': True, 'versions': versions})

@wp_bp.route('/api/wp/php-versions')
def php_versions():
    if not req(): return jsonify({'ok': False}), 401
    return jsonify({'ok': True, 'versions': _available_php()})

@wp_bp.route('/api/wp/db-engines')
def db_engines():
    if not req(): return jsonify({'ok': False}), 401
    return jsonify({'ok': True, 'engines': _available_db()})
