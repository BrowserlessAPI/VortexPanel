"""
VortexPanel WP Toolkit
Supports: PHP 7.4–8.5 | Nginx / Apache / OpenLiteSpeed / Caddy | MariaDB / MySQL
"""
import os, re, json, uuid, shutil, subprocess, secrets, string, threading, shlex
from datetime import datetime
from flask import Blueprint, jsonify, request, session

try:
    from panel.routes.os_utils import get_os, get_webserver_user, panel_cache
    from panel.routes import os_utils as _ou
    from panel.routes.php import php_layout, installed_php_layouts
except ImportError:
    from os_utils import get_os, get_webserver_user, panel_cache
    import os_utils as _ou
    from php import php_layout, installed_php_layouts

wp_bp = Blueprint('wp_toolkit', __name__)
Q = shlex.quote

# <domain> here is often a folder name found by the scanner (may contain
# '_' etc.), so the check is looser than is_valid_domain(), but it never
# allows '/', '..' or shell metacharacters.
_WP_DOMAIN_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$')
_SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,99}$')


@wp_bp.before_request
def _wp_guard():
    va = request.view_args or {}
    dom = va.get('domain')
    if dom is not None and (not _WP_DOMAIN_RE.match(dom) or '..' in dom):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    for k in ('plugin', 'theme'):
        if k in va and va[k] != 'update-all' and not _SLUG_RE.match(va[k] or ''):
            return jsonify({'ok': False, 'error': f'Invalid {k} slug'}), 400
    if 'filename' in va and not re.match(r'^[A-Za-z0-9._-]+\.tar\.gz$', va['filename'] or ''):
        return jsonify({'ok': False, 'error': 'Invalid backup file name'}), 400
    # every path a request names must be a real WordPress install (it is
    # used for rm -rf, rsync --delete, chown -R and wp-cli as root)
    if request.method in ('POST', 'PUT', 'DELETE') or request.args.get('path'):
        body = request.get_json(silent=True) or {}
        for key in ('path', 'staging_path', 'live_path'):
            p = body.get(key) if key in body else (request.args.get(key) if key == 'path' else None)
            if p:
                err = _wp_path_error(str(p), require_wp=not (request.endpoint or '').endswith('install_wp'))
                if err:
                    return jsonify({'ok': False, 'error': err}), 400
    return None


def _wp_path_error(path, require_wp=True):
    """'' when `path` is an acceptable WordPress directory, else an error."""
    if not path.startswith('/') or '..' in path.split('/') or re.search(r'[\x00-\x1f]', path):
        return 'Invalid site path'
    real = os.path.realpath(path).rstrip('/')
    try:
        from panel.routes.websites_core import valid_site_path
        perr = valid_site_path(real)
    except Exception:
        perr = '' if real.count('/') >= 2 else 'Invalid site path'
    if perr:
        return perr
    if real in [w.rstrip('/') for w in WEBROOTS]:
        return 'The site path cannot be a web root itself'
    if require_wp and os.path.exists(real) and not os.path.isfile(os.path.join(real, 'wp-config.php')):
        return f'{path} is not a WordPress installation (no wp-config.php)'
    return ''

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

def _web_user(php=None, ws=None):
    """The user PHP-FPM runs as for this PHP version (www-data on Debian,
    the php-fpm pool's `user =` -- usually apache -- on RHEL even when nginx
    serves the site; the OpenLiteSpeed external-app user for OLS sites)."""
    try:
        from panel.routes.websites_core import web_owner
        return web_owner(php, ws)
    except Exception:
        u = get_webserver_user()
        return u or 'www-data'


def _owner_spec(php=None, ws=None):
    """'user:group' for chown of a WordPress tree (see _web_user)."""
    try:
        from panel.routes.websites_core import web_owner_group
        u, g = web_owner_group(php, ws)
    except Exception:
        u = g = _web_user(php, ws)
    return f'{u}:{g}'


def _fix_site_tree(path, php=None, ws=None, mail=True):
    """Ownership for the PHP-FPM user + SELinux web label + the booleans a
    WordPress site needs on SELinux (outbound HTTP for updates/plugins, DB,
    mail()). Without the label every request was 403/permission denied on
    RHEL-family servers for sites created/cloned/restored here."""
    sh(f'chown -R {Q(_owner_spec(php, ws))} {Q(path)} 2>/dev/null || true', t=600)
    try:
        _ou.selinux_label_path(path, writable=True)
        _ou.selinux_web_booleans(proxy=True, db=True, mail=mail)
    except Exception:
        pass


def _site_php_of(domain):
    """PHP X.Y the existing vhost of `domain` hands .php to, or None."""
    try:
        from panel.routes.websites_core import _find_site_config, _site_php
        fp = _find_site_config(domain)[0]
        return _site_php(fp) if fp else None
    except Exception:
        return None


def _wpc():
    """wp-cli command prefix. The phar runs `#!/usr/bin/env php`: on a
    remi-only RHEL server there is no `php` on PATH, so run it with the
    newest installed PHP binary explicitly."""
    if shutil.which('php'):
        return WP_CLI
    try:
        lays = installed_php_layouts()
        if lays:
            return f'{Q(lays[0]["bin"])} {WP_CLI}'
    except Exception:
        pass
    return WP_CLI


def _default_wp_path(domain):
    """Default site path when the request names none: the existing site's
    root if it has one, else <webroot>/<domain>."""
    try:
        from panel.routes.websites_core import _get_site_path
        return _get_site_path(domain)
    except Exception:
        return os.path.join(_ou.get_webroot(), domain)

def _wp(path, cmd, t=60):
    """Run a wp-cli command in the given path."""
    web_user = _web_user()
    # Try running as web user; fall back to --allow-root
    if os.path.exists(WP_CLI):
        out, err, rc = sh3(f'sudo -u {web_user} {_wpc()} --path={Q(path)} {cmd} 2>&1', t=t)
        if rc != 0 and 'sudo' in err:
            out, err, rc = sh3(f'{_wpc()} --path={Q(path)} --allow-root {cmd} 2>&1', t=t)
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
    """Return the web server new sites are written for: nginx | apache |
    openlitespeed | caddy | '' (none installed).

    With several running, nginx wins (it is the one on :80/:443 in the
    usual nginx-in-front-of-Apache setup). When NONE is running (stopped,
    crashed, just installed) the old code returned '' and site creation
    claimed "No web server is installed" -- fall back to what is installed."""
    if sh('systemctl is-active nginx 2>/dev/null') == 'active':
        return 'nginx'
    if sh('systemctl is-active apache2 2>/dev/null') == 'active' or \
       sh('systemctl is-active httpd 2>/dev/null') == 'active':
        return 'apache'
    if sh('systemctl is-active lsws 2>/dev/null') == 'active' or \
       sh('systemctl is-active lshttpd 2>/dev/null') == 'active':
        return 'openlitespeed'
    if sh('systemctl is-active caddy 2>/dev/null') == 'active':
        return 'caddy'
    inst = _installed_webservers()
    return inst[0] if inst else ''  # honestly report nothing, never a fake nginx

def _installed_webservers():
    """Return list of actually installed webservers. Empty list means genuinely none installed --
    confirmed via a real report that silently defaulting to ['nginx'] here made the WP Toolkit UI
    show "Nginx ✓ installed" even when the App Store correctly showed it as Not Installed."""
    installed = []
    if shutil.which('nginx'):
        installed.append('nginx')
    if shutil.which('apache2') or shutil.which('httpd'):
        installed.append('apache')
    if os.path.exists('/usr/local/lsws/bin/lshttpd'):
        installed.append('openlitespeed')
    if shutil.which('caddy'):
        installed.append('caddy')
    return installed

def _php_sock(ver):
    """PHP-FPM socket path for version X.Y on this server's layout (Debian
    /run/php/phpX.Y-fpm.sock, remi /var/opt/remi/phpXY/run/php-fpm/www.sock,
    RHEL module stream /run/php-fpm/www.sock -- the latter ONLY for the one
    PHP version it really is; the old list returned www.sock for any version)."""
    try:
        from panel.routes.websites_core import php_fpm_socket
        sock = php_fpm_socket(ver)
        if sock:
            return sock
    except Exception:
        pass
    lay = php_layout(str(ver))
    if lay:
        return lay['sock']   # installed but FPM not started yet
    return f'/run/php/php{ver}-fpm.sock'

def _available_php(webserver=None):
    """Return list of installed PHP versions (7.4-8.5) with runtime status.

    On OpenLiteSpeed, the only thing that matters is whether
    /usr/local/lsws/lsphp<ver>/bin/lsphp actually exists -- OLS never talks
    to php-fpm sockets or the generic `php` CLI at all. Checking only
    php-fpm sockets / `which php{ver}` (as this used to do unconditionally)
    reported PHP 8.2 as "available" on a live box that had a system-wide
    php8.2 CLI package installed for unrelated reasons, while OpenLiteSpeed
    itself only had lsphp83 installed. The panel let a WordPress site get
    created with php_version=8.2 for OpenLiteSpeed, which wrote a vhost
    pointing its LSAPI extprocessor at a lsphp82 binary that never existed
    on disk -- LSAPI silently never started, and OLS fell back to (and then
    refused) serving .php as a static file, 403ing every request. Confirmed
    directly on that box: `ls /usr/local/lsws/lsphp82/bin/lsphp` -> No such
    file or directory, while `ls /usr/local/lsws/` showed only lsphp83/.
    """
    versions = []
    if webserver == 'openlitespeed':
        for v in ['8.5', '8.4', '8.3', '8.2', '8.1', '8.0', '7.4']:
            lsphp_bin = f'/usr/local/lsws/lsphp{v.replace(".", "")}/bin/lsphp'
            if os.path.exists(lsphp_bin):
                versions.append({'version': v, 'sock': lsphp_bin, 'active': True})
        return versions
    for lay in installed_php_layouts():
        sock = _php_sock(lay['ver'])
        versions.append({'version': lay['ver'], 'sock': sock, 'active': os.path.exists(sock)})
    return versions

def _available_db():
    """Return available DB engines. Empty list means genuinely none installed."""
    engines = []
    if shutil.which('mysql') or sh('systemctl is-active mysql 2>/dev/null') == 'active' or \
       sh('systemctl is-active mysqld 2>/dev/null') == 'active':
        engines.append('mysql')
    if shutil.which('mariadb') or sh('systemctl is-active mariadb 2>/dev/null') == 'active':
        engines.append('mariadb')
    return engines

def _mysql_cmd(query, engine='mysql'):
    """Run a MySQL/MariaDB query as root.

    IMPORTANT: this must NOT go through sh()/sh3() (shell=True), because SQL
    identifier quoting uses backticks (`` `db_name` ``) which /bin/sh
    interprets as command substitution when the query is embedded in a
    double-quoted shell string (e.g. `db_name` gets *executed* as a command).
    Running the query as a real argument list avoids the shell entirely, so
    backticks, quotes, and any other SQL syntax are passed to the mysql/
    mariadb client literally and safely — this is a real, confirmed command
    injection point since callers build queries from user-influenced values
    (domain-derived database names, etc.), not just a theoretical concern.
    """
    # Same connection logic as the Databases page (socket auth, /root/.my.cnf,
    # debian.cnf): a bare `mysql -u root` fails on servers where root has a
    # password, and the WordPress install then failed at "Creating database".
    try:
        from panel.routes.databases import mysql_cmd
        out, err = mysql_cmd(query, timeout=60)
        return (out or '').strip(), (err or ''), (1 if err else 0)
    except ImportError:
        pass
    cli = 'mariadb' if (engine == 'mariadb' and shutil.which('mariadb')) else 'mysql'
    try:
        r = subprocess.run([cli, '-u', 'root', '-e', query], capture_output=True, text=True, timeout=30)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return '', str(e), 1

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
    # IPv6 listener only where the kernel has IPv6 (nginx refuses to start
    # with `listen [::]:80` when IPv6 is disabled)
    v6 = '\n    listen [::]:80;' if os.path.exists('/proc/net/if_inet6') else ''
    return f"""server {{
    listen 80;{v6}
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

    ErrorLog  {_apache_log_dir()}/{domain}.error.log
    CustomLog {_apache_log_dir()}/{domain}.access.log combined
</VirtualHost>
"""

def _apache_log_dir():
    return '/var/log/httpd' if (os.path.isdir('/etc/httpd') and not os.path.isdir('/etc/apache2')) else '/var/log/apache2'

def _apache_conf_path(domain):
    """Where VortexPanel keeps a site's Apache vhost: sites-available on
    Debian/Ubuntu, conf.d on RHEL-family (which has no sites-available,
    a2ensite or a2enmod -- the old code wrote Debian paths everywhere)."""
    if os.path.isdir('/etc/httpd') and not os.path.isdir('/etc/apache2'):
        return f'/etc/httpd/conf.d/{domain}.conf'
    return f'/etc/apache2/sites-available/{domain}.conf'

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

def _lsphp_binary(php_ver):
    """Locate the actual LSPHP binary for a given VortexPanel PHP version
    (e.g. "8.3" -> lsphp83). OpenLiteSpeed does NOT talk to php-fpm at all --
    it uses its own bundled LSPHP builds via LSAPI, communicating through a
    per-site unix socket that OLS spawns and manages itself. Confirmed
    against a real, working vhconf.conf from a live aaPanel+OLS install
    (GitHub issue #14) that the previous version of this function got
    fundamentally wrong: it pointed 'path' at the system php-fpm binary and
    used type=fcgi, neither of which OLS's LSAPI processor actually uses --
    the site would never have been able to run PHP at all, regardless of
    how correct the rest of the vhost config was.
    """
    short = php_ver.replace('.', '')
    for candidate in [f'/usr/local/lsws/lsphp{short}/bin/lsphp']:
        if os.path.exists(candidate):
            return candidate
    return f'/usr/local/lsws/lsphp{short}/bin/lsphp'


def _ols_vhost(domain, path, php_ver):
    """OpenLiteSpeed virtual host config in /usr/local/lsws/conf/vhosts/.

    Rebuilt to match a real, working vhconf.conf taken directly from a live
    aaPanel+OpenLiteSpeed install (GitHub issue #14) rather than a plausible-
    looking guess: extprocessor named after the domain (not a shared generic
    "lsphp" processor -- this is what lets each site run its own PHP version
    independently), type lsapi (not fcgi), address on a per-site unix socket
    that OLS itself creates and owns, path pointing at OLS's own bundled
    LSPHP binary, and a phpIniOverride restricting open_basedir to the
    site's own webroot for isolation between sites.
    """
    php_bin = _lsphp_binary(php_ver)
    try:
        from panel.routes.websites_core import ols_owner
        ext_user, ext_group = ols_owner()
    except Exception:
        ext_user, ext_group = 'nobody', 'nobody'
    return f"""docRoot                   {path}/
vhDomain                  {domain}
vhAliases                 www.{domain}
adminEmails               webmaster@{domain}
enableGzip                1
enableIpGeo               1

index  {{
  useServer               0
  indexFiles              index.php, index.html
}}

errorlog /var/log/openlitespeed/{domain}.error_log {{
  useServer               0
  logLevel                ERROR
  rollingSize             10M
}}

accesslog /var/log/openlitespeed/{domain}.access_log {{
  useServer               0
  logFormat               '%h %l %u %t "%r" %>s %b "%{{Referer}}i" "%{{User-Agent}}i"'
  logHeaders              5
  rollingSize             10M
  keepDays                10
  compressArchive         1
}}

scripthandler  {{
  add                     lsapi:{domain} php
}}

extprocessor {domain}{{
  type                    lsapi
  address                 UDS://tmp/lshttpd/{domain}.sock
  maxConns                35
  env                     PHP_LSAPI_CHILDREN=35
  env                     LSAPI_AVOID_FORK=1
  initTimeout             60
  retryTimeout            0
  persistConn             1
  pcKeepAliveTimeout      30
  respBuffer              0
  autoStart               1
  path                    {php_bin}
  extUser                 {ext_user}
  extGroup                {ext_group}
  backlog                 100
  instances               1
  priority                0
  memSoftLimit            2047M
  memHardLimit            2047M
  procSoftLimit           400
  procHardLimit           500
}}

phpIniOverride  {{
  php_admin_value open_basedir "{path}/:/tmp/"
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

OLS_MAIN_CONF = '/usr/local/lsws/conf/httpd_config.conf'

def _find_ols_port80_listener(content):
    """Return the name of an existing listener block bound to port 80
    (e.g. `address *:80` or `address 0.0.0.0:80`), or None if none exists.

    IMPORTANT: `listener Default` is frequently bound to OLS's admin/example
    port (commonly 8088), NOT to 80. Mapping a real domain into a listener
    that isn't actually bound to 80/443 leaves the site completely
    unreachable from outside (connection refused at the network layer)
    even though the vhost and virtualhost block are both configured
    correctly -- because nothing is listening on 80 for that domain at all.
    """
    for m in re.finditer(r'listener\s+(\S+)\s*\{(.*?)\n\}', content, re.DOTALL):
        name, body = m.group(1), m.group(2)
        if re.search(r'address\s+\S*:80\b', body):
            return name
    return None


def _ensure_ols_http_listener(content):
    """Ensure a listener bound to *:80 exists in httpd_config.conf, named
    'HTTP'. Returns (content, listener_name). Idempotent: never creates a
    duplicate 'listener HTTP{' block, even if called multiple times."""
    existing = _find_ols_port80_listener(content)
    if existing:
        return content, existing

    if re.search(r'listener\s+HTTP\s*\{', content):
        # A listener named HTTP already exists but isn't on port 80 (unlikely,
        # but don't create a second one -- fall through and reuse it, the map
        # step below will still add this domain to it).
        return content, 'HTTP'

    listener_block = """
listener HTTP{
    address                  *:80
    secure                   0
}
"""
    content = content.rstrip('\n') + '\n' + listener_block
    return content, 'HTTP'


def _register_ols_vhost(domain, vhost_dir, site_path):
    """Register a vhost in the main OpenLiteSpeed httpd_config.conf.

    Writing conf/vhosts/<domain>/vhconf.conf alone is NOT enough for OLS to
    serve the site: the main config must also contain a `virtualhost
    {domain} {...}` block AND a `map` entry inside a listener that is
    actually bound to port 80 (or 443). Without this, OLS silently keeps
    routing every request to whatever the listener's existing catch-all/
    default vhost is, and the new site is unreachable even though its files
    and vhconf.conf exist on disk.
    """
    if not os.path.exists(OLS_MAIN_CONF):
        return False, f'{OLS_MAIN_CONF} not found'

    with open(OLS_MAIN_CONF, 'r') as f:
        content = f.read()

    changed = False
    vh_root = site_path.rstrip('/')

    # 1. virtualhost block
    #
    # vhRoot MUST be (an ancestor of) the site's real docRoot, NOT the
    # /usr/local/lsws/conf/vhosts/<domain> config directory. And `restrained`
    # MUST be off (0), not on (1) -- confirmed as a second, distinct
    # restrained-related bug on top of the vhRoot one: even after vhRoot was
    # corrected to point at the real docRoot, sites still 403'd, this time
    # with OLS's error log showing
    # `MIME type [application/x-httpd-php] for suffix '.php' does not allow
    # serving as static file, access denied!` -- i.e. OLS was falling back
    # to serving .php as a plain static file instead of routing it through
    # the LSAPI PHP handler at all, even though the vhost's own
    # scripthandler/extprocessor config was correct. The reason: with
    # `restrained 1`, OLS confines the vhost to vhRoot for *all* filesystem
    # access, not just docRoot -- and the LSAPI extprocessor's unix socket
    # lives at /tmp/lshttpd/<domain>.sock (see the extprocessor block in
    # _ols_vhost), a path this panel intentionally keeps outside vhRoot.
    # Restrained blocked that socket from ever being opened, LSAPI silently
    # never started, and OLS fell back to (and then refused) static
    # serving. `restrained` is meant for genuinely self-contained,
    # chroot-style site layouts; this panel's OLS sites deliberately keep
    # logs, sockets, and config outside the docRoot, so it's simply not a
    # fit here.
    existing_block_m = re.search(r'(virtualhost\s+' + re.escape(domain) + r'\s*\{)(.*?)(\n\})', content, re.DOTALL)
    if not existing_block_m:
        vh_block = f"""
virtualhost {domain} {{
  vhRoot                  {vh_root}/
  configFile              {vhost_dir}/vhconf.conf
  allowSymbolLink         1
  enableScript            1
  restrained              0
}}
"""
        content = content.rstrip('\n') + '\n' + vh_block
        changed = True
    else:
        # Self-heal sites registered by an older, buggy version of this
        # function before this fix -- otherwise this guard would silently
        # leave their vhRoot/restrained wrong forever, since "already
        # registered" short-circuited any further correction on every
        # later call (including calls made after deploying earlier fixes).
        body = existing_block_m.group(2)
        vhroot_m = re.search(r'vhRoot\s+(\S+)', body)
        current = vhroot_m.group(1).rstrip('/') if vhroot_m else None
        if current != vh_root:
            body = re.sub(r'vhRoot\s+\S+', f'vhRoot                  {vh_root}/', body, count=1) \
                if vhroot_m else body + f'\n  vhRoot                  {vh_root}/'
            changed = True
        restrained_m = re.search(r'restrained\s+(\d)', body)
        if not restrained_m or restrained_m.group(1) != '0':
            body = re.sub(r'restrained\s+\d', 'restrained              0', body, count=1) \
                if restrained_m else body + '\n  restrained              0'
            changed = True
        if changed:
            content = content[:existing_block_m.start(2)] + body + content[existing_block_m.end(2):]

    # 2. make sure a listener actually bound to :80 exists
    content, listener_name = _ensure_ols_http_listener(content)

    # 3. map entry inside that listener (added alongside any existing
    #    catch-all map, never duplicated on repeat calls)
    map_marker = f'map                      {domain} '
    if map_marker not in content:
        m = re.search(r'(listener\s+' + re.escape(listener_name) + r'\s*\{)(.*?)(\n\})', content, re.DOTALL)
        if not m:
            return False, f'Could not find listener {listener_name} block in httpd_config.conf'
        block_body = m.group(2)
        map_line = f'\n    map                      {domain} {domain},www.{domain}'
        content = content[:m.start(2)] + block_body + map_line + content[m.end(2):]
        changed = True

    # (Previously step 4 here added OLS's default worker user to the
    # www-data group, to work around php-fpm socket permissions. That
    # workaround no longer applies -- OLS now spawns its own LSPHP process
    # per site via LSAPI rather than connecting to an external php-fpm
    # socket at all, so there is no shared socket permission to align.)

    if changed:
        shutil.copy(OLS_MAIN_CONF, OLS_MAIN_CONF + '.bak')
        with open(OLS_MAIN_CONF, 'w') as f:
            f.write(content)

    return True, 'ok'


def _unregister_ols_vhost(domain):
    """Remove a domain's `virtualhost {}` block and its listener map entry
    from httpd_config.conf. Best-effort; safe to call even if never
    registered."""
    if not os.path.exists(OLS_MAIN_CONF):
        return
    with open(OLS_MAIN_CONF, 'r') as f:
        content = f.read()

    content = re.sub(
        r'\n?virtualhost ' + re.escape(domain) + r' \{.*?\n\}\n?',
        '\n', content, flags=re.DOTALL
    )
    content = re.sub(
        r'\n?\s*map\s+' + re.escape(domain) + r' [^\n]*',
        '', content
    )

    shutil.copy(OLS_MAIN_CONF, OLS_MAIN_CONF + '.bak')
    with open(OLS_MAIN_CONF, 'w') as f:
        f.write(content)


def _reload_ols():
    """Actually apply new OpenLiteSpeed vhost config to the running server.

    The previous command here was
    `kill -USR1 $(cat /tmp/lshttpd.pid 2>/dev/null) 2>/dev/null || systemctl reload lsws 2>/dev/null`.
    /tmp/lshttpd/ is where per-vhost LSAPI *sockets* live
    (UDS://tmp/lshttpd/<domain>.sock, see the extprocessor block in
    _ols_vhost) -- it was never OLS's PID file location, so `cat` always
    failed, the `kill` target was always empty, and the command silently
    fell through to `systemctl reload lsws`, which likely doesn't match the
    real service/unit name on an aaPanel-managed OpenLiteSpeed install
    either. Because sh() swallows all errors/exit codes and neither
    _write_vhost nor _delete_vhost checked the outcome, every single site
    create/delete "succeeded" while the running OLS process kept serving
    its old configuration untouched -- vhconf.conf and httpd_config.conf on
    disk were always 100% correct (confirmed directly on a live box: right
    vhRoot, right map entry, right virtualhost block), OLS just never
    reloaded them, so every new site 403'd as unregistered/default until a
    manual Graceful Restart was done by hand through the WebAdmin UI.
    lswsctrl is OpenLiteSpeed's own official control script -- it finds and
    signals the real running process correctly regardless of how the
    service happens to be supervised (systemd, aaPanel, init script, ...),
    so it's used first; systemctl variants remain only as a last-resort
    fallback for non-standard installs without lswsctrl.
    """
    for cmd in (
        '/usr/local/lsws/bin/lswsctrl restart',
        'systemctl restart lsws',
        'systemctl restart lshttpd',
        'systemctl reload lsws',
    ):
        out, err, rc = sh3(f'{cmd} 2>&1', t=30)
        if rc == 0:
            return True, out
    return False, f'All OpenLiteSpeed restart methods failed. Last attempt: {cmd} -> {out}{err}'.strip()


def _write_vhost(domain, path, php_ver, webserver):
    """Write vhost config for the given webserver and reload it. Never
    replaces an existing site's config (the failure path below deletes
    the file it wrote)."""
    ws = webserver or _detect_webserver()
    try:
        from panel.routes.websites_core import _find_site_config, is_valid_domain, valid_site_path
        if not is_valid_domain(domain):
            return False, 'Invalid domain name'
        perr = valid_site_path(path)
        if perr:
            return False, perr
        if _find_site_config(domain)[0]:
            return False, f'A site for {domain} already exists'
    except ImportError:
        pass
    if not ws:
        return False, 'No web server is installed'

    if ws == 'nginx':
        vhost_dir = '/etc/nginx/vortex'
        os.makedirs(vhost_dir, exist_ok=True)
        conf_path = f'{vhost_dir}/{domain}.conf'
        with open(conf_path, 'w') as f:
            f.write(_nginx_vhost(domain, path, php_ver))
        test_out, test_err, rc = sh3('nginx -t 2>&1', t=60)
        if rc != 0:
            os.unlink(conf_path)
            return False, f'nginx config error: {test_out}{test_err}'
        sh('systemctl reload nginx 2>/dev/null')

    elif ws == 'apache':
        conf_path = _apache_conf_path(domain)
        os.makedirs(os.path.dirname(conf_path), exist_ok=True)
        with open(conf_path, 'w') as f:
            f.write(_apache_vhost(domain, path, php_ver))
        htaccess_path = os.path.join(path, '.htaccess')
        if not os.path.exists(htaccess_path):
            with open(htaccess_path, 'w') as f:
                f.write(_apache_htaccess())
        debian_layout = conf_path.startswith('/etc/apache2/')
        if debian_layout:
            sh(f'a2ensite {domain}.conf 2>/dev/null')
            sh('a2enmod rewrite proxy_fcgi setenvif 2>/dev/null')
        test_out, test_err, rc = sh3('apachectl configtest 2>&1', t=60)
        if rc != 0 or 'Syntax error' in (test_out + test_err):
            if debian_layout:
                sh(f'a2dissite {domain}.conf 2>/dev/null')
            try: os.unlink(conf_path)
            except OSError: pass
            return False, f'Apache config error: {test_out}{test_err}'
        sh('systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null')

    elif ws == 'openlitespeed':
        vhost_dir = f'/usr/local/lsws/conf/vhosts/{domain}'
        os.makedirs(vhost_dir, exist_ok=True)
        # vhconf.conf points its errorlog/accesslog directives at
        # /var/log/openlitespeed/<domain>.{error,access}_log (see
        # _ols_vhost below) but nothing ever created that directory --
        # confirmed missing entirely on a live box (`ls /var/log/openlitespeed`
        # -> "No such file or directory") despite every other part of the
        # vhost config (vhRoot, docRoot, map entry, virtualhost block) being
        # correct and OLS having been properly restarted. OLS refuses to
        # activate a vhost whose log file can't be opened, which produced
        # exactly this symptom: a fully correct config that 403s anyway,
        # with the domain's own error log never even coming into existence.
        os.makedirs('/var/log/openlitespeed', exist_ok=True)
        conf_path = f'{vhost_dir}/vhconf.conf'
        with open(conf_path, 'w') as f:
            f.write(_ols_vhost(domain, path, php_ver))
        reg_ok, reg_msg = _register_ols_vhost(domain, vhost_dir, path)
        if not reg_ok:
            return False, f'OpenLiteSpeed registration error: {reg_msg}'
        htaccess_path = os.path.join(path, '.htaccess')
        if not os.path.exists(htaccess_path):
            with open(htaccess_path, 'w') as f:
                f.write(_apache_htaccess())
        _reload_ols()

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
        out, err, rc = sh3('caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1', t=60)
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
        sh(f'a2dissite {domain}.conf {domain}-le-ssl.conf 2>/dev/null')
        for p in [f'/etc/apache2/sites-available/{domain}.conf', f'/etc/apache2/sites-enabled/{domain}.conf',
                  f'/etc/apache2/sites-available/{domain}-le-ssl.conf', f'/etc/apache2/sites-enabled/{domain}-le-ssl.conf',
                  f'/etc/httpd/conf.d/{domain}.conf', f'/etc/httpd/conf.d/{domain}-le-ssl.conf']:
            try: os.unlink(p)
            except: pass
        sh('systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null')
    elif ws == 'openlitespeed':
        try: shutil.rmtree(f'/usr/local/lsws/conf/vhosts/{domain}')
        except: pass
        _unregister_ols_vhost(domain)
        _reload_ols()
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
    for conf_dir in ['/etc/nginx/vortex', '/etc/nginx/conf.d', '/etc/apache2/sites-enabled', '/etc/httpd/conf.d']:
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
            vm = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", vc)
            if vm: info['wp_version'] = vm.group(1)
        except: pass

    # PHP version from the site's vhost (any web server, any PHP layout:
    # the old regex only knew Debian's phpX.Y-fpm.sock)
    try:
        from panel.routes.websites_core import _find_site_config, php_ver_from_conf
        fp_v = _find_site_config(domain)[0] if re.fullmatch(r'[a-z0-9.-]+', domain or '') else None
        if fp_v:
            pv = php_ver_from_conf(open(fp_v).read())
            if pv != 'Static':
                info['php_version'] = pv
    except Exception:
        pass

    # SSL check
    for d in [f'/etc/letsencrypt/live/{domain}', f'/etc/nginx/ssl/{domain}']:
        if os.path.isdir(d):
            info['ssl'] = True
            break

    # Disk usage
    try:
        du = sh(f'du -sb {Q(path)} 2>/dev/null | cut -f1')
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
        out = sh(f'{_wpc()} --path={Q(path)} --allow-root option get siteurl 2>/dev/null')
        if out and 'http' in out:
            info['site_url'] = out

        out = sh(f'{_wpc()} --path={Q(path)} --allow-root option get blogname 2>/dev/null')
        if out: info['site_title'] = out

        out = sh(f'{_wpc()} --path={Q(path)} --allow-root option get admin_email 2>/dev/null')
        if out: info['admin_email'] = out

        out = sh(f'{_wpc()} --path={Q(path)} --allow-root option get blog_public 2>/dev/null')
        info['search_visible'] = out.strip() != '0'

        # Admin user
        out = sh(f'{_wpc()} --path={Q(path)} --allow-root user list --role=administrator --field=user_login --format=csv 2>/dev/null')
        if out: info['admin_user'] = out.split('\n')[0].strip()

        # DB engine
        out = sh(f'{_wpc()} --path={Q(path)} --allow-root db query "SELECT @@version_comment" 2>/dev/null')
        if 'mariadb' in out.lower() or 'Maria' in out:
            info['db_engine'] = 'mariadb'
        elif out:
            info['db_engine'] = 'mysql'

        # Update count
        out = sh(f'{_wpc()} --path={Q(path)} --allow-root core check-update --field=version --format=count 2>/dev/null')
        plugin_updates = sh(f'{_wpc()} --path={Q(path)} --allow-root plugin update --all --dry-run --format=count 2>/dev/null')
        try:
            core_upd  = 1 if out and out.strip() and not out.strip().startswith('0') and 'Success' not in out else 0
            plug_upd  = int(plugin_updates) if plugin_updates.isdigit() else 0
            info['update_count'] = core_upd + plug_upd
        except: pass

        # System cron check
        out = sh(f'{_wpc()} --path={Q(path)} --allow-root config get DISABLE_WP_CRON 2>/dev/null')
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
        'php_versions': _available_php(_detect_webserver()),
        'db_engines': _available_db(),
        'wpcli_installed': _wp_installed(),
        'active_webserver': _detect_webserver(),
    }
    panel_cache.set('wp_sites', resp, ttl=30)
    return jsonify(resp)


@wp_bp.route('/api/wp/install', methods=['POST'])
def install_wp():
    """Full WordPress install: download, create DB, configure, create vhost.

    Runs as a background job rather than one long blocking request -- this
    is genuinely capable of taking longer than gunicorn's configured worker
    timeout (120s) once you add WordPress core download, wp-cli's own
    install/migration step, recursive chown/chmod, vhost writing and cron
    setup together under real-world network/disk conditions. A killed
    worker mid-request gives the frontend nothing at all, which is exactly
    what "installation gets stuck, nothing happens" describes.
    """
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

    # Fast, cheap validation stays synchronous -- bad input should fail
    # immediately, not after the caller waits on a job that was never
    # going to succeed.
    if not domain:
        return jsonify({'ok': False, 'error': 'Domain is required'}), 400
    from panel.routes.websites_core import is_valid_domain
    if not is_valid_domain(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain name'}), 400
    if not webserver:
        return jsonify({'ok': False, 'error': 'No web server is installed. Install Nginx, Apache2, OpenLiteSpeed, or Caddy from the App Store first.'}), 400
    if webserver not in _installed_webservers():
        return jsonify({'ok': False, 'error': f'{webserver} is not installed on this server. Install it from the App Store first, or pick a different web server.'}), 400
    if not db_engine or db_engine not in _available_db():
        return jsonify({'ok': False, 'error': 'No supported database engine (MySQL or MariaDB) is installed. Install one from the App Store first.'}), 400
    php_ver = str(php_ver or '').strip()
    if not re.fullmatch(r'\d+\.\d+', php_ver):
        return jsonify({'ok': False, 'error': 'Invalid PHP version'}), 400
    if webserver == 'openlitespeed':
        if not os.path.exists(_lsphp_binary(php_ver)):
            return jsonify({'ok': False, 'error': f'LSPHP {php_ver} is not installed for OpenLiteSpeed.'}), 400
    elif not php_layout(php_ver):
        # php_layout() knows Debian/sury, remi SCL and the RHEL module-stream
        # PHP (`which php8.3` is empty on RHEL, so WordPress could not be
        # installed there at all)
        inst = ', '.join(l['ver'] for l in installed_php_layouts()) or 'none'
        return jsonify({'ok': False, 'error': f'PHP {php_ver} is not installed on this server (installed: {inst}). Install it from the App Store first.'}), 400
    # Values below are passed to wp-cli on a root shell: validate the ones
    # with a fixed shape, everything else is shell-quoted where it is used.
    if not re.fullmatch(r'[A-Za-z]{2,3}(_[A-Za-z0-9]{2,8})*', str(locale or '')):
        return jsonify({'ok': False, 'error': 'Invalid locale'}), 400
    if not re.fullmatch(r'latest|\d+\.\d+(\.\d+)?', str(wp_ver or 'latest')):
        return jsonify({'ok': False, 'error': 'Invalid WordPress version'}), 400
    prefix = str(prefix or '').strip() or _rand_prefix()
    if not re.fullmatch(r'[A-Za-z0-9_]{1,20}', prefix):
        return jsonify({'ok': False, 'error': 'Table prefix may contain letters, digits and _ only'}), 400
    admin_user = str(admin_user or '').strip() or ('admin_' + _rand_str(5))
    admin_pass = str(admin_pass or '') or _rand_pass()
    admin_email = str(admin_email or '').strip() or f'admin@{domain}'
    title = str(title or '').strip() or f'WordPress - {domain}'
    if not re.fullmatch(r'[A-Za-z0-9._@-]{1,60}', admin_user):
        return jsonify({'ok': False, 'error': 'Admin user name may contain letters, digits and . _ @ - only'}), 400
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', admin_email):
        return jsonify({'ok': False, 'error': 'Invalid admin e-mail'}), 400
    try:
        from panel.routes.websites_core import _find_site_config
        existing_vhost = _find_site_config(domain)[0]
    except Exception:
        existing_vhost = None

    from panel.routes.job_state import load_job, save_job
    existing = load_job(f'wp_install_{domain}', {'running': False})
    if existing.get('running'):
        return jsonify({'ok': False, 'error': f'An install for {domain} is already in progress'}), 409

    # Always /www/wwwroot: /var/www/html is the default site's docroot, where
    # this site's wp-config.php would be served as source to anyone.
    webroot = _ou.get_webroot()
    # `d.get('path', default)` only falls back to `default` when the key is
    # *missing* -- the Install WordPress modal has no path field and always
    # submits path:'' explicitly, so the key is always present with an empty
    # string, the "default" here never actually applied, and os.makedirs('')
    # failed immediately with "[Errno 2] No such file or directory: ''"
    # before anything else in the install ever ran.
    path = (d.get('path') or f'{webroot}/{domain}').strip().rstrip('/')
    if existing_vhost and not d.get('path'):
        # install into the existing site's document root
        from panel.routes.websites_core import _get_site_path
        path = _get_site_path(domain).rstrip('/')
    perr = _wp_path_error(path, require_wp=False)
    if perr:
        return jsonify({'ok': False, 'error': perr}), 400

    def run_install():
        import time as _t
        save_job(f'wp_install_{domain}', {'running': True, 'done': False, 'step': 'Starting...', 'started': _t.time()})

        def step(msg):
            st = load_job(f'wp_install_{domain}', {})
            st['step'] = msg
            save_job(f'wp_install_{domain}', st)

        def fail(msg):
            save_job(f'wp_install_{domain}', {'running': False, 'done': True, 'success': False, 'error': msg})

        try:
            os.makedirs(path, exist_ok=True)

            step('Checking wp-cli...')
            if not _wp_installed():
                if not _install_wpcli():
                    return fail('Failed to install wp-cli')

            step('Creating database...')
            db_name = re.sub(r'[^a-zA-Z0-9_]', '_', domain.replace('.', '_'))[:32]
            db_user = 'wp_' + _rand_str(8)
            db_pass = _rand_pass(16)
            _, db_err, db_rc = _mysql_cmd(
                f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;",
                engine=db_engine)
            if db_rc != 0:
                return fail(f'DB creation failed: {db_err}')
            _, db_err, db_rc = _mysql_cmd(f"CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{db_pass}';", engine=db_engine)
            if db_rc == 0:
                _, db_err, db_rc = _mysql_cmd(f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'localhost'; FLUSH PRIVILEGES;", engine=db_engine)
            if db_rc != 0:
                return fail(f'DB user creation failed: {db_err}')

            step('Downloading WordPress...')
            ver_flag = f'--version={wp_ver}' if wp_ver and wp_ver != 'latest' else ''
            locale_q = Q(locale)
            out, err, rc = sh3(
                f'{_wpc()} core download --path={Q(path)} --locale={locale_q} {ver_flag} --allow-root --force 2>&1', t=180)
            if rc != 0:
                return fail(f'WP download failed: {out}{err}')

            step('Writing wp-config.php...')
            # Start on http://; switched to https:// below only once a
            # certificate was really issued (auto_ssl used to set an https URL
            # without ever requesting a certificate -> unreachable site).
            site_url = f'http://{domain}'
            out, err, rc = sh3(
                f'{_wpc()} config create --path={Q(path)} --allow-root'
                f' --dbname={db_name} --dbuser={db_user} --dbpass={Q(db_pass)}'
                f' --dbhost=localhost --dbprefix={prefix} --force 2>&1', t=30)
            if rc != 0:
                return fail(f'wp-config creation failed: {out}{err}')

            extras = []
            if system_cron: extras.append("define('DISABLE_WP_CRON', true);")
            if block_xmlrpc: extras.append("define('XMLRPC_DISABLE', true);")
            if extras:
                try:
                    cfg = open(f'{path}/wp-config.php').read()
                    cfg = cfg.replace("/* That's all, stop editing!", '\n'.join(extras) + "\n\n/* That's all, stop editing!")
                    with open(f'{path}/wp-config.php', 'w') as f: f.write(cfg)
                except Exception: pass

            step('Running WordPress installer...')
            out, err, rc = sh3(
                f'{_wpc()} core install --path={Q(path)} --allow-root'
                f' --url={Q(site_url)} --title={Q(title)}'
                f' --admin_user={Q(admin_user)} --admin_password={Q(admin_pass)}'
                f' --admin_email={Q(admin_email)} --skip-email 2>&1', t=90)
            if rc != 0:
                return fail(f'WP install failed: {out}{err}')

            step('Setting file permissions...')
            # the PHP the site will really run on: an existing vhost keeps its own
            site_php = (_site_php_of(domain) if existing_vhost else None) or php_ver
            web_user = _web_user(site_php, webserver)
            sh(f'find {Q(path)} -type d -exec chmod 755 {{}} + 2>/dev/null || true', t=600)
            sh(f'find {Q(path)} -type f -exec chmod 644 {{}} + 2>/dev/null || true', t=600)
            sh(f'chmod 600 {Q(path + "/wp-config.php")} 2>/dev/null || true')
            _fix_site_tree(path, site_php, webserver)

            step('Creating web server config...')
            if existing_vhost:
                # never overwrite an existing site's vhost (SSL/proxy edits)
                step('Using the existing web server config for this domain...')
            else:
                ok, result = _write_vhost(domain, path, php_ver, webserver)
                if not ok:
                    return fail(f'Vhost creation failed: {result}')

            ssl_note = ''
            if auto_ssl:
                step('Requesting SSL certificate...')
                try:
                    from panel.routes.websites_ssl import _issue_cert
                    ssl_ok, ssl_out, _m = _issue_cert(domain, admin_email)
                except Exception as e:
                    ssl_ok, ssl_out = False, str(e)
                if ssl_ok:
                    site_url = f'https://{domain}'
                    for opt in ('home', 'siteurl'):
                        sh3(f'{_wpc()} --path={Q(path)} --allow-root option update {opt} {Q(site_url)} 2>&1', t=60)
                else:
                    ssl_note = 'SSL certificate could not be issued (the domain must point to this server); the site uses http:// -- issue SSL later from Websites.'

            if system_cron:
                cron_line = f'*/5 * * * * {web_user} {_wpc()} --path={Q(path)} --allow-root cron event run --due-now >/dev/null 2>&1'
                cron_file = f'/etc/cron.d/vortex-wp-{re.sub(chr(46), "_", domain)}'
                try:
                    with open(cron_file, 'w') as f: f.write(cron_line + '\n')
                    os.chmod(cron_file, 0o644)
                except Exception: pass

            panel_cache.invalidate('wp_sites')

            save_job(f'wp_install_{domain}', {
                'running': False, 'done': True, 'success': True,
                'domain': domain, 'path': path, 'site_url': site_url,
                'admin_user': admin_user, 'admin_pass': admin_pass, 'admin_email': admin_email,
                'db_name': db_name, 'db_user': db_user, 'db_pass': db_pass,
                'webserver': webserver, 'php_version': php_ver, 'ssl_note': ssl_note,
            })
        except Exception as e:
            fail(f'Unexpected error: {e}')

    threading.Thread(target=run_install, daemon=True).start()
    return jsonify({'ok': True, 'started': True, 'domain': domain})


@wp_bp.route('/api/wp/install/status')
def install_wp_status():
    if not req(): return jsonify({'ok': False}), 401
    from panel.routes.job_state import load_job
    domain = request.args.get('domain', '').strip().lower()
    if not domain:
        return jsonify({'ok': False, 'error': 'domain required'}), 400
    state = load_job(f'wp_install_{domain}', {'running': False, 'done': False})
    return jsonify({'ok': True, **state})


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

    admin_user = sh(f'{_wpc()} --path={Q(path)} --allow-root user list --role=administrator --field=user_login --format=csv 2>/dev/null').split('\n')[0].strip()
    if not admin_user:
        return jsonify({'ok': False, 'error': 'No admin user found'}), 404

    login_url, err, rc = sh3(f'{_wpc()} --path={Q(path)} --allow-root user session create {Q(admin_user)} --url-only 2>&1')
    if rc != 0 or not login_url.startswith('http'):
        # Fallback: magic link via eval
        login_url, err, rc = sh3(
            f'{_wpc()} --path={Q(path)} --allow-root eval '
            f'"echo wp_login_url(admin_url(), true);" 2>/dev/null'
        )
    return jsonify({'ok': True, 'login_url': login_url.strip()})


# --- Plugins --------------------------------------------------------------------

@wp_bp.route('/api/wp/<domain>/plugins')
def list_plugins(domain):
    if not req(): return jsonify({'ok': False}), 401
    path = (request.args.get('path') or _default_wp_path(domain))
    if not _wp_installed():
        return jsonify({'ok': False, 'error': 'wp-cli not installed'}), 400

    out, err, rc = sh3(
        f'{_wpc()} --path={Q(path)} --allow-root plugin list --format=json 2>/dev/null', t=30
    )
    try:
        plugins = json.loads(out) if out else []
    except: plugins = []

    # Check for updates
    upd_out = sh(f'{_wpc()} --path={Q(path)} --allow-root plugin update --all --dry-run --format=json 2>/dev/null')
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
    path = (d.get('path') or _default_wp_path(domain))
    action = d.get('action', 'activate')  # activate | deactivate | update | delete | install

    if not _wp_installed():
        return jsonify({'ok': False, 'error': 'wp-cli not installed'}), 400

    if action == 'install':
        out, err, rc = sh3(f'{_wpc()} --path={Q(path)} --allow-root plugin install {plugin} --activate 2>&1', t=120)
    elif action == 'activate':
        out, err, rc = sh3(f'{_wpc()} --path={Q(path)} --allow-root plugin activate {plugin} 2>&1')
    elif action == 'deactivate':
        out, err, rc = sh3(f'{_wpc()} --path={Q(path)} --allow-root plugin deactivate {plugin} 2>&1')
    elif action == 'update':
        out, err, rc = sh3(f'{_wpc()} --path={Q(path)} --allow-root plugin update {plugin} 2>&1', t=120)
    elif action == 'delete':
        out, err, rc = sh3(f'{_wpc()} --path={Q(path)} --allow-root plugin deactivate {plugin} 2>/dev/null; '
                           f'{_wpc()} --path={Q(path)} --allow-root plugin delete {plugin} 2>&1')
    else:
        return jsonify({'ok': False, 'error': 'Unknown action'}), 400

    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': rc == 0, 'output': (out + err)[-500:]})


@wp_bp.route('/api/wp/<domain>/plugins/update-all', methods=['POST'])
def update_all_plugins(domain):
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    path = (d.get('path') or _default_wp_path(domain))
    out, err, rc = sh3(f'{_wpc()} --path={Q(path)} --allow-root plugin update --all 2>&1', t=300)
    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': rc == 0, 'output': (out + err)[-1000:]})


# --- Themes ---------------------------------------------------------------------

@wp_bp.route('/api/wp/<domain>/themes')
def list_themes(domain):
    if not req(): return jsonify({'ok': False}), 401
    path = (request.args.get('path') or _default_wp_path(domain))
    if not _wp_installed():
        return jsonify({'ok': False, 'error': 'wp-cli not installed'}), 400
    out, err, rc = sh3(f'{_wpc()} --path={Q(path)} --allow-root theme list --format=json 2>/dev/null', t=30)
    try: themes = json.loads(out) if out else []
    except: themes = []
    return jsonify({'ok': True, 'themes': themes})


@wp_bp.route('/api/wp/<domain>/themes/<theme>', methods=['POST'])
def theme_action(domain, theme):
    if not req(): return jsonify({'ok': False}), 401
    d      = request.get_json() or {}
    path   = (d.get('path') or _default_wp_path(domain))
    action = d.get('action', 'activate')

    if not _wp_installed():
        return jsonify({'ok': False, 'error': 'wp-cli not installed'}), 400

    if action == 'install':
        out, err, rc = sh3(f'{_wpc()} --path={Q(path)} --allow-root theme install {theme} 2>&1', t=120)
    elif action == 'activate':
        out, err, rc = sh3(f'{_wpc()} --path={Q(path)} --allow-root theme activate {theme} 2>&1')
    elif action == 'update':
        out, err, rc = sh3(f'{_wpc()} --path={Q(path)} --allow-root theme update {theme} 2>&1', t=120)
    elif action == 'delete':
        out, err, rc = sh3(f'{_wpc()} --path={Q(path)} --allow-root theme delete {theme} 2>&1')
    else:
        return jsonify({'ok': False, 'error': 'Unknown action'}), 400

    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': rc == 0, 'output': (out + err)[-500:]})


# --- Core update ----------------------------------------------------------------

@wp_bp.route('/api/wp/<domain>/update-core', methods=['POST'])
def update_core(domain):
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    path = (d.get('path') or _default_wp_path(domain))
    out, err, rc = sh3(f'{_wpc()} --path={Q(path)} --allow-root core update 2>&1', t=300)
    out2, err2, _ = sh3(f'{_wpc()} --path={Q(path)} --allow-root core update-db 2>&1', t=60)
    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': rc == 0, 'output': (out + err + out2 + err2)[-1000:]})


# --- Security scanner -----------------------------------------------------------

@wp_bp.route('/api/wp/<domain>/security')
def security_scan(domain):
    if not req(): return jsonify({'ok': False}), 401
    path = (request.args.get('path') or _default_wp_path(domain))
    checks = []

    def chk(label, passed, detail='', fix=''):
        checks.append({'label': label, 'passed': passed, 'detail': detail, 'fix': fix})

    # 1. Admin username check
    admin_users = sh(f'{_wpc()} --path={Q(path)} --allow-root user list --role=administrator --field=user_login --format=csv 2>/dev/null')
    bad_users = [u for u in admin_users.split('\n') if u.strip().lower() in ('admin', 'administrator', 'root')]
    chk('No weak admin username', len(bad_users) == 0,
        'Admin account uses a non-obvious username' if not bad_users else f'Weak admin username: {", ".join(bad_users)}',
        'rename_admin_user')

    # 2. File permissions
    cfg_perms = sh(f'stat -c "%a" {Q(path + "/wp-config.php")} 2>/dev/null')
    chk('wp-config.php permissions', cfg_perms in ('600', '640', '644'),
        f'wp-config.php is {cfg_perms}' if cfg_perms else 'Could not check permissions',
        'fix_permissions')

    # 3. WP version up to date
    update_check = sh(f'{_wpc()} --path={Q(path)} --allow-root core check-update --field=version 2>/dev/null')
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
    try:
        from panel.routes.websites_core import _find_site_config
        _fp = _find_site_config(domain)[0]
        site_conf = open(_fp).read() if _fp else ''
    except Exception:
        site_conf = ''
    if 'xmlrpc.php' in site_conf:
        xmlrpc_blocked = True
    chk('XML-RPC disabled', xmlrpc_blocked, 'xmlrpc.php is blocked at web server level' if xmlrpc_blocked else 'xmlrpc.php is publicly accessible', 'block_xmlrpc')

    # 7. wp-config.php HTTP access blocked
    cfg_blocked = 'wp-config' in site_conf
    chk('wp-config.php HTTP access blocked', cfg_blocked,
        'Direct HTTP access denied' if cfg_blocked else 'wp-config.php may be accessible over HTTP', 'block_wpconfig')

    # 8. No vulnerable plugins (basic check via wp update list)
    vuln_count = 0
    if _wp_installed():
        upd = sh(f'{_wpc()} --path={Q(path)} --allow-root plugin update --all --dry-run --format=count 2>/dev/null')
        try: vuln_count = int(upd)
        except: vuln_count = 0
    chk('Plugins up to date', vuln_count == 0,
        'All plugins are current' if vuln_count == 0 else f'{vuln_count} plugin(s) have updates available', 'update_plugins')

    # 9. Login URL exposed
    login_hidden = False
    if _wp_installed():
        wps = sh(f'{_wpc()} --path={Q(path)} --allow-root plugin is-installed wps-hide-login 2>/dev/null')
        login_hidden = 'installed' not in (sh(f'{_wpc()} --path={Q(path)} --allow-root plugin status wps-hide-login 2>/dev/null') or '').lower()
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
    path = (d.get('path') or _default_wp_path(domain))
    fix  = d.get('fix', '')

    out = ''
    if fix == 'fix_permissions':
        sh(f'chmod 600 {Q(path + "/wp-config.php")}')
        sh(f'find {Q(path)} -type d -exec chmod 755 {{}} \\;')
        sh(f'find {Q(path)} -type f -exec chmod 644 {{}} \\;')
        sh(f'chmod 600 {Q(path + "/wp-config.php")}')
        out = 'File permissions corrected'

    elif fix == 'disable_debug':
        if os.path.exists(f'{path}/wp-config.php'):
            cfg = open(f'{path}/wp-config.php').read()
            cfg = re.sub(r"define\s*\(\s*'WP_DEBUG'\s*,\s*true\s*\)", "define('WP_DEBUG', false)", cfg)
            cfg = re.sub(r'define\s*\(\s*"WP_DEBUG"\s*,\s*true\s*\)', 'define("WP_DEBUG", false)', cfg)
            with open(f'{path}/wp-config.php', 'w') as f: f.write(cfg)
        out = 'WP_DEBUG disabled'

    elif fix == 'block_xmlrpc':
        # The old code searched for 'location ~ /\\.ht' (the generated vhost
        # has 'location ~* /\\.ht'), so nothing was ever inserted while
        # "XML-RPC blocked" was reported; it also edited any nginx file whose
        # text merely contained the domain, without a rollback.
        try:
            from panel.routes.websites_core import _find_site_config, nginx_edit_site, nginx_insert_in_servers, apache_edit_site
            fp_ws, ws = _find_site_config(domain)
        except Exception:
            fp_ws, ws = None, None
        if ws == 'nginx':
            ok_x, err_x, _c = nginx_edit_site(domain, lambda c: c if 'location = /xmlrpc.php' in c else
                                              nginx_insert_in_servers(c, '    location = /xmlrpc.php { deny all; }\n', at='end'))
        elif ws == 'apache':
            blk = '    <Files "xmlrpc.php">\n        Require all denied\n    </Files>\n'
            ok_x, err_x = apache_edit_site(fp_ws, lambda c: c if 'xmlrpc.php' in c else
                                           re.sub(r'(\n)(</VirtualHost>)', lambda m: '\n' + blk + m.group(2), c))
        else:
            ok_x, err_x = False, f'Blocking XML-RPC automatically is supported for nginx and Apache sites ({ws or "site config not found"})'
        if not ok_x:
            panel_cache.invalidate('wp_sites')
            return jsonify({'ok': False, 'error': err_x})
        out = 'XML-RPC blocked at web server level'

    elif fix == 'system_cron':
        if os.path.exists(f'{path}/wp-config.php'):
            cfg = open(f'{path}/wp-config.php').read()
            if 'DISABLE_WP_CRON' not in cfg:
                cfg = cfg.replace("/* That's all, stop editing!", "define('DISABLE_WP_CRON', true);\n/* That's all, stop editing!")
                with open(f'{path}/wp-config.php', 'w') as f: f.write(cfg)
        web_user = _web_user(_site_php_of(domain))
        cron_line = f'*/5 * * * * {web_user} {_wpc()} --path={Q(path)} --allow-root cron event run --due-now >/dev/null 2>&1'
        cron_file = f'/etc/cron.d/vortex-wp-{re.sub(chr(46), "_", domain)}'
        with open(cron_file, 'w') as f: f.write(cron_line + '\n')
        out = 'System cron configured, wp-cron disabled'

    elif fix == 'update_core':
        out_c, err_c, _ = sh3(f'{_wpc()} --path={Q(path)} --allow-root core update 2>&1', t=300)
        out = out_c or err_c

    elif fix == 'update_plugins':
        out_p, err_p, _ = sh3(f'{_wpc()} --path={Q(path)} --allow-root plugin update --all 2>&1', t=300)
        out = out_p or err_p

    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': True, 'output': out})


# --- Settings -------------------------------------------------------------------

@wp_bp.route('/api/wp/<domain>/settings', methods=['PUT'])
def save_settings(domain):
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    path = (d.get('path') or _default_wp_path(domain))

    if not _wp_installed():
        return jsonify({'ok': False, 'error': 'wp-cli not installed'}), 400

    results = []
    if 'site_title' in d:
        sh(f'{_wpc()} --path={Q(path)} --allow-root option update blogname {Q(d["site_title"])} 2>/dev/null')
        results.append('title updated')
    if 'admin_email' in d:
        sh(f'{_wpc()} --path={Q(path)} --allow-root option update admin_email {Q(d["admin_email"])} 2>/dev/null')
        results.append('email updated')
    if 'language' in d:
        sh(f'{_wpc()} --path={Q(path)} --allow-root option update WPLANG {Q(d["language"])} 2>/dev/null')
        results.append('language updated')
    if 'admin_password' in d and d['admin_password']:
        admin_user = sh(f'{_wpc()} --path={Q(path)} --allow-root user list --role=administrator --field=user_login --format=csv 2>/dev/null').split('\n')[0].strip()
        if admin_user:
            sh(f'{_wpc()} --path={Q(path)} --allow-root user update {Q(admin_user)} --user_pass={Q(d["admin_password"])} 2>/dev/null')
            results.append('password updated')

    if 'search_visible' in d:
        val = '1' if d['search_visible'] else '0'
        sh(f'{_wpc()} --path={Q(path)} --allow-root option update blog_public {val} 2>/dev/null')

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
        # Same validated path as Websites -> PHP (nginx -t / configtest with
        # rollback, existing socket only). The old code rewrote every nginx
        # file whose text merely contained the domain string, without a
        # rollback, and ignored Apache / Caddy sites.
        php_ver = str(d['php_version'])
        try:
            from panel.routes.websites_core import switch_site_php
            ok_p, err_p, _sock = switch_site_php(domain, php_ver)
            results.append(f'PHP switched to {php_ver}' if ok_p else f'PHP not switched: {err_p}')
        except Exception as e:
            results.append(f'PHP not switched: {e}')

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
    path = (d.get('path') or _default_wp_path(domain)).rstrip('/')
    if not os.path.isfile(os.path.join(path, 'wp-config.php')):
        return jsonify({'ok': False, 'error': 'WordPress not found at path'}), 404
    label = re.sub(r'[^A-Za-z0-9-]', '', str(d.get('label', 'manual')))[:20] or 'manual'
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_file = os.path.join(WP_BACKUP_DIR, f'{domain}_{label}_{ts}.tar.gz')

    # Back up files + database. The dump is stored at the top level of the
    # archive as vortex_db.sql (it used to be added by absolute path, so a
    # restore unpacked it to <webroot>/opt/vortexpanel/... and never imported it).
    db_dump = os.path.join(WP_BACKUP_DIR, 'vortex_db.sql')
    tmpdir = None
    if _wp_installed():
        import tempfile
        tmpdir = tempfile.mkdtemp(prefix='vp-wpbak-', dir=WP_BACKUP_DIR)
        db_dump = os.path.join(tmpdir, 'vortex_db.sql')
        _, derr, drc = sh3(f'{_wpc()} --path={Q(path)} --allow-root db export {Q(db_dump)} 2>&1', t=600)
        if drc != 0:
            shutil.rmtree(tmpdir, ignore_errors=True)
            return jsonify({'ok': False, 'error': f'Database export failed: {derr[-300:]}'}), 500

    cmd = f'tar -czf {Q(out_file)} -C {Q(os.path.dirname(path))} {Q(os.path.basename(path))}'
    if tmpdir and os.path.exists(db_dump):
        cmd += f' -C {Q(tmpdir)} vortex_db.sql'
    out, err, rc = sh3(cmd + ' 2>&1', t=1800)
    if tmpdir:
        shutil.rmtree(tmpdir, ignore_errors=True)
    if rc != 0:
        try: os.unlink(out_file)
        except OSError: pass
    else:
        os.chmod(out_file, 0o600)   # contains wp-config.php and the database
    return jsonify({'ok': rc == 0, 'filename': os.path.basename(out_file), 'error': (out + err) if rc != 0 else ''})


@wp_bp.route('/api/wp/<domain>/backups/<filename>/restore', methods=['POST'])
def restore_backup(domain, filename):
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    path = (d.get('path') or _default_wp_path(domain)).rstrip('/')
    backup_path = os.path.join(WP_BACKUP_DIR, filename)
    if not filename.startswith(domain + '_') or not os.path.isfile(backup_path):
        return jsonify({'ok': False, 'error': 'Backup file not found'}), 404
    import tarfile
    try:
        with tarfile.open(backup_path, 'r:gz') as tf:
            names = tf.getnames()
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Unreadable backup: {e}'}), 400
    base = os.path.basename(path)
    # only members of the site folder (+ the dump) are restored
    if any(n.startswith('/') or '..' in n.split('/') for n in names):
        return jsonify({'ok': False, 'error': 'Backup contains unsafe paths'}), 400
    _, err, rc = sh3(f'tar -xzf {Q(backup_path)} -C {Q(os.path.dirname(path))} {Q(base)} 2>&1', t=1800)
    if rc != 0:
        return jsonify({'ok': False, 'error': err})
    db_msg = ''
    if 'vortex_db.sql' in names and _wp_installed():
        import tempfile
        tmpdir = tempfile.mkdtemp(prefix='vp-wprst-', dir=WP_BACKUP_DIR)
        try:
            sh3(f'tar -xzf {Q(backup_path)} -C {Q(tmpdir)} vortex_db.sql 2>&1', t=600)
            o2, e2, rc2 = sh3(f'{_wpc()} --path={Q(path)} --allow-root db import {Q(os.path.join(tmpdir, "vortex_db.sql"))} 2>&1', t=1800)
            if rc2 != 0:
                return jsonify({'ok': False, 'error': f'Files restored but the database import failed: {(o2 + e2)[-300:]}'})
            db_msg = 'database restored'
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
    else:
        db_msg = 'this backup has no database dump (files only)'
    _fix_site_tree(path, _site_php_of(domain))
    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': True, 'error': '', 'message': f'Files restored, {db_msg}'})


@wp_bp.route('/api/wp/<domain>/backups/<filename>', methods=['DELETE'])
def delete_backup(domain, filename):
    if not req(): return jsonify({'ok': False}), 401
    backup_path = os.path.join(WP_BACKUP_DIR, filename)
    if filename.startswith(domain + '_') and os.path.isfile(backup_path):
        os.unlink(backup_path)
    return jsonify({'ok': True})


# --- Staging / Clone ------------------------------------------------------------

def _set_wp_db_config(cfg, name, user, password):
    """Point wp-config.php at another database. Handles both quote styles;
    returns (new_cfg, ok)."""
    ok = True
    for key, val in (('DB_NAME', name), ('DB_USER', user), ('DB_PASSWORD', password)):
        pat = r"define\s*\(\s*(['\"])" + key + r"\1\s*,\s*(['\"]).*?\2\s*\)"
        cfg, n = re.subn(pat, lambda m, k=key, v=val: f"define('{k}', '{v}')", cfg, count=1)
        ok = ok and n == 1
    return cfg, ok


@wp_bp.route('/api/wp/<domain>/clone', methods=['POST'])
def clone_site(domain):
    """Clone WP site to a staging subdomain."""
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    src_path    = (d.get('path') or _default_wp_path(domain)).rstrip('/')
    dest_domain = str(d.get('dest_domain') or f'staging.{domain}').strip().lower()
    clone_type  = d.get('type', 'full')  # full | files | db
    php_ver     = str(d.get('php_version', '8.4'))
    webserver   = d.get('webserver', '') or _detect_webserver()

    from panel.routes.websites_core import is_valid_domain, _find_site_config
    if not is_valid_domain(domain) or not is_valid_domain(dest_domain):
        return jsonify({'ok': False, 'error': 'Invalid domain name'}), 400
    if not re.fullmatch(r'\d+\.\d+', php_ver):
        return jsonify({'ok': False, 'error': 'Invalid PHP version'}), 400
    if clone_type not in ('full', 'files', 'db'):
        return jsonify({'ok': False, 'error': 'Unknown clone type'}), 400
    if webserver != 'openlitespeed' and not php_layout(php_ver):
        # the 8.4 default is often not installed (RHEL module stream ships one
        # PHP): use the live site's PHP, else the newest installed one
        _lays = installed_php_layouts()
        php_ver = _site_php_of(domain) or (_lays[0]['ver'] if _lays else php_ver)
    if not os.path.isfile(os.path.join(src_path, 'wp-config.php')):
        return jsonify({'ok': False, 'error': 'WordPress not found at path'}), 404
    if clone_type in ('full', 'db') and not _wp_installed():
        # without wp-cli the copied wp-config.php would keep pointing at the
        # LIVE database and the staging site would write to production
        return jsonify({'ok': False, 'error': 'wp-cli is required to clone the database -- install it first'}), 400

    dest_path = os.path.join(os.path.dirname(src_path), dest_domain)
    # never clobber an existing site / directory
    if _find_site_config(dest_domain)[0]:
        return jsonify({'ok': False, 'error': f'A site for {dest_domain} already exists'}), 400
    if os.path.isdir(dest_path) and os.listdir(dest_path):
        return jsonify({'ok': False, 'error': f'{dest_path} already exists and is not empty'}), 400
    os.makedirs(dest_path, exist_ok=True)

    results = []

    # 1. Copy files
    if clone_type in ('full', 'files'):
        _, err, rc = sh3(f'rsync -a --exclude=wp-content/cache/ {Q(src_path + "/")} {Q(dest_path + "/")} 2>&1', t=1800)
        if rc != 0:
            return jsonify({'ok': False, 'error': f'File copy failed: {err}'}), 500
        results.append('files copied')

    # 2. Clone database
    if clone_type in ('full', 'db'):
        new_db   = re.sub(r'[^a-zA-Z0-9_]', '_', dest_domain.replace('.', '_'))[:32]
        new_user = 'wp_' + _rand_str(8)
        new_pass = _rand_str(20)
        out, err_s, _rc = _mysql_cmd(f"SHOW DATABASES LIKE '{new_db}';")
        if new_db in (out or '').split():
            return jsonify({'ok': False, 'error': f'A database named {new_db} already exists'}), 400
        for q in (f'CREATE DATABASE `{new_db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;',
                  f"CREATE USER '{new_user}'@'localhost' IDENTIFIED BY '{new_pass}';",
                  f"GRANT ALL PRIVILEGES ON `{new_db}`.* TO '{new_user}'@'localhost'; FLUSH PRIVILEGES;"):
            _o, qerr, qrc = _mysql_cmd(q)
            if qrc != 0:
                return jsonify({'ok': False, 'error': f'Database setup failed: {qerr}'}), 500

        # Update wp-config.php in destination FIRST: every later wp-cli call on
        # dest_path must hit the new database, never the live one
        if clone_type == 'db' and not os.path.exists(f'{dest_path}/wp-config.php'):
            shutil.copy2(f'{src_path}/wp-config.php', f'{dest_path}/wp-config.php')
        cfg = open(f'{dest_path}/wp-config.php').read()
        cfg, cfg_ok = _set_wp_db_config(cfg, new_db, new_user, new_pass)
        if not cfg_ok:
            return jsonify({'ok': False, 'error': 'Could not rewrite the DB settings in the staging wp-config.php -- aborted before touching any database'}), 500
        with open(f'{dest_path}/wp-config.php', 'w') as f: f.write(cfg)

        import tempfile
        tmpdir = tempfile.mkdtemp(prefix='vp-clone-', dir=WP_BACKUP_DIR)
        dump_file = os.path.join(tmpdir, 'db.sql')
        try:
            _, err, rc = sh3(f'{_wpc()} --path={Q(src_path)} --allow-root db export {Q(dump_file)} 2>&1', t=600)
            if rc == 0:
                _, err, rc = sh3(f'{_wpc()} --path={Q(dest_path)} --allow-root db import {Q(dump_file)} 2>&1', t=1800)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
        if rc != 0:
            return jsonify({'ok': False, 'error': f'Database copy failed: {err[-300:]}'}), 500

        # Update siteurl + home in staging DB
        staging_url = f'http://{dest_domain}'
        src_url = sh(f'{_wpc()} --path={Q(src_path)} --allow-root option get siteurl 2>/dev/null')
        if src_url.startswith('http'):
            sh(f'{_wpc()} --path={Q(dest_path)} --allow-root search-replace {Q(src_url)} {Q(staging_url)} --all-tables-with-prefix 2>/dev/null', t=600)
        results.append('database cloned')

    # 3. Create vhost for staging
    ok, result = _write_vhost(dest_domain, dest_path, php_ver, webserver)
    if not ok:
        return jsonify({'ok': False, 'error': f'Staging vhost failed: {result}'}), 500

    # 4. Fix ownership + SELinux label (a clone next to a site outside the
    # labelled web root was 403 on RHEL)
    _fix_site_tree(dest_path, php_ver, webserver)

    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': True, 'staging_domain': dest_domain, 'staging_path': dest_path, 'steps': results})


@wp_bp.route('/api/wp/<domain>/push-staging', methods=['POST'])
def push_staging(domain):
    """Push staging site to live. Always creates a backup of live first."""
    if not req(): return jsonify({'ok': False}), 401
    d           = request.get_json() or {}
    staging_path = str(d.get('staging_path', '')).rstrip('/')
    live_path    = str(d.get('live_path', '')).rstrip('/')
    if not staging_path or not live_path:
        return jsonify({'ok': False, 'error': 'staging_path and live_path required'}), 400
    for p_ in (staging_path, live_path):
        if not os.path.isfile(os.path.join(p_, 'wp-config.php')):
            return jsonify({'ok': False, 'error': f'{p_} is not a WordPress installation'}), 400
    if os.path.realpath(staging_path) == os.path.realpath(live_path):
        return jsonify({'ok': False, 'error': 'Staging and live paths are the same'}), 400

    # 1. Auto-backup live site first -- and stop if it fails
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    bak = os.path.join(WP_BACKUP_DIR, f'{domain}_pre_push_{ts}.tar.gz')
    _, berr, brc = sh3(f'tar -czf {Q(bak)} -C {Q(os.path.dirname(live_path))} {Q(os.path.basename(live_path))} 2>&1', t=1800)
    if brc != 0:
        return jsonify({'ok': False, 'error': f'Backup of the live site failed, nothing was pushed: {berr[-300:]}'}), 500

    # keep the live wp-config.php (it holds the LIVE database credentials):
    # rsync --delete copied the staging one over it, so the live site then
    # ran on the staging database
    _, err, rc = sh3(
        f'rsync -a --delete --exclude=wp-content/uploads/ --exclude=/wp-config.php {Q(staging_path + "/")} {Q(live_path + "/")} 2>&1', t=1800
    )
    if rc != 0:
        return jsonify({'ok': False, 'error': f'Rsync failed: {err}'}), 500

    # 3. Sync DB if wp-cli available
    if _wp_installed():
        import tempfile
        live_url = sh(f'{_wpc()} --path={Q(live_path)} --allow-root option get siteurl 2>/dev/null')
        staging_url = sh(f'{_wpc()} --path={Q(staging_path)} --allow-root option get siteurl 2>/dev/null')
        tmpdir = tempfile.mkdtemp(prefix='vp-push-', dir=WP_BACKUP_DIR)
        dump = os.path.join(tmpdir, 'db.sql')
        try:
            _, e1, r1 = sh3(f'{_wpc()} --path={Q(staging_path)} --allow-root db export {Q(dump)} 2>&1', t=600)
            if r1 == 0:
                _, e1, r1 = sh3(f'{_wpc()} --path={Q(live_path)} --allow-root db import {Q(dump)} 2>&1', t=1800)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
        if r1 != 0:
            return jsonify({'ok': False, 'error': f'Files pushed but the database push failed: {e1[-300:]}', 'backup': os.path.basename(bak)}), 500
        if staging_url.startswith('http') and live_url.startswith('http') and staging_url != live_url:
            sh(f'{_wpc()} --path={Q(live_path)} --allow-root search-replace {Q(staging_url)} {Q(live_url)} --all-tables-with-prefix 2>/dev/null', t=600)

    # 4. Fix ownership
    _fix_site_tree(live_path, _site_php_of(domain))

    panel_cache.invalidate('wp_sites')
    return jsonify({'ok': True, 'backup': os.path.basename(bak), 'message': 'Staging pushed to live'})


# --- Delete site ----------------------------------------------------------------

_SYSTEM_DB_USERS = {'root', 'mysql', 'mariadb.sys', 'debian-sys-maint', 'mysql.sys', 'mysql.session', 'mysql.infoschema'}


@wp_bp.route('/api/wp/<domain>', methods=['DELETE'])
def delete_site(domain):
    if not req(): return jsonify({'ok': False}), 401
    d    = request.get_json() or {}
    path = str(d.get('path') or _default_wp_path(domain)).rstrip('/')
    delete_db = d.get('delete_db', True)
    webserver = d.get('webserver', '') or None

    # rm -rf target: must be a WordPress folder below a web root (the guard
    # already rejected system directories and web roots themselves)
    if os.path.exists(path) and not os.path.isfile(os.path.join(path, 'wp-config.php')):
        return jsonify({'ok': False, 'error': f'{path} is not a WordPress installation -- nothing deleted'}), 400

    # Drop DB
    if delete_db and os.path.exists(f'{path}/wp-config.php'):
        cfg = open(f'{path}/wp-config.php').read()
        db_m = re.search(r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]", cfg)
        user_m = re.search(r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]", cfg)
        if db_m and db_m.group(1) not in ('mysql', 'information_schema', 'performance_schema', 'sys'):
            _mysql_cmd(f"DROP DATABASE IF EXISTS `{db_m.group(1).replace('`', '')}`;")
        # never drop root or another system account a site was (mis)configured with
        if user_m and user_m.group(1) not in _SYSTEM_DB_USERS:
            _mysql_cmd(f"DROP USER IF EXISTS '{user_m.group(1).replace(chr(39), '')}'@'localhost';")

    # Remove files
    try: shutil.rmtree(path)
    except: pass

    # Remove vhost (of the web server that really serves the site)
    try:
        from panel.routes.websites_core import _find_site_config, is_valid_domain
        if is_valid_domain(domain):
            ws_real = _find_site_config(domain)[1]
            if ws_real:
                webserver = ws_real
    except Exception:
        pass
    if webserver:
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
    return jsonify({'ok': ok, 'version': sh(f'{_wpc()} --version --allow-root 2>/dev/null')})

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
    return jsonify({'ok': True, 'versions': _available_php(_detect_webserver())})

@wp_bp.route('/api/wp/db-engines')
def db_engines():
    if not req(): return jsonify({'ok': False}), 401
    return jsonify({'ok': True, 'engines': _available_db()})
