from flask import Blueprint, jsonify, request, session
import os, re, subprocess, shlex, shutil
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

try:
    from panel.routes import os_utils as _ou
except ImportError:
    import os_utils as _ou
try:
    from panel.routes.php import php_layout, installed_php_layouts, php_svc_status
    from panel.routes.php import _system_php_ver as _php_system_ver
except ImportError:
    from php import php_layout, installed_php_layouts, php_svc_status
    from php import _system_php_ver as _php_system_ver


websites_bp = Blueprint('websites', __name__)
WEBROOT = '/www/wwwroot'
CF_CONFIG_FILE = '/opt/vortexpanel/cdn_config.json'
INTEGRITY_DIR = '/opt/vortexpanel/integrity'

# Default ownership for newly created site directories so PHP/Node processes
# (running as this user) can write configs, uploads, caches, etc.
WEB_USER  = 'www-data'
WEB_GROUP = 'www-data'


def req(): return 'user' in session


# Per-site features that currently edit nginx configs only. For a site served
# by Apache / OpenLiteSpeed / Caddy they would fail with a confusing "site not
# found", so they answer with a clear message instead (reads still work).
_NGINX_ONLY_FEATURES = {'proxy', 'redirect', 'rewrite', 'hotlink', 'limit-access', 'maintenance',
                        'http3', 'nodejs', 'env'}
_WS_LABEL = {'apache': 'Apache', 'openlitespeed': 'OpenLiteSpeed', 'caddy': 'Caddy', 'nginx': 'nginx'}

@websites_bp.before_request
def _site_guard():
    va = request.view_args or {}
    domain = va.get('domain')
    if domain is None or not request.path.startswith('/api/websites/'):
        return None
    if not is_valid_domain(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    if request.method in ('POST', 'PUT', 'DELETE'):
        parts = request.path.split('/')
        feature = parts[4] if len(parts) > 4 else ''
        accesslog = request.path.endswith('/directory/accesslog')
        if feature in _NGINX_ONLY_FEATURES or accesslog:
            try:
                ws = _find_site_config(domain)[1]
            except Exception:
                ws = None
            if ws and ws != 'nginx':
                return jsonify({'ok': False, 'error': f'This feature currently supports nginx sites only -- {domain} is served by {_WS_LABEL.get(ws, ws)}. '
                                                        'Use the Config tab to change it directly.'}), 400
    return None


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

_WEBROOT_READY = [False]


def get_webroot():
    """Where NEW sites are created: always os_utils.get_webroot()
    (/www/wwwroot), never the distro default docroot (/var/www/html,
    /usr/share/nginx/html), where a site's wp-config.php would also be
    served as http://<ip>/<domain>/wp-config.php. Existing sites keep the
    root their vhost names (list_sites() reads it).
    os_utils.get_webroot() relabels the whole tree on SELinux (semanage +
    restorecon -R) on every call, so it runs once per process here: this is
    called for every site in list_sites()."""
    if _WEBROOT_READY[0] and os.path.isdir(WEBROOT):
        return WEBROOT
    p = _ou.get_webroot()
    _WEBROOT_READY[0] = True
    return p


def reload_nginx():
    for cmd in ['systemctl reload nginx', 'nginx -s reload', 'service nginx reload', 'systemctl reload nginx.service']:
        out = sh(f'{cmd} 2>/dev/null; echo $?')
        if out.strip() == '0': break


def _account_exists(user=None, group=None):
    import pwd, grp
    try:
        if user: pwd.getpwnam(user)
        if group: grp.getgrnam(group)
        return True
    except KeyError:
        return False


def _pool_owner(lay):
    """(user, group) the PHP-FPM pool of this PHP layout runs as, read from
    its pool files (www.conf first). None when unreadable / not a real account."""
    files = [lay.get('pool')]
    pd = lay.get('pool_dir')
    if pd and os.path.isdir(pd):
        files += sorted(os.path.join(pd, f) for f in os.listdir(pd) if f.endswith('.conf'))
    for fp in files:
        if not fp or not os.path.isfile(fp):
            continue
        try:
            txt = open(fp, errors='replace').read()
        except OSError:
            continue
        mu = re.search(r'^[ \t]*user[ \t]*=[ \t]*([A-Za-z0-9_.-]+)', txt, re.M)
        if not mu:
            continue
        mg = re.search(r'^[ \t]*group[ \t]*=[ \t]*([A-Za-z0-9_.-]+)', txt, re.M)
        u = mu.group(1)
        g = mg.group(1) if mg else u
        if _account_exists(u, g):
            return u, g
        if _account_exists(u):
            return u, u if _account_exists(group=u) else 'root'
    return None


def ols_owner():
    """(user, group) OpenLiteSpeed runs its external apps as: the `user` /
    `group` of httpd_config.conf (default nobody:nogroup on Debian,
    nobody:nobody on RHEL, where there is no 'nogroup')."""
    u, g = 'nobody', ''
    try:
        txt = open('/usr/local/lsws/conf/httpd_config.conf', errors='replace').read()
        mu = re.search(r'^[ \t]*user[ \t]+(\S+)', txt, re.M)
        mg = re.search(r'^[ \t]*group[ \t]+(\S+)', txt, re.M)
        if mu and _account_exists(mu.group(1)): u = mu.group(1)
        if mg and _account_exists(group=mg.group(1)): g = mg.group(1)
    except OSError:
        pass
    if not g:
        g = 'nogroup' if _account_exists(group='nogroup') else 'nobody'
    return u, g


def web_owner_group(php=None, webserver=None):
    """(user, group) that must own a site's files so PHP can write them:
    the user the site's PHP-FPM pool really runs as (RHEL's php-fpm pool
    runs as 'apache' even when nginx is the web server -- chowning to nginx
    left WordPress unable to write uploads / install plugins). Files are
    not chmodded, so the web server keeps reading them through the usual
    644/755 modes. OpenLiteSpeed sites: the OLS external-app user."""
    if webserver == 'openlitespeed':
        return ols_owner()
    try:
        lays = []
        if php:
            lay = php_layout(str(php))
            if lay:
                lays.append(lay)
        if not lays:
            lays = installed_php_layouts()
        for lay in lays:
            own = _pool_owner(lay)
            if own:
                return own
    except Exception:
        pass
    # No PHP-FPM installed: the web server's own account.
    cands = ['www-data']
    if apache_layout() == 'rhel' and not os.path.isdir('/etc/nginx'):
        cands += ['apache', 'nginx']
    else:
        cands += ['nginx', 'apache']
    for u in cands:
        if _account_exists(u):
            return u, (u if _account_exists(group=u) else 'root')
    try:
        u = _ou.get_webserver_user()
        if _account_exists(u):
            return u, (u if _account_exists(group=u) else 'root')
    except Exception:
        pass
    return 'root', 'root'


def web_owner(php=None, webserver=None):
    """The user PHP-FPM runs as for this site's PHP (see web_owner_group)."""
    return web_owner_group(php, webserver)[0]


def selinux_web_context(path):
    """Persistent httpd_sys_rw_content_t label for a web directory (no-op
    without SELinux). Delegates to os_utils.selinux_label_path()."""
    try:
        _ou.selinux_label_path(path, writable=True)
    except Exception:
        pass


def selinux_allow_proxy():
    """nginx/httpd may not open TCP connections to a local app port (proxy_pass
    to Node/Go/Docker apps) or a DB under SELinux unless these booleans are on."""
    try:
        _ou.selinux_web_booleans(proxy=True, db=True)
    except Exception:
        pass


def ensure_web_ownership(path, php=None, webserver=None):
    """Ensure a site directory (and its contents) are owned by the account
    PHP-FPM runs as for this site, and carry the SELinux web label, so PHP
    can write configs, uploads, sessions and caches. Safe to call repeatedly."""
    try:
        u, g = web_owner_group(php, webserver)
        r = subprocess.run(['chown', '-R', f'{u}:{g}', path], capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            print(f'[VortexPanel] chown -R {u}:{g} {path} failed: {r.stderr.strip()[:300]}')
    except Exception:
        pass
    selinux_web_context(path)


def _site_php(conf_path):
    """PHP X.Y a site's vhost uses, or None (static / unknown)."""
    try:
        with open(conf_path) as f:
            v = php_ver_from_conf(f.read())
    except Exception:
        return None
    return v if re.fullmatch(r'\d+\.\d+', v or '') else None


# --- PHP socket <-> version -----------------------------------------------------
_SYSPHP = {'ts': 0.0, 'ver': ''}


def _system_php_ver_cached():
    now = time.time()
    if now - _SYSPHP['ts'] > 60:
        try:
            _SYSPHP['ver'] = _php_system_ver()
        except Exception:
            _SYSPHP['ver'] = ''
        _SYSPHP['ts'] = now
    return _SYSPHP['ver']


def php_ver_from_sock(sock):
    """PHP version X.Y served by a PHP-FPM socket path: Debian/sury
    /run/php/phpX.Y-fpm.sock, remi SCL /var/opt/remi/phpXY/run/php-fpm/*.sock,
    RHEL module stream /run/php-fpm/www.sock (the one system PHP). '' if unknown."""
    sock = (sock or '').strip()
    m = re.search(r'/opt/remi/php(\d)(\d+)/', sock)
    if m:
        return f'{m.group(1)}.{m.group(2)}'
    m = re.search(r'php(\d+\.\d+)-fpm', sock)
    if m:
        return m.group(1)
    if re.search(r'/run/php-fpm/[^/]+\.sock$', sock):
        return _system_php_ver_cached() or 'FPM'
    return ''


def php_ver_from_conf(content):
    """PHP version a vhost (nginx / Apache / Caddy / OLS) hands requests to,
    else 'Static'."""
    content = content or ''
    for pat in (r'fastcgi_pass\s+unix:([^;\s]+)', r'proxy:unix:([^|"\s]+)', r'php_fastcgi\s+unix/(\S+)'):
        for m in re.finditer(pat, content):
            v = php_ver_from_sock(m.group(1))
            if v:
                return v
    m = re.search(r'lsphp(\d)(\d+)', content)
    if m:
        return f'{m.group(1)}.{m.group(2)}'
    return 'Static'


# Top-level directories a site root must never be (or live directly in):
# create_site / set_directory chown -R the path to the web user.
_SYSTEM_DIRS = {'/', '/bin', '/boot', '/dev', '/etc', '/lib', '/lib32', '/lib64', '/libx32', '/proc',
                '/root', '/run', '/sbin', '/sys', '/usr', '/var', '/tmp', '/opt', '/home', '/srv',
                '/mnt', '/media', '/snap', '/www', '/var/www', '/var/lib', '/var/log', '/usr/local',
                '/opt/vortexpanel'}


def valid_site_path(path):
    """Return an error string, or '' when `path` is acceptable as a site
    document root: absolute, no '..', no characters that break nginx/Apache
    config syntax or shell commands, and not a system directory."""
    if not path or not path.startswith('/'):
        return 'The site path must be an absolute path'
    if '..' in path.split('/') or re.search(r'[\s;"\'`$\\{}<>|&#*?]', path):
        return 'Enter an absolute path without spaces, ".." or special characters'
    real = os.path.realpath(path).rstrip('/') or '/'
    if real in _SYSTEM_DIRS or path.rstrip('/') in _SYSTEM_DIRS:
        return f'{path} is a system directory and cannot be used as a site root'
    for d in ('/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/lib', '/boot', '/proc', '/sys', '/dev',
              '/lib', '/lib64', '/root', '/opt/vortexpanel', '/var/lib'):
        if real == d or real.startswith(d + '/'):
            return f'{path} is inside a system directory and cannot be used as a site root'
    return ''


# --- nginx vhost editing helpers ------------------------------------------------
# Shared by site stop/start and SSL enable/disable. Every change goes through
# _nginx_apply(): write -> `nginx -t` -> reload, restoring the original file if
# the test fails, so a bad edit can never take down the other sites on the
# server at the next reload.

STOP_BEGIN = '# VORTEX-STOPPED-BEGIN'
STOP_END = '# VORTEX-STOPPED-END'
SSL_BEGIN = '# VORTEX-SSL-BEGIN'
SSL_END = '# VORTEX-SSL-END'
SSL_REDIRECT_TAG = '# VORTEX-SSL-REDIRECT'


def nginx_server_blocks(content):
    """Return [(start, end)] spans of top-level `server { ... }` blocks using
    real brace counting (skipping comments and quoted strings)."""
    blocks, i, n, depth, start = [], 0, len(content), 0, None
    while i < n:
        c = content[i]
        if c == '#':
            j = content.find('\n', i)
            i = n if j == -1 else j
            continue
        if c in ('"', "'"):
            j = i + 1
            while j < n and content[j] != c:
                j += 2 if content[j] == '\\' else 1
            i = j + 1
            continue
        if depth == 0 and content.startswith('server', i) and (i == 0 or not (content[i-1].isalnum() or content[i-1] == '_')):
            k = i + 6
            while k < n and content[k] in ' \t\r\n':
                k += 1
            if k < n and content[k] == '{':
                start, depth, i = i, 1, k + 1
                continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0 and start is not None:
                blocks.append((start, i + 1))
                start = None
        i += 1
    return blocks


def nginx_test():
    out = sh('nginx -t 2>&1')
    ok = ('test is successful' in out) or ('syntax is ok' in out and 'failed' not in out.lower())
    return ok, out


def _nginx_apply(conf_path, new_content):
    """Write new_content, validate with nginx -t, reload. Restores the
    previous file and returns (False, error) if validation fails."""
    with open(conf_path) as f:
        old = f.read()
    if new_content == old:
        return True, ''
    with open(conf_path, 'w') as f:
        f.write(new_content)
    ok, out = nginx_test()
    if not ok:
        with open(conf_path, 'w') as f:
            f.write(old)
        return False, 'nginx rejected the change (restored previous config): ' + out.strip()[-600:]
    reload_nginx()
    return True, ''


def nginx_conf_file(domain):
    """Path of a site's VortexPanel nginx vhost (does not create anything)."""
    return os.path.join('/etc/nginx/vortex', f'{domain}.conf')


def nginx_insert_in_servers(content, text, at='end'):
    """Insert `text` into EVERY top-level server block of a vhost.

    The per-site feature editors used to insert into "the first server block"
    with a regex anchored on the end of the file: once HTTPS was enabled (the
    443 block sits between VortexPanel SSL markers at the end of the file)
    the anchor never matched, so proxies / hotlink rules / access rules were
    silently not added at all, and IP denies / maintenance / redirects were
    only added to the port-80 block -- HTTPS visitors bypassed them.
    at='start': right after the line holding `server {`; text must be whole
    lines ending in '\\n'.  at='end': before the block's closing brace."""
    blocks = nginx_server_blocks(content)
    if not blocks:
        return None
    out, last = [], 0
    for s, e in blocks:
        block = content[s:e]
        if at == 'start':
            i = block.find('{') + 1
            nl = block.find('\n', i)
            if nl == -1:
                block = block[:i] + '\n' + text + block[i:]
            else:
                block = block[:nl + 1] + text + block[nl + 1:]
        else:
            block = block[:-1].rstrip() + '\n' + text.rstrip('\n').lstrip('\n') + '\n}'
        out.append(content[last:s]); out.append(block); last = e
    out.append(content[last:])
    return ''.join(out)


def nginx_edit_site(domain, fn):
    """Read a site's nginx vhost, apply fn(content) -> new content (or a
    (None, error) tuple), validate with nginx -t (restoring the original on
    failure) and reload. Returns (ok, error, http_status)."""
    fp = nginx_conf_file(domain)
    if not os.path.exists(fp):
        return False, 'Site config not found', 404
    with open(fp) as f:
        content = f.read()
    res = fn(content)
    if isinstance(res, tuple):
        return False, res[1], 400
    if res is None:
        return False, 'Could not locate a server block in this site\'s config', 400
    ok, err = _nginx_apply(fp, res)
    return ok, err, (200 if ok else 400)


_STOP_PAGE = ("<!doctype html><html><head><meta charset=utf-8><title>Site stopped</title></head>"
              "<body style=font-family:system-ui,sans-serif;text-align:center;padding-top:18vh;color:#444>"
              "<h1 style=font-weight:600>This site has been stopped</h1>"
              "<p>The administrator has temporarily disabled this website.</p></body></html>")


def nginx_site_stopped(content):
    return STOP_BEGIN in content


def nginx_set_stopped(content, stopped):
    """Add/remove a server-level `return 503` stop page in every server block.
    The vhost itself stays in place (aaPanel-style) so the domain keeps
    answering with a clear page instead of falling through to whatever
    default_server happens to be - which could be a different site."""
    # always start from a clean state
    content = re.sub(r'\n[ \t]*' + re.escape(STOP_BEGIN) + r'.*?' + re.escape(STOP_END) + r'[^\n]*', '', content, flags=re.S)
    if not stopped:
        return content
    out, last = [], 0
    for s, e in nginx_server_blocks(content):
        block = content[s:e]
        m = re.search(r'\n([ \t]*)server_name[^;]*;[^\n]*', block)
        if m:
            ind = m.group(1) or '    '
            ins = (f'\n{ind}{STOP_BEGIN}\n{ind}default_type text/html;\n'
                   f"{ind}return 503 '{_STOP_PAGE}';\n{ind}{STOP_END}")
            block = block[:m.end()] + ins + block[m.end():]
        out.append(content[last:s]); out.append(block); last = e
    out.append(content[last:])
    return ''.join(out)


def _cert_days(cert_paths):
    for cp in cert_paths:
        if cp and os.path.exists(cp):
            end_str = sh(f'openssl x509 -in "{cp}" -noout -enddate 2>/dev/null')
            if end_str.startswith('notAfter='):
                try:
                    end_dt = datetime.strptime(end_str[9:].strip(), '%b %d %H:%M:%S %Y %Z')
                    return (end_dt - datetime.utcnow()).days
                except Exception:
                    pass
            return None
    return None


# --- Apache helpers -------------------------------------------------------------
# Debian/Ubuntu: /etc/apache2/sites-available + a2ensite.  RHEL family:
# /etc/httpd/conf.d (no sites-available / a2ensite / a2enmod).
APACHE_DEB_AVAIL = '/etc/apache2/sites-available'
APACHE_DEB_ENABLED = '/etc/apache2/sites-enabled'
APACHE_RHEL_DIR = '/etc/httpd/conf.d'
_APACHE_SKIP = {'000-default.conf', 'default-ssl.conf', 'ssl.conf', 'welcome.conf', 'autoindex.conf',
                'userdir.conf', 'php.conf', 'README'}


def apache_layout():
    if os.path.isdir('/etc/apache2'):
        return 'debian'
    if os.path.isdir('/etc/httpd'):
        return 'rhel'
    return ''


def apache_conf_path(domain):
    return (os.path.join(APACHE_RHEL_DIR, f'{domain}.conf') if apache_layout() == 'rhel'
            else os.path.join(APACHE_DEB_AVAIL, f'{domain}.conf'))


def apache_log_dir():
    return '/var/log/httpd' if apache_layout() == 'rhel' else '/var/log/apache2'


def apache_test():
    try:
        r = subprocess.run('apachectl configtest 2>&1 || apache2ctl configtest 2>&1', shell=True,
                           capture_output=True, text=True, timeout=30)
        out = r.stdout + r.stderr
        return ('Syntax OK' in out and 'Syntax error' not in out), out
    except Exception as e:
        return False, str(e)


def apache_reload():
    sh('systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null', t=60)


def apache_apply(conf_path, new_content):
    """Write new_content, run apachectl configtest, reload. Restores the
    previous file and returns (False, error) if the test fails."""
    with open(conf_path) as f:
        old = f.read()
    if new_content == old:
        return True, ''
    with open(conf_path, 'w') as f:
        f.write(new_content)
    ok, out = apache_test()
    if not ok:
        with open(conf_path, 'w') as f:
            f.write(old)
        return False, 'Apache rejected the change (restored previous config): ' + out.strip()[-600:]
    apache_reload()
    return True, ''


def apache_companion(fp):
    """certbot --apache keeps the HTTPS vhost in <name>-le-ssl.conf next to
    the site's own file. Returns its path when present (and, on Debian,
    enabled), else None."""
    if not fp or not fp.endswith('.conf'):
        return None
    comp = fp[:-5] + '-le-ssl.conf'
    if not os.path.isfile(comp):
        return None
    if apache_layout() == 'debian' and not os.path.exists(os.path.join(APACHE_DEB_ENABLED, os.path.basename(comp))):
        return None
    return comp


def apache_apply_many(changes):
    """apache_apply() for several files at once: [(path, new_content)].
    Writes all, runs one configtest, restores every file if it fails."""
    olds = []
    for p, new in changes:
        with open(p) as f:
            olds.append((p, f.read()))
    if all(new == old for (_, new), (_, old) in zip(changes, olds)):
        return True, ''
    for p, new in changes:
        with open(p, 'w') as f:
            f.write(new)
    ok, out = apache_test()
    if not ok:
        for p, old in olds:
            with open(p, 'w') as f:
                f.write(old)
        return False, 'Apache rejected the change (restored previous config): ' + out.strip()[-600:]
    apache_reload()
    return True, ''


def apache_edit_site(fp, fn):
    """Apply fn(content) to a site's Apache file AND its certbot -le-ssl.conf
    companion (so HTTPS gets the same change), validated together."""
    changes = []
    for p in [fp, apache_companion(fp)]:
        if not p:
            continue
        with open(p) as f:
            changes.append((p, fn(f.read())))
    return apache_apply_many(changes)


def apache_set_stopped(content, stopped):
    """Apache equivalent of nginx_set_stopped(): a marked block in every
    VirtualHost answering 503 with a "site stopped" page."""
    content = re.sub(r'\n[ \t]*' + re.escape(STOP_BEGIN) + r'.*?' + re.escape(STOP_END) + r'[^\n]*', '', content, flags=re.S)
    if not stopped:
        return content
    def add(m):
        block = m.group(0)
        sn = re.search(r'\n([ \t]*)ServerName[^\n]*', block)
        if not sn:
            return block
        ind = sn.group(1) or '    '
        # mod_alias (loaded by default on Debian and RHEL) rather than
        # mod_rewrite, which is not enabled on a stock Debian/Ubuntu Apache
        # and may be absent from a trimmed RHEL httpd -- `RewriteEngine` then
        # made configtest fail and Stop always errored.
        ins = (f'\n{ind}{STOP_BEGIN}\n{ind}ErrorDocument 503 "<h1>This site has been stopped</h1><p>The administrator has temporarily disabled this website.</p>"\n'
               f'{ind}Redirect 503 /\n{ind}{STOP_END}')
        return block[:sn.end()] + ins + block[sn.end():]
    return re.sub(r'<VirtualHost\s+[^>]*>.*?</VirtualHost>', add, content, flags=re.S | re.I)


def _apache_site(fp, fname):
    try:
        with open(fp) as fh:
            content = fh.read()
    except Exception:
        return None
    if '<VirtualHost' not in content:
        return None
    m = re.search(r'^\s*ServerName\s+(\S+)', content, re.M)
    if not m:
        return None
    domain = m.group(1).strip().split(':')[0].lower()
    root_m = re.search(r'^\s*DocumentRoot\s+"?([^"\n]+?)"?\s*$', content, re.M)
    php_v = php_ver_from_conf(content)
    certs = re.findall(r'^\s*SSLCertificateFile\s+"?([^"\s]+)', content, re.M)
    # certbot --apache puts HTTPS in a companion <domain>-le-ssl.conf
    companion = os.path.join(os.path.dirname(fp), fname.replace('.conf', '') + '-le-ssl.conf')
    if os.path.exists(companion):
        try:
            certs += re.findall(r'^\s*SSLCertificateFile\s+"?([^"\s]+)', open(companion).read(), re.M)
        except Exception:
            pass
    if apache_layout() == 'debian':
        enabled = os.path.exists(os.path.join(APACHE_DEB_ENABLED, fname))
    else:
        enabled = True
    enabled = enabled and STOP_BEGIN not in content
    return {'domain': domain, 'ssl': bool(certs), 'ssl_days': _cert_days(certs) if certs else None,
            'php': php_v, 'enabled': enabled,
            'path': root_m.group(1).strip().rstrip('/') if root_m else f'{get_webroot()}/{domain}',
            'conf_file': fname, 'conf_path': fp, 'waf_enabled': False, 'webserver': 'apache'}


def _list_apache_sites():
    out = []
    lay = apache_layout()
    d = APACHE_DEB_AVAIL if lay == 'debian' else (APACHE_RHEL_DIR if lay == 'rhel' else '')
    if not d or not os.path.isdir(d):
        return out
    for f in sorted(os.listdir(d)):
        if f in _APACHE_SKIP or not f.endswith('.conf') or f.endswith('-le-ssl.conf'):
            continue
        fp = os.path.join(d, f)
        if os.path.isfile(fp):
            site = _apache_site(fp, f)
            if site:
                out.append(site)
    return out


def _list_ols_sites():
    out = []
    base = '/usr/local/lsws/conf/vhosts'
    if not os.path.isdir(base):
        return out
    for name in sorted(os.listdir(base)):
        fp = os.path.join(base, name, 'vhconf.conf')
        if name == 'Example' or not os.path.isfile(fp):
            continue
        try:
            content = open(fp).read()
        except Exception:
            continue
        dom_m = re.search(r'^\s*vhDomain\s+(\S+)', content, re.M)
        root_m = re.search(r'^\s*docRoot\s+(\S+)', content, re.M)
        php_m = re.search(r'lsphp(\d)(\d+)', content)
        certs = re.findall(r'^\s*certFile\s+(\S+)', content, re.M)
        domain = (dom_m.group(1) if dom_m else name).lower()
        out.append({'domain': domain, 'ssl': bool(certs), 'ssl_days': _cert_days(certs) if certs else None,
                    'php': f'{php_m.group(1)}.{php_m.group(2)}' if php_m else 'Static', 'enabled': True,
                    'path': (root_m.group(1).replace('$VH_ROOT', os.path.join(base, name)).rstrip('/')
                             if root_m else f'{get_webroot()}/{domain}'),
                    'conf_file': 'vhconf.conf', 'conf_path': fp, 'waf_enabled': False, 'webserver': 'openlitespeed'})
    return out


def _list_caddy_sites():
    out = []
    base = '/etc/caddy/sites'
    if not os.path.isdir(base):
        return out
    for f in sorted(os.listdir(base)):
        if not (f.endswith('.caddy') or f.endswith('.conf')):
            continue
        fp = os.path.join(base, f)
        try:
            content = open(fp).read()
        except Exception:
            continue
        domain = f.rsplit('.', 1)[0].lower()
        root_m = re.search(r'^\s*root\s+\*\s+(\S+)', content, re.M)
        # Caddy obtains and renews certificates by itself for public domains.
        auto_https = not domain.startswith(':') and not domain.startswith('http://')
        out.append({'domain': domain, 'ssl': auto_https, 'ssl_days': None,
                    'php': php_ver_from_conf(content), 'enabled': True,
                    'path': root_m.group(1).rstrip('/') if root_m else f'{get_webroot()}/{domain}',
                    'conf_file': f, 'conf_path': fp,
                    'waf_enabled': ('waf {' in content or 'waf{' in content), 'webserver': 'caddy'})
    return out


def _list_nginx_sites():
    sites = []
    if not os.path.isdir('/etc/nginx'):
        return sites   # never create /etc/nginx/vortex on a server without nginx
    avail, enabled = get_nginx_dirs()
    for f in sorted(os.listdir(avail)):
        fp = os.path.join(avail, f)
        if not os.path.isfile(fp): continue
        try:
            with open(fp) as fh: content = fh.read()
        except Exception: continue
        domains = re.findall(r'server_name\s+([^;]+);', content)
        domain = domains[0].strip().split()[0] if domains else f.replace('.conf','')
        ssl    = 'ssl_certificate' in content
        php_v  = php_ver_from_conf(content)
        enabled_path = os.path.join(enabled, f)
        is_enabled = (os.path.exists(enabled_path) or avail == enabled) and not nginx_site_stopped(content)
        path_m = re.search(r'root\s+([^;]+);', content)
        path   = path_m.group(1).strip() if path_m else f'{get_webroot()}/{domain}'
        ssl_days = _cert_days([f'/etc/nginx/ssl/{domain}/fullchain.pem', f'/etc/letsencrypt/live/{domain}/fullchain.pem']) if ssl else None
        waf_enabled = ('waf {' in content or 'waf{' in content)
        sites.append({'domain':domain,'ssl':ssl,'ssl_days':ssl_days,'php':php_v,'enabled':is_enabled,'path':path,
                      'conf_file':f,'conf_path':fp,'waf_enabled':waf_enabled,'webserver':'nginx'})
    return sites


def list_sites():
    """Every site VortexPanel can manage, from whichever web server(s) are on
    this server. Previously only nginx vhosts were read, so a site created
    while Apache (or OpenLiteSpeed / Caddy) was the web server was written
    correctly and served, but never appeared in Websites."""
    sites, seen = [], set()
    for fn in (_list_nginx_sites, _list_apache_sites, _list_ols_sites, _list_caddy_sites):
        try:
            for st in fn():
                if st['domain'] in seen:
                    continue
                seen.add(st['domain'])
                sites.append(st)
        except Exception:
            pass
    return sites


def site_webserver(domain):
    fp, ws = _find_site_config(domain)
    return ws


def _get_site_path(domain):
    for s in list_sites():
        if s['domain'] == domain:
            return s['path']
    return os.path.join(get_webroot(), domain)


@websites_bp.route('/api/websites/php-versions')
def get_php_versions():
    if not req(): return jsonify({'ok':False}), 401
    versions = []
    # Debian/sury, remi SCL and the RHEL module-stream PHP (`which phpX.Y`
    # found nothing on RHEL, so no PHP version was offered there).
    for lay in installed_php_layouts():
        sock = php_fpm_socket(lay['ver']) or lay['sock']
        versions.append({'version':lay['ver'],'active':os.path.exists(sock),'sock':sock})
    return jsonify({'ok':True,'versions':versions})


@websites_bp.route('/api/websites')
def get_sites():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, 'sites':list_sites(), 'webroot':get_webroot()})


@websites_bp.route('/api/websites/<domain>/status', methods=['POST'])
def set_site_status(domain):
    """Stop / start a site. Stopping keeps the vhost but answers every
    request with a 503 "site stopped" page; starting removes it again."""
    if not req(): return jsonify({'ok':False}), 401
    if not is_valid_domain(domain):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400
    enabled = bool((request.get_json() or {}).get('enabled'))
    fp, webserver = _find_site_config(domain)
    if not fp:
        return jsonify({'ok':False,'error':f'No config found for {domain}'}), 404
    if webserver == 'apache':
        if apache_layout() == 'debian':
            if enabled and not os.path.exists(os.path.join(APACHE_DEB_ENABLED, os.path.basename(fp))):
                sh(f'a2ensite {shlex.quote(os.path.basename(fp))} 2>/dev/null')
        # the certbot -le-ssl.conf companion is stopped too, otherwise the
        # site kept answering normally over HTTPS
        ok, err = apache_edit_site(fp, lambda c: apache_set_stopped(c, stopped=not enabled))
        if not ok:
            return jsonify({'ok':False,'error':err}), 500
        return jsonify({'ok':True,'enabled':enabled})
    if webserver != 'nginx':
        return jsonify({'ok':False,'error':f'Stopping a site is currently supported for nginx and Apache sites only (this site uses {webserver})'}), 400
    with open(fp) as f:
        content = f.read()
    new = nginx_set_stopped(content, stopped=not enabled)
    ok, err = _nginx_apply(fp, new)
    if not ok:
        return jsonify({'ok':False,'error':err}), 500
    return jsonify({'ok':True,'enabled':enabled})


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
    path = (path or f'{get_webroot()}/{domain}').strip().rstrip('/')
    php = str(php or '8.3').strip()
    if not domain:
        return False, {'error': 'Domain required'}
    if not is_valid_domain(domain):
        return False, {'error': 'Invalid domain name'}
    perr = valid_site_path(path)
    if perr:
        return False, {'error': perr}
    if not re.fullmatch(r'\d+\.\d+', php):
        php = '8.3'
    # Never overwrite an existing site: _write_vhost() replaced the existing
    # vhost (losing its SSL / proxy / rewrite edits) and, when the new config
    # failed its test, deleted the existing site's config file outright.
    if _find_site_config(domain)[0]:
        return False, {'error': f'A site for {domain} already exists'}

    from panel.routes.wp_toolkit import _write_vhost, _detect_webserver
    webserver = _detect_webserver()
    if not webserver:
        return False, {'error': 'No web server is installed. Install Nginx, Apache2, OpenLiteSpeed, or Caddy from the App Store first.'}
    if webserver != 'openlitespeed' and not php_layout(php):
        # e.g. the 8.3 default on a RHEL box whose module-stream PHP is 8.2:
        # the vhost pointed at a socket that never exists (502 for .php)
        lays = installed_php_layouts()
        if lays:
            php = lays[0]['ver']

    os.makedirs(path, exist_ok=True)
    idx = os.path.join(path, 'index.html')
    if not os.path.exists(idx):
        with open(idx, 'w') as f:
            f.write(f'<!DOCTYPE html><html><body><h1>Welcome to {domain}</h1><p>VortexPanel - site created successfully.</p></body></html>')

    ensure_web_ownership(path, php, webserver)

    ok, result = _write_vhost(domain, path, php, webserver)
    if not ok:
        return False, {'error': result}
    return True, {'domain': domain, 'path': path, 'webserver': webserver, 'php': php}


@websites_bp.route('/api/websites', methods=['POST'])
def create_site():
    if not req(): return jsonify({'ok':False}), 401
    d      = request.get_json() or {}
    domain = d.get('domain','').strip().lower()
    path   = (d.get('path') or f'{get_webroot()}/{domain}').strip()
    php    = d.get('php','8.3')
    if not domain: return jsonify({'ok':False,'error':'Domain required'}), 400

    ok, result = create_site_core(domain, path, php)
    if not ok:
        err = result.get('error', '')
        return jsonify({'ok': False, **result}), (500 if 'config error' in err or 'registration error' in err else 400)

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
            import secrets as _secrets, string as _string
            # random suffix: the old 'u_<first label>' collided with an existing
            # user (CREATE USER IF NOT EXISTS kept its old password, so the
            # password shown to the admin did not work)
            db_user = ('u_' + re.sub(r'[^a-zA-Z0-9_]', '', domain.split('.')[0]))[:11] + '_' + \
                ''.join(_secrets.choice(_string.ascii_lowercase + _string.digits) for _ in range(4))
            db_pass = ''.join(_secrets.choice(_string.ascii_letters + _string.digits) for _ in range(20))
            out, err = mysql_cmd(f"SHOW DATABASES LIKE '{db_name}';")
            if not err and db_name in (out or '').split():
                warnings.append(f'Database not created: a database named {db_name} already exists')
            else:
                _, err = mysql_cmd(f'CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;')
                if not err:
                    _, err = mysql_cmd(f"CREATE USER '{db_user}'@'localhost' IDENTIFIED BY '{_sql_escape(db_pass)}';")
                if not err:
                    _, err = mysql_cmd(f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'localhost'; FLUSH PRIVILEGES;")
                if err:
                    warnings.append(f'Database not created: {err}')
                else:
                    result['db_name'] = db_name
                    result['db_user'] = db_user
                    result['db_pass'] = db_pass
        except Exception as e:
            warnings.append(f'Database not created: {e}')

    if d.get('createFtp'):
        try:
            from panel.routes.ftp import is_ftp_installed, create_ftp_account
            if not is_ftp_installed():
                warnings.append('FTP account not created: no FTP server (Pure-FTPd/ProFTPD) is installed - install one from the App Store first')
            else:
                import secrets as _secrets, string as _string
                ftp_user = (re.sub(r'[^a-z0-9_-]', '', domain.split('.')[0])[:16] + '_' +
                            re.sub(r'[^a-z0-9_]', '', domain.split('.')[-1])[:8])
                if not re.match(r'^[a-z_]', ftp_user):
                    ftp_user = 'ftp_' + ftp_user
                ftp_user = ftp_user[:32]
                ftp_pass = ''.join(_secrets.choice(_string.ascii_letters + _string.digits) for _ in range(20))
                # Same code path as the FTP page: Pure-FTPd virtual user with
                # PureDB auth enabled (ftp._ensure_puredb_enabled: it was off on
                # Debian/RHEL, so the shown credentials never worked), passive
                # ports + firewall, ftpd_full_access on SELinux; ProFTPD/vsftpd
                # get a nologin system account listed in /etc/shells.
                code, res = create_ftp_account(ftp_user, ftp_pass, result.get('path') or path)
                if not res.get('ok'):
                    warnings.append('FTP account not created: ' + str(res.get('error', 'unknown error')))
                else:
                    result['ftp_user'] = ftp_user
                    result['ftp_pass'] = ftp_pass
                    if res.get('warning'):
                        warnings.append(res['warning'])
        except Exception as e:
            warnings.append(f'FTP account not created: {e}')

    if warnings:
        result['warnings'] = warnings
    return jsonify({'ok': True, **result})


@websites_bp.route('/api/websites/<domain>', methods=['DELETE'])
def delete_site(domain):
    """Remove a site's vhost from whichever web server serves it (previously
    only nginx files were removed, so Apache/OLS/Caddy sites could not be
    deleted). The site's files are kept."""
    if not req(): return jsonify({'ok':False}), 401
    if not is_valid_domain(domain):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400
    fp, ws = _find_site_config(domain)
    if not fp:
        return jsonify({'ok':False,'error':f'No config found for {domain}'}), 404
    site_path = _get_site_path(domain)
    if ws and ws != 'nginx':
        from panel.routes.wp_toolkit import _delete_vhost
        _delete_vhost(domain, ws)
    elif os.path.isdir('/etc/nginx'):
        avail, enabled_dir = get_nginx_dirs()
        for d in [avail, enabled_dir]:
            for f in [f'{domain}.conf', domain]:
                p = os.path.join(d, f)
                try: os.unlink(p)
                except: pass
        reload_nginx()
    removed = _cleanup_site_runtime(domain)
    # Communicated explicitly: deleting a site removes its web-server config
    # and the panel-managed runtime pieces above, never user data.
    kept = [f'site files in {site_path}']
    logs = [p for p in (f'/var/log/nginx/{domain}.access.log', f'{apache_log_dir()}/{domain}.access.log',
                        f'/var/log/openlitespeed/{domain}.access_log', f'/var/log/caddy/{domain}.log') if os.path.exists(p)]
    if logs:
        kept.append('access/error logs (' + ', '.join(os.path.dirname(p) for p in logs) + ')')
    for cdir in (f'/etc/letsencrypt/live/{domain}', f'/etc/nginx/ssl/{domain}', f'/etc/ssl/vortexpanel/{domain}'):
        if os.path.isdir(cdir):
            kept.append(f'SSL certificate in {cdir}' + (' (still auto-renewed; remove with: certbot delete --cert-name '
                                                       f'{domain})' if 'letsencrypt' in cdir else ''))
    kept.append('any databases / FTP accounts created for the site (Databases / FTP pages)')
    return jsonify({'ok':True, 'removed':removed, 'kept':kept})


def _cleanup_site_runtime(domain):
    """Remove panel-managed pieces that keep running or keep referencing a
    deleted site: its PM2 app (kept listening on its port forever), the WP
    Toolkit system-cron file, the per-site Fail2ban jail/filter, the
    Limit-Access htpasswd files, App-Runner metadata and the integrity
    baseline. Returns a list of what was removed."""
    removed = []
    pm2_name = domain.replace('.', '_')
    meta = f'/opt/vortexpanel/node_env/{domain}.json'
    if os.path.exists(meta) or os.path.isdir(f'/opt/vortexpanel/node_env/{domain}'):
        if shutil.which('pm2'):
            sh(f'pm2 delete {shlex.quote(pm2_name)} 2>/dev/null; pm2 save 2>/dev/null', t=30)
        try: os.unlink(meta)
        except OSError: pass
        shutil.rmtree(f'/opt/vortexpanel/node_env/{domain}', ignore_errors=True)
        removed.append('App Runner process and settings')
    cron = f'/etc/cron.d/vortex-wp-{domain.replace(".", "_")}'
    if os.path.exists(cron):
        try: os.unlink(cron); removed.append('WordPress system cron')
        except OSError: pass
    safe_site = re.sub(r'[^a-zA-Z0-9_-]', '', domain.replace('.', '_'))[:60]
    jail = f'/etc/fail2ban/jail.d/vortex-site-{safe_site}.conf'
    if os.path.exists(jail):
        for p in (jail, f'/etc/fail2ban/filter.d/vortex-site-{safe_site}.conf'):
            try: os.unlink(p)
            except OSError: pass
        sh('fail2ban-client reload 2>/dev/null', t=30)
        removed.append('Fail2ban site jail')
    htdir = '/etc/nginx/htpasswd'
    if os.path.isdir(htdir):
        for f in os.listdir(htdir):
            if f.startswith(domain + '_'):
                try: os.unlink(os.path.join(htdir, f))
                except OSError: pass
    base = os.path.join(INTEGRITY_DIR, domain + '.json')
    if os.path.exists(base):
        try: os.unlink(base)
        except OSError: pass
    return removed


def _find_site_config(domain):
    """Locate a site's real config file regardless of which webserver it
    was created under. Returns (path, webserver) or (None, None).

    Previously get_config()/save_config() only ever checked nginx's path
    (/etc/nginx/vortex/{domain}.conf) - confirmed via GitHub issue #14 that
    this meant OpenLiteSpeed sites (config at a completely different path
    and format) always hit a 404, and Apache/Caddy sites had the identical
    problem despite not being reported yet.
    """
    if not is_valid_domain(domain):
        return None, None
    candidates = [
        (os.path.join('/etc/nginx/vortex', f'{domain}.conf'), 'nginx'),
        (os.path.join(APACHE_DEB_AVAIL, f'{domain}.conf'), 'apache'),
        (os.path.join(APACHE_RHEL_DIR, f'{domain}.conf'), 'apache'),
        (os.path.join(f'/usr/local/lsws/conf/vhosts/{domain}', 'vhconf.conf'), 'openlitespeed'),
        # _write_vhost() writes Caddy sites as .caddy -- the old .conf-only
        # lookup meant Caddy sites never had a Config tab either.
        (os.path.join('/etc/caddy/sites', f'{domain}.caddy'), 'caddy'),
        (os.path.join('/etc/caddy/sites', f'{domain}.conf'), 'caddy'),
    ]
    for path, ws in candidates:
        if os.path.exists(path):
            return path, ws
    # A vhost whose file name differs from its ServerName / vhDomain
    for st in list_sites():
        if st['domain'] == domain and st.get('conf_path'):
            return st['conf_path'], st['webserver']
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
    """Save a site's config. Every web server's own config test runs first
    and the previous file is restored if it fails (previously a broken nginx
    or Apache config was left on disk, taking the web server down at its
    next restart)."""
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    # The Directory tab ("Save" root) and the Default Document tab send
    # {action:'set_root'|'set_index'} to this endpoint. They were treated as a
    # config save with no content, which wrote an EMPTY file over the site's
    # vhost -- nginx -t / configtest accept an empty file, so the site
    # silently vanished from the web server.
    action = d.get('action')
    if action == 'set_root':
        return set_directory(domain)
    if action == 'set_index':
        return _set_index(domain, d.get('indexes', ''))
    if action:
        return jsonify({'ok':False,'error':f'Unknown action: {action}'}), 400
    content = d.get('content', '')
    if not isinstance(content, str) or not content.strip():
        return jsonify({'ok':False,'error':'Refusing to save an empty config (delete the site instead)'}), 400
    fp, webserver = _find_site_config(domain)
    if not fp:
        return jsonify({'ok':False, 'error':f'No config found for {domain} under any supported web server'}), 404
    if webserver == 'nginx':
        ok, err = _nginx_apply(fp, content)
    elif webserver == 'apache':
        ok, err = apache_apply(fp, content)
    else:
        with open(fp) as f: old = f.read()
        with open(fp, 'w') as f: f.write(content)
        ok, err = True, ''
        if webserver == 'caddy':
            r = subprocess.run('caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1', shell=True,
                               capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                with open(fp, 'w') as f: f.write(old)
                ok, err = False, 'Caddy rejected the change (restored previous config): ' + (r.stdout + r.stderr).strip()[-600:]
            else:
                sh('systemctl reload caddy 2>/dev/null')
        elif webserver == 'openlitespeed':
            sh('/usr/local/lsws/bin/lswsctrl restart 2>/dev/null || systemctl restart lsws 2>/dev/null', t=60)
    if not ok:
        return jsonify({'ok':False, 'error':err}), 400
    return jsonify({'ok':True})


def _set_index(domain, indexes):
    """Default Document tab: set the site's index file list."""
    names = [x for x in re.split(r'[\s,]+', str(indexes or '')) if x]
    if not names:
        return jsonify({'ok':False,'error':'Enter at least one file name'}), 400
    if any(not re.fullmatch(r'[A-Za-z0-9._-]+', n) or n in ('.', '..') for n in names):
        return jsonify({'ok':False,'error':'File names may contain only letters, digits, ".", "_" and "-"'}), 400
    fp, ws = _find_site_config(domain)
    if not fp:
        return jsonify({'ok':False,'error':'Site not found'}), 404
    line = ' '.join(names)
    if ws == 'nginx':
        def fn(c):
            if re.search(r'^[ \t]*index\s+[^;]*;', c, re.M):
                return re.sub(r'^([ \t]*)index\s+[^;]*;', lambda m: f'{m.group(1)}index {line};', c, flags=re.M)
            return nginx_insert_in_servers(c, f'    index {line};\n', at='start')
        ok, err, code = nginx_edit_site(domain, fn)
        return jsonify({'ok':ok, 'error':err} if not ok else {'ok':True}), (200 if ok else code)
    if ws == 'apache':
        def fn(c):
            if re.search(r'^[ \t]*DirectoryIndex\s', c, re.M):
                return re.sub(r'^([ \t]*)DirectoryIndex\s[^\n]*', lambda m: f'{m.group(1)}DirectoryIndex {line}', c, flags=re.M)
            return re.sub(r'^([ \t]*)(DocumentRoot\s[^\n]*)', lambda m: f'{m.group(1)}{m.group(2)}\n{m.group(1)}DirectoryIndex {line}', c, flags=re.M)
        ok, err = apache_edit_site(fp, fn)
        return jsonify({'ok':ok, 'error':err} if not ok else {'ok':True}), (200 if ok else 400)
    return jsonify({'ok':False,'error':f'Change the default document of this {_WS_LABEL.get(ws, ws)} site in the Config tab'}), 400


@websites_bp.route('/api/websites/webroot')
def webroot():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, 'path':get_webroot()})


# --- DOMAIN MANAGER -------------------------------------------------------------
@websites_bp.route('/api/websites/<domain>/domains')
def get_domains(domain):
    if not req(): return jsonify({'ok':False}), 401
    fp_ws, ws = _find_site_config(domain)
    if ws == 'apache':
        with open(fp_ws) as f: content = f.read()
        names = []
        for m in re.finditer(r'^\s*(ServerName|ServerAlias)\s+([^\n]+)', content, re.M):
            for n in m.group(2).split():
                if n not in names: names.append(n)
        return jsonify({'ok':True,'domains':[{'domain':n,'port':'80'} for n in names]})
    if ws and ws != 'nginx':
        return jsonify({'ok':True,'domains':[{'domain':domain,'port':'80'}]})
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


def _domain_in_use(name, own_files):
    """Return the config file of ANOTHER site that already answers for
    `name` (nginx server_name / Apache ServerName|ServerAlias), else ''."""
    files = []
    for d in ('/etc/nginx/vortex', APACHE_DEB_AVAIL, APACHE_RHEL_DIR):
        if os.path.isdir(d):
            files += [os.path.join(d, f) for f in os.listdir(d) if f.endswith('.conf')]
    own = {os.path.realpath(p) for p in own_files if p}
    for p in files:
        if os.path.realpath(p) in own:
            continue
        try:
            c = open(p).read()
        except Exception:
            continue
        toks = []
        for m in re.finditer(r'server_name\s+([^;]+);', c):
            toks += m.group(1).split()
        for m in re.finditer(r'^\s*Server(?:Name|Alias)\s+([^\n]+)', c, re.M):
            toks += [t.split(':')[0] for t in m.group(1).split()]
        if name in [t.lower() for t in toks]:
            return p
    return ''


@websites_bp.route('/api/websites/<domain>/domains', methods=['POST'])
def add_domain_binding(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    new_domain = str(d.get('domain','')).strip().lower()
    if not new_domain: return jsonify({'ok':False,'error':'Domain required'}), 400
    if ':' in new_domain:
        host, _, port = new_domain.partition(':')
        if port not in ('80', ''):
            return jsonify({'ok':False,'error':'Binding a domain on a custom port is not supported -- enter the domain name only'}), 400
        new_domain = host
    if not is_valid_domain(new_domain):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400
    fp_ws, ws = _find_site_config(domain)
    if not fp_ws:
        return jsonify({'ok':False,'error':'Site not found'}), 404
    if ws not in ('nginx', 'apache'):
        return jsonify({'ok':False,'error':f'Add domains to this {_WS_LABEL.get(ws, ws)} site in the Config tab'}), 400
    other = _domain_in_use(new_domain, [fp_ws, apache_companion(fp_ws) if ws == 'apache' else None])
    if other:
        return jsonify({'ok':False,'error':f'{new_domain} is already bound to another site ({os.path.basename(other)})'}), 400
    if ws == 'apache':
        def fn(content):
            names = []
            for m in re.finditer(r'^\s*Server(?:Name|Alias)\s+([^\n]+)', content, re.M):
                names += [t.split(':')[0].lower() for t in m.group(1).split()]
            if new_domain in names:
                return content
            if re.search(r'^[ \t]*ServerAlias\s', content, re.M):
                return re.sub(r'^([ \t]*ServerAlias[ \t]+[^\n]*)', lambda m2: m2.group(1).rstrip() + ' ' + new_domain, content, flags=re.M)
            return re.sub(r'^([ \t]*)(ServerName[ \t]+[^\n]*)', lambda m2: m2.group(1) + m2.group(2) + '\n' + m2.group(1) + 'ServerAlias ' + new_domain, content, flags=re.M)
        ok, err = apache_edit_site(fp_ws, fn)
        return jsonify({'ok':ok, 'error':err} if not ok else {'ok':True}), (200 if ok else 400)

    def fn(content):
        # add to every server_name of the site (the HTTPS block too, so the
        # new name also works over https); certbot's redirect-only blocks
        # carry the same server_name and get it as well
        def add(m):
            toks = m.group(2).split()
            if new_domain in [t.lower() for t in toks]:
                return m.group(0)
            return m.group(1) + ' '.join(toks + [new_domain]) + m.group(3)
        return re.sub(r'(server_name\s+)([^;]+)(;)', add, content)
    ok, err, code = nginx_edit_site(domain, fn)
    return jsonify({'ok':ok, 'error':err} if not ok else {'ok':True}), (200 if ok else code)


@websites_bp.route('/api/websites/<domain>/domains/<target>', methods=['DELETE'])
def remove_domain_binding(domain, target):
    if not req(): return jsonify({'ok':False}), 401
    target = (target or '').strip().lower().split(':')[0]
    if not is_valid_domain(target):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400
    if target == domain:
        return jsonify({'ok':False,'error':'The site\'s main domain cannot be removed'}), 400
    fp_ws, ws = _find_site_config(domain)
    if not fp_ws:
        return jsonify({'ok':False,'error':'Not found'}), 404
    if ws == 'apache':
        def fn(content):
            new = re.sub(r'^([ \t]*ServerAlias[ \t]+)([^\n]*)',
                         lambda m2: (m2.group(1) + ' '.join(x for x in m2.group(2).split() if x.split(':')[0].lower() != target)),
                         content, flags=re.M)
            return re.sub(r'^[ \t]*ServerAlias[ \t]*\n', '', new, flags=re.M)
        ok, err = apache_edit_site(fp_ws, fn)
        return jsonify({'ok':ok, 'error':err} if not ok else {'ok':True}), (200 if ok else 400)
    if ws != 'nginx':
        return jsonify({'ok':False,'error':f'Remove domains from this {_WS_LABEL.get(ws, ws)} site in the Config tab'}), 400

    def fn(content):
        # Only whole server_name tokens are removed. The old
        # re.sub(r'\s+' + target, '', whole_file) also deleted any matching
        # text anywhere in the file (log paths, root, a longer name ending in
        # the target such as "shop.<target>"...), corrupting the vhost, and it
        # was written without nginx -t.
        def strip(m):
            toks = [t for t in m.group(2).split() if t.split(':')[0].lower() != target]
            if not toks:
                return m.group(0)
            return m.group(1) + ' '.join(toks) + m.group(3)
        return re.sub(r'(server_name\s+)([^;]+)(;)', strip, content)
    ok, err, code = nginx_edit_site(domain, fn)
    return jsonify({'ok':ok, 'error':err} if not ok else {'ok':True}), (200 if ok else code)


# --- PHP VERSIONS FOR DOMAIN ----------------------------------------------------
@websites_bp.route('/api/websites/<domain>/php-versions')
def get_php_versions_for_domain(domain):
    if not req(): return jsonify({'ok':False}), 401
    versions = []
    for lay in installed_php_layouts():
        versions.append({'version':lay['ver'],'binary':lay['bin'],
                         'sock':php_fpm_socket(lay['ver']) or lay['sock'],'status':php_svc_status(lay)})
    fp_ws, ws = _find_site_config(domain)
    current = 'static'
    if fp_ws:
        try:
            with open(fp_ws) as f:
                v = php_ver_from_conf(f.read())
            current = 'static' if v == 'Static' else v
        except Exception:
            pass
    if ws and ws != 'nginx':
        return jsonify({'ok':True,'versions':versions,'current':current,'webserver':ws})
    return jsonify({'ok':True,'versions':versions,'current':current})


# --- PHP VERSION PER DOMAIN (set) -----------------------------------------------
@websites_bp.route('/api/websites/<domain>/php', methods=['PUT'])
def set_php_version(domain):
    if not req(): return jsonify({'ok':False}), 401
    ver = str((request.get_json() or {}).get('version','8.3'))
    if not re.match(r'^\d+\.\d+$', ver):
        return jsonify({'ok':False,'error':'Invalid PHP version'}), 400
    ok, err, sock = switch_site_php(domain, ver)
    if not ok:
        return jsonify({'ok':False,'error':err}), (404 if err == 'Site not found' else 400)
    return jsonify({'ok':True,'sock':sock})


def switch_site_php(domain, ver):
    """Point a site at PHP-FPM X.Y (nginx / Apache / Caddy), validated with
    the web server's own config test. Returns (ok, error, socket)."""
    if not re.match(r'^\d+\.\d+$', str(ver)):
        return False, 'Invalid PHP version', None
    fp_ws, ws = _find_site_config(domain)
    if not fp_ws:
        return False, 'Site not found', None
    if ws == 'openlitespeed':
        return False, 'Switch the PHP version of OpenLiteSpeed sites in the Config tab (extprocessor path lsphpXY)', None
    sock = php_fpm_socket(ver)
    if not sock:
        return False, f'PHP {ver} FPM is not running on this server (no socket found) -- install/start it first', None
    if ws == 'apache':
        with open(fp_ws) as f: content = f.read()
        if 'proxy:unix:' not in content:
            return False, 'This Apache site has no PHP-FPM handler to switch', None
        ok, err = apache_edit_site(fp_ws, lambda c: re.sub(r'proxy:unix:[^|"]+', f'proxy:unix:{sock}', c))
    elif ws == 'caddy':
        with open(fp_ws) as f: content = f.read()
        new = re.sub(r'php_fastcgi\s+unix/\S+', f'php_fastcgi unix/{sock}', content)
        with open(fp_ws, 'w') as f: f.write(new)
        r = subprocess.run('caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1', shell=True, capture_output=True, text=True, timeout=60)
        ok, err = r.returncode == 0, (r.stdout + r.stderr)[-600:]
        if ok: sh('systemctl reload caddy 2>/dev/null')
        else:
            with open(fp_ws, 'w') as f: f.write(content)
    else:
        def fn(c):
            if not re.search(r'fastcgi_pass\s+unix:[^;]+;', c):
                return (None, 'This site has no PHP handler (fastcgi_pass) to switch -- it is a static or proxied site')
            return re.sub(r'fastcgi_pass\s+unix:[^;]+;', f'fastcgi_pass unix:{sock};', c)
        ok, err, _code = nginx_edit_site(domain, fn)
    return ok, ('' if ok else err), sock


def php_fpm_socket(ver):
    """Existing PHP-FPM socket for version X.Y on Debian (ondrej/sury) or
    RHEL (remi SCL, or the single system php-fpm), else None."""
    lay = php_layout(str(ver))
    if lay:
        if os.path.exists(lay['sock']):
            return lay['sock']
        # a pool whose `listen =` was changed from the package default
        try:
            pool = open(lay['pool']).read()
            m = re.search(r'^[ \t]*listen[ \t]*=[ \t]*(/\S+)', pool, re.M)
            if m and os.path.exists(m.group(1)):
                return m.group(1)
        except OSError:
            pass
        return None
    # not a layout php.py knows: hand-built FPMs at the usual places
    for c in (f'/run/php/php{ver}-fpm.sock', f'/var/run/php/php{ver}-fpm.sock',
              f'/run/php-fpm/php{ver}-fpm.sock', f'/tmp/php{ver}-fpm.sock'):
        if os.path.exists(c):
            return c
    return None


# --- DIRECTORY ------------------------------------------------------------------
DIRECTORY_INI_MARKER = '; Added by VortexPanel Directory Protection (Anti-XSS / open_basedir)'

@websites_bp.route('/api/websites/<domain>/directory')
def get_directory(domain):
    if not req(): return jsonify({'ok':False}), 401
    root_path = get_webroot() + '/' + domain
    accesslog_off = False
    fp_ws, ws = _find_site_config(domain)
    conf_path = fp_ws if ws == 'nginx' else ''
    if ws and ws != 'nginx':
        root_path = _get_site_path(domain)
    if conf_path and os.path.exists(conf_path):
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
    return jsonify({'ok':True,'path':root_path, 'antixss':antixss, 'accesslog': not accesslog_off,
                    'indexes': _site_indexes(fp_ws, ws)})


def _site_indexes(fp, ws):
    """Current default-document list of a site, space separated (what the
    Default Doc tab edits): nginx `index`, Apache `DirectoryIndex`,
    OpenLiteSpeed `indexFiles`. Falls back to the server's built-in default."""
    try:
        with open(fp) as f:
            c = f.read()
    except Exception:
        c = ''
    if ws == 'nginx':
        m = re.search(r'^[ \t]*index\s+([^;]+);', c, re.M)
        return ' '.join(m.group(1).split()) if m else 'index.html'
    if ws == 'apache':
        m = re.search(r'^[ \t]*DirectoryIndex\s+([^\n]+)', c, re.M)
        return ' '.join(m.group(1).split()) if m else 'index.html index.php'
    if ws == 'openlitespeed':
        m = re.search(r'^[ \t]*indexFiles\s+([^\n]+)', c, re.M)
        return ' '.join(x.strip() for x in m.group(1).split(',') if x.strip()) if m else 'index.html'
    if ws == 'caddy':
        return 'index.html index.php' if 'php_fastcgi' in c else 'index.html'
    return ''


@websites_bp.route('/api/websites/<domain>/directory', methods=['PUT'])
def set_directory(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    new_path = d.get('path','').strip().rstrip('/')
    if not new_path: return jsonify({'ok':False,'error':'Path required'})
    perr = valid_site_path(new_path)
    if perr:
        return jsonify({'ok':False,'error':perr})
    fp_ws, ws = _find_site_config(domain)
    if not fp_ws:
        return jsonify({'ok':False,'error':'Config not found'})
    site_php = _site_php(fp_ws)
    if ws == 'apache':
        old_root = _get_site_path(domain)
        def fn(content):
            new = re.sub(r'^(\s*DocumentRoot\s+).*$', lambda m2: m2.group(1) + new_path, content, flags=re.M)
            return new.replace(f'<Directory {old_root}>', f'<Directory {new_path}>').replace(f'<Directory "{old_root}">', f'<Directory "{new_path}">') \
                      .replace(f'<Directory {old_root}/>', f'<Directory {new_path}/>')
        os.makedirs(new_path, exist_ok=True)
        ensure_web_ownership(new_path, site_php, ws)
        ok, err = apache_edit_site(fp_ws, fn)
        return jsonify({'ok':ok,'error':err} if not ok else {'ok':True})
    if ws != 'nginx':
        return jsonify({'ok':False,'error':'Change the root directory of this site in the Config tab'})
    with open(fp_ws) as f: content = f.read()
    m = re.search(r'^[ \t]*root\s+([^;]+);', content, re.M)
    if not m:
        return jsonify({'ok':False,'error':'This site has no root directive to change'})
    old_root = m.group(1).strip()
    os.makedirs(new_path, exist_ok=True)
    ensure_web_ownership(new_path, site_php, ws)
    # replace only the site's own root (every server block / the maintenance
    # page location share it), not unrelated roots such as an ACME
    # challenge location; validated with nginx -t and rolled back on failure
    ok, err, _code = nginx_edit_site(domain, lambda c: re.sub(r'(^[ \t]*root\s+)' + re.escape(old_root) + r'(\s*;)',
                                                               lambda m2: m2.group(1) + new_path + m2.group(2), c, flags=re.M))
    if not ok:
        return jsonify({'ok':False,'error':err})
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

    root_path = _get_site_path(domain)

    if not os.path.isdir(root_path):
        return jsonify({'ok':False, 'error': f'Site directory not found: {root_path}'}), 404

    ini_path = os.path.join(root_path, '.user.ini')

    if enabled:
        directive = f'open_basedir = "{root_path}/:/tmp/:/var/tmp/:/proc/:/dev/urandom"'
        try:
            with open(ini_path, 'w') as f:
                f.write(f'{DIRECTORY_INI_MARKER}\n{directive}\n')
            # root-owned, readable by PHP: the site itself must not be able
            # to rewrite its own open_basedir limit
            os.chmod(ini_path, 0o644)
            selinux_web_context(ini_path)
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

    ok, err = _nginx_apply(conf_path, content)
    if not ok:
        return jsonify({'ok':False, 'error': err}), 500

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
    if not is_valid_domain(domain):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400
    ws = site_webserver(domain) or 'nginx'
    if ws == 'apache':
        access_log = f'{apache_log_dir()}/{domain}.access.log'
        error_log  = f'{apache_log_dir()}/{domain}.error.log'
    elif ws == 'openlitespeed':
        access_log = f'/var/log/openlitespeed/{domain}.access_log'
        error_log  = f'/var/log/openlitespeed/{domain}.error_log'
    elif ws == 'caddy':
        access_log = f'/var/log/caddy/{domain}.log'
        error_log  = access_log
    else:
        access_log = f'/var/log/nginx/{domain}.access.log'
        error_log  = f'/var/log/nginx/{domain}.error.log'
    def read_log(p):
        if not os.path.exists(p): return 'Log file not found'
        return sh(f'tail -100 {shlex.quote(p)}') or 'Empty log'
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
    qp = shlex.quote(path)
    out = sh(f'du -sh {qp} 2>/dev/null | cut -f1', t=20)
    size_human = out.strip() if out else 'Unknown'
    # Also get byte count for sorting/comparison if needed later
    out_bytes = sh(f'du -sb {qp} 2>/dev/null | cut -f1', t=20)
    try:
        size_bytes = int(out_bytes.strip())
    except (ValueError, AttributeError):
        size_bytes = 0
    # File + folder counts (fast, no size calc)
    file_count = sh(f'find {qp} -type f 2>/dev/null | wc -l', t=15)
    dir_count  = sh(f'find {qp} -type d 2>/dev/null | wc -l', t=15)
    return jsonify({
        'ok': True, 'domain': domain, 'path': path,
        'size_human': size_human, 'size_bytes': size_bytes,
        'file_count': int(file_count.strip() or 0),
        'dir_count':  int(dir_count.strip() or 0),
    })


