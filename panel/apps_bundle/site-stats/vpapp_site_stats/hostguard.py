"""Which requests really belong to a website.

Without a catch-all server, nginx answers a request for ANY host name that points
at this server's IP with the first (default) website, and writes it to that
site's access log. Other people's domains pointed at the server (an embedded
player on itachi.tv, an old DNS record, scanners) then show up as that site's
pages and visitors.

  - vp_stats log format: the panel sites' nginx access logs get the request's host
    name as a last field (still the combined format for every other tool). The
    collector counts a request only when the host is one of the site's own names;
    the others are listed as "Other domains" so the admin can see who points here.
  - catch-all: an optional default server that closes connections for host names
    no website on this server serves (HTTP 444 / TLS handshake refused).
"""
import glob
import os
import re

from panel import appkit

APP = 'site-stats'
FORMAT_CONF = '/etc/nginx/conf.d/00-vortex-logformat.conf'
CATCHALL_CONF = '/etc/nginx/conf.d/00-vortex-catchall.conf'
FORMAT_NAME = 'vp_stats'
FORMAT_TEXT = ('# VortexPanel Website Statistics: combined log format + the request\'s host name\n'
               f"log_format {FORMAT_NAME} '$remote_addr - $remote_user [$time_local] \"$request\" '\n"
               "                 '$status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" \"$host\"';\n")
_LOG_LINE = re.compile(r'(\n[ \t]*access_log[ \t]+(/var/log/nginx/[A-Za-z0-9.*_-]+\.access\.log))[ \t]*;')


def _conf_files():
    out = []
    for pat in ('/etc/nginx/conf.d/*.conf', '/etc/nginx/sites-enabled/*', '/etc/nginx/vortex/*.conf'):
        out += [p for p in glob.glob(pat) if os.path.isfile(p)]
    return sorted(set(out))


def nginx_present():
    return os.path.isdir('/etc/nginx') and (appkit.have('nginx') or os.path.exists('/usr/sbin/nginx'))


def _nginx_test():
    rc, out, err = appkit.run(['nginx', '-t'], timeout=30)
    return rc == 0, (err or out).strip()[-400:]


def _reload():
    appkit.run(['systemctl', 'reload', 'nginx'], timeout=60)


# ---------------------------------------------------------------- site names

def site_names(site):
    """Host names one website answers to (nginx server_name / Apache ServerName and
    ServerAlias / Caddy site addresses). Empty set = unknown (nothing is filtered)."""
    names = set()
    log_bits = (f'/{site}.access.log', f'/{site}.access_log', f'/{site}.log')
    files = _conf_files()
    for d in ('/etc/apache2/sites-enabled', '/etc/httpd/conf.d', '/usr/local/lsws/conf/vhosts'):
        files += [p for p in glob.glob(d + '/**/*', recursive=True) if os.path.isfile(p)]
    for p in files:
        try:
            txt = open(p, errors='replace').read()
        except OSError:
            continue
        if not any(b in txt for b in log_bits) and os.path.basename(p) not in (f'{site}.conf', site):
            continue
        for m in re.finditer(r'server_name\s+([^;]+);', txt):
            names.update(t.lower() for t in m.group(1).split())
        for m in re.finditer(r'^\s*Server(?:Name|Alias)\s+(.+)$', txt, re.M):
            names.update(t.lower().split(':')[0] for t in m.group(1).split())
    try:
        for line in open('/etc/caddy/Caddyfile', errors='replace'):
            if site in line and line.rstrip().endswith('{'):
                names.update(t.strip(',').lower().split('://')[-1].split(':')[0] for t in line.rstrip(' {\n').split())
    except OSError:
        pass
    names.discard('_')
    names.discard('')
    return names


def host_matches(host, names):
    h = host.lower().split(':')[0].rstrip('.')
    if h in names:
        return True
    for n in names:
        if n.startswith('*.') and h.endswith(n[1:]):
            return True
        if n.startswith('.') and (h == n[1:] or h.endswith(n)):
            return True
    return False


# ------------------------------------------------------------ host in the logs

def logging_status():
    files = _conf_files()
    tagged = untagged = 0
    for p in files:
        try:
            txt = open(p, errors='replace').read()
        except OSError:
            continue
        for m in re.finditer(r'\n[ \t]*access_log[ \t]+/var/log/nginx/[A-Za-z0-9.*_-]+\.access\.log([^;]*);', txt):
            if FORMAT_NAME in m.group(1):
                tagged += 1
            else:
                untagged += 1
    return {'nginx': nginx_present(), 'format': os.path.exists(FORMAT_CONF), 'tagged': tagged, 'untagged': untagged}


def apply_logging():
    """Add the host name to every panel site's nginx access log. Tested with nginx -t;
    every file is put back when the test fails. Returns (ok, message)."""
    if not nginx_present():
        return True, 'nginx is not installed'
    with appkit.locked(APP, 'nginx-conf'):
        changed = {}
        if not os.path.exists(FORMAT_CONF):
            changed[FORMAT_CONF] = None
            with open(FORMAT_CONF, 'w') as f:
                f.write(FORMAT_TEXT)
        for p in _conf_files():
            if p == FORMAT_CONF:
                continue
            try:
                txt = open(p).read()
            except OSError:
                continue
            new = _LOG_LINE.sub(lambda m: f'{m.group(1)} {FORMAT_NAME};', txt)
            if new != txt:
                changed[p] = txt
                with open(p, 'w') as f:
                    f.write(new)
        if not changed:
            return True, 'already recording host names'
        ok, err = _nginx_test()
        if not ok:
            for p, old in changed.items():
                if old is None:
                    os.remove(p)
                else:
                    with open(p, 'w') as f:
                        f.write(old)
            return False, 'nginx rejected the change, nothing was changed: ' + err
        _reload()
        n = len([p for p in changed if p != FORMAT_CONF])
        appkit.oplog(APP, 'host names in logs', f'{n} site configuration(s) updated')
        return True, f'{n} website(s) now record the host name'


def remove_logging():
    if not nginx_present():
        return True, ''
    with appkit.locked(APP, 'nginx-conf'):
        changed = {}
        for p in _conf_files():
            if p == FORMAT_CONF:
                continue
            try:
                txt = open(p).read()
            except OSError:
                continue
            new = re.sub(r'(\n[ \t]*access_log[ \t]+/var/log/nginx/[A-Za-z0-9.*_-]+\.access\.log)[ \t]+' + FORMAT_NAME + r'[ \t]*;',
                         r'\1;', txt)
            if new != txt:
                changed[p] = txt
                with open(p, 'w') as f:
                    f.write(new)
        fmt_old = open(FORMAT_CONF).read() if os.path.exists(FORMAT_CONF) else None
        if fmt_old is not None:
            os.remove(FORMAT_CONF)
        ok, err = _nginx_test()
        if not ok:
            for p, old in changed.items():
                with open(p, 'w') as f:
                    f.write(old)
            if fmt_old is not None:
                with open(FORMAT_CONF, 'w') as f:
                    f.write(fmt_old)
            return False, err
        _reload()
        return True, 'removed'


# --------------------------------------------------------------- catch-all

STOCK_DEFAULT = '/etc/nginx/sites-enabled/default'
STOCK_AWAY = '/etc/nginx/vortex-stock-default.disabled'     # outside sites-enabled (nginx loads sites-enabled/*)


def _is_stock_default(p):
    """Debian/Ubuntu's own welcome site: the catch-all replaces it."""
    try:
        txt = open(p, errors='replace').read()
    except OSError:
        return False
    return os.path.realpath(p) == '/etc/nginx/sites-available/default' and 'root /var/www/html' in txt \
        and 'server_name _' in txt


def catchall_status():
    other = []
    for p in _conf_files():
        if p == CATCHALL_CONF or (p == STOCK_DEFAULT and _is_stock_default(p)):
            continue
        try:
            if re.search(r'listen[^;]*default_server', open(p, errors='replace').read()):
                other.append(os.path.basename(p))
        except OSError:
            pass
    return {'nginx': nginx_present(), 'on': os.path.exists(CATCHALL_CONF), 'other_default': other}


def _ipv6():
    """IPv6 listen lines in use (active lines, not the welcome site the catch-all replaces)."""
    for p in _conf_files():
        if p == STOCK_DEFAULT and _is_stock_default(p):
            continue
        try:
            if re.search(r'^[ \t]*listen[ \t]+\[::\]', open(p, errors='replace').read(), re.M):
                return True
        except OSError:
            pass
    return False


def set_catchall(on):
    """Close connections for host names no website here serves. (ok, message)"""
    if not nginx_present():
        return False, 'nginx is not installed'
    with appkit.locked(APP, 'nginx-conf'):
        if not on:
            if os.path.exists(CATCHALL_CONF):
                old = open(CATCHALL_CONF).read()
                os.remove(CATCHALL_CONF)
                stock_back = os.path.lexists(STOCK_AWAY) and not os.path.lexists(STOCK_DEFAULT)
                if stock_back:
                    os.rename(STOCK_AWAY, STOCK_DEFAULT)
                ok, err = _nginx_test()
                if not ok:
                    with open(CATCHALL_CONF, 'w') as f:
                        f.write(old)
                    if stock_back:
                        os.rename(STOCK_DEFAULT, STOCK_AWAY)
                    return False, err
                _reload()
            appkit.oplog(APP, 'unknown host names', 'allowed')
            return True, 'Unknown host names are answered by the default website again.'
        st = catchall_status()
        if st['other_default']:
            return False, ('These configurations already mark a default website (default_server): '
                           + ', '.join(st['other_default'][:5]) + '. Remove that first.')
        v6 = _ipv6()
        txt = ('# VortexPanel: requests for host names that no website on this server serves\n'
               '# are closed instead of being answered by the first website.\n'
               'server {\n    listen 80 default_server;\n' + ('    listen [::]:80 default_server;\n' if v6 else '') +
               '    server_name _;\n    access_log off;\n    return 444;\n}\n'
               'server {\n    listen 443 ssl default_server;\n' + ('    listen [::]:443 ssl default_server;\n' if v6 else '') +
               '    server_name _;\n    access_log off;\n    ssl_reject_handshake on;\n}\n')
        # the distro's welcome site is the current default: set it aside (kept, put back when turned off)
        stock = os.path.lexists(STOCK_DEFAULT) and _is_stock_default(STOCK_DEFAULT)
        if stock:
            os.rename(STOCK_DEFAULT, STOCK_AWAY)
        with open(CATCHALL_CONF, 'w') as f:
            f.write(txt)
        ok, err = _nginx_test()
        if not ok:
            os.remove(CATCHALL_CONF)
            if stock:
                os.rename(STOCK_AWAY, STOCK_DEFAULT)
            return False, 'nginx rejected the catch-all server, nothing was changed: ' + err
        _reload()
        appkit.oplog(APP, 'unknown host names', 'blocked')
        return True, 'Requests for unknown host names are now closed.'
