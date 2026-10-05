from flask import Blueprint, jsonify, request, session
import subprocess, os, re, glob

caddy_bp = Blueprint('caddy', __name__)
def req(): return 'user' in session
def sh(c, t=15):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return '', f'timed out after {t}s', 124
    except Exception as e:
        return '', str(e), 1

CADDYFILE = '/etc/caddy/Caddyfile'
CADDY_SITES_DIR = '/etc/caddy/sites'
CADDY_LOG_DIR = '/var/log/caddy'

# A site address: hostname (optionally wildcard / with port) or :port.
_DOMAIN_RE = re.compile(r'^(?:(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::\d{1,5})?|:\d{1,5})$')
_PATH_RE = re.compile(r'^/[A-Za-z0-9._/@+-]*$')
_TARGET_RE = re.compile(r'^[A-Za-z0-9._:/\[\]-]{1,200}$')

def valid_domain(d):
    return bool(d) and len(d) <= 253 and bool(_DOMAIN_RE.match(d))

def is_caddy_installed():
    import shutil
    return bool(shutil.which('caddy'))

def get_webroot():
    """The panel's web root (/www/wwwroot) -- one implementation for the
    whole panel (websites_core -> os_utils.get_webroot()). Never the distro
    default docroot: a new site there would be served from the default site too."""
    try:
        from panel.routes.websites_core import get_webroot as _gw
    except ImportError:
        from websites_core import get_webroot as _gw
    return _gw()

def reload_caddy():
    """Reload the running Caddy. Returns (ok, message). A stopped Caddy is
    not an error -- the new config is used when it starts."""
    _, _, rc = sh('systemctl is-active --quiet caddy')
    if rc != 0:
        return True, 'Caddy is not running -- the configuration is used when it starts.'
    out, err, rc = sh('systemctl reload caddy 2>&1', t=90)
    if rc != 0:
        out2, err2, rc = sh(f'caddy reload --config {CADDYFILE} --adapter caddyfile 2>&1', t=90)
        out, err = out2, err2
    if rc != 0:
        tail, _, _ = sh('journalctl -u caddy -n 8 --no-pager -o cat 2>/dev/null')
        return False, ((out + err).strip() or tail)[-800:]
    return True, ''

def validate_caddy():
    out, err, rc = sh(f'caddy validate --config {CADDYFILE} --adapter caddyfile 2>&1', t=90)
    return rc == 0, (out + err)[-1500:]

def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None

def _write(path, content):
    with open(path, 'w') as f:
        f.write(content)

def _restore(path, old):
    try:
        if old is None:
            os.remove(path)
        else:
            _write(path, old)
    except Exception:
        pass

def apply_caddy_file(path, content):
    """Write a Caddy config file, validate the whole config, reload Caddy;
    restore the previous file on any failure. Returns (ok, message)."""
    old = _read(path)
    _write(path, content)
    ok, msg = validate_caddy()
    if not ok:
        _restore(path, old)
        return False, 'Caddyfile validation failed (previous file restored): ' + msg
    ok, msg = reload_caddy()
    if not ok:
        _restore(path, old)
        reload_caddy()
        return False, 'Caddy rejected the new configuration (previous file restored): ' + msg
    return True, msg

def _blocks(content):
    """Top-level blocks of a Caddyfile: list of (address_line, start, end)
    where content[start:end] is the whole block including its braces.
    Brace matching skips quoted strings and comments."""
    # Mask comments and quoted strings (same length) so braces inside them
    # are never counted.
    chars = list(content)
    n = len(chars)
    k, in_q = 0, False
    while k < n:
        c = chars[k]
        if in_q:
            if c == '\\' and k + 1 < n:
                chars[k] = chars[k + 1] = ' '; k += 2; continue
            if c == '"':
                in_q = False
            if c != '\n':
                chars[k] = ' '
        elif c == '"':
            in_q = True; chars[k] = ' '
        elif c == '#' and (k == 0 or content[k - 1] in ' \t\n'):
            while k < n and chars[k] != '\n':
                chars[k] = ' '; k += 1
            continue
        k += 1
    masked = ''.join(chars)
    out = []
    i = 0
    while i < n:
        j = masked.find('{', i)
        if j < 0:
            break
        line_start = masked.rfind('\n', 0, j) + 1
        addr = masked[line_start:j].strip()
        depth, k = 0, j
        while k < n:
            c = masked[k]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    break
            k += 1
        end = min(k + 1, n)
        out.append((addr, line_start, end))
        i = end
    return out

def _site_info(domain_line, block, conf_path, source):
    domain = domain_line.split(',')[0].split()[0].strip() if domain_line else ''
    root_m = re.search(r'^\s*root\s+(?:\*\s+)?(\S+)', block, re.M)
    has_php   = 'php_fastcgi' in block
    has_proxy = 'reverse_proxy' in block
    has_tls   = not domain.startswith(':') and not domain.startswith('http://') and \
                ('tls' in block or (not domain.startswith('localhost') and '.' in domain))
    php_ver = ''
    if has_php:
        m = re.search(r'php(\d+\.\d+)-fpm', block) or re.search(r'/opt/remi/php(\d)(\d)', block)
        if m: php_ver = m.group(1) if m.lastindex == 1 else f'{m.group(1)}.{m.group(2)}'
    return {
        'domain':    domain,
        'path':      root_m.group(1) if root_m else '',
        'php':       php_ver or ('FPM' if has_php else 'Static'),
        'ssl':       has_tls,
        'proxy':     has_proxy,
        'type':      'php' if has_php else ('proxy' if has_proxy else 'static'),
        'conf_path': conf_path,
        'source':    source,
    }

def list_caddy_sites():
    """Sites in the main Caddyfile plus the per-site files in /etc/caddy/sites
    (Websites, Docker and Go projects write those)."""
    sites = []
    content = _read(CADDYFILE)
    if content:
        for addr, s, e in _blocks(content):
            if not addr or addr.startswith('(') or addr.startswith('import'):
                continue   # global options, snippets
            sites.append(_site_info(addr, content[s:e], CADDYFILE, 'caddyfile'))
    if os.path.isdir(CADDY_SITES_DIR):
        for fp in sorted(glob.glob(os.path.join(CADDY_SITES_DIR, '*'))):
            if not os.path.isfile(fp):
                continue
            c = _read(fp) or ''
            for addr, s, e in _blocks(c):
                if addr and not addr.startswith('('):
                    sites.append(_site_info(addr, c[s:e], fp, 'sites'))
    return sites

def _find_site(domain):
    for s in list_caddy_sites():
        if s['domain'].lower() == domain.lower():
            return s
    return None

def get_global_options():
    content = _read(CADDYFILE)
    if not content:
        return ''
    for addr, s, e in _blocks(content):
        if addr == '':
            return content[s:e].strip()[1:-1].strip()
        break
    return ''

def _prepare_log(domain):
    """Create the access log as the caddy user. `caddy validate` runs as root
    and would otherwise create it root-owned, so the caddy service could not
    open it and every reload failed with "permission denied"."""
    try:
        os.makedirs(CADDY_LOG_DIR, exist_ok=True)
        lp = os.path.join(CADDY_LOG_DIR, f'{domain}.access.log')
        if not os.path.exists(lp):
            open(lp, 'a').close()
        sh(f'id caddy >/dev/null 2>&1 && chown caddy:caddy {CADDY_LOG_DIR} {lp}')
    except Exception:
        pass

def _php_sock(ver):
    try:
        from panel.routes.php import php_layout
    except ImportError:
        from php import php_layout
    lay = php_layout(ver)
    if lay:
        if os.path.exists(lay['sock']):
            return lay['sock']
        pool = _read(lay['pool']) or ''
        m = re.search(r'^\s*listen\s*=\s*(/\S+)', pool, re.M)
        if m:
            return m.group(1)
        return lay['sock']
    return ''

@caddy_bp.route('/api/caddy/status')
def status():
    if not req(): return jsonify({'ok':False}), 401
    installed = is_caddy_installed()
    if not installed:
        return jsonify({'ok':True, 'installed':False, 'version':'', 'status':'not installed'})
    version, _, _ = sh('caddy version 2>/dev/null | head -1')
    svc_status, _, _ = sh('systemctl is-active caddy 2>/dev/null')
    return jsonify({'ok':True, 'installed':True, 'version':version, 'status':svc_status or 'inactive'})

@caddy_bp.route('/api/caddy/sites')
def list_sites():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, 'sites':list_caddy_sites(), 'webroot':get_webroot()})

@caddy_bp.route('/api/caddy/sites', methods=['POST'])
def create_site():
    if not req(): return jsonify({'ok':False}), 401
    if not is_caddy_installed():
        return jsonify({'ok':False, 'error':'Caddy is not installed. Install it via Modules first.'}), 400

    d      = request.get_json() or {}
    domain = (d.get('domain') or '').strip().lower()
    path   = ((d.get('path') or '').strip() or f"{get_webroot()}/{domain}").rstrip('/')
    php    = str(d.get('php') or 'none')     # '8.3', '8.2', 'none'
    stype  = d.get('type', 'static')  # static | php | proxy | nodejs
    proxy_target = str(d.get('proxy_target') or '').strip()

    if not domain: return jsonify({'ok':False, 'error':'Domain required'}), 400
    if not valid_domain(domain):
        return jsonify({'ok':False, 'error':'Invalid domain name'}), 400
    if stype not in ('static', 'php', 'proxy', 'nodejs'):
        return jsonify({'ok':False, 'error':'Invalid site type'}), 400
    if stype in ('static', 'php') and (not _PATH_RE.match(path) or '/../' in path + '/' or path in ('', '/')):
        return jsonify({'ok':False, 'error':'Invalid site directory'}), 400
    if stype == 'proxy' and not _TARGET_RE.match(proxy_target):
        return jsonify({'ok':False, 'error':'Invalid proxy target (example: 127.0.0.1:3000)'}), 400
    if stype == 'nodejs' and not (proxy_target.isdigit() and 0 < int(proxy_target) < 65536):
        return jsonify({'ok':False, 'error':'Invalid Node.js port'}), 400
    if _find_site(domain):
        return jsonify({'ok':False, 'error':f'{domain} already exists in the Caddy configuration'}), 409

    sock = ''
    if stype == 'php':
        if php == 'none':
            stype = 'static'
        else:
            sock = _php_sock(php)
            if not sock:
                return jsonify({'ok':False, 'error':f'PHP {php} is not installed'}), 400

    if stype in ('static', 'php'):
        created = not os.path.isdir(path)
        os.makedirs(path, exist_ok=True)
        idx = os.path.join(path, 'index.html')
        if not os.path.exists(idx) and not os.path.exists(os.path.join(path, 'index.php')):
            with open(idx,'w') as f:
                f.write(f'<!DOCTYPE html><html><body><h1>Welcome to {domain}</h1><p>Powered by Caddy + VortexPanel</p></body></html>')
        # PHP must be able to write the site (uploads, caches); SELinux label
        # so the web server may read it. An existing directory keeps its owner.
        try:
            from panel.routes.websites_core import ensure_web_ownership, selinux_web_context
            if created and stype == 'php':
                ensure_web_ownership(path, php, 'caddy')
            else:
                selinux_web_context(path)
        except Exception:
            pass
    # a non-standard listen port (site address ":8080" / "host:8080") must be
    # an http_port_t on SELinux or Caddy cannot bind it after a reboot
    mport = re.search(r':(\d{1,5})$', domain)
    if mport:
        try:
            from panel.routes.os_utils import selinux_allow_port
            selinux_allow_port(mport.group(1))
        except Exception:
            pass
    _prepare_log(domain)

    log_block = f"""    log {{
        output file {CADDY_LOG_DIR}/{domain}.access.log
    }}
"""
    if stype == 'php':
        site_block = f"""{domain} {{
    root * {path}
    encode gzip
    php_fastcgi unix/{sock}
    file_server
{log_block}}}
"""
    elif stype == 'proxy':
        site_block = f"""{domain} {{
    reverse_proxy {proxy_target} {{
        header_up Host {{host}}
        header_up X-Real-IP {{remote_host}}
    }}
{log_block}}}
"""
    elif stype == 'nodejs':
        # Caddy proxies WebSocket upgrades by itself.
        site_block = f"""{domain} {{
    reverse_proxy localhost:{proxy_target}
{log_block}}}
"""
    else:
        site_block = f"""{domain} {{
    root * {path}
    encode gzip
    file_server
{log_block}}}
"""

    content = _read(CADDYFILE)
    if content is None:
        os.makedirs(os.path.dirname(CADDYFILE), exist_ok=True)
        content = '# VortexPanel Caddyfile\n# Caddy automatically provisions HTTPS for all domains\n\n'
    ok, msg = apply_caddy_file(CADDYFILE, content.rstrip('\n') + '\n\n' + site_block)
    if not ok:
        return jsonify({'ok':False, 'error':msg}), 400
    return jsonify({'ok':True, 'domain':domain, 'path':path,
                   'note':'Caddy will automatically provision a free SSL certificate for this domain.' + (' ' + msg if msg else '')})

@caddy_bp.route('/api/caddy/sites/<domain>', methods=['DELETE'])
def delete_site(domain):
    if not req(): return jsonify({'ok':False}), 401
    domain = (domain or '').strip().lower()
    if not valid_domain(domain):
        return jsonify({'ok':False, 'error':'Invalid domain name'}), 400
    site = _find_site(domain)
    if not site:
        return jsonify({'ok':False, 'error':f'{domain} was not found in the Caddy configuration'}), 404
    path = site['conf_path']
    content = _read(path) or ''
    new = None
    for addr, s, e in _blocks(content):
        first = addr.split(',')[0].split()[0].strip().lower() if addr else ''
        if first == domain:
            new = (content[:s].rstrip('\n') + '\n\n' + content[e:].lstrip('\n')).strip('\n') + '\n'
            break
    if new is None:
        return jsonify({'ok':False, 'error':'Could not locate the site block'}), 404
    ok, msg = apply_caddy_file(path, new)
    if not ok:
        return jsonify({'ok':False, 'error':msg}), 400
    return jsonify({'ok':True})

@caddy_bp.route('/api/caddy/sites/<domain>/config')
def get_site_config(domain):
    if not req(): return jsonify({'ok':False}), 401
    site = _find_site(domain) if valid_domain((domain or '').lower()) else None
    path = site['conf_path'] if site else CADDYFILE
    content = _read(path)
    if content is None:
        return jsonify({'ok':False, 'error':'Caddyfile not found'}), 404
    return jsonify({'ok':True, 'content':content, 'path':path})

@caddy_bp.route('/api/caddy/sites/<domain>/config', methods=['PUT'])
def save_site_config(domain):
    if not req(): return jsonify({'ok':False}), 401
    content = (request.get_json() or {}).get('content','')
    if not isinstance(content, str) or not content.strip():
        return jsonify({'ok':False, 'error':'Refusing to save an empty configuration'}), 400
    site = _find_site(domain) if valid_domain((domain or '').lower()) else None
    path = site['conf_path'] if site else CADDYFILE
    ok, msg = apply_caddy_file(path, content)
    if not ok:
        return jsonify({'ok':False, 'error':msg}), 400
    return jsonify({'ok':True, 'message':msg})

@caddy_bp.route('/api/caddy/caddyfile')
def get_caddyfile():
    if not req(): return jsonify({'ok':False}), 401
    content = _read(CADDYFILE)
    return jsonify({'ok':True, 'content':content or '', 'path':CADDYFILE})

@caddy_bp.route('/api/caddy/caddyfile', methods=['PUT'])
def save_caddyfile():
    if not req(): return jsonify({'ok':False}), 401
    content = (request.get_json() or {}).get('content','')
    if not isinstance(content, str) or not content.strip():
        return jsonify({'ok':False, 'error':'Refusing to save an empty Caddyfile'}), 400
    ok, msg = apply_caddy_file(CADDYFILE, content)
    if not ok:
        return jsonify({'ok':False, 'error':msg}), 400
    return jsonify({'ok':True, 'message':msg})

@caddy_bp.route('/api/caddy/control', methods=['POST'])
def control():
    if not req(): return jsonify({'ok':False}), 401
    action = (request.get_json() or {}).get('action','status')
    if action not in ('start','stop','restart','reload'): return jsonify({'ok':False,'error':'Invalid action'}), 400
    out, err, rc = sh(f'systemctl {action} caddy 2>&1', t=90)
    status, _, _ = sh('systemctl is-active caddy 2>/dev/null')
    if rc != 0:
        return jsonify({'ok':False, 'status':status or 'inactive', 'error':(out + err)[-500:] or f'{action} failed'})
    return jsonify({'ok':True, 'status':status or 'inactive'})

@caddy_bp.route('/api/caddy/logs')
def caddy_logs():
    if not req(): return jsonify({'ok':False}), 401
    try:
        lines = max(1, min(int(request.args.get('lines', 100)), 5000))
    except (TypeError, ValueError):
        lines = 100
    out, _, _ = sh(f'journalctl -u caddy -n {lines} --no-pager 2>/dev/null')
    return jsonify({'ok':True, 'logs':out})

def caddy_cert_dirs():
    """Every Caddy certificate directory per issuer (Let's Encrypt, ZeroSSL...)."""
    out = []
    for home in ('/var/lib/caddy/.local/share/caddy', '/root/.local/share/caddy'):
        out += [d for d in glob.glob(os.path.join(home, 'certificates', '*')) if os.path.isdir(d)]
    return out

@caddy_bp.route('/api/caddy/sites/<domain>/ssl')
def ssl_info(domain):
    if not req(): return jsonify({'ok':False}), 401
    domain = (domain or '').strip().lower()
    if not valid_domain(domain):
        return jsonify({'ok':False, 'error':'Invalid domain name'}), 400
    for base in caddy_cert_dirs():
        cert_file = os.path.join(base, domain, f'{domain}.crt')
        if os.path.exists(cert_file):
            try:
                r = subprocess.run(['openssl', 'x509', '-in', cert_file, '-noout', '-dates', '-subject', '-issuer'],
                                   capture_output=True, text=True, timeout=10)
                info = r.stdout.strip()
            except Exception:
                info = ''
            return jsonify({'ok':True, 'info':info, 'path':cert_file})
    return jsonify({'ok':True, 'info':'Certificate will be provisioned automatically when domain resolves to this server.'})
