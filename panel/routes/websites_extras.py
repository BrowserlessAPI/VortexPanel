"""Website > Security & limits: force HTTPS, HSTS, HTTP/2, blocked paths,
bandwidth and connection limits, and an expiry date.

Everything except the expiry date is written into the site's nginx vhost
between #VP_EXTRAS markers (one copy per server block, so HTTP and HTTPS both
get it) and the whole edit is checked with `nginx -t` and rolled back when it
fails. The expiry date is kept in data/site_expiry.json; the backups timer
stops a site once its date has passed (panel.tasks -> run_expiry()).
"""
import json
import os
import re
import subprocess
import time

from flask import jsonify, request

try:
    from panel.routes.websites_core import (websites_bp, req, nginx_edit_site, nginx_insert_in_servers,
                                            nginx_server_blocks, is_valid_domain, nginx_conf_file,
                                            SSL_REDIRECT_TAG, SSL_BEGIN, SSL_END)
except ImportError:
    from websites_core import (websites_bp, req, nginx_edit_site, nginx_insert_in_servers,
                               nginx_server_blocks, is_valid_domain, nginx_conf_file,
                               SSL_REDIRECT_TAG, SSL_BEGIN, SSL_END)

EXPIRY_FILE = '/opt/vortexpanel/data/site_expiry.json'
LIMITS_CONF = '/etc/nginx/conf.d/vortexpanel-limits.conf'
_BLOCK_RE = re.compile(r'\n?[ \t]*#VP_EXTRAS\n.*?#VP_EXTRAS_END[^\n]*', re.S)
_JSON_RE = re.compile(r'#VP_EXTRAS_JSON:(\{[^\n]*\})')
_PATH_RE = re.compile(r'^[A-Za-z0-9._\-/*]{1,100}$')
_OFF = '#VP_HTTPS_OPTIONAL '
DEFAULT_DENY = ['.git', '.env', '.svn', '.htaccess', 'composer.json', 'composer.lock', '*.sql', '*.bak']


def _nginx_version():
    try:
        out = subprocess.run(['nginx', '-v'], capture_output=True, text=True, timeout=10).stderr
        m = re.search(r'nginx/(\d+)\.(\d+)\.(\d+)', out)
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)
    except Exception:
        return (0, 0, 0)


def _expiry_all():
    try:
        return json.load(open(EXPIRY_FILE))
    except Exception:
        return {}


def _expiry_save(d):
    os.makedirs(os.path.dirname(EXPIRY_FILE), exist_ok=True)
    tmp = EXPIRY_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(d, f, indent=2)
    os.replace(tmp, EXPIRY_FILE)


def _read_state(content):
    m = _JSON_RE.search(content)
    st = json.loads(m.group(1)) if m else {}
    has_ssl = SSL_BEGIN in content or bool(re.search(r'listen[^;]*\b443\b', content))
    st['ssl'] = has_ssl
    st['force_https'] = has_ssl and bool(re.search(r'^[ \t]*return 301 https://[^\n]*' + re.escape(SSL_REDIRECT_TAG), content, re.M))
    st['http2'] = bool(re.search(r'^[ \t]*http2\s+on;|listen[^;]*\b443\b[^;]*\bhttp2\b', content, re.M))
    return st


def _deny_location(patterns):
    """One regex location that answers 404 for the listed paths/patterns."""
    parts = []
    for p in patterns:
        p = p.strip().strip('/')
        if not p:
            continue
        rx = re.escape(p).replace(r'\*', '[^/]*')
        parts.append(rx)
    if not parts:
        return ''
    return ('    location ~* (^|/)(' + '|'.join(parts) + ')(/|$) {\n'
            '        deny all;\n        return 404;\n    }\n')


def _ensure_limit_zone():
    if os.path.exists(LIMITS_CONF):
        return True
    try:
        nconf = open('/etc/nginx/nginx.conf').read()
    except Exception:
        return False
    if 'conf.d/*.conf' not in nconf:
        return False
    with open(LIMITS_CONF, 'w') as f:
        f.write('# Managed by VortexPanel: zones for per-site connection limits\n'
                'limit_conn_zone $binary_remote_addr zone=vp_perip:10m;\n')
    return True


@websites_bp.route('/api/websites/<domain>/extras')
def get_extras(domain):
    if not req(): return jsonify({'ok': False}), 401
    if not is_valid_domain(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    fp = nginx_conf_file(domain)
    if not os.path.exists(fp):
        return jsonify({'ok': False, 'error': 'These settings are available for nginx sites'}), 404
    st = _read_state(open(fp).read())
    return jsonify({'ok': True, 'force_https': st['force_https'], 'ssl': st['ssl'], 'http2': st['http2'],
                    'hsts': st.get('hsts', False), 'hsts_subdomains': st.get('hsts_subdomains', False),
                    'deny_paths': st.get('deny_paths', []), 'rate_kbps': st.get('rate_kbps', 0),
                    'conn_limit': st.get('conn_limit', 0), 'expires': _expiry_all().get(domain, ''),
                    'default_deny': DEFAULT_DENY, 'http2_supported': _nginx_version() >= (1, 9, 5)})


@websites_bp.route('/api/websites/<domain>/extras', methods=['PUT'])
def set_extras(domain):
    if not req(): return jsonify({'ok': False}), 401
    if not is_valid_domain(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    d = request.get_json(silent=True) or {}
    try:
        rate = max(0, min(1_000_000, int(d.get('rate_kbps') or 0)))
        conns = max(0, min(10_000, int(d.get('conn_limit') or 0)))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Limits must be numbers'}), 400
    deny = d.get('deny_paths') or []
    if isinstance(deny, str):
        deny = re.split(r'[\s,]+', deny)
    deny = [x.strip() for x in deny if x.strip()]
    bad = [x for x in deny if not _PATH_RE.match(x) or '..' in x]
    if bad:
        return jsonify({'ok': False, 'error': f'Blocked paths may contain letters, digits, . _ - / and *: {bad[0]}'}), 400
    expires = str(d.get('expires') or '').strip()
    if expires and not re.fullmatch(r'\d{4}-\d{2}-\d{2}', expires):
        return jsonify({'ok': False, 'error': 'Expiry date must be YYYY-MM-DD'}), 400
    hsts = bool(d.get('hsts'))
    hsts_sub = bool(d.get('hsts_subdomains'))
    force = bool(d.get('force_https', True))
    http2 = bool(d.get('http2'))
    if conns and not _ensure_limit_zone():
        return jsonify({'ok': False, 'error': 'Connection limits need nginx.conf to include conf.d/*.conf'}), 400
    ver = _nginx_version()
    state = {'hsts': hsts, 'hsts_subdomains': hsts_sub, 'deny_paths': deny, 'rate_kbps': rate, 'conn_limit': conns}

    def fn(content):
        has_ssl = SSL_BEGIN in content or bool(re.search(r'listen[^;]*\b443\b', content))
        if (hsts or http2) and not has_ssl:
            return (None, 'Turn on SSL for this site first (SSL tab)')
        content = _BLOCK_RE.sub('', content)
        lines = ['    #VP_EXTRAS', '    #VP_EXTRAS_JSON:' + json.dumps(state, separators=(',', ':'))]
        if hsts:
            lines.append('    add_header Strict-Transport-Security "max-age=31536000'
                         + ('; includeSubDomains' if hsts_sub else '') + '" always;')
        if rate:
            lines.append(f'    limit_rate {rate}k;')
        if conns:
            lines.append(f'    limit_conn vp_perip {conns};')
        loc = _deny_location(deny)
        block = '\n'.join(lines) + '\n' + loc + '    #VP_EXTRAS_END\n'
        if len(lines) > 2 or loc:
            content = nginx_insert_in_servers(content, block, at='start')
            if content is None:
                return None
        # Force HTTPS: the redirect written by the SSL tab is switched off by
        # commenting it, so turning SSL off later still removes it cleanly.
        if has_ssl:
            if force:
                content = re.sub(r'^([ \t]*)' + re.escape(_OFF) + r'(return 301 https://)', r'\1\2', content, flags=re.M)
            else:
                content = re.sub(r'^([ \t]*)(return 301 https://[^\n]*' + re.escape(SSL_REDIRECT_TAG) + ')',
                                 r'\1' + _OFF + r'\2', content, flags=re.M)
        # HTTP/2 on the HTTPS server blocks.
        content = re.sub(r'^[ \t]*http2\s+on;[^\n]*\n', '', content, flags=re.M)
        content = re.sub(r'(listen[^;]*\b443\b[^;]*?)\s+http2\b', r'\1', content)
        if http2 and has_ssl:
            if ver >= (1, 25, 1):
                # one "http2 on;" in every HTTPS server block
                out, last = [], 0
                for s_, e_ in nginx_server_blocks(content):
                    b = content[s_:e_]
                    if re.search(r'listen[^;]*\b443\b', b) and not re.search(r'^[ \t]*http2\s+on;', b, re.M):
                        b = re.sub(r'^([ \t]*)(listen[^;\n]*\b443\b[^;\n]*;[^\n]*\n)',
                                   lambda m: m.group(1) + m.group(2) + m.group(1) + 'http2 on;\n', b, count=1, flags=re.M)
                    out.append(content[last:s_]); out.append(b); last = e_
                out.append(content[last:])
                content = ''.join(out)
            else:
                content = re.sub(r'(listen[^;]*\b443\b\s+ssl)(?![^;]*http2)', r'\1 http2', content)
        return content

    ok, err, code = nginx_edit_site(domain, fn)
    if not ok:
        return jsonify({'ok': False, 'error': err}), code
    ex = _expiry_all()
    if expires:
        ex[domain] = expires
    else:
        ex.pop(domain, None)
    _expiry_save(ex)
    return jsonify({'ok': True})


def run_expiry(today=None):
    """Stop every site whose expiry date has passed (called by the timer)."""
    today = today or time.strftime('%Y-%m-%d')
    ex = _expiry_all()
    done = []
    if not ex:
        return done
    from panel.routes import websites_core as wc
    for domain, date_ in list(ex.items()):
        if date_ >= today:
            continue
        fp, ws = wc._find_site_config(domain)
        if not fp:
            continue
        try:
            if ws == 'nginx':
                content = open(fp).read()
                if wc.nginx_site_stopped(content):
                    continue
                ok, err, _ = wc.nginx_edit_site(domain, lambda c: wc.nginx_set_stopped(c, True))
            elif ws == 'apache':
                ok, err = wc.apache_edit_site(fp, lambda c: wc.apache_set_stopped(c, stopped=True))
            else:
                continue
            done.append((domain, ok, err))
        except Exception as e:
            done.append((domain, False, str(e)))
    return done
