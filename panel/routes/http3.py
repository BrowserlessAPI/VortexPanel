"""
VortexPanel HTTP/3 (QUIC) support.

Most distro-packaged nginx builds do NOT include the HTTP/3 module —
confirmed directly: Ubuntu 24.04's default `nginx` package (1.24.0) has
no --with-http_v3_module, same for most other distros' default repos.
HTTP/3 requires nginx 1.25+ built with QUIC support, which generally
means installing from nginx.org's official mainline repository instead
of the distro's own package.

This module is honest about that rather than pretending the toggle
always works: it detects real capability first and gives clear,
actionable guidance when it's missing, instead of silently writing a
config that nginx will refuse to start with.
"""
import os, re
from flask import jsonify, request

try:
    from panel.routes.websites_core import websites_bp, req, sh, get_nginx_dirs, reload_nginx
except ImportError:
    from websites_core import websites_bp, req, sh, get_nginx_dirs, reload_nginx


def _nginx_supports_http3():
    out = sh('nginx -V 2>&1')
    return 'with-http_v3_module' in out

def _nginx_version():
    out = sh('nginx -v 2>&1')
    m = re.search(r'nginx/(\d+\.\d+\.\d+)', out)
    return m.group(1) if m else 'unknown'


@websites_bp.route('/api/websites/<domain>/http3')
def http3_status(domain):
    if not req(): return jsonify({'ok':False}), 401
    capable = _nginx_supports_http3()
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    enabled = False
    has_ssl = False
    if os.path.exists(fp):
        content = open(fp).read()
        has_ssl = 'ssl_certificate' in content
        enabled = bool(re.search(r'listen\s+443\s+quic', content))
    return jsonify({
        'ok': True, 'enabled': enabled, 'has_ssl': has_ssl,
        'nginx_supports_http3': capable, 'nginx_version': _nginx_version(),
    })


@websites_bp.route('/api/websites/<domain>/http3', methods=['POST'])
def http3_toggle(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    enable = d.get('enable', True)

    if enable and not _nginx_supports_http3():
        return jsonify({'ok':False,
            'error': "Your nginx build doesn't include HTTP/3 (QUIC) support "
                     f"(version {_nginx_version()}, no --with-http_v3_module). "
                     "This requires nginx 1.25+ built with QUIC, which usually means "
                     "installing from nginx.org's official mainline repository instead "
                     "of your distro's default package. See "
                     "https://nginx.org/en/linux_packages.html#mainline for instructions.",
            'nginx_supports_http3': False,
        }), 400

    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp):
        return jsonify({'ok':False,'error':'Site not found'}), 404

    content = open(fp).read()
    if 'ssl_certificate' not in content:
        return jsonify({'ok':False,'error':'Enable SSL for this site first — HTTP/3 requires HTTPS.'}), 400

    backup = content

    if enable:
        if re.search(r'listen\s+443\s+quic', content):
            return jsonify({'ok':True, 'message':'HTTP/3 already enabled'})
        # Add the QUIC (UDP) listener alongside the existing TCP SSL listener,
        # plus the Alt-Svc header so browsers know to upgrade to HTTP/3, and
        # http2 for backward-compatible clients that don't speak QUIC yet.
        content = re.sub(
            r'(listen\s+443\s+ssl;)',
            r'\1\n    listen 443 quic reuseport;\n    http2 on;\n'
            r'    add_header Alt-Svc \'h3=":443"; ma=86400\' always;\n'
            r'    add_header X-Quic-Status $http3 always;',
            content, count=1
        )
    else:
        content = re.sub(r'\n\s*listen\s+443\s+quic[^\n;]*;', '', content)
        content = re.sub(r'\n\s*add_header\s+Alt-Svc[^\n;]*;', '', content)
        content = re.sub(r'\n\s*add_header\s+X-Quic-Status[^\n;]*;', '', content)
        content = re.sub(r'\n\s*http2\s+on;', '', content)

    with open(fp, 'w') as f:
        f.write(content)

    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower():
        with open(fp, 'w') as f:
            f.write(backup)
        return jsonify({'ok':False,'error':f'nginx config error, rolled back: {test}'}), 400

    reload_nginx()

    # HTTP/3 runs over UDP, not TCP — TCP/443 is presumably already open for
    # regular HTTPS, but UDP/443 needs its own firewall rule.
    if enable:
        sh('ufw allow 443/udp 2>/dev/null')
        sh('firewall-cmd --add-port=443/udp --permanent 2>/dev/null; firewall-cmd --reload 2>/dev/null')

    return jsonify({'ok':True, 'enabled':enable})
