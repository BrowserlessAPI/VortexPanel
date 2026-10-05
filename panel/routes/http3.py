"""
VortexPanel HTTP/3 (QUIC) support — multi-webserver aware.

Per-webserver reality:
  nginx (nginx.org pkg, 1.25+) — manual config needed; auto-handled here
  nginx (distro pkg)            — compiled without --with-http_v3_module;
                                  one-click upgrade to nginx.org mainline offered
  Caddy                         — HTTP/3 is ON by default when TLS is active;
                                  nothing for the user to do
  OpenLiteSpeed                 — HTTP/3 is ON by default; just needs UDP 443 open
  Apache                        — no native HTTP/3; not supported, UI says so clearly
  LiteSpeed Enterprise          — not supported by VortexPanel (paid/closed-source)
"""
import os, re, shutil
from flask import jsonify, request

try:
    from panel.routes.websites_core import websites_bp, req, sh, get_nginx_dirs, reload_nginx, _nginx_apply, _find_site_config, nginx_test
    from panel.routes.os_utils import get_os, pkg_install
except ImportError:
    from websites_core import websites_bp, req, sh, get_nginx_dirs, reload_nginx, _nginx_apply, _find_site_config, nginx_test
    from os_utils import get_os, pkg_install


def _site_ws(domain):
    """The web server that serves THIS site (several may be installed);
    falls back to whichever is running."""
    try:
        ws = _find_site_config(domain)[1]
    except Exception:
        ws = None
    return ws or _active_webserver()


def _other_quic_sites(fp):
    import glob as _glob
    for cf in _glob.glob('/etc/nginx/vortex/*.conf') + _glob.glob('/etc/nginx/conf.d/*.conf'):
        if os.path.realpath(cf) == os.path.realpath(fp):
            continue
        try:
            if re.search(r'listen\s+\S*443\s+quic', open(cf).read()):
                return True
        except Exception:
            pass
    return False


# --- Webserver detection -------------------------------------------------------

def _active_webserver():
    """Return the active webserver: nginx | apache | openlitespeed | caddy"""
    if sh('systemctl is-active nginx 2>/dev/null') == 'active':
        return 'nginx'
    if sh('systemctl is-active apache2 2>/dev/null') == 'active' or \
       sh('systemctl is-active httpd 2>/dev/null') == 'active':
        return 'apache'
    if sh('systemctl is-active lsws 2>/dev/null') == 'active':
        return 'openlitespeed'
    if sh('systemctl is-active caddy 2>/dev/null') == 'active':
        return 'caddy'
    return 'nginx'


# --- Nginx-specific helpers ----------------------------------------------------

def _nginx_version():
    out = sh('nginx -v 2>&1')
    m = re.search(r'nginx/(\d+\.\d+\.\d+)', out)
    return m.group(1) if m else 'unknown'

def _nginx_supports_http3():
    """True only if the running nginx was compiled with --with-http_v3_module."""
    out = sh('nginx -V 2>&1')
    return 'with-http_v3_module' in out

def _nginx_from_official_repo():
    """True if nginx was installed from nginx.org packages (not distro repo)."""
    out = sh('nginx -V 2>&1')
    return 'nginx.org' in out or 'nginx-mainline' in out or 'nginx-stable' in out

def _nginx_version_tuple():
    v = _nginx_version()
    try:
        parts = v.split('.')
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except:
        return (0, 0, 0)


# --- Firewall helpers ----------------------------------------------------------

def _open_udp_443():
    """Open UDP 443 in whatever firewall is active (UFW or firewalld)."""
    results = []
    if shutil.which('ufw') and sh('ufw status 2>/dev/null | head -1') == 'Status: active':
        out = sh('ufw allow 443/udp 2>&1')
        results.append(f'ufw: {out}')
    if sh('firewall-cmd --state 2>/dev/null') == 'running':
        sh('firewall-cmd --add-port=443/udp --permanent 2>/dev/null')
        sh('firewall-cmd --reload 2>/dev/null')
        results.append('firewalld: UDP 443 added')
    return results

def _close_udp_443():
    """Remove UDP 443 firewall rule."""
    if shutil.which('ufw') and sh('ufw status 2>/dev/null | head -1') == 'Status: active':
        sh('ufw delete allow 443/udp 2>/dev/null')
    if shutil.which('firewall-cmd'):
        sh('firewall-cmd --remove-port=443/udp --permanent 2>/dev/null')
        sh('firewall-cmd --reload 2>/dev/null')

def _udp_443_open():
    """Check if UDP 443 is currently open in the firewall."""
    ufw_out = sh('ufw status 2>/dev/null')
    ufw_active = ufw_out.startswith('Status: active')
    fwd_active = sh('firewall-cmd --state 2>/dev/null') == 'running'
    if ufw_active and re.search(r'^443/udp\s+ALLOW', ufw_out, re.M):
        return True
    if fwd_active and '443/udp' in sh('firewall-cmd --list-ports 2>/dev/null'):
        return True
    # No firewall active (installed but disabled counts as none) - open
    return not ufw_active and not fwd_active


# --- Nginx upgrade to nginx.org mainline ---------------------------------------

def _upgrade_nginx_to_mainline():
    """
    Replace distro nginx with nginx.org official mainline package.
    This is the only way to get --with-http_v3_module on distro systems.
    Works on all 9 supported distros.
    """
    os_info = get_os()
    family  = os_info['family']
    steps   = []

    if family == 'debian':
        cmds = [
            'apt-get install -y curl gnupg2 ca-certificates lsb-release',
            'curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor --batch -o /usr/share/keyrings/nginx-archive-keyring.gpg',
            'echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] '
            'https://nginx.org/packages/mainline/$(. /etc/os-release && echo $ID) '
            '$(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx-mainline.list',
            'apt-get update -qq',
            'apt-get install -y --allow-downgrades nginx',
        ]
    elif family in ('rhel', 'fedora'):
        pkg = os_info['pkg']
        cmds = [
            f'cat > /etc/yum.repos.d/nginx-mainline.repo << \'EOF\'\n'
            '[nginx-mainline]\nname=nginx mainline repo\n'
            'baseurl=https://nginx.org/packages/mainline/centos/$releasever/$basearch/\n'
            'gpgcheck=1\nenabled=1\n'
            'gpgkey=https://nginx.org/keys/nginx_signing.key\nmodule_hotfixes=true\nEOF',
            f'{pkg} install -y nginx',
        ]
    else:
        return False, f'Unsupported OS family: {family}', []

    for cmd in cmds:
        out, err, rc = sh.__func__(cmd) if hasattr(sh, '__func__') else (sh(cmd), '', 0)
        if isinstance(out, str):
            rc = 0 if out else 1
            steps.append({'cmd': cmd[:80], 'rc': rc})
        else:
            steps.append({'cmd': cmd[:80], 'rc': rc, 'out': out, 'err': err})

    # Test config
    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower():
        return False, f'nginx config test failed after upgrade: {test}', steps

    sh('systemctl restart nginx 2>/dev/null || service nginx restart')
    return True, 'nginx upgraded to mainline with HTTP/3 support', steps


# --- Status endpoint -----------------------------------------------------------

@websites_bp.route('/api/websites/<domain>/http3')
def http3_status(domain):
    if not req(): return jsonify({'ok': False}), 401

    ws = _site_ws(domain)

    # Per-webserver HTTP/3 capability and status
    if ws == 'caddy':
        return jsonify({
            'ok': True, 'webserver': 'caddy',
            'http3_support': 'auto',
            'message': 'Caddy enables HTTP/3 automatically when SSL is active — no configuration needed.',
            'enabled': True,
            'udp_443_open': _udp_443_open(),
        })

    if ws == 'openlitespeed':
        return jsonify({
            'ok': True, 'webserver': 'openlitespeed',
            'http3_support': 'auto',
            'message': 'OpenLiteSpeed enables HTTP/3 by default — just ensure UDP port 443 is open in your firewall.',
            'enabled': True,
            'udp_443_open': _udp_443_open(),
        })

    if ws == 'apache':
        return jsonify({
            'ok': True, 'webserver': 'apache',
            'http3_support': 'unsupported',
            'message': 'Apache does not have native HTTP/3 support. To use HTTP/3 with Apache, '
                       'you would need to place nginx in front as a QUIC proxy — a complex setup '
                       'not currently managed by VortexPanel.',
            'enabled': False,
        })

    # nginx — check compile-time support
    capable    = _nginx_supports_http3()
    ng_ver     = _nginx_version()
    from_org   = _nginx_from_official_repo()
    ver_tuple  = _nginx_version_tuple()
    old_enough = ver_tuple >= (1, 25, 0)

    avail, _ = get_nginx_dirs()
    fp       = os.path.join(avail, f'{domain}.conf')
    enabled  = False
    has_ssl  = False
    if os.path.exists(fp):
        content = open(fp).read()
        has_ssl = 'ssl_certificate' in content
        enabled = bool(re.search(r'listen\s+\S*443\s+quic', content))

    upgrade_needed = not capable and old_enough and not from_org

    return jsonify({
        'ok': True, 'webserver': 'nginx',
        'http3_support': 'manual',
        'nginx_supports_http3': capable,
        'nginx_version': ng_ver,
        'nginx_from_official_repo': from_org,
        'upgrade_needed': upgrade_needed,
        'enabled': enabled,
        'has_ssl': has_ssl,
        'udp_443_open': _udp_443_open(),
        'message': (
            'HTTP/3 is active.' if enabled else
            'Ready to enable.' if capable and has_ssl else
            'SSL must be enabled first.' if capable and not has_ssl else
            f'nginx {ng_ver} from distro repo lacks HTTP/3. Use the upgrade button to switch to nginx.org mainline.'
            if upgrade_needed else
            f'nginx {ng_ver} does not support HTTP/3 (requires 1.25+).'
        ),
    })


# --- Toggle endpoint -----------------------------------------------------------

@websites_bp.route('/api/websites/<domain>/http3', methods=['POST'])
def http3_toggle(domain):
    if not req(): return jsonify({'ok': False}), 401

    d      = request.get_json() or {}
    enable = d.get('enable', True)
    ws     = _site_ws(domain)

    # Caddy and OpenLiteSpeed: HTTP/3 is always on, just need UDP 443
    if ws in ('caddy', 'openlitespeed'):
        if enable:
            fw = _open_udp_443()
            return jsonify({
                'ok': True,
                'message': f'HTTP/3 is always enabled on {ws}. '
                           f'UDP 443 firewall rule ensured: {fw}',
                'webserver': ws,
            })
        return jsonify({'ok': True, 'message': f'HTTP/3 cannot be disabled on {ws} — it is always on.'})

    # Apache: unsupported
    if ws == 'apache':
        return jsonify({
            'ok': False,
            'error': 'Apache does not support HTTP/3 natively. '
                     'VortexPanel does not manage the nginx-in-front workaround.',
        }), 400

    # nginx path
    if enable and not _nginx_supports_http3():
        return jsonify({
            'ok': False,
            'error': f'nginx {_nginx_version()} was not compiled with --with-http_v3_module. '
                     f'Use the "Upgrade nginx" button to switch to nginx.org mainline (1.25+) which includes HTTP/3.',
            'nginx_supports_http3': False,
            'upgrade_available': True,
        }), 400

    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp):
        return jsonify({'ok': False, 'error': 'Site config not found'}), 404

    content = open(fp).read()
    if enable and 'ssl_certificate' not in content:
        return jsonify({'ok': False, 'error': 'Enable SSL for this domain first — HTTP/3 requires HTTPS.'}), 400

    if enable:
        if re.search(r'listen\s+\S*443\s+quic', content):
            _open_udp_443()
            return jsonify({'ok': True, 'message': 'HTTP/3 already enabled', 'enabled': True})
        # `reuseport` may appear on only ONE listen directive per address:port
        # across the whole nginx config. If any other site already owns it,
        # adding a second makes `nginx -t` fail and HTTP/3 becomes un-enableable
        # beyond the first site. Detect it and omit the keyword here if so.
        reuseport_taken = False
        try:
            import glob as _glob
            for _cf in _glob.glob(os.path.join(avail, '*')) + _glob.glob('/etc/nginx/conf.d/*'):
                try:
                    if _cf != fp and 'quic reuseport' in open(_cf).read():
                        reuseport_taken = True; break
                except Exception:
                    pass
        except Exception:
            pass
        reuse = '' if reuseport_taken else ' reuseport'
        quic_listen = f'listen 443 quic{reuse};'
        # a site that also listens on [::]:443 needs the QUIC listener there too
        # (only present when the vhost already has an IPv6 HTTPS listener)
        if re.search(r'^[ \t]*listen\s+\[::\]:443\b[^;]*\bssl\b', content, re.M) and \
                os.path.exists('/proc/net/if_inet6'):
            quic_listen += f' listen [::]:443 quic{reuse};'
        # any `listen [addr:]443 ssl ...;` (e.g. "listen 443 ssl default_server;"
        # or certbot's "# managed by Certbot" lines); the old exact match on
        # "listen 443 ssl;" left the file unchanged and still reported success
        m = re.search(r'^([ \t]*)listen\s+(?:[^\s;]*:)?443\s+[^;]*\bssl\b[^;]*;[^\n]*', content, re.M)
        if not m:
            return jsonify({'ok': False, 'error': 'Could not find the HTTPS "listen 443 ssl" line in this site\'s config'}), 400
        ind = m.group(1) or '    '
        add = ''.join(f'\n{ind}{l.strip()};' for l in quic_listen.split(';') if l.strip())
        # `http2 on;` is only valid once per server and needs nginx >= 1.25.1
        if not re.search(r'^\s*http2\s+on\s*;', content, re.M) and not re.search(r'listen[^;]*\bhttp2\b', content):
            add += f'\n{ind}http2 on;'
        add += f"\n{ind}add_header Alt-Svc 'h3=\":443\"; ma=86400' always;"
        content = content[:m.end()] + add + content[m.end():]
    else:
        content = re.sub(r'\n\s*listen\s+\S*443\s+quic[^\n;]*;', '', content)
        content = re.sub(r'\n\s*add_header\s+Alt-Svc[^\n]*;', '', content)
        content = re.sub(r'\n\s*add_header\s+X-Quic-Status[^\n;]*;', '', content)

    ok, err = _nginx_apply(fp, content)
    if not ok:
        return jsonify({'ok': False, 'error': f'nginx config test failed, rolled back: {err}'}), 400

    if enable:
        fw = _open_udp_443()
    else:
        fw = []
        # other sites may still serve HTTP/3 on the same UDP port
        if not _other_quic_sites(fp):
            _close_udp_443()

    return jsonify({
        'ok': True,
        'enabled': enable,
        'udp_443': fw,
        'message': 'HTTP/3 enabled — UDP 443 opened in firewall.' if enable else 'HTTP/3 disabled.',
    })


# --- Nginx mainline upgrade endpoint ------------------------------------------

@websites_bp.route('/api/nginx/upgrade-mainline', methods=['POST'])
def nginx_upgrade_mainline():
    """
    One-click upgrade from distro nginx to nginx.org mainline.
    Required to get --with-http_v3_module on distro systems.
    """
    if not req(): return jsonify({'ok': False}), 401

    if _nginx_supports_http3():
        return jsonify({'ok': True, 'message': 'nginx already has HTTP/3 support — no upgrade needed.'})

    os_info = get_os()
    family  = os_info['family']
    pkg     = os_info['pkg']
    steps   = []

    if family == 'debian':
        # upstream layout + codename from os_utils (Mint/Pop!_OS report their
        # own ID/codename, for which nginx.org has no repository; lsb_release
        # is missing on minimal images)
        base = os_info.get('base') or ('debian' if os_info.get('id') == 'debian' else 'ubuntu')
        codename = os_info.get('codename') or ''
        if not re.fullmatch(r'[a-z]+', base) or not re.fullmatch(r'[a-z]+', codename):
            return jsonify({'ok': False, 'error': 'Could not determine the distribution codename'}), 400
        cmds = [
            'DEBIAN_FRONTEND=noninteractive apt-get install -y curl gnupg2 ca-certificates 2>&1',
            'curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor --batch --yes -o /usr/share/keyrings/nginx-archive-keyring.gpg 2>&1',
            'echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] '
            f'https://nginx.org/packages/mainline/{base} '
            f'{codename} nginx" > /etc/apt/sources.list.d/nginx-mainline.list',
            'apt-get update -qq 2>&1',
            # keep the existing nginx.conf / site configs: without these options
            # dpkg stops at the conffile prompt (no tty) and the install fails
            'DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades '
            '-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold nginx 2>&1',
        ]
    elif family in ('rhel', 'fedora'):
        if get_os().get('id') == 'fedora':
            return jsonify({'ok': False, 'error': 'nginx.org publishes no Fedora packages -- Fedora\'s own nginx is already a recent release'}), 400
        cmds = [
            r'''cat > /etc/yum.repos.d/nginx-mainline.repo << 'EOF'
[nginx-mainline]
name=nginx mainline repo
baseurl=https://nginx.org/packages/mainline/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF''',
            f'{pkg} install -y nginx 2>&1',
        ]
    else:
        return jsonify({'ok': False, 'error': f'Unsupported OS family: {family}'}), 400

    for cmd in cmds:
        out = sh(cmd, 120)
        rc  = 0 if out is not None else 1
        steps.append({'cmd': cmd.split('\n')[0][:80], 'out': (out or '')[:300]})

    # Verify upgrade worked
    if not _nginx_supports_http3():
        return jsonify({
            'ok': False,
            'error': 'nginx was updated but still lacks HTTP/3. '
                     'Your distro may not have a mainline package available. '
                     'You may need to compile nginx from source with --with-http_v3_module.',
            'steps': steps,
            'nginx_version': _nginx_version(),
        }), 500

    ok_t, test = nginx_test()
    if not ok_t:
        return jsonify({'ok': False, 'error': 'nginx was upgraded but its configuration test fails -- fix it before restarting nginx: '
                                              + test.strip()[-600:], 'steps': steps}), 500
    sh('systemctl restart nginx 2>/dev/null || service nginx restart 2>/dev/null', 60)
    _open_udp_443()

    return jsonify({
        'ok': True,
        'message': f'nginx upgraded to {_nginx_version()} with HTTP/3 support. UDP 443 opened.',
        'nginx_version': _nginx_version(),
        'nginx_supports_http3': True,
        'steps': steps,
    })
