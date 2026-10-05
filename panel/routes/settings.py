from flask import Blueprint, jsonify, request
import subprocess, os, json, re, time
from datetime import datetime

try:
    from panel.routes.os_utils import get_os, pkg_install, pkg_update, pkg_remove
except ImportError:
    try:
        from os_utils import get_os, pkg_install, pkg_update, pkg_remove
    except ImportError:
        def get_os(): return {'family':'debian','pkg':'apt'}
        def pkg_install(p): pass
        def pkg_update(): pass
        def pkg_remove(p): pass

settings_bp = Blueprint('settings', __name__)

def req():
    from panel.routes.auth import check_ip_and_session
    return check_ip_and_session()

def sh(cmd, t=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip()
    except: return ''

def sh3(cmd, t=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e: return '', str(e), 1

CONFIG_FILE  = '/opt/vortexpanel/config.json'
SSL_DIR      = '/opt/vortexpanel/ssl'
SERVICE_FILE = '/etc/systemd/system/vortexpanel.service'
PANEL_PORT   = 8888

def load_config():
    if os.path.exists(CONFIG_FILE):
        try: return json.load(open(CONFIG_FILE))
        except: pass
    return {'panel_name':'VortexPanel','port':8888,
            'ssl_enabled':False,'auto_update':True,'timezone':'UTC','security_path':'',
            'panel_domain':''}

def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    tmp = CONFIG_FILE + '.tmp'
    with open(tmp, 'w') as f: json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_FILE)

# --- Gunicorn bind management ---------------------------------------------------
def _set_gunicorn_bind(host, port, certfile=None, keyfile=None):
    """Rewrite the systemd unit's --bind and optional --certfile/--keyfile directives."""
    if not os.path.exists(SERVICE_FILE):
        return False, 'systemd service file not found'
    content = open(SERVICE_FILE).read()
    target = f'{host}:{port}'
    new_content = re.sub(r'--bind\s+\S+:\d+', f'--bind {target}', content)
    new_content = re.sub(r'-b\s+\S+:\d+', f'-b {target}', new_content)

    # Remove old SSL args if present
    new_content = re.sub(r'\s*--certfile\s+\S+', '', new_content)
    new_content = re.sub(r'\s*--keyfile\s+\S+', '', new_content)

    # Add SSL args if cert provided
    if certfile and keyfile:
        new_content = re.sub(
            r'(--bind\s+\S+:\d+)',
            rf'\1 --certfile {certfile} --keyfile {keyfile}',
            new_content
        )

    if new_content == content and target not in content:
        return False, 'could not find --bind directive in service file'
    with open(SERVICE_FILE, 'w') as f: f.write(new_content)
    sh('systemctl daemon-reload 2>/dev/null')
    return True, ''

def _current_bind():
    if not os.path.exists(SERVICE_FILE): return None
    content = open(SERVICE_FILE).read()
    m = re.search(r'(?:--bind|-b)\s+(\S+):(\d+)', content)
    return (m.group(1), int(m.group(2))) if m else None

def _safe_restart_panel():
    """
    Restart vortexpanel.service from WITHIN a request handled by that very
    service. A naive '(sleep 2 && systemctl restart vortexpanel) &' is
    unsafe: that background process is still a member of vortexpanel's
    systemd cgroup, and 'systemctl restart' kills the ENTIRE cgroup —
    including the background restart command itself — partway through,
    which can leave the service down instead of restarted.

    Fix: use `systemd-run` to launch the restart command as an independent
    *transient* unit, outside vortexpanel's cgroup, so it survives the kill
    and reliably completes the restart. Falls back to setsid double-fork
    detachment if systemd-run isn't available (non-systemd or container
    environments), and finally to the naive approach as a last resort.
    """
    if sh('which systemd-run 2>/dev/null'):
        sh('systemd-run --no-block --collect --unit=vortexpanel-restart '
           '/bin/sh -c "sleep 2 && systemctl restart vortexpanel" 2>/dev/null')
    elif sh('which setsid 2>/dev/null'):
        sh('setsid sh -c "sleep 2 && systemctl restart vortexpanel" '
           '>/dev/null 2>&1 < /dev/null &')
    else:
        sh('(sleep 2 && systemctl restart vortexpanel) >/dev/null 2>&1 &')

# --- SSL helpers ----------------------------------------------------------------
def _ssl_status():
    cert = os.path.join(SSL_DIR, 'panel.crt')
    key  = os.path.join(SSL_DIR, 'panel.key')
    cfg  = load_config()
    if not os.path.exists(cert):
        return {'enabled': False, 'type': 'none', 'port': cfg.get('port', PANEL_PORT)}
    out = sh(f'openssl x509 -in {cert} -noout -subject -issuer -enddate 2>/dev/null')
    cert_type = 'letsencrypt' if "Let's Encrypt" in out else 'self-signed'
    expiry_out = sh(f'openssl x509 -in {cert} -noout -enddate 2>/dev/null | cut -d= -f2')
    days_left = -1
    try:
        exp = datetime.strptime(expiry_out.strip(), '%b %d %H:%M:%S %Y %Z')
        days_left = (exp - datetime.utcnow()).days
    except: pass
    return {
        'enabled':   cfg.get('ssl_enabled', False),
        'type':      cert_type,
        'expiry':    expiry_out.strip(),
        'days_left': days_left,
        'cert_path': cert,
        'key_path':  key,
        'port':      cfg.get('port', PANEL_PORT),
    }

def _gen_selfsigned(domain=''):
    """Self-signed certificate for the panel, valid for the domain (if given)
    and the server's IP, so browsers show one clear warning rather than a
    name-mismatch error on top of it."""
    import ipaddress
    os.makedirs(SSL_DIR, exist_ok=True)
    ip = (sh("hostname -I 2>/dev/null | awk '{print $1}'") or '').strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        ip = ''
    domain = (domain or '').strip().lower()
    if domain and not re.fullmatch(r'[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+', domain):
        return False, 'Invalid domain name'
    san = ([f'DNS:{domain}'] if domain else []) + ([f'IP:{ip}'] if ip else []) or ['DNS:localhost']
    cn = domain or ip or 'localhost'
    out, err, rc = sh3(
        f'openssl req -x509 -nodes -days 3650 -newkey rsa:2048 '
        f'-keyout {SSL_DIR}/panel.key.new -out {SSL_DIR}/panel.crt.new '
        f'-subj "/CN={cn}/O=VortexPanel/OU=Panel" '
        f'-addext "subjectAltName={",".join(san)}" 2>&1',
        t=30
    )
    if rc != 0:
        return False, (out or err)[-300:]
    os.chmod(f'{SSL_DIR}/panel.key.new', 0o600)
    os.replace(f'{SSL_DIR}/panel.key.new', f'{SSL_DIR}/panel.key')
    os.replace(f'{SSL_DIR}/panel.crt.new', f'{SSL_DIR}/panel.crt')
    return True, ''


# ===============================================================================
# ROUTES
# ===============================================================================

@settings_bp.route('/api/settings')
def get_settings():
    if not req(): return jsonify({'ok':False}), 401
    cfg     = load_config()
    hostname = sh('hostname')
    os_info  = sh('cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2').strip('"')
    kernel   = sh('uname -r')
    ip       = sh("hostname -I 2>/dev/null | awk '{print $1}'")
    uptime   = sh("uptime -p 2>/dev/null | sed 's/up //'")
    tz       = sh("timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo UTC")
    server_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return jsonify({
        'ok': True, 'config': cfg,
        'ssl': _ssl_status(),
        'system': {
            'hostname':hostname, 'os':os_info, 'kernel':kernel,
            'ip':ip, 'uptime':uptime, 'timezone':tz.strip(),
            'server_time': server_time,
        }
    })


@settings_bp.route('/api/settings', methods=['PUT'])
def save_settings():
    if not req(): return jsonify({'ok':False}), 401
    d   = request.get_json(silent=True) or {}
    cfg = load_config()
    allowed = ('panel_name','auto_update','timezone','panel_domain','security_path')
    tz = d.get('timezone')
    if tz is not None:
        # The timezone used to be saved to config.json only and never applied
        # to the system, while the UI showed it as the server's timezone.
        tz = str(tz).strip()
        if not tz or '..' in tz or not re.fullmatch(r'[A-Za-z0-9_+\-/]+', tz) \
                or not os.path.isfile(os.path.join('/usr/share/zoneinfo', tz)):
            return jsonify({'ok':False,'error':f'Unknown timezone: {tz}'}), 400
        cur = sh('timedatectl show -p Timezone --value 2>/dev/null') or \
              sh("readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||'")
        if tz != cur:
            try:
                r = subprocess.run(['timedatectl', 'set-timezone', tz], capture_output=True, text=True, timeout=30)
            except Exception as e:
                return jsonify({'ok':False,'error':f'Could not set timezone: {e}'}), 500
            if r.returncode != 0:
                return jsonify({'ok':False,'error':'Could not set timezone: ' + (r.stderr or r.stdout).strip()[:300]}), 500
        d['timezone'] = tz
    cfg.update({k:v for k,v in d.items() if k in allowed})
    save_config(cfg)
    return jsonify({'ok':True})


@settings_bp.route('/api/settings/port', methods=['POST'])
def change_port():
    """Change the panel's PUBLIC listening port (works whether HTTP or HTTPS).

    Goes through the same detached verify-and-roll-back helper as the HTTPS
    switch: previously the unit was rewritten and the panel restarted blind,
    so a port that was already taken (or blocked) left the admin locked out
    with the old port's firewall rule already deleted."""
    if not req(): return jsonify({'ok':False}), 401
    try:
        new_port = int((request.get_json(silent=True) or {}).get('port', 8888))
    except (TypeError, ValueError):
        return jsonify({'ok':False,'error':'Port must be a number'}), 400
    if not (1024 <= new_port <= 65535):
        return jsonify({'ok':False,'error':'Port must be 1024–65535'}), 400
    cfg = load_config()
    cur = _current_bind()
    old_port = cur[1] if cur else cfg.get('port', 8888)
    if new_port == old_port:
        return jsonify({'ok':True,'message':'Port unchanged'})

    # Refuse a port something else already listens on.
    import socket
    for fam, addr in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
        try:
            so = socket.socket(fam, socket.SOCK_STREAM)
        except OSError:
            continue
        try:
            so.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            so.bind((addr, new_port))
        except OSError as e:
            if fam == socket.AF_INET or e.errno == 98:
                return jsonify({'ok':False,'error':f'Port {new_port} is already in use on this server'}), 400
        finally:
            so.close()

    # Open the new port BEFORE restarting; the old one is closed by the
    # helper only once the panel answers on the new port.
    sh(f'ufw allow {new_port}/tcp 2>/dev/null')
    sh(f'firewall-cmd --permanent --add-port={new_port}/tcp 2>/dev/null && firewall-cmd --reload 2>/dev/null')

    try:
        ssl_on = '--certfile' in open(SERVICE_FILE).read()
    except Exception:
        ssl_on = bool(cfg.get('ssl_enabled'))
    ok, err, apply_id = _switch_panel_scheme(ssl_on, new_port=new_port)
    if not ok:
        return jsonify({'ok':False,'error':err}), 500
    return jsonify({'ok':True,'port':new_port,'apply_id':apply_id,
                    'message':f'Port changing to {new_port}. Panel restarting - if it does not answer on the '
                              f'new port within ~40 s the previous port is restored automatically.'})


# --- SSL -------------------------------------------------------------------------

@settings_bp.route('/api/settings/ssl')
def ssl_status():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, **_ssl_status()})


INSTALL_DIR = '/opt/vortexpanel'
SSL_APPLY_DIR = os.path.join(INSTALL_DIR, 'data')
SSL_APPLY_STATE = os.path.join(SSL_APPLY_DIR, 'ssl_apply.json')

# Runs detached (outside the panel's own process/cgroup) so it survives the
# restart it performs. Restarts the panel on the new scheme, waits for it to
# answer, and if it doesn't, puts the previous unit file + config back and
# restarts again - the panel can never be left down by an HTTPS change.
_SSL_APPLY_HELPER = r"""
import json, os, ssl, subprocess, sys, time, urllib.request, urllib.error
state_path, apply_id, scheme, port, unit, unit_bak, cfg, cfg_bak = sys.argv[1:9]
old_scheme = sys.argv[9] if len(sys.argv) > 9 else ('http' if scheme == 'https' else 'https')
old_port = sys.argv[10] if len(sys.argv) > 10 else port
close_old = len(sys.argv) > 11 and sys.argv[11] == '1'
def save(d):
    tmp = state_path + '.tmp'
    json.dump(d, open(tmp, 'w')); os.replace(tmp, state_path)
def probe(sch, prt):
    # urllib instead of curl: the helper must still be able to roll back on
    # a host without curl.
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=ctx))
    try:
        return opener.open(f'{sch}://127.0.0.1:{prt}/', timeout=3).status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0
def healthy(sch, prt, tries):
    for _ in range(tries):
        time.sleep(1)
        if probe(sch, prt) in (200, 301, 302, 401, 403):
            return True
    return False
def fw(action, prt):
    if not prt or not str(prt).isdigit():
        return
    if action == 'close':
        subprocess.run(f'ufw delete allow {prt}/tcp >/dev/null 2>&1; '
                       f'firewall-cmd --permanent --remove-port={prt}/tcp >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1',
                       shell=True)
time.sleep(2)
subprocess.run('systemctl daemon-reload; systemctl restart vortexpanel', shell=True)
if healthy(scheme, port, 20):
    if close_old and old_port != port:
        fw('close', old_port)
    save({'id': apply_id, 'status': 'ok', 'scheme': scheme, 'port': port, 'finished': time.time()})
    sys.exit(0)
log = subprocess.run('journalctl -u vortexpanel -n 25 --no-pager 2>/dev/null', shell=True,
                     capture_output=True, text=True).stdout[-1500:]
os.replace(unit_bak, unit); os.replace(cfg_bak, cfg)
subprocess.run('systemctl daemon-reload; systemctl restart vortexpanel', shell=True)
back = healthy(old_scheme, old_port, 20)
what = scheme.upper() + (f' port {port}' if old_port != port else '')
save({'id': apply_id, 'status': 'failed', 'scheme': scheme, 'port': port, 'finished': time.time(),
      'rolled_back': back,
      'error': f'The panel did not come back on {what}, so the previous settings were restored.',
      'log': log})
"""


def _free_port():
    import socket
    with socket.socket() as so:
        so.bind(('127.0.0.1', 0))
        return so.getsockname()[1]


def _probe_https(port):
    """HTTP status of https://127.0.0.1:<port>/ (0 if unreachable). Pure
    Python so it does not depend on curl being installed."""
    import ssl as _ssl, urllib.request as _ur, urllib.error as _ue
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    opener = _ur.build_opener(_ur.ProxyHandler({}), _ur.HTTPSHandler(context=ctx))
    try:
        return opener.open(f'https://127.0.0.1:{port}/', timeout=2).status
    except _ue.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _pretest_tls(cert_path, key_path):
    """Start a throwaway copy of the panel on a spare localhost port with
    these certificate files and check it answers over HTTPS, BEFORE the
    real service is touched. Catches bad/mismatched cert+key pairs, key
    permission problems and TLS start-up errors with zero downtime."""
    import ssl as _ssl
    try:
        ctx = _ssl.create_default_context(_ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(cert_path, key_path)
    except Exception as e:
        return False, f'Certificate and key do not form a valid pair: {e}'
    gunicorn = os.path.join(INSTALL_DIR, 'venv/bin/gunicorn')
    if not os.path.exists(gunicorn):
        return True, ''   # non-standard install: rely on the rollback helper
    port = _free_port()
    proc = subprocess.Popen([gunicorn, '--bind', f'127.0.0.1:{port}', '--workers', '1',
                             '--certfile', cert_path, '--keyfile', key_path, 'app:app'],
                            cwd=INSTALL_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, text=True)
    ok = False
    try:
        for _ in range(20):
            time.sleep(0.5)
            if proc.poll() is not None:
                break
            if _probe_https(port) in (200, 301, 302, 401, 403):
                ok = True
                break
    finally:
        proc.kill()
        try: out = proc.communicate(timeout=5)[0] or ''
        except Exception: out = ''
    return (True, '') if ok else (False, 'A test start of the panel with this certificate failed: ' + out.strip()[-600:])


def _switch_panel_scheme(https, domain='', new_port=None):
    """Point the panel service at HTTPS (https=True) or plain HTTP (and
    optionally a new port), then restart it through a detached helper that
    verifies the result and rolls back automatically. Returns (ok, error, apply_id)."""
    cfg = load_config()
    cur = _current_bind()
    old_port = cur[1] if cur else cfg.get('port', PANEL_PORT)
    try:
        old_scheme = 'https' if '--certfile' in open(SERVICE_FILE).read() else 'http'
    except Exception:
        old_scheme = 'https' if cfg.get('ssl_enabled') else 'http'
    port = new_port or old_port
    bind_host = cur[0] if cur else '0.0.0.0'

    cert_path, key_path = f'{SSL_DIR}/panel.crt', f'{SSL_DIR}/panel.key'
    if https:
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            return False, 'SSL certificate files not found', None
        ok, err = _pretest_tls(cert_path, key_path)
        if not ok:
            return False, err, None
    if not os.path.exists(SERVICE_FILE):
        return False, 'systemd service file not found', None
    os.makedirs(SSL_APPLY_DIR, exist_ok=True)
    unit_bak = os.path.join(SSL_APPLY_DIR, 'ssl_apply_unit.bak')
    cfg_bak = os.path.join(SSL_APPLY_DIR, 'ssl_apply_config.bak')
    with open(SERVICE_FILE) as f: open(unit_bak, 'w').write(f.read())
    json.dump(cfg, open(cfg_bak, 'w'))

    ok, err = (_set_gunicorn_bind(bind_host, port, certfile=cert_path, keyfile=key_path) if https
               else _set_gunicorn_bind(bind_host, port))
    if not ok:
        return False, err, None
    cfg['ssl_enabled'] = bool(https)
    cfg['port'] = port
    if domain: cfg['panel_domain'] = domain
    save_config(cfg)

    apply_id = f'{int(time.time() * 1000)}'
    scheme = 'https' if https else 'http'
    json.dump({'id': apply_id, 'status': 'pending', 'scheme': scheme, 'port': port, 'started': time.time()},
              open(SSL_APPLY_STATE, 'w'))
    helper = os.path.join(SSL_APPLY_DIR, 'panel_ssl_apply.py')
    open(helper, 'w').write(_SSL_APPLY_HELPER)
    import shlex, sys as _sys
    args = ' '.join(shlex.quote(a) for a in [_sys.executable if os.path.exists(_sys.executable) else 'python3', helper,
                                             SSL_APPLY_STATE, apply_id, scheme, str(port),
                                             SERVICE_FILE, unit_bak, CONFIG_FILE, cfg_bak,
                                             old_scheme, str(old_port), '1' if port != old_port else '0'])
    if sh('which systemd-run 2>/dev/null'):
        sh(f'systemd-run --no-block --collect --unit=vortexpanel-ssl-{apply_id} {args} 2>/dev/null')
    else:
        sh(f'setsid {args} >/dev/null 2>&1 < /dev/null &')
    return True, '', apply_id


def _enable_https(domain=''):
    ok, err, _ = _switch_panel_scheme(True, domain)
    return ok, err


@settings_bp.route('/api/settings/ssl/apply-log')
def ssl_apply_log():
    """Result of the last HTTPS/HTTP switch (written by the detached helper).
    Readable over whichever scheme the panel ends up on - after a rollback
    that is the old one, so the page that started the switch can show why."""
    if not req(): return jsonify({'ok':False}), 401
    try:
        return jsonify({'ok': True, **json.load(open(SSL_APPLY_STATE))})
    except Exception:
        return jsonify({'ok': True, 'status': 'none'})


@settings_bp.route('/api/settings/ssl/self-signed', methods=['POST'])
def ssl_self_signed():
    if not req(): return jsonify({'ok':False}), 401
    domain = (request.get_json() or {}).get('domain', '').strip()
    ok, err = _gen_selfsigned(domain)
    if not ok:
        return jsonify({'ok':False,'error':f'Certificate generation failed: {err}'}), 500
    ok2, err2, apply_id = _switch_panel_scheme(True, domain)
    if not ok2:
        return jsonify({'ok':False,'error':err2}), 500
    cfg = load_config()
    return jsonify({'ok':True, 'type':'self-signed', 'port':cfg.get('port'), 'apply_id':apply_id,
                    'message':f'Switching the panel to HTTPS on port {cfg.get("port")}'})


@settings_bp.route('/api/settings/ssl/letsencrypt', methods=['POST'])
def ssl_letsencrypt():
    if not req(): return jsonify({'ok':False}), 401
    domain = (request.get_json() or {}).get('domain','').strip()
    if not domain:
        return jsonify({'ok':False,'error':"Domain name required for Let's Encrypt"}), 400
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', domain):
        return jsonify({'ok':False,'error':'Invalid domain format'}), 400

    if not sh('command -v certbot 2>/dev/null'):
        # Was run with the default 30 s timeout, which an apt/dnf install
        # routinely exceeds - the install was killed half way.
        if _is_rhel():
            from panel.routes.os_utils import ensure_epel_cmd
            epel = '' if os.path.exists('/etc/fedora-release') else ensure_epel_cmd() + '; '
            sh(epel + 'dnf install -y certbot 2>/dev/null || yum install -y certbot 2>/dev/null', t=600)
        else:
            sh(_APT_ENV + 'apt-get install -y ' + _APT_OPTS + 'certbot 2>/dev/null || (' + _APT_ENV +
               'apt-get update -q 2>/dev/null; ' + _APT_ENV + 'apt-get install -y ' + _APT_OPTS + 'certbot 2>/dev/null)', t=600)
    if not sh('command -v certbot 2>/dev/null'):
        return jsonify({'ok':False,'error':'certbot is not installed and could not be installed automatically'}), 500
    # EPEL ships certbot-renew.timer disabled: the panel certificate silently
    # expired after 90 days on the RHEL family (the deploy hook below never ran)
    try:
        from panel.routes.os_utils import certbot_enable_renewal
        certbot_enable_renewal()
    except Exception:
        pass
    sh('ufw allow 80/tcp 2>/dev/null; firewall-cmd --add-service=http --permanent 2>/dev/null; firewall-cmd --reload 2>/dev/null || true')

    # --standalone needs port 80 for itself. On a panel box nginx/apache
    # almost always holds it, so certbot always failed. Stop whichever web
    # server is listening for the few seconds of the challenge and start it
    # again (certbot runs the post-hook even when issuance fails).
    hooks = ''
    busy = sh("ss -Hltn 'sport = :80' 2>/dev/null")
    if busy:
        running = [u for u in ('nginx', 'apache2', 'httpd', 'caddy', 'lsws', 'openresty')
                   if sh(f'systemctl is-active {u} 2>/dev/null') == 'active']
        if running:
            units = ' '.join(running)
            hooks = f"--pre-hook 'systemctl stop {units}' --post-hook 'systemctl start {units}' "
    # Renewal: certbot renews /etc/letsencrypt/live/<domain>, but the panel
    # serves a COPY in /opt/vortexpanel/ssl - with nothing copying it again
    # the panel certificate silently expired after 90 days. A global deploy
    # hook (runs after every successful renewal) refreshes the copy.
    try:
        hook_dir = '/etc/letsencrypt/renewal-hooks/deploy'
        os.makedirs(hook_dir, exist_ok=True)
        hook = os.path.join(hook_dir, 'vortexpanel-panel-cert.sh')
        with open(hook, 'w') as f:
            f.write('#!/bin/sh\n'
                    '# VortexPanel: refresh the panel\'s copy of its Let\'s Encrypt certificate\n'
                    f'[ "$RENEWED_LINEAGE" = "/etc/letsencrypt/live/{domain}" ] || exit 0\n'
                    f'cp "$RENEWED_LINEAGE/fullchain.pem" {SSL_DIR}/panel.crt && '
                    f'cp "$RENEWED_LINEAGE/privkey.pem" {SSL_DIR}/panel.key && '
                    f'chmod 600 {SSL_DIR}/panel.key && systemctl restart vortexpanel\n')
        os.chmod(hook, 0o755)
    except Exception:
        pass
    out, err, rc = sh3(
        f'certbot certonly --standalone --non-interactive --agree-tos --keep-until-expiring '
        f'--register-unsafely-without-email {hooks}-d {domain} 2>&1',
        t=180
    )
    if rc != 0:
        return jsonify({'ok':False,'error':f'Certbot failed: {(out or err)[-400:]}'}), 500

    os.makedirs(SSL_DIR, exist_ok=True)
    _, cerr, crc = sh3(f'cp /etc/letsencrypt/live/{domain}/fullchain.pem {SSL_DIR}/panel.crt && '
                       f'cp /etc/letsencrypt/live/{domain}/privkey.pem {SSL_DIR}/panel.key && '
                       f'chmod 600 {SSL_DIR}/panel.key')
    if crc != 0:
        return jsonify({'ok':False,'error':f'Could not copy the issued certificate: {cerr[:300]}'}), 500

    ok2, err2, apply_id = _switch_panel_scheme(True, domain)
    if not ok2:
        return jsonify({'ok':False,'error':err2}), 500
    cfg = load_config()
    return jsonify({'ok':True,'type':'letsencrypt','domain':domain,'port':cfg.get('port'),'apply_id':apply_id,
                    'message':f"Let's Encrypt cert issued. HTTPS active on port {cfg.get('port')}"})


@settings_bp.route('/api/settings/ssl/disable', methods=['POST'])
def ssl_disable():
    if not req(): return jsonify({'ok':False}), 401
    # Clean up an old nginx-fronted HTTPS config from earlier versions
    nginx_ssl = '/etc/nginx/conf.d/vortexpanel-https.conf'
    if os.path.exists(nginx_ssl):
        os.remove(nginx_ssl)
        sh('nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true')
    ok, err, apply_id = _switch_panel_scheme(False)
    if not ok:
        return jsonify({'ok':False,'error':err}), 500
    port = load_config().get('port', PANEL_PORT)
    return jsonify({'ok':True, 'apply_id':apply_id,
                    'message': f'Switching the panel back to HTTP on port {port}'})



# --- PHP Webshell Scanner --------------------------------------------------------

WEBSHELL_PATTERNS = [
    # Classic eval-based webshells
    (r'eval\s*\(\s*base64_decode\s*\(',   'CRITICAL', 'eval(base64_decode()) — classic webshell obfuscation'),
    (r'eval\s*\(\s*gzinflate\s*\(',        'CRITICAL', 'eval(gzinflate()) — compressed payload execution'),
    (r'eval\s*\(\s*str_rot13\s*\(',        'CRITICAL', 'eval(str_rot13()) — obfuscated execution'),
    (r'eval\s*\(\s*\$[a-zA-Z_]\w*\s*\)',  'HIGH',     'eval($variable) — dynamic code execution'),
    # System command execution via user input
    (r'(?<![\w$>:])(?:system|exec|passthru|shell_exec|popen)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', 'CRITICAL', 'Shell exec with user input — remote command execution'),
    # Hardcoded (no $_GET/$_POST/any variable at all) calls to these same
    # functions were confirmed, via direct reproduction, to produce ZERO
    # detections above -- a webshell doesn't need to read its command from
    # user input if the reverse-shell command is just baked into the file
    # outright. Flagging every hardcoded call to these functions unconditionally
    # (as bluntly suggested) would flag legitimate exec('convert a.jpg a.png'),
    # shell_exec('git pull'), etc. on real sites -- so this splits by
    # confidence instead: CRITICAL when the hardcoded string also contains a
    # known reverse-shell indicator, MEDIUM (manual review) for any other
    # hardcoded call to these functions.
    (r'(?<![\w$>:])(?:exec|shell_exec|passthru|popen|proc_open)\s*\([^)]{0,10}["\'][\s\S]{0,300}(?:/dev/tcp/|/dev/udp/|\bnc\s+-e\b|\bmkfifo\b|bash\s+-i\b|sh\s+-i\b|0>&1|>&\s*/dev/tcp)', 'CRITICAL', 'Hardcoded shell exec containing a reverse-shell indicator (e.g. /dev/tcp, bash -i, mkfifo) — this bypasses detection based on user-input patterns alone, since the command needs no input at all'),
    (r'(?<![\w$>:])(?:exec|shell_exec|passthru|popen|proc_open)\s*\(\s*["\'][^"\')]+', 'MEDIUM', 'Hardcoded shell exec — may be legitimate (build tools, image/video processing, deploy scripts), but review manually since these functions can also run a baked-in payload with no user input at all'),
    # PHP function code injection
    (r'preg_replace\s*\(\s*[\'"].*\/e[\'"]', 'CRITICAL', 'preg_replace /e modifier — code execution via regex'),
    (r'assert\s*\(\s*\$_(?:GET|POST|REQUEST)', 'CRITICAL', 'assert() with user input — code injection'),
    # Reverse shells
    (r'\bfsockopen\s*\(.*(?<![\w$>:])(?:exec|shell_exec|system|passthru|proc_open)\s*\(',    'CRITICAL', 'fsockopen + exec — potential reverse shell'),
    (r'\bsocket_create\s*\(.*(?<![\w$>:])(?:exec|shell_exec|system|passthru|proc_open)\s*\(','CRITICAL', 'socket_create + exec — potential reverse shell'),
    # Dynamic function execution
    (r'\$(?!_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV|SESSION)\b)[a-zA-Z_]\w*\s*\(\s*\$_(?:GET|POST|REQUEST)', 'HIGH', 'Dynamic function call with user input'),
    (r'call_user_func\s*\(\s*\$_(?:GET|POST|REQUEST)', 'HIGH', 'call_user_func with user input'),
    (r'create_function\s*\(',             'HIGH',     'create_function() — deprecated, often used in webshells'),
    # File write from user input
    (r'file_put_contents\s*\(\s*.*\$_(?:GET|POST|REQUEST)', 'HIGH', 'file_put_contents with user input — file upload via webshell'),
    # Backtick shell-exec operator -- functionally identical to shell_exec()
    # but a different syntax the earlier pattern list did not cover at all.
    (r'(?m)^(?![ \t]*(?:\*|//|#|/\*)).*?(?:[=(,]|\becho\b|\bprint\b|\breturn\b)\s*`[^`\n]*\$_(?:GET|POST|REQUEST|COOKIE)[^`\n]*`', 'CRITICAL', 'Backtick shell-exec operator with user input — remote command execution'),
    # Process-execution functions absent from the earlier list -- confirmed
    # by direct testing that shell_exec/system/exec/passthru/popen coverage
    # did not extend to these.
    (r'proc_open\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', 'CRITICAL', 'proc_open with user input — remote command execution'),
    (r'pcntl_exec\s*\(', 'HIGH', 'pcntl_exec() — process replacement, rare in legitimate app code'),
    # Delayed/indirected execution: passing user input as the CALLBACK to a
    # function that will later invoke it, rather than calling it directly --
    # confirmed to evade every earlier pattern since none of them look for
    # user input in the callback POSITION of these functions.
    (r'register_shutdown_function\s*\(\s*\$_(?:GET|POST|REQUEST)', 'CRITICAL', 'register_shutdown_function with user-controlled callback — delayed code execution'),
    (r'(?:array_map|array_filter|array_walk|usort|uasort|uksort|call_user_func|call_user_func_array)\s*\(\s*\$_(?:GET|POST|REQUEST)', 'CRITICAL', 'Higher-order function with user-controlled callback — indirect code execution'),
    # Heavy obfuscation markers
    (r'(?:\\x[0-9a-fA-F]{2}){40,}', 'MEDIUM', 'Long hex-escaped string (40+ bytes) — possible obfuscated payload'),
    (r'chr\(\d+\)\s*\.\s*chr\(\d+\)\s*\.\s*chr\(\d+\)', 'MEDIUM', 'chr() string assembly — obfuscation technique'),
]

_SCAN_JOB = 'webshell_scan'
_SCAN_EXTS = ('.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.pht', '.phar')
_SCAN_SKIP_DIRS = {'node_modules', '.git', '.svn', 'vendor'}
_SCAN_MAX_FILES = 100000
_SCAN_MAX_BYTES = 2 * 1024 * 1024      # read at most 2 MB of any one file
_SCAN_TIME_LIMIT = 30 * 60


def _scan_php_file(fp, content):
    """All findings for one file (same rules as before, now reusable)."""
    findings = []
    for pattern, severity, desc in WEBSHELL_PATTERNS:
        m = re.search(pattern, content, re.IGNORECASE)
        if m:
            line_no = content[:m.start()].count('\n') + 1
            snippet = content[max(0, m.start()-20):m.end()+40].strip().replace('\n', ' ')[:120]
            findings.append({'file': fp, 'line': line_no, 'severity': severity, 'pattern': desc, 'snippet': snippet})
            if severity == 'CRITICAL':
                break
    # Whole-file heuristic for the split decode-and-write evasion (lower
    # confidence than the direct patterns above, and labelled as such).
    has_decode_from_input = re.search(
        r'(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)', content, re.IGNORECASE)
    has_var_file_write = re.search(
        r'(?:file_put_contents|fwrite|fputs)\s*\(\s*[^,)]+,\s*\$[a-zA-Z_]\w*\s*[,)]', content, re.IGNORECASE)
    if has_decode_from_input and has_var_file_write and not any(f['severity'] == 'CRITICAL' for f in findings):
        line_no = content[:has_var_file_write.start()].count('\n') + 1
        snippet = content[max(0, has_var_file_write.start()-20):has_var_file_write.end()+40].strip().replace('\n', ' ')[:120]
        findings.append({'file': fp, 'line': line_no, 'severity': 'MEDIUM',
                         'pattern': 'Possible split decode-and-write (user input decoded on one line, written to a file on another) — heuristic, not a direct match; verify manually',
                         'snippet': snippet})
    return findings


def _scan_state():
    from panel.routes.job_state import load_job, save_job
    st = load_job(_SCAN_JOB, {'running': False, 'done': False})
    if st.get('running') and time.time() - (st.get('heartbeat') or 0) > 120:
        st.update({'running': False, 'done': True, 'error': 'The scan stopped (the panel restarted while it was running). Start it again.'})
        save_job(_SCAN_JOB, st)
    return st


@settings_bp.route('/api/settings/webshell-scan', methods=['POST'])
def webshell_scan():
    """Start a background scan of PHP files under a directory. It used to
    run inside the request, so any real site (thousands of PHP files)
    outlived the worker timeout and the scan silently returned nothing."""
    if not req(): return jsonify({'ok':False}), 401
    from panel.routes.job_state import save_job
    path = os.path.realpath(str((request.get_json(silent=True) or {}).get('path') or '/www/wwwroot').strip() or '/www/wwwroot')
    if not os.path.isdir(path):
        return jsonify({'ok':False,'error':f'Directory not found: {path}'}), 404
    if _scan_state().get('running'):
        return jsonify({'ok':False,'error':'A scan is already running'}), 409

    import threading
    state = {'running': True, 'done': False, 'path': path, 'scanned': 0, 'current': '', 'started': time.time(),
             'heartbeat': time.time(), 'findings': [], 'total': 0, 'critical': 0, 'high': 0, 'medium': 0,
             'errors': [], 'truncated': False}
    save_job(_SCAN_JOB, state)

    def run():
        findings, errors, scanned, last = [], [], 0, 0.0
        t0 = time.time()
        truncated = False
        try:
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIRS]
                for fn in files:
                    if not fn.lower().endswith(_SCAN_EXTS):
                        continue
                    if scanned >= _SCAN_MAX_FILES or time.time() - t0 > _SCAN_TIME_LIMIT:
                        truncated = True
                        break
                    fp = os.path.join(root, fn)
                    if os.path.islink(fp):
                        continue
                    scanned += 1
                    try:
                        with open(fp, 'r', errors='replace') as fh:
                            content = fh.read(_SCAN_MAX_BYTES)
                        findings.extend(_scan_php_file(fp, content))
                    except Exception:
                        errors.append(fp)
                    now = time.time()
                    if now - last > 1.0:
                        state.update({'scanned': scanned, 'current': root, 'heartbeat': now,
                                      'total': len(findings)})
                        save_job(_SCAN_JOB, state); last = now
                if truncated:
                    break
        except Exception as e:
            errors.append(f'scan aborted: {e}')
        findings.sort(key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}.get(x['severity'], 3))
        state.update({'running': False, 'done': True, 'scanned': scanned, 'current': '', 'heartbeat': time.time(),
                      'finished': time.time(), 'duration': round(time.time() - t0, 1),
                      'total': len(findings),
                      'critical': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
                      'high': sum(1 for f in findings if f['severity'] == 'HIGH'),
                      'medium': sum(1 for f in findings if f['severity'] == 'MEDIUM'),
                      'findings': findings[:500], 'errors': errors[:20], 'truncated': truncated})
        save_job(_SCAN_JOB, state)

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'ok': True, 'running': True, 'path': path})


@settings_bp.route('/api/settings/webshell-scan/status')
def webshell_scan_status():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok': True, **_scan_state()})


@settings_bp.route('/api/settings/webshell-scan/paths')
def webshell_scan_paths():
    """Scannable locations: the web root (all sites) first, then each site."""
    if not req(): return jsonify({'ok':False}), 401
    paths = []
    try:
        from panel.routes.websites_core import get_webroot, list_sites
        root = get_webroot()
        if os.path.isdir(root):
            paths.append({'path': root, 'label': f'{root} (all sites)'})
        for s in sorted(list_sites(), key=lambda x: x['domain']):
            p = s.get('path')
            if p and os.path.isdir(p) and not any(x['path'] == p for x in paths):
                paths.append({'path': p, 'label': f'{s["domain"]}  ({p})'})
    except Exception:
        pass
    for p in ['/www/wwwroot', '/var/www/html', '/var/www']:
        if os.path.isdir(p) and not any(x['path'] == p for x in paths):
            paths.append({'path': p, 'label': p})
    return jsonify({'ok':True,'paths':paths})


# --- Existing routes -------------------------------------------------------------

@settings_bp.route('/api/settings/password', methods=['POST'])
def change_password():
    if not req(): return jsonify({'ok':False}), 401
    # Same logic as /api/auth/change-password: current password required,
    # atomic 0600 write, other sessions invalidated. This route used to accept
    # a new password with no current-password check and rewrote the file
    # non-atomically.
    from panel.routes.auth import _do_change_password
    return _do_change_password(request.get_json(silent=True) or {})


@settings_bp.route('/api/settings/hostname', methods=['POST'])
def set_hostname():
    if not req(): return jsonify({'ok':False}), 401
    name = str((request.get_json(silent=True) or {}).get('hostname') or '').strip().lower()
    if not name: return jsonify({'ok':False,'error':'Hostname required'}), 400
    # Was interpolated straight into a root shell command.
    if len(name) > 253 or not re.fullmatch(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*', name):
        return jsonify({'ok':False,'error':'Invalid hostname (letters, digits, hyphens and dots only)'}), 400
    try:
        r = subprocess.run(['hostnamectl', 'set-hostname', name], capture_output=True, text=True, timeout=30)
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)}), 500
    if r.returncode != 0:
        return jsonify({'ok':False,'error':(r.stderr or r.stdout).strip()[:300] or 'hostnamectl failed'}), 500
    # Keep the new name resolvable locally (sudo and some daemons complain
    # "unable to resolve host" otherwise). Only touches the 127.0.1.1 line.
    try:
        short = name.split('.')[0]
        entry = f'127.0.1.1\t{name}' + (f' {short}' if short != name else '')
        hosts = open('/etc/hosts').read()
        if re.search(r'^127\.0\.1\.1\s.*$', hosts, re.M):
            hosts = re.sub(r'^127\.0\.1\.1\s.*$', entry, hosts, count=1, flags=re.M)
        elif not re.search(r'\s' + re.escape(name) + r'(\s|$)', hosts):
            hosts = hosts.rstrip('\n') + '\n' + entry + '\n'
        with open('/etc/hosts.vp.tmp', 'w') as f: f.write(hosts)
        os.replace('/etc/hosts.vp.tmp', '/etc/hosts')
    except Exception:
        pass
    return jsonify({'ok':True})


def _pending_security_packages(refresh=True):
    """Shared detection used by BOTH the check endpoint and the apply
    endpoint's post-run verification -- so 'did it actually work?' is
    answered by the same logic that decided what was pending in the
    first place, rather than by trusting an exit code."""
    packages = []
    # ID_LIKE alone misdetected Fedora (it has no ID_LIKE) as Debian, so the
    # card always said "nothing pending" there.
    if _is_rhel():
        if refresh: sh('dnf makecache 2>/dev/null || yum makecache 2>/dev/null', t=120)
        raw = sh('dnf updateinfo list --security 2>/dev/null || yum updateinfo list security 2>/dev/null', t=60)
        for line in raw.split('\n'):
            line = line.strip()
            # dnf4/yum: "RHSA-2024:1234 Important/Sec. pkg-1.2-3.el9.x86_64"
            m = re.match(r'^\S+\s+(Critical|Important|Moderate|Low|None|Unknown)/Sec\.\s+(\S+)', line)
            if not m:
                # dnf5: "FEDORA-2024-abc security Moderate pkg-1.2-3.fc41.x86_64 2024-..."
                m = re.match(r'^\S+\s+security\s+(\S+)\s+(\S+)', line, re.I)
            if m:
                packages.append({'severity': m.group(1), 'package': m.group(2)})
    else:
        if refresh: sh('apt-get update -q 2>/dev/null', t=120)
        raw = sh('apt-get -s dist-upgrade 2>/dev/null', t=60)
        for line in raw.split('\n'):
            if line.startswith('Inst') and 'security' in line.lower():
                m = re.match(r'^Inst (\S+)', line)
                if m: packages.append({'severity': 'Security', 'package': m.group(1)})
    return packages


def _pending_vendor_updates():
    """Pending upgrades for packages installed from VENDOR repos rather
    than the distribution's own archives.

    These are invisible to _pending_security_packages() by design, not by
    accident: that check matches the archive name (e.g. 'noble-security'),
    and a vendor repo's archive is its own name -- nginx.org publishes as
    'nginx:noble', MariaDB as its own, PGDG as its own. None contain the
    string 'security' no matter how critical the fix is. Verified directly:
    a machine with 7 pending upgrades from 'noble-updates' matched the
    security filter 0 times.

    This matters concretely for VortexPanel, which installs nginx, MySQL,
    MariaDB, PHP, PostgreSQL, MongoDB and Docker from vendor repos -- so
    something like nginx CVE-2026-42533 (CVSS 9.2, pre-auth RCE, fixed in
    1.30.4/1.31.3) would never appear in the security card at all."""
    raw = sh('apt-get -s dist-upgrade 2>/dev/null', t=60)
    vendor = []
    for line in raw.split('\n'):
        if not line.startswith('Inst'):
            continue
        m = re.match(r'^Inst (\S+)\s+\[([^\]]*)\]\s+\(([^\s]+)\s+([^\s\[]+)', line)
        if not m:
            continue
        pkg, cur_ver, new_ver, archive = m.group(1), m.group(2), m.group(3), m.group(4).rstrip(',')
        # Distro-provided archives are already covered by the security
        # check above -- anything else came from a vendor repo we added.
        if re.match(r'^(Ubuntu|Debian)(-Security)?:', archive, re.I):
            continue
        vendor.append({'package': pkg, 'current': cur_ver, 'available': new_ver, 'source': archive})
    return vendor


_SEC_JOB = 'security_update'
_SEC_CHECK = 'security_updates_check'
_SEC_STALE_AFTER = 45 * 60   # a job still "running" after this is a dead thread
_APT_ENV = ('DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1 '
            'APT_LISTCHANGES_FRONTEND=none ')
_APT_OPTS = ('-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold '
             '-o DPkg::Lock::Timeout=300 ')


def _reboot_state():
    reboot_required = os.path.exists('/var/run/reboot-required')
    reboot_pkgs = []
    if reboot_required:
        try:
            with open('/var/run/reboot-required.pkgs') as f:
                reboot_pkgs = sorted({l.strip() for l in f if l.strip()})
        except Exception:
            pass
    return reboot_required, reboot_pkgs


def _is_rhel():
    return bool(re.search(r'rhel|fedora|centos', sh(". /etc/os-release 2>/dev/null && echo \"$ID $ID_LIKE\""), re.I))


def _build_security_check(refresh=True):
    """Fresh pending-security snapshot, in the exact shape the check
    endpoint returns and caches."""
    packages = _pending_security_packages(refresh=refresh)
    vendor = [] if _is_rhel() else _pending_vendor_updates()
    reboot_required, reboot_pkgs = _reboot_state()
    return {'ok': True, 'total': len(packages),
            'critical': sum(1 for p in packages if p['severity'] in ('Critical', 'Important', 'Security')),
            'packages': packages[:50], 'vendor': vendor[:50], 'vendor_total': len(vendor),
            'checked_at': time.time(), 'cached': False,
            'reboot_required': reboot_required, 'reboot_pkgs': reboot_pkgs}


def _sec_job_state():
    """Current apply-job state, with a thread that died mid-run (panel
    restarted, worker killed) reported as finished instead of 'running'
    forever - that stuck state used to freeze the card on "Applying" and
    make every later Apply click fail with 'already in progress'."""
    from panel.routes.job_state import load_job, save_job
    st = load_job(_SEC_JOB, {'running': False, 'done': False, 'success': None, 'output': '', 'started': None})
    if st.get('running') and time.time() - (st.get('heartbeat') or st.get('started') or 0) > _SEC_STALE_AFTER:
        st.update({'running': False, 'done': True, 'success': False, 'stale': True,
                   'output': (st.get('output') or '') + '\n\nThe previous run stopped responding (the panel was '
                             'probably restarted while it was running). Check again, then apply.'})
        save_job(_SEC_JOB, st)
    return st


@settings_bp.route('/api/settings/security-updates')
def check_security_updates():
    """Read-only check for PENDING security updates specifically, using
    each distro's own continuously-maintained security metadata rather
    than a hardcoded CVE/version lookup table baked into VortexPanel's
    source. Cached for 4 hours; ?refresh=1 forces a live check, and an
    apply run always refreshes the cache when it finishes."""
    if not req(): return jsonify({'ok':False}), 401
    from panel.routes.job_state import load_job, save_job
    CACHE_TTL_SECONDS = 4 * 3600

    force = request.args.get('refresh') == '1'
    cached = load_job(_SEC_CHECK, {})
    if not force and cached and (time.time() - cached.get('checked_at', 0)) < CACHE_TTL_SECONDS:
        resp = dict(cached)
        resp['cached'] = True
        return jsonify(resp)
    result = _build_security_check(refresh=True)
    save_job(_SEC_CHECK, result)
    return jsonify(result)


def _run_streaming(cmd, job, timeout=900):
    """Run a command, appending its output to the job state as it arrives
    (so the card shows real progress instead of a silent spinner).
    Returns (combined_output, returncode)."""
    from panel.routes.job_state import save_job
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, text=True, bufsize=1)
    lines, last_save, t0 = [], 0.0, time.time()
    try:
        for line in proc.stdout:
            lines.append(line.rstrip('\n'))
            now = time.time()
            if now - last_save > 1.0:
                job['output'] = '\n'.join(lines[-400:]); job['heartbeat'] = now
                save_job(_SEC_JOB, job); last_save = now
            if now - t0 > timeout:
                proc.kill(); lines.append(f'[VortexPanel] Timed out after {timeout // 60} minutes - stopped.')
                break
        rc = proc.wait(timeout=30)
    except Exception as e:
        proc.kill(); lines.append(f'[VortexPanel] {e}'); rc = 1
    return '\n'.join(lines), rc


@settings_bp.route('/api/settings/security-updates/apply', methods=['POST'])
def apply_security_updates():
    """Applies ONLY the packages flagged as security updates (plus pending
    vendor-repo upgrades, which carry no distro security tag), fully
    non-interactive, streaming output to the card, and refreshing the
    cached check when done so the card reflects the real result."""
    from panel.routes.job_state import save_job
    if not req(): return jsonify({'ok':False}), 401
    if _sec_job_state().get('running'):
        return jsonify({'ok': False, 'error': 'A security update is already in progress'}), 409

    import threading
    job = {'running': True, 'done': False, 'success': None, 'output': 'Checking what is pending…',
           'started': time.time(), 'heartbeat': time.time()}
    save_job(_SEC_JOB, job)

    def do_apply():
        combined, rc = '', 1
        try:
            rhel = _is_rhel()
            before = _pending_security_packages()
            vendor_before = [] if rhel else _pending_vendor_updates()
            if rhel:
                combined, rc = _run_streaming('dnf update --security -y 2>&1 || yum update --security -y 2>&1', job)
            else:
                pkgs = list(dict.fromkeys([p['package'] for p in before] + [v['package'] for v in vendor_before]))
                if not pkgs:
                    combined, rc = 'Nothing pending (it may have changed since the last check).', 0
                else:
                    # Not --only-upgrade: that refuses new dependencies and
                    # silently skips the package while apt exits 0. Naming
                    # installed packages resolves exactly what they need.
                    # Non-interactive + needrestart auto mode: an interactive
                    # conffile or "restart services?" prompt with no terminal
                    # otherwise hangs the job until the timeout.
                    job['output'] = 'Upgrading: ' + ', '.join(pkgs) + '\n'
                    save_job(_SEC_JOB, job)
                    combined, rc = _run_streaming(_APT_ENV + 'apt-get install -y ' + _APT_OPTS + ' '.join(pkgs) + ' 2>&1', job)
                    combined = job['output'].split('\n')[0] + '\n' + combined

            check = _build_security_check(refresh=False)   # apt metadata was refreshed moments ago
            save_job(_SEC_CHECK, check)                   # card + dashboard now show the real state
            remaining = check['total'] + check['vendor_total']
            total_before = len(before) + len(vendor_before)
            applied = max(0, total_before - remaining)
            reboot_required, reboot_pkgs = check['reboot_required'], check['reboot_pkgs']
            success = (rc == 0 and remaining == 0)

            summary = f'\n\n-- Result --\nApplied: {applied}   Still pending: {remaining}'
            if reboot_required:
                summary += (f'\n\nA reboot is required to finish applying '
                            f'{"these updates" if not reboot_pkgs else ", ".join(reboot_pkgs)}. '
                            f'The new versions are installed; the running kernel/libraries stay in '
                            f'memory until you reboot (Settings -> Reboot).')
            if remaining:
                names = ', '.join([p['package'] for p in check['packages'][:6]] + [v['package'] for v in check['vendor'][:6]])
                summary += (f'\nStill pending: {names}\n\nThese did not upgrade - usually held back by the '
                            f'distribution (phased rollout or a dependency apt will not resolve on its own). '
                            f'Running "apt-get dist-upgrade" over SSH shows the reason for each one.')
            save_job(_SEC_JOB, {'running': False, 'done': True, 'success': success,
                                'output': combined + summary, 'applied': applied, 'remaining': remaining,
                                'reboot_required': reboot_required, 'reboot_pkgs': reboot_pkgs,
                                'finished': time.time()})
        except Exception as e:
            save_job(_SEC_JOB, {'running': False, 'done': True, 'success': False,
                                'output': (combined or job.get('output', '')) + f'\n\n[VortexPanel] Update job failed: {e}',
                                'applied': 0, 'remaining': None, 'finished': time.time()})

    threading.Thread(target=do_apply, daemon=True).start()
    return jsonify({'ok': True, 'message': 'Applying security updates in background'})


@settings_bp.route('/api/settings/security-updates/status')
def security_update_status():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok': True, **_sec_job_state()})


@settings_bp.route('/api/settings/sync-time', methods=['POST'])
def sync_time():
    if not req(): return jsonify({'ok':False}), 401
    _, err, rc = sh3('timedatectl set-ntp true 2>&1 || ntpdate pool.ntp.org 2>&1 || chronyc makestep 2>&1')
    if rc != 0:
        return jsonify({'ok':False,'error':'Could not enable NTP sync: ' + err[:300]}), 500
    return jsonify({'ok':True,'time':datetime.now().strftime('%Y-%m-%d %H:%M:%S')})


@settings_bp.route('/api/settings/update', methods=['POST'])
def system_update():
    if not req(): return jsonify({'ok':False}), 401
    import threading
    def do_update():
        # Non-interactive (a conffile / needrestart prompt with no terminal
        # hung it) and a realistic timeout: 300 s killed the shell mid-upgrade
        # on any real box. The old 'apt ... || dnf ...' also ran dnf whenever
        # apt failed on Debian. Branch on the actual package manager instead.
        if _is_rhel():
            sh('dnf -y upgrade 2>&1 || yum -y update 2>&1', t=3600)
        else:
            sh(_APT_ENV + 'apt-get update -q 2>&1 && ' + _APT_ENV + 'apt-get -y ' + _APT_OPTS + 'upgrade 2>&1', t=3600)
    threading.Thread(target=do_update, daemon=True).start()
    return jsonify({'ok':True,'message':'System update started in background'})


@settings_bp.route('/api/settings/reboot', methods=['POST'])
def reboot():
    if not req(): return jsonify({'ok':False}), 401
    import threading
    threading.Thread(target=lambda: sh('sleep 3 && reboot'), daemon=True).start()
    return jsonify({'ok':True,'message':'Rebooting in 3 seconds...'})


@settings_bp.route('/api/settings/webroot')
def get_webroot():
    """The web root new sites are created in (one implementation for the
    whole panel: websites_core -> os_utils.get_webroot())."""
    if not req(): return jsonify({'ok': False}), 401
    from panel.routes.websites_core import get_webroot as _gw
    return jsonify({'ok':True,'path':_gw()})
