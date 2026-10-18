#!/usr/bin/env python3
"""VortexPanel - main application (Flask, served by gunicorn)."""
import os, sys, secrets, json
from datetime import timedelta
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, g, jsonify, session, redirect, send_from_directory, Response
try:
    from flask_compress import Compress
    _compress_available = True
except ImportError:
    _compress_available = False

try:
    from flask_session import Session as FlaskSession
    _server_session_available = True
except ImportError:
    _server_session_available = False

from panel.routes.auth      import auth_bp
from panel.routes.dashboard import dashboard_bp
from panel.routes.websites_core import websites_bp
from panel.routes.websites_ssl import *  # noqa
from panel.routes.websites_proxy import *  # noqa
from panel.routes.websites_security import *  # noqa
from panel.routes.websites_nodejs import *  # noqa
from panel.routes.websites_extras import *  # noqa
from panel.routes.http3 import *  # noqa
from panel.routes.websites_deploy import *  # noqa
from panel.routes.websites_composer import *  # noqa
from panel.routes.websites_clone import *  # noqa
from panel.routes.websites_git import *  # noqa
from panel.routes.websites_integrity import *  # noqa
from panel.routes.databases import databases_bp
from panel.routes.files     import files_bp
from panel.routes.php       import php_bp
from panel.routes.services  import services_bp
from panel.routes.firewall  import firewall_bp
from panel.routes.terminal  import terminal_bp
from panel.routes.backups   import backups_bp
from panel.routes.dns       import dns_bp
from panel.routes.mail      import mail_bp
from panel.routes.livepatch import livepatch_bp
from panel.routes.ftp       import ftp_bp
from panel.routes.cron      import cron_bp
from panel.routes.docker    import docker_bp
from panel.routes.update    import update_bp
from panel.routes.ai        import ai_bp
from panel.routes.monitoring import monitoring_bp
from panel.routes.settings  import settings_bp
from panel.routes.main      import main_bp
from panel.routes.ddns      import ddns_bp
from panel.routes.modules   import modules_bp
from panel.routes.security  import security_bp
from panel.routes.caddy      import caddy_bp
from panel.routes.wp_toolkit import wp_bp
from panel.routes.cdn       import cdn_bp
from panel.routes.bandwidth import bandwidth_bp
from panel.routes.terminal_ws import sock as terminal_sock
from panel.routes.cloud_backup import cloud_backup_bp
from panel.routes.logs import logs_bp
from panel.routes.nodejs_projects import nodejs_bp
from panel.routes.go_projects import go_bp
from panel.routes.import_website import import_bp
from panel.routes.acme import acme_bp
from panel.routes.migration import migration_bp
from panel.routes.bot_protection import botprot_bp
from panel.routes.licence_routes import licence_bp
from panel.routes.onboarding import onboarding_bp
from panel.routes.diskusage import disk_bp
from panel.routes.users_admin import users_bp
from panel.routes.storage_routes import storage_bp
from panel.routes.alerts_routes import alerts_bp
from panel.routes.plugins_routes import plugins_bp
from panel.routes.python_projects import python_bp

# -- Secret key: auto-generate and persist on first run -----------------------
_SECRET_KEY_FILE = '/opt/vortexpanel/secret.key'

def _get_secret_key() -> bytes:
    """
    Load secret key from file if it exists, otherwise generate a new
    64-byte random key and save it.  The hardcoded fallback is only used
    when the install directory isn't writable (e.g. CI/test environments).
    """
    def _read():
        try:
            with open(_SECRET_KEY_FILE, 'rb') as f:
                k = f.read()
            return k if len(k) >= 32 else None
        except Exception:
            return None
    key = _read()
    if key:
        return key
    # Generate a new key. gunicorn imports this module in each of its 4
    # workers at the same moment on first start; with a plain write every
    # worker kept its OWN random key, so a login made on one worker was
    # rejected by the other three until the next restart. Publish the key
    # with link() (fails if the file already exists) so exactly one wins and
    # every worker then reads that one.
    key = secrets.token_bytes(64)
    try:
        os.makedirs('/opt/vortexpanel', exist_ok=True)
        tmp = f'{_SECRET_KEY_FILE}.{os.getpid()}.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(key)
        try:
            if os.path.exists(_SECRET_KEY_FILE):
                os.remove(_SECRET_KEY_FILE)   # present but too short / unreadable
            os.link(tmp, _SECRET_KEY_FILE)
        except FileExistsError:
            pass
        finally:
            try: os.unlink(tmp)
            except Exception: pass
        return _read() or key
    except Exception:
        return key


def _read_panel_config():
    try:
        import json
        with open('/opt/vortexpanel/config.json') as f:
            cfg = json.load(f)
        return cfg if isinstance(cfg, dict) else {}
    except Exception:
        return {}


_lifetime_cache = {'mtime': None}
_entrance_cache = {'mtime': None, 'path': '', 'domain': ''}

def _entrance_path():
    """The panel's secret login path ("security entrance"), '' when off.
    Cached by config.json mtime: it is read on every request."""
    try:
        mtime = os.path.getmtime('/opt/vortexpanel/config.json')
    except OSError:
        mtime = 0
    if _entrance_cache['mtime'] != mtime:
        p = str(_read_panel_config().get('security_path') or '').strip().strip('/')
        import re as _re
        _cfg = _read_panel_config()
        # Only enforced once saved by v3.7+ (older versions stored the domain
        # without enforcing it; enforcing it silently after an upgrade could
        # lock people out).
        dom = str(_cfg.get('panel_domain') or '').strip().lower().rstrip('.') if _cfg.get('panel_domain_enforced') else ''
        _entrance_cache.update(mtime=mtime, path=p if _re.fullmatch(r'[A-Za-z0-9_-]{4,64}', p) else '',
                               domain=dom if _re.fullmatch(r'[a-z0-9.-]{3,253}', dom) else '')
    return _entrance_cache['path']


def _panel_domain():
    _entrance_path()
    return _entrance_cache['domain']


def _request_is_https():
    """TLS served by gunicorn itself, or by a local reverse proxy that says so."""
    if request.is_secure:
        return True
    peer = (request.remote_addr or '').replace('::ffff:', '')
    if peer in ('127.0.0.1', '::1') or os.environ.get('VORTEX_TRUST_PROXY'):
        return request.headers.get('X-Forwarded-Proto', '').split(',')[0].strip().lower() == 'https'
    return False

def _apply_session_lifetime(app):
    try:
        mtime = os.path.getmtime('/opt/vortexpanel/config.json')
    except OSError:
        mtime = 0
    if _lifetime_cache['mtime'] == mtime:
        return
    _lifetime_cache['mtime'] = mtime
    try:
        hours = int(_read_panel_config().get('session_hours', 24))
    except (TypeError, ValueError):
        hours = 24
    app.permanent_session_lifetime = timedelta(hours=max(1, min(720, hours)))


def create_app():
    app = Flask(__name__, template_folder='web/templates', static_folder='web/static')

    # -- Secret key ------------------------------------------------------------
    # ENV var override available for Docker/container deployments
    app.secret_key = os.environ.get('SECRET_KEY', '').encode() or _get_secret_key()

    # -- Session hardening -----------------------------------------------------
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    app.config['SESSION_COOKIE_HTTPONLY']    = True
    app.config['SESSION_COOKIE_SAMESITE']    = 'Lax'
    # Set the Secure flag when the panel is served over HTTPS. Defaults to auto:
    # honour the VORTEX_HTTPS env var (set by the installer/reverse proxy), so
    # the session cookie is never sent in cleartext on HTTPS deployments while
    # still allowing plain-HTTP setups. Explicit override: SESSION_COOKIE_SECURE=1/0.
    _secure_env = os.environ.get('SESSION_COOKIE_SECURE', os.environ.get('VORTEX_HTTPS', ''))
    if _secure_env:
        app.config['SESSION_COOKIE_SECURE'] = _secure_env.lower() in ('1', 'true', 'yes', 'on')
    else:
        # Panel HTTPS (Settings -> Panel SSL) is served by gunicorn itself
        # (--certfile in the unit) and every switch restarts the service, so
        # mark the cookie Secure exactly when this process serves TLS.
        try:
            with open('/etc/systemd/system/vortexpanel.service') as _u:
                app.config['SESSION_COOKIE_SECURE'] = '--certfile' in _u.read()
        except Exception:
            app.config['SESSION_COOKIE_SECURE'] = False

    # -- Server-side sessions (survives gunicorn restarts / nginx reloads) -----
    # flask-session stores session data in files on disk; the cookie only holds
    # the session ID. This means:
    #   1. Sessions are NOT lost when gunicorn restarts or workers are recycled.
    #   2. No multi-worker race condition on secret-key generation at boot.
    #   3. Sessions can be individually invalidated server-side (logout).
    _SESSION_DIR = '/opt/vortexpanel/sessions'
    if _server_session_available:
        os.makedirs(_SESSION_DIR, mode=0o700, exist_ok=True)
        app.config['SESSION_TYPE']              = 'filesystem'
        app.config['SESSION_FILE_DIR']          = _SESSION_DIR
        app.config['SESSION_FILE_THRESHOLD']    = 500      # max session files kept
        app.config['SESSION_USE_SIGNER']        = True     # signs session ID cookie
        app.config['SESSION_PERMANENT']         = True
        FlaskSession(app)

    # -- Gzip compression ------------------------------------------------------
    if _compress_available:
        app.config['COMPRESS_MIMETYPES'] = [
            'text/html', 'application/json', 'application/javascript',
            'text/css', 'text/plain',
        ]
        app.config['COMPRESS_LEVEL']    = 6
        app.config['COMPRESS_MIN_SIZE'] = 500
        Compress(app)

    # -- Register blueprints ---------------------------------------------------
    for bp in [auth_bp, dashboard_bp, websites_bp, databases_bp, files_bp,
               php_bp, services_bp, firewall_bp, terminal_bp, backups_bp,
               dns_bp, mail_bp, ftp_bp, cron_bp, docker_bp, monitoring_bp,
               settings_bp, modules_bp, main_bp, security_bp, bandwidth_bp,
               caddy_bp, cdn_bp, update_bp, ai_bp, ddns_bp, cloud_backup_bp,
               logs_bp, wp_bp, nodejs_bp, go_bp, import_bp, livepatch_bp,
               onboarding_bp, disk_bp, users_bp, storage_bp, alerts_bp, plugins_bp, python_bp, acme_bp, migration_bp, botprot_bp, licence_bp]:
        app.register_blueprint(bp)
    # Add-on modules from /opt/vortexpanel/plugins. Each is loaded inside its
    # own try/except: a broken or incompatible plugin is skipped and reported,
    # never a reason for the panel not to start.
    try:
        from panel import plugins as _vp_plugins
        _vp_plugins.load_all(app)
    except Exception as _e:  # pragma: no cover - the loader itself failing
        print(f'[plugins] loader failed, starting without plugins: {_e}', flush=True)
    terminal_sock.init_app(app)

    # -- Background task timers (traffic history, scheduled site backups) ----
    # Installed/enabled once per start, off the request path. The systemd
    # timers run `python3 -m panel.tasks ...`, so no gunicorn worker owns a
    # schedule (there are several worker processes).
    def _ensure_task_timers():
        import fcntl
        try:
            os.makedirs('/opt/vortexpanel/data', exist_ok=True)
            with open('/opt/vortexpanel/data/.timers.lock', 'w') as lf:
                fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                from panel.tasks import install_timers
                for p in install_timers():
                    print('[VortexPanel] task timers:', p)
        except OSError:
            pass  # another worker is doing it
        except Exception as e:
            print('[VortexPanel] task timers not installed:', e)
    # VP_NO_INIT=1: import without side effects (the updater's import test).
    if os.geteuid() == 0 and not app.config.get('TESTING') and not os.environ.get('VP_NO_INIT'):
        import threading as _th
        _th.Thread(target=_ensure_task_timers, daemon=True).start()

    # -- Health probe (used by the updater, deploy and the CLI) ---------------
    @app.route('/api/health')
    def health():
        return jsonify({'ok': True})

    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(os.path.join(app.root_path, 'web', 'static'), 'favicon.svg',
                                   mimetype='image/svg+xml', max_age=86400)

    # -- Language packs (public: the sign-in page is translated too) ---------
    _I18N_DIRS = (os.path.join(app.root_path, 'web', 'static', 'i18n'), '/opt/vortexpanel/data/i18n')

    @app.route('/api/i18n')
    def i18n_list():
        langs = {'en': 'English'}
        import re as _re
        for d in _I18N_DIRS:
            try:
                for f in sorted(os.listdir(d)):
                    code = f[:-5]
                    if f.endswith('.json') and _re.fullmatch(r'[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})?', code):
                        try:
                            with open(os.path.join(d, f), encoding='utf-8') as fh:
                                langs[code] = (json.load(fh) or {}).get('_name') or code
                        except Exception:
                            continue
            except OSError:
                continue
        return jsonify({'ok': True, 'languages': [{'code': k, 'name': v} for k, v in langs.items()]})

    @app.route('/api/i18n/<code>')
    def i18n_pack(code):
        import re as _re
        if not _re.fullmatch(r'[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})?', code):
            return jsonify({'ok': False}), 404
        for d in reversed(_I18N_DIRS):        # your own packs win
            fp = os.path.join(d, code + '.json')
            if os.path.isfile(fp):
                return send_from_directory(d, code + '.json', mimetype='application/json', max_age=300)
        return jsonify({'ok': False, 'error': 'No such language'}), 404

    # -- Security entrance (secret login path) --------------------------------
    # When Settings > Panel > Login path is set (the installer sets a random
    # one), the panel answers 404 to everything until that path has been
    # opened once in this browser session, so a port scan finds nothing that
    # looks like a control panel. Signed-in sessions, static files, the health
    # probe and API-key requests are not affected.
    def _not_found():
        return Response('<!doctype html><title>404 Not Found</title><h1>Not Found</h1>'
                        '<p>The requested URL was not found on this server.</p>', 404, mimetype='text/html')

    @app.before_request
    def enforce_entrance():
        path = _entrance_path()
        p = request.path
        # Settings > Panel domain: answer only on that name (loopback, e.g. an
        # SSH tunnel, always works so the setting can be undone).
        if p.startswith('/api/hooks/'):
            return None          # Git webhooks: authenticated by their secret token
        dom = _panel_domain()
        if dom and p != '/api/health':
            host = (request.host or '').lower()
            host = host[1:host.find(']')] if host.startswith('[') else host.rsplit(':', 1)[0]
            peer = (request.remote_addr or '').replace('::ffff:', '')
            if host != dom and peer not in ('127.0.0.1', '::1') and host not in ('127.0.0.1', 'localhost', '::1'):
                return _not_found()
        if not path:
            return None
        if p.startswith('/static/') or p in ('/api/health', '/favicon.ico'):
            return None
        if request.headers.get('Authorization', '').startswith('Bearer vp_'):
            return None          # API keys are checked by the auth gate
        if session.get('entrance_ok') or 'user' in session or session.get('2fa_pending'):
            return None
        if p.rstrip('/') == '/' + path:
            session['entrance_ok'] = True
            session.permanent = True
            return redirect('/')
        return _not_found()

    # -- IP allowlist enforcement on EVERY API request ------------------------
    # The allowlist in auth.py is also checked at login, but checking every
    # API call prevents use of a stolen session cookie from an unlisted IP.
    @app.before_request
    def enforce_ip_allowlist():
        # Session lifetime configured in Settings -> Security (session_hours)
        # was saved but never applied; the lifetime stayed fixed at 24 h.
        _apply_session_lifetime(app)
        # Enforce on API calls AND the terminal WebSocket (/ws/…). The WS gives
        # a full root shell, so it must be subject to the same IP allowlist as
        # /api/ — previously only /api/ was checked, letting a stolen session
        # cookie open the terminal from any IP.
        if not (request.path.startswith('/api/') or request.path.startswith('/ws/')):
            return None   # Static files / HTML — not checked
        if request.path.startswith('/api/auth/') or request.path.startswith('/api/hooks/'):
            return None   # Auth endpoints and token webhooks handle their own checks
        # Import here to avoid circular import at module level
        from panel.routes.auth import _client_ip, _ip_allowed
        ip = _client_ip()
        if not _ip_allowed(ip):
            return jsonify({'ok': False, 'error': 'Access denied from this IP address'}), 403
        return None

    # -- CSRF: reject cross-site state-changing requests ----------------------
    # The session cookie is SameSite=Lax, which does not cover sites on the
    # same registrable domain (e.g. a hosted site on example.com vs the panel
    # on panel.example.com), and the terminal WebSocket handshake is a GET.
    # Browsers always send Origin on cross-origin POST/PUT/DELETE and on
    # WebSocket handshakes, so a mismatching Origin is a forged request.
    @app.before_request
    def enforce_same_origin():
        p = request.path
        if not (p.startswith('/api/') or p.startswith('/ws/')):
            return None
        if request.method in ('GET', 'HEAD', 'OPTIONS') and not p.startswith('/ws/'):
            return None
        origin = request.headers.get('Origin')
        if not origin:
            return None          # non-browser client (curl, scripts)
        from urllib.parse import urlsplit
        try:
            o_host = (urlsplit(origin).hostname or '').lower()
        except ValueError:
            o_host = ''
        def _h(v):
            v = (v or '').split(',')[0].strip().lower()
            if v.startswith('['):
                return v[1:v.find(']')] if ']' in v else v
            return v.rsplit(':', 1)[0] if v.count(':') == 1 else v
        allowed = {_h(request.host)}
        peer = (request.remote_addr or '').replace('::ffff:', '')
        if peer in ('127.0.0.1', '::1') or os.environ.get('VORTEX_TRUST_PROXY'):
            # Behind a local reverse proxy the public name arrives here.
            allowed.add(_h(request.headers.get('X-Forwarded-Host', '')))
            if _h(request.host) in ('127.0.0.1', 'localhost', '::1') and not request.headers.get('X-Forwarded-Host'):
                # Panel opened through an SSH tunnel (http://127.0.0.1:8888)
                # or a proxy that does not pass Host: only a loopback page
                # may write. A blanket allow here let any website the admin
                # visited forge requests to a tunnelled panel.
                allowed.update({'127.0.0.1', 'localhost', '::1'})
        if o_host and o_host in allowed:
            return None
        return jsonify({'ok': False, 'error': 'Cross-origin request blocked'}), 403

    # -- Central authentication gate ------------------------------------------
    # Every blueprint has its own `if not req()` line; one forgotten line
    # (e.g. /api/import/job/<id>) exposed data unauthenticated, and most of
    # those req() helpers only check 'user' in session (no fingerprint, no
    # session_version after a password change). Enforce the full check once
    # for everything under /api/ and /ws/; /api/auth/* handles its own.
    @app.before_request
    def enforce_authentication():
        p = request.path
        if not (p.startswith('/api/') or p.startswith('/ws/')):
            return None
        if p.startswith('/api/auth/') or p == '/api/health' or p == '/api/i18n' or p.startswith('/api/i18n/') \
                or p.startswith('/api/hooks/'):
            return None
        from panel.routes.auth import check_ip_and_session
        if not check_ip_and_session():
            return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
        u = g.get('vp_user') or {}
        if u.get('role', 'admin') != 'admin':
            from panel.users import is_allowed
            body = None
            if p.startswith('/api/files/'):
                body = dict(request.form) if request.form else (request.get_json(silent=True) or {})
            ok, why = is_allowed(u.get('role'), u.get('sites'), request.method, p,
                                 dict(request.args), body)
            if not ok:
                return jsonify({'ok': False, 'error': why, 'forbidden': True}), 403
        return None

    # Site managers only see their own websites in the site lists.
    @app.after_request
    def filter_site_lists(response):
        u = g.get('vp_user') or {}
        if u.get('role') != 'site' or request.method != 'GET':
            return response
        if request.path not in ('/api/websites', '/api/wp/sites', '/api/backups/sites'):
            return response
        try:
            data = response.get_json(silent=True)
            if isinstance(data, dict) and isinstance(data.get('sites'), list):
                allowed = set(u.get('sites') or [])
                data['sites'] = [x for x in data['sites']
                                 if isinstance(x, dict) and (x.get('domain') or x.get('name')) in allowed]
                response.set_data(json.dumps(data))
                response.headers['Content-Length'] = str(len(response.get_data()))
        except Exception:
            pass
        return response

    # -- Security headers on every response -----------------------------------
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Frame-Options']        = 'SAMEORIGIN'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy']      = 'geolocation=(), camera=(), microphone=()'
        # Everything is self-hosted (Alpine, Chart.js, xterm, CodeMirror, fonts).
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "font-src 'self' data:; "
            "img-src 'self' data: https:; "
            "connect-src 'self' wss: ws:; "
            "object-src 'none'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'self';"
        )
        if _request_is_https():
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
            # Behind a TLS reverse proxy gunicorn itself speaks plain HTTP, so
            # the Secure flag is not set by the config above: add it here.
            if not app.config.get('SESSION_COOKIE_SECURE'):
                cookies = response.headers.getlist('Set-Cookie')
                if cookies:
                    response.headers.remove('Set-Cookie')
                    for c in cookies:
                        response.headers.add('Set-Cookie', c if '; Secure' in c else c + '; Secure')
        return response

    # -- Auto-init built-in features -------------------------------------------
    try:
        os.makedirs('/opt/vortexpanel', exist_ok=True)
        for _cfg in ['/opt/vortexpanel/cdn_config.json',
                     '/opt/vortexpanel/ai_config.json',
                     '/opt/vortexpanel/config.json']:
            if not os.path.exists(_cfg):
                # 0600: these hold API keys / tokens
                fd = os.open(_cfg, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w') as _f:
                    _f.write('{}')
            else:
                os.chmod(_cfg, 0o600)
    except Exception:
        pass

    return app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8888))
    # '::' binds to all IPv6 + IPv4 on dual-stack systems (covers 0.0.0.0 too)
    # Falls back to 0.0.0.0 if IPv6 not available
    try:
        import socket
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.close()
        host = '::'   # dual-stack: covers IPv4 + IPv6
    except Exception:
        host = '0.0.0.0'  # IPv4 only fallback
    app.run(host=host, port=port, debug=False)
