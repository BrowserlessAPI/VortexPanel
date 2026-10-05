#!/usr/bin/env python3
"""VortexPanel v3.0 — Main Application"""
import os, sys, secrets
from datetime import timedelta
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, g, jsonify
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
from panel.routes.http3 import *  # noqa
from panel.routes.websites_deploy import *  # noqa
from panel.routes.websites_composer import *  # noqa
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
               logs_bp, wp_bp, nodejs_bp, go_bp, import_bp, livepatch_bp]:
        app.register_blueprint(bp)
    terminal_sock.init_app(app)

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
        if request.path.startswith('/api/auth/'):
            return None   # Auth endpoints handle their own IP check
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
        if p.startswith('/api/auth/'):
            return None
        from panel.routes.auth import check_ip_and_session
        if not check_ip_and_session():
            return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
        return None

    # -- Security headers on every response -----------------------------------
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Frame-Options']        = 'SAMEORIGIN'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection']       = '1; mode=block'
        response.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy']      = 'geolocation=(), camera=(), microphone=()'
        # CSP — everything is self-hosted now (Alpine, Chart.js, xterm, CodeMirror),
        # so no external script/style origins need to be trusted anymore.
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' data: https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' wss: ws:; "
            "frame-ancestors 'self';"
        )
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
