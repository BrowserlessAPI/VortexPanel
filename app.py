#!/usr/bin/env python3
"""VortexPanel v3.0 — Main Application"""
import os, sys, secrets
from datetime import timedelta
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, g
try:
    from flask_compress import Compress
    _compress_available = True
except ImportError:
    _compress_available = False

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

# ── Secret key: auto-generate and persist on first run ───────────────────────
_SECRET_KEY_FILE = '/opt/vortexpanel/secret.key'

def _get_secret_key() -> bytes:
    """
    Load secret key from file if it exists, otherwise generate a new
    64-byte random key and save it.  The hardcoded fallback is only used
    when the install directory isn't writable (e.g. CI/test environments).
    """
    if os.path.exists(_SECRET_KEY_FILE):
        try:
            key = open(_SECRET_KEY_FILE, 'rb').read()
            if len(key) >= 32:
                return key
        except Exception:
            pass
    # Generate a new key
    key = secrets.token_bytes(64)
    try:
        os.makedirs('/opt/vortexpanel', exist_ok=True)
        with open(_SECRET_KEY_FILE, 'wb') as f:
            f.write(key)
        os.chmod(_SECRET_KEY_FILE, 0o600)
    except Exception:
        pass
    return key


def create_app():
    app = Flask(__name__, template_folder='web/templates', static_folder='web/static')

    # ── Secret key ────────────────────────────────────────────────────────────
    # ENV var override available for Docker/container deployments
    app.secret_key = os.environ.get('SECRET_KEY', '').encode() or _get_secret_key()

    # ── Session hardening ─────────────────────────────────────────────────────
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    app.config['SESSION_COOKIE_HTTPONLY']    = True
    app.config['SESSION_COOKIE_SAMESITE']    = 'Lax'
    # Don't force Secure flag — panel may run HTTP; let admin configure HTTPS

    # ── Gzip compression ──────────────────────────────────────────────────────
    if _compress_available:
        app.config['COMPRESS_MIMETYPES'] = [
            'text/html', 'application/json', 'application/javascript',
            'text/css', 'text/plain',
        ]
        app.config['COMPRESS_LEVEL']    = 6
        app.config['COMPRESS_MIN_SIZE'] = 500
        Compress(app)

    # ── Register blueprints ───────────────────────────────────────────────────
    for bp in [auth_bp, dashboard_bp, websites_bp, databases_bp, files_bp,
               php_bp, services_bp, firewall_bp, terminal_bp, backups_bp,
               dns_bp, mail_bp, ftp_bp, cron_bp, docker_bp, monitoring_bp,
               settings_bp, modules_bp, main_bp, security_bp, bandwidth_bp,
               caddy_bp, cdn_bp, update_bp, ai_bp, ddns_bp, cloud_backup_bp,
               logs_bp, wp_bp]:
        app.register_blueprint(bp)
    terminal_sock.init_app(app)

    # ── IP allowlist enforcement on EVERY API request ────────────────────────
    # The allowlist in auth.py is also checked at login, but checking every
    # API call prevents use of a stolen session cookie from an unlisted IP.
    @app.before_request
    def enforce_ip_allowlist():
        if not request.path.startswith('/api/'):
            return None   # Static files / HTML — not checked
        if request.path.startswith('/api/auth/'):
            return None   # Auth endpoints handle their own IP check
        # Import here to avoid circular import at module level
        from panel.routes.auth import _client_ip, _ip_allowed
        ip = _client_ip()
        if not _ip_allowed(ip):
            return jsonify({'ok': False, 'error': 'Access denied from this IP address'}), 403
        return None

    # ── Security headers on every response ───────────────────────────────────
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Frame-Options']        = 'SAMEORIGIN'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection']       = '1; mode=block'
        response.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy']      = 'geolocation=(), camera=(), microphone=()'
        # CSP — Alpine.js needs unsafe-inline; adjust if you add a nonce
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' data: https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' wss: ws:; "
            "frame-ancestors 'self';"
        )
        return response

    # ── Auto-init built-in features ───────────────────────────────────────────
    try:
        os.makedirs('/opt/vortexpanel', exist_ok=True)
        for _cfg in ['/opt/vortexpanel/cdn_config.json',
                     '/opt/vortexpanel/ai_config.json',
                     '/opt/vortexpanel/config.json']:
            if not os.path.exists(_cfg):
                with open(_cfg, 'w') as _f:
                    _f.write('{}')
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
