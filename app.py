#!/usr/bin/env python3
"""VortexPanel v3.0 — Main Application"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask
from panel.routes.auth      import auth_bp
from panel.routes.dashboard import dashboard_bp
from panel.routes.websites  import websites_bp
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
from panel.routes.monitoring import monitoring_bp
from panel.routes.settings  import settings_bp
from panel.routes.main      import main_bp
from panel.routes.modules   import modules_bp
from panel.routes.security  import security_bp
from panel.routes.bandwidth import bandwidth_bp

def create_app():
    app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
    app.secret_key = os.environ.get('SECRET_KEY', 'vortex-dev-secret-change-in-prod')

    for bp in [auth_bp, dashboard_bp, websites_bp, databases_bp, files_bp,
               php_bp, services_bp, firewall_bp, terminal_bp, backups_bp,
               dns_bp, mail_bp, ftp_bp, cron_bp, docker_bp, monitoring_bp,
               settings_bp, modules_bp, main_bp, security_bp, bandwidth_bp]:
        app.register_blueprint(bp)

    return app

if __name__ == '__main__':
    app = create_app()
    port = int(os.environ.get('PORT', 8888))
    app.run(host='0.0.0.0', port=port, debug=False)
