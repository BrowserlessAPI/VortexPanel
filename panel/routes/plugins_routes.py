"""Settings > Plugins and the endpoints the admin UI uses to load plugin pages."""
import os

from flask import Blueprint, jsonify, request, send_file, send_from_directory, abort

from panel import plugins
from panel.utils.authctx import is_admin

plugins_bp = Blueprint('plugins', __name__)


@plugins_bp.route('/api/plugins')
def list_plugins():
    if not is_admin():
        return jsonify({'ok': False, 'error': 'Administrator only'}), 403
    return jsonify({'ok': True, 'plugins': plugins.public_list(), 'safe_mode': plugins.safe_mode(),
                    'core_version': plugins.core_version(), 'dir': plugins.PLUGINS_DIR})


@plugins_bp.route('/api/plugins/<pid>/fragment/<page>')
def plugin_fragment(pid, page):
    if not is_admin():
        abort(403)
    path = plugins.fragment_path(pid, page)
    if not path:
        abort(404)
    resp = send_file(path, mimetype='text/html')
    resp.headers['Cache-Control'] = 'no-cache'
    return resp


@plugins_bp.route('/api/plugins/<pid>/assets/<path:fname>')
def plugin_asset(pid, fname):
    if not is_admin():
        abort(403)
    d = plugins.asset_dir(pid)
    if not d:
        abort(404)
    resp = send_from_directory(d, fname)
    resp.headers['Cache-Control'] = 'no-cache'
    return resp


@plugins_bp.route('/api/plugins/<pid>/<action>', methods=['POST'])
def plugin_toggle(pid, action):
    if not is_admin():
        return jsonify({'ok': False, 'error': 'Administrator only'}), 403
    if action not in ('enable', 'disable'):
        return jsonify({'ok': False, 'error': 'Unknown action'}), 400
    if pid not in plugins.REGISTRY:
        return jsonify({'ok': False, 'error': 'No such plugin'}), 404
    plugins.set_enabled(pid, action == 'enable')
    from panel.routes.auth import audit_event
    try:
        audit_event(f'plugin_{action}', pid)
    except Exception:
        pass
    return jsonify({'ok': True, 'restart_required': True,
                    'message': f'Plugin {action}d. Restart the panel to apply (Settings > Restart panel, or vortexpanel restart).'})
