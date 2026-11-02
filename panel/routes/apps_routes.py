"""App Store > Panel Apps: list, install, update and remove VortexPanel Apps."""
from flask import Blueprint, jsonify, request

from panel import apps
from panel.utils.authctx import is_admin

apps_bp = Blueprint('apps', __name__)


def _deny():
    return jsonify({'ok': False, 'error': 'Administrator only'}), 403


@apps_bp.route('/api/apps')
def list_apps():
    if not is_admin():
        return _deny()
    return jsonify({'ok': True, 'apps': apps.catalog(), 'job': apps.job(), 'job_running': apps.job_running()})


@apps_bp.route('/api/apps/<aid>/<action>', methods=['POST'])
def app_action(aid, action):
    if not is_admin():
        return _deny()
    if action not in ('install', 'update', 'uninstall'):
        return jsonify({'ok': False, 'error': 'Unknown action'}), 400
    d = request.get_json(silent=True) or {}
    ok, msg = apps.start(action, aid, purge=bool(d.get('purge')) and action == 'uninstall')
    if ok:
        try:
            from panel.routes.auth import audit_event
            audit_event(f'app_{action}', aid)
        except Exception:  # noqa: BLE001
            pass
    return jsonify({'ok': ok, 'error': '' if ok else msg, 'message': msg}), (200 if ok else 400)


@apps_bp.route('/api/apps/job')
def app_job():
    if not is_admin():
        return _deny()
    j = apps.job()
    running = apps.job_running()
    # a job that died without writing its end state (e.g. the server rebooted)
    if j.get('state') == 'running' and not running and j.get('started', 0) and \
            __import__('time').time() - j['started'] > 20:
        j['state'] = 'failed'
        j['message'] = j.get('message') or 'The job stopped before it finished. Check: journalctl -u vortexpanel-apps-job'
    return jsonify({'ok': True, 'job': j, 'running': running})
