"""Settings > Update: check for and install signed releases (see panel/updater.py)."""
import json
import os
import threading
import time

from flask import Blueprint, jsonify, request

from panel import updater

update_bp = Blueprint('update', __name__)

INSTALL_DIR = updater.INSTALL_DIR
_UPDATE_STALE_AFTER = 20 * 60
_check_cache = {'at': 0, 'data': None}


def req():
    from panel.routes.auth import check_ip_and_session
    return check_ip_and_session()


def get_current_version():
    return updater.current_version()


@update_bp.route('/api/update/check')
def check_update():
    if not req():
        return jsonify({'ok': False}), 401
    # GitHub is asked at most every 10 minutes (the dashboard checks too).
    if request.args.get('force') or time.time() - _check_cache['at'] > 600 or not _check_cache['data']:
        _check_cache['data'] = updater.check()
        _check_cache['at'] = time.time()
    data = dict(_check_cache['data'])
    data['current'] = updater.current_version()
    data['has_update'] = updater.semver(data.get('latest', '')) > updater.semver(data['current'])
    data['allow_unsigned'] = updater.allow_unsigned()
    return jsonify(data)


@update_bp.route('/api/update/settings', methods=['POST'])
def update_settings():
    from panel.routes.auth import require_admin, _get_config, _save_config, audit_event
    e = require_admin()
    if e:
        return e
    d = request.get_json(silent=True) or {}
    cfg = _get_config()
    if 'allow_unsigned_updates' in d:
        cfg['allow_unsigned_updates'] = bool(d['allow_unsigned_updates'])
        audit_event('update setting', f'allow_unsigned_updates={cfg["allow_unsigned_updates"]}')
    _save_config(cfg)
    return jsonify({'ok': True, 'allow_unsigned': bool(cfg.get('allow_unsigned_updates'))})


@update_bp.route('/api/update/start', methods=['POST'])
def start_update():
    from panel.routes.job_state import save_job, load_job, _job_path
    if not req():
        return jsonify({'ok': False}), 401
    existing = load_job('panel_update', {'running': False})
    if existing.get('running') and time.time() - (existing.get('heartbeat') or 0) < _UPDATE_STALE_AFTER:
        return jsonify({'ok': False, 'error': 'Update already in progress'}), 400
    target = str((request.get_json(silent=True) or {}).get('version', '') or '').strip()
    if target and not updater.TAG_RE.match(target if target.startswith('v') else 'v' + target):
        return jsonify({'ok': False, 'error': 'Invalid version tag'}), 400

    save_job('panel_update', {'running': True, 'lines': [], 'done': False, 'success': False,
                              'error': '', 'heartbeat': time.time()})

    def run():
        lines = []
        try:
            # The job is marked done before the restart helper runs: the
            # restart kills this worker. The helper appends its result.
            def log_done(msg):
                lines.append(msg)
                if msg.startswith('Release ') and 'installed' in msg:
                    lines.extend(['', 'VortexPanel updated. Reload this page in a few seconds.',
                                  'If the new version does not start, the previous one is restored automatically.'])
                    save_job('panel_update', {'running': False, 'lines': lines, 'done': True, 'success': True,
                                              'error': '', 'heartbeat': time.time()})
                else:
                    save_job('panel_update', {'running': True, 'lines': lines, 'done': False, 'success': False,
                                              'error': '', 'heartbeat': time.time()})
            updater.run_update(target, log=log_done, job_path=_job_path('panel_update'))
        except Exception as e:
            lines.append(f'FAILED: {e}')
            save_job('panel_update', {'running': False, 'lines': lines, 'done': True, 'success': False,
                                      'error': str(e)})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'ok': True})


@update_bp.route('/api/update/status')
def update_status():
    from panel.routes.job_state import load_job
    if not req():
        return jsonify({'ok': False}), 401
    state = load_job('panel_update', {'running': False, 'lines': [], 'done': False, 'success': False, 'error': ''})
    return jsonify({'ok': True, **state})


@update_bp.route('/api/update/version')
def current_version():
    if not req():
        return jsonify({'ok': False}), 401
    return jsonify({'ok': True, 'version': get_current_version()})


@update_bp.route('/api/update/backups')
def backups():
    if not req():
        return jsonify({'ok': False}), 401
    return jsonify({'ok': True, 'backups': [{k: b[k] for k in ('name', 'version')} for b in updater.list_backups()]})
