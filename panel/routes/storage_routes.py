"""Backups > Storage (destinations) and Backups > Panel backup."""
import os
import threading
import uuid

from flask import Blueprint, jsonify, request, send_file

from panel import storage, panelbackup
from panel.routes.auth import require_admin, audit_event

storage_bp = Blueprint('storage', __name__)


def _err(msg, code=400):
    return jsonify({'ok': False, 'error': msg}), code


@storage_bp.route('/api/storage/targets')
def targets():
    e = require_admin()
    if e:
        return e
    return jsonify({'ok': True, 'targets': [storage.public(t) for t in storage.list_targets()],
                    'types': storage.TYPES, 'rclone_installed': storage.rclone_installed()})


@storage_bp.route('/api/storage/targets', methods=['POST'])
@storage_bp.route('/api/storage/targets/<tid>', methods=['PUT'])
def save_target(tid=None):
    e = require_admin()
    if e:
        return e
    if tid == 's3':
        return _err('Edit S3 storage in its own form')
    try:
        t = storage.save_target(request.get_json(silent=True) or {}, tid)
    except storage.StorageError as ex:
        return _err(str(ex))
    except (TypeError, ValueError) as ex:
        return _err(f'Invalid value: {ex}')
    audit_event('backup destination saved', t['name'])
    return jsonify({'ok': True, 'target': storage.public(t)})


@storage_bp.route('/api/storage/targets/<tid>', methods=['DELETE'])
def delete_target(tid):
    e = require_admin()
    if e:
        return e
    if tid == 's3':
        return _err('Disconnect S3 storage in its own form')
    storage.delete_target(tid)
    audit_event('backup destination deleted', tid)
    return jsonify({'ok': True})


@storage_bp.route('/api/storage/targets/<tid>/test', methods=['POST'])
def test_target(tid):
    e = require_admin()
    if e:
        return e
    try:
        return jsonify({'ok': True, 'message': storage.test(tid)})
    except Exception as ex:
        return _err(str(ex))


@storage_bp.route('/api/storage/targets/<tid>/files')
def target_files(tid):
    e = require_admin()
    if e:
        return e
    try:
        return jsonify({'ok': True, 'files': storage.list_files(tid)[:500]})
    except Exception as ex:
        return _err(str(ex))


@storage_bp.route('/api/storage/targets/<tid>/files/<name>', methods=['DELETE'])
def target_file_delete(tid, name):
    e = require_admin()
    if e:
        return e
    try:
        storage.delete(tid, name)
        return jsonify({'ok': True})
    except Exception as ex:
        return _err(str(ex))


def _job(fn):
    """Run fn(log) in a thread; state lives in a file so every gunicorn
    worker can answer the status poll."""
    from panel.routes.job_state import save_job
    jid = 'storage_' + uuid.uuid4().hex[:12]
    st = {'done': False, 'success': False, 'lines': [], 'error': '', 'result': None}
    save_job(jid, st)

    def log(m):
        st['lines'].append(str(m))
        save_job(jid, st)

    def run():
        try:
            res = fn(log)
            st['result'] = res if isinstance(res, (str, int, float)) else None
            st['success'] = True
        except Exception as ex:
            st['error'] = str(ex)
        st['done'] = True
        save_job(jid, st)
    threading.Thread(target=run, daemon=True).start()
    return jid


@storage_bp.route('/api/storage/job/<jid>')
def job(jid):
    e = require_admin()
    if e:
        return e
    from panel.routes.job_state import load_job
    st = load_job(jid if jid.startswith('storage_') else 'x', None)
    if not st:
        return _err('No such job', 404)
    return jsonify({'ok': True, **st})


@storage_bp.route('/api/storage/targets/<tid>/fetch', methods=['POST'])
def target_fetch(tid):
    """Copy a remote backup to this server, where it can be restored."""
    e = require_admin()
    if e:
        return e
    name = os.path.basename(str((request.get_json(silent=True) or {}).get('name') or ''))
    if not name or name.startswith('.'):
        return _err('Choose a file')
    if name.startswith('panel_'):
        dest_dir = panelbackup.OUT_DIR
    else:
        from panel import sitebackup
        dest_dir = sitebackup.BACKUP_DIR if hasattr(sitebackup, 'BACKUP_DIR') else '/opt/vortexpanel/backups'
    os.makedirs(dest_dir, mode=0o700, exist_ok=True)

    def work(log):
        dest = os.path.join(dest_dir, name)
        log(f'Downloading {name}...')
        storage.download(tid, name, dest + '.part')
        os.chmod(dest + '.part', 0o600)
        os.replace(dest + '.part', dest)
        log(f'Saved to {dest}')
        return dest
    return jsonify({'ok': True, 'job_id': _job(work)})


@storage_bp.route('/api/storage/rclone/install', methods=['POST'])
def rclone_install():
    e = require_admin()
    if e:
        return e
    return jsonify({'ok': True, 'job_id': _job(lambda log: storage.install_rclone(log))})


# --- panel backup -----------------------------------------------------------------------
@storage_bp.route('/api/panel-backup')
def pb_overview():
    e = require_admin()
    if e:
        return e
    return jsonify({'ok': True, 'settings': panelbackup.load(), 'backups': panelbackup.list_local(),
                    'targets': [{'id': t['id'], 'name': t['name']} for t in storage.list_targets()]})


@storage_bp.route('/api/panel-backup/settings', methods=['PUT'])
def pb_settings():
    e = require_admin()
    if e:
        return e
    d = request.get_json(silent=True) or {}
    cfg = panelbackup.load()
    try:
        cfg['enabled'] = bool(d.get('enabled', cfg['enabled']))
        cfg['hour'] = max(0, min(23, int(d.get('hour', cfg['hour']))))
        cfg['keep'] = max(1, min(365, int(d.get('keep', cfg['keep']))))
        cfg['keep_remote'] = max(1, min(3650, int(d.get('keep_remote', cfg['keep_remote']))))
    except (TypeError, ValueError):
        return _err('Numbers expected')
    t = str(d.get('target', cfg.get('target')) or '')
    if t and not storage.get_target(t):
        return _err('Unknown backup destination')
    cfg['target'] = t
    panelbackup.save(cfg)
    return jsonify({'ok': True, 'settings': cfg})


@storage_bp.route('/api/panel-backup/create', methods=['POST'])
def pb_create():
    e = require_admin()
    if e:
        return e
    try:
        path = panelbackup.create(note='manual')
    except Exception as ex:
        return _err(str(ex), 500)
    cfg = panelbackup.load()
    msg = ''
    if (request.get_json(silent=True) or {}).get('upload') and cfg.get('target'):
        try:
            storage.upload(cfg['target'], path)
            msg = 'uploaded'
        except Exception as ex:
            msg = f'upload failed: {ex}'
    audit_event('panel backup created', os.path.basename(path))
    return jsonify({'ok': True, 'name': os.path.basename(path), 'upload': msg})


@storage_bp.route('/api/panel-backup/<name>/download')
def pb_download(name):
    e = require_admin()
    if e:
        return e
    if not panelbackup.NAME_RE.match(name):
        return _err('Invalid name')
    p = os.path.join(panelbackup.OUT_DIR, name)
    if not os.path.exists(p):
        return _err('Not found', 404)
    return send_file(p, as_attachment=True, download_name=name)


@storage_bp.route('/api/panel-backup/<name>', methods=['DELETE'])
def pb_delete(name):
    e = require_admin()
    if e:
        return e
    if not panelbackup.NAME_RE.match(name):
        return _err('Invalid name')
    try:
        os.unlink(os.path.join(panelbackup.OUT_DIR, name))
    except FileNotFoundError:
        return _err('Not found', 404)
    return jsonify({'ok': True})


@storage_bp.route('/api/panel-backup/<name>/restore', methods=['POST'])
def pb_restore(name):
    e = require_admin()
    if e:
        return e
    d = request.get_json(silent=True) or {}
    what = [w for w in ('accounts', 'settings') if d.get(w, True)]
    if not what:
        return _err('Choose what to restore')
    try:
        restored, snap = panelbackup.restore(name, what)
    except Exception as ex:
        return _err(str(ex))
    audit_event('panel backup restored', f'{name} ({", ".join(what)})')
    # Settings such as the port or HTTPS only apply after a restart.
    from panel.routes.settings import _safe_restart_panel
    _safe_restart_panel()
    return jsonify({'ok': True, 'restored': len(restored), 'snapshot': os.path.basename(snap)})


@storage_bp.route('/api/panel-backup/upload', methods=['POST'])
def pb_upload():
    e = require_admin()
    if e:
        return e
    f = request.files.get('file')
    if not f or not panelbackup.NAME_RE.match(os.path.basename(f.filename or '')):
        return _err('Choose a panel backup file (panel_YYYYMMDD-HHMMSS.tar.gz)')
    os.makedirs(panelbackup.OUT_DIR, mode=0o700, exist_ok=True)
    dest = os.path.join(panelbackup.OUT_DIR, os.path.basename(f.filename))
    f.save(dest)
    os.chmod(dest, 0o600)
    return jsonify({'ok': True, 'name': os.path.basename(dest)})
