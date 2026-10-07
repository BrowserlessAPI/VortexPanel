"""First-run setup guide (onboarding wizard).

The wizard itself runs in the browser and drives the existing App Store,
security and website APIs. This module only stores whether the guide has
been completed and reports a short summary of the server for its first step.
"""
from flask import Blueprint, jsonify, request
import os, json, socket, shutil, subprocess, time

onboarding_bp = Blueprint('onboarding', __name__)

STATE_FILE = '/opt/vortexpanel/data/onboarding.json'


def req():
    from panel.routes.auth import check_ip_and_session
    return check_ip_and_session()


def _load():
    try:
        with open(STATE_FILE) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save(d):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(d, f, indent=2)
    os.replace(tmp, STATE_FILE)


def _site_count():
    try:
        from panel.routes.websites_core import list_sites
        return len(list_sites())
    except Exception:
        return 0


def _os_name():
    try:
        with open('/etc/os-release') as f:
            for line in f:
                if line.startswith('PRETTY_NAME='):
                    return line.split('=', 1)[1].strip().strip('"')
    except Exception:
        pass
    return 'Linux'


def _primary_ip():
    try:
        out = subprocess.run(['ip', '-4', 'route', 'get', '1.1.1.1'], capture_output=True,
                             text=True, timeout=5).stdout
        parts = out.split()
        if 'src' in parts:
            return parts[parts.index('src') + 1]
    except Exception:
        pass
    try:
        out = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=5).stdout.split()
        return out[0] if out else ''
    except Exception:
        return ''


def _server_summary():
    mem_total = 0
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    mem_total = int(line.split()[1]) * 1024
                    break
    except Exception:
        pass
    try:
        du = shutil.disk_usage('/')
        disk_total, disk_free = du.total, du.free
    except Exception:
        disk_total = disk_free = 0
    return {
        'os': _os_name(),
        'kernel': os.uname().release,
        'hostname': socket.gethostname(),
        'ip': _primary_ip(),
        'cpus': os.cpu_count() or 1,
        'ram': mem_total,
        'disk_total': disk_total,
        'disk_free': disk_free,
    }


@onboarding_bp.route('/api/onboarding/status')
def onboarding_status():
    if not req():
        return jsonify({'ok': False}), 401
    st = _load()
    done = bool(st.get('completed_at') or st.get('dismissed_at'))
    sites = _site_count()
    # Open the guide automatically only on a fresh server: a panel upgraded on
    # a server that already hosts sites is not "first run".
    show = (not done) and sites == 0
    return jsonify({'ok': True, 'show': show, 'done': done, 'sites': sites,
                    'state': st, 'server': _server_summary()})


@onboarding_bp.route('/api/onboarding/complete', methods=['POST'])
def onboarding_complete():
    if not req():
        return jsonify({'ok': False}), 401
    d = request.get_json(silent=True) or {}
    st = _load()
    now = int(time.time())
    if d.get('skipped'):
        st['dismissed_at'] = now
    else:
        st['completed_at'] = now
    steps = d.get('steps')
    if isinstance(steps, list):
        st['steps'] = [str(s)[:40] for s in steps[:20]]
    _save(st)
    return jsonify({'ok': True})


@onboarding_bp.route('/api/onboarding/reset', methods=['POST'])
def onboarding_reset():
    if not req():
        return jsonify({'ok': False}), 401
    _save({})
    return jsonify({'ok': True})
