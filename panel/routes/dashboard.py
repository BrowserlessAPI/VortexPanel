from flask import Blueprint, jsonify, session
import subprocess, re, time
from concurrent.futures import ThreadPoolExecutor

dashboard_bp = Blueprint('dashboard', __name__)

def req():
    return 'user' in session

_stats_cache = {'data': None, 'ts': 0}
_STATS_TTL   = 1.5


def _get_stats():
    def _proc_stat():
        line1 = open('/proc/stat').readline()
        v1 = list(map(int, line1.split()[1:]))
        time.sleep(0.1)
        line2 = open('/proc/stat').readline()
        v2 = list(map(int, line2.split()[1:]))
        idle_d  = (v2[3] + v2[4]) - (v1[3] + v1[4])
        total_d = sum(v2) - sum(v1)
        return round((1 - idle_d / total_d) * 100, 1) if total_d else 0.0

    def _proc_mem():
        mem = open('/proc/meminfo').read()
        def mi(k):
            m = re.search(rf'^{k}:\s+(\d+)', mem, re.M)
            return int(m.group(1)) * 1024 if m else 0
        total = mi('MemTotal')
        return total, total - mi('MemAvailable')

    def _disk():
        try:
            out = subprocess.check_output(
                'df / --output=size,used 2>/dev/null | tail -1',
                shell=True, text=True, stderr=subprocess.DEVNULL
            ).split()
            return int(out[0]) * 1024, int(out[1]) * 1024
        except:
            return 0, 0

    def _proc_uptime():
        try:
            sec = int(float(open('/proc/uptime').read().split()[0]))
            d, h, m = sec // 86400, (sec % 86400) // 3600, (sec % 3600) // 60
            return f"{d}d {h}h {m}m"
        except:
            return '—'

    def _proc_net():
        try:
            rx = tx = 0
            for line in open('/proc/net/dev').readlines()[2:]:
                f = line.split()
                if f[0].rstrip(':') == 'lo': continue
                rx += int(f[1]); tx += int(f[9])
            return rx, tx
        except:
            return 0, 0

    def _services():
        svcs = ['nginx', 'apache2', 'mysql', 'mariadb',
                'php8.5-fpm', 'php8.4-fpm', 'php8.3-fpm', 'php8.2-fpm',
                'php8.1-fpm', 'php7.4-fpm',
                'redis-server', 'docker', 'fail2ban', 'supervisor']
        r = subprocess.run(
            'systemctl is-active ' + ' '.join(svcs) + ' 2>/dev/null',
            shell=True, capture_output=True, text=True
        )
        lines = r.stdout.strip().split('\n')
        out = {}
        for i, svc in enumerate(svcs):
            state = lines[i].strip() if i < len(lines) else ''
            if state in ('active', 'inactive', 'failed'): out[svc] = state
        return {k: v for k, v in out.items() if v}

    def _webserver_conflicts():
        """Detect multiple webservers running simultaneously."""
        webservers = {
            'nginx':         'systemctl is-active nginx 2>/dev/null',
            'apache2':       'systemctl is-active apache2 2>/dev/null || systemctl is-active httpd 2>/dev/null',
            'openlitespeed': 'systemctl is-active lsws 2>/dev/null',
            'caddy':         'systemctl is-active caddy 2>/dev/null',
        }
        active = []
        for name, cmd in webservers.items():
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if 'active' in result.stdout:
                active.append(name)
        if len(active) > 1:
            return {'conflict': True, 'active': active,
                    'message': f"Multiple webservers running simultaneously: {', '.join(active)}. "
                               f"This causes port 80/443 conflicts. Stop all but one."}
        return {'conflict': False, 'active': active}

    cpu_result = [0.0]; disk_result = [(0,0)]; svc_result = [{}]; ws_result = [{}]
    def _get_cpu():  cpu_result[0]  = _proc_stat()
    def _get_disk(): disk_result[0] = _disk()
    def _get_svcs(): svc_result[0]  = _services()
    def _get_ws():   ws_result[0]   = _webserver_conflicts()

    with ThreadPoolExecutor(max_workers=4) as ex:
        for f in [ex.submit(_get_cpu), ex.submit(_get_disk), ex.submit(_get_svcs), ex.submit(_get_ws)]:
            f.result()

    ram_total, ram_used   = _proc_mem()
    disk_total, disk_used = disk_result[0]
    rx, tx = _proc_net()
    return {
        'ok': True, 'cpu': cpu_result[0],
        'ram':  {'used': ram_used,  'total': ram_total},
        'disk': {'used': disk_used, 'total': disk_total},
        'load': open('/proc/loadavg').read().split()[:3],
        'uptime': _proc_uptime(),
        'services': svc_result[0],
        'net': {'rx': rx, 'tx': tx},
        'webserver_conflict': ws_result[0],
    }


@dashboard_bp.route('/api/dashboard/stats')
def stats():
    if not req(): return jsonify({'ok': False}), 401
    now = time.monotonic()
    if _stats_cache['data'] is None or (now - _stats_cache['ts']) > _STATS_TTL:
        _stats_cache['data'] = _get_stats()
        _stats_cache['ts']   = now
    return jsonify(_stats_cache['data'])


@dashboard_bp.route('/api/dashboard/history')
def history():
    if not req(): return jsonify({'ok': False}), 401
    import random, math
    now = int(time.time())
    points = []
    for i in range(30):
        t = now - (29 - i) * 60
        points.append({
            'time': t,
            'cpu':  round(15 + 25*abs(math.sin(i*0.4)) + random.uniform(-3,3), 1),
            'ram':  round(45 + 15*abs(math.sin(i*0.3)) + random.uniform(-2,2), 1),
        })
    return jsonify({'ok': True, 'history': points})
