from flask import Blueprint, jsonify
import subprocess, re, time

dashboard_bp = Blueprint('dashboard', __name__)

def req():
    from panel.routes.auth import check_ip_and_session
    return check_ip_and_session()


def _unit_states(names):
    """{name: (LoadState, ActiveState)} from one `systemctl show` call.
    `systemctl is-active` prints 'inactive' for units that do not exist at
    all, so the dashboard listed apache2/mysql/php7.4-fpm/... as stopped on
    servers that never had them."""
    try:
        r = subprocess.run(['systemctl', 'show', '--property=LoadState,ActiveState', '--'] +
                           [n + '.service' for n in names], capture_output=True, text=True, timeout=10)
    except Exception:
        return {}
    res = {}
    for name, block in zip(names, r.stdout.strip().split('\n\n')):
        props = dict(l.split('=', 1) for l in block.splitlines() if '=' in l)
        res[name] = (props.get('LoadState', ''), props.get('ActiveState', ''))
    return res

_stats_cache = {'data': None, 'ts': 0}
_STATS_TTL   = 1.5

@dashboard_bp.route('/api/dashboard/ssl-alerts')
def ssl_alerts():
    """Aggregate SSL expiry across all sites for a dashboard-level warning banner.
    Reuses list_sites() from websites_core, which already computes ssl_days per site."""
    if not req(): return jsonify({'ok': False}), 401
    try:
        from panel.routes.websites_core import list_sites
        sites = list_sites()
    except Exception as e:
        return jsonify({'ok': True, 'alerts': [], 'error': str(e)})

    THRESHOLD_DAYS = 14
    alerts = []
    for s in sites:
        days = s.get('ssl_days')
        if s.get('ssl') and days is not None and days <= THRESHOLD_DAYS:
            alerts.append({
                'domain': s['domain'],
                'days_left': days,
                'severity': 'expired' if days < 0 else ('critical' if days <= 7 else 'warning'),
            })
    alerts.sort(key=lambda a: a['days_left'])
    return jsonify({'ok': True, 'alerts': alerts, 'threshold_days': THRESHOLD_DAYS})


def _get_stats():
    def _proc_stat():
        try:
            a = open('/proc/stat').readline().split()[1:]
            time.sleep(0.08)
            b = open('/proc/stat').readline().split()[1:]
            da = [int(b[i]) - int(a[i]) for i in range(min(len(a), len(b)))]
            idle = da[3] if len(da) > 3 else 0
            total = sum(da) or 1
            return round((1 - idle / total) * 100, 1)
        except:
            return 0.0

    def _proc_mem():
        try:
            info = {}
            for line in open('/proc/meminfo').readlines()[:5]:
                k, v = line.split(':')
                info[k.strip()] = int(v.strip().split()[0]) * 1024
            total = info.get('MemTotal', 1)
            avail = info.get('MemAvailable', info.get('MemFree', 0))
            return total, total - avail
        except:
            return 0, 0

    def _disk():
        try:
            st = __import__('os').statvfs('/')
            total = st.f_blocks * st.f_frsize
            used  = (st.f_blocks - st.f_bfree) * st.f_frsize
            return total, used
        except:
            return 0, 0

    def _proc_uptime():
        try:
            sec = int(float(open('/proc/uptime').read().split()[0]))
            d, h, m = sec // 86400, (sec % 86400) // 3600, (sec % 3600) // 60
            return f"{d}d {h}h {m}m"
        except:
            return '---'

    def _proc_net():
        try:
            rx = tx = 0
            for line in open('/proc/net/dev').readlines()[2:]:
                f = line.split()
                name = f[0].rstrip(':')
                # Skip loopback and virtual/bridge links: container traffic
                # crosses veth + docker0/br-* and the uplink, so it was
                # counted two or three times.
                if name == 'lo' or name.startswith(('veth', 'docker', 'br-', 'virbr', 'cni', 'flannel')):
                    continue
                rx += int(f[1]); tx += int(f[9])
            return rx, tx
        except:
            return 0, 0

    def _services():
        svcs = ['nginx', 'apache2', 'httpd', 'mysql', 'mysqld', 'mariadb',
                'php8.5-fpm', 'php8.4-fpm', 'php8.3-fpm', 'php8.2-fpm',
                'php8.1-fpm', 'php7.4-fpm', 'php-fpm',
                'redis-server', 'redis', 'docker', 'fail2ban', 'supervisor', 'supervisord']
        try:
            out = {}
            for svc, (load, state) in _unit_states(svcs).items():
                if load == 'loaded' and state in ('active', 'inactive', 'failed', 'activating', 'reloading'):
                    out[svc] = state
            return out
        except Exception:
            return {}

    def _webserver_conflicts():
        # 'active' in stdout also matched "inactive" (printed for stopped AND
        # non-existent units), so every server showed a permanent
        # "multiple webservers running" warning.
        units = {'nginx': 'nginx', 'apache2': 'apache2', 'httpd': 'apache2',
                 'lsws': 'openlitespeed', 'caddy': 'caddy'}
        active = []
        try:
            for unit, (_load, state) in _unit_states(list(units)).items():
                if state == 'active' and units[unit] not in active:
                    active.append(units[unit])
        except Exception:
            pass
        if len(active) > 1:
            return {'conflict': True, 'active': active,
                    'message': "Multiple webservers running: " + ', '.join(active) + ". Stop all but one."}
        return {'conflict': False, 'active': active}

    # Sequential calls only. /proc reads are instant (<1ms each),
    # systemctl calls take ~30ms total. No need for threads.
    # ThreadPoolExecutor caused RuntimeError crashes during gunicorn worker shutdown.
    cpu   = _proc_stat()
    ram_total, ram_used   = _proc_mem()
    disk_total, disk_used = _disk()
    rx, tx   = _proc_net()
    svcs     = _services()
    ws       = _webserver_conflicts()

    return {
        'ok': True, 'cpu': cpu,
        'ram':  {'used': ram_used,  'total': ram_total},
        'disk': {'used': disk_used, 'total': disk_total},
        'load': open('/proc/loadavg').read().split()[:3],
        'uptime': _proc_uptime(),
        'services': svcs,
        'net': {'rx': rx, 'tx': tx},
        'webserver_conflict': ws,
    }



@dashboard_bp.route('/api/dashboard')
def dashboard_index():
    return stats()

@dashboard_bp.route('/api/system/info')
def system_info():
    return stats()

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
