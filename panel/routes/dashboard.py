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


_p2s_cache = {'data': None, 'ts': 0.0, 'fp': None}
_P2S_TTL = 600


def _p2s_fingerprint():
    """Cheap stat()s that change whenever a PHP is installed, updated or removed (VortexPanel
    builds, OS packages, Remi, LiteSpeed) or the protection setting changes. Each panel worker
    keeps its own cache, so a change seen by one worker is noticed by all of them."""
    import glob, os
    try:
        from panel.php2shell import CONF
    except Exception:  # noqa: BLE001
        CONF = '/opt/vortexpanel/data/php2shell.json'
    fp = []
    for p in (['/usr/local/vortex/php', '/var/lib/dpkg/status', '/var/lib/rpm', '/var/lib/rpm/rpmdb.sqlite',
               '/opt/remi', '/usr/local/lsws', CONF]
              + sorted(glob.glob('/usr/local/vortex/php/*'))):
        try:
            st = os.stat(p)
            fp.append((p, st.st_mtime_ns, os.path.realpath(p)))
        except OSError:
            pass
    return tuple(fp)


@dashboard_bp.route('/api/dashboard/php2shell')
def php2shell_alert():
    """PHP2Shell (CVE-2026-109618/109619) warning for the dashboard: the PHP versions on this
    server that are affected or get no fixed release. Reading every PHP's version runs each
    binary, so the answer is cached for 10 minutes, and read again as soon as a PHP is
    installed, updated or removed or the protection changes."""
    if not req(): return jsonify({'ok': False}), 401
    now = time.monotonic()
    fp = _p2s_fingerprint()
    if _p2s_cache['data'] is None or now - _p2s_cache['ts'] > _P2S_TTL or fp != _p2s_cache['fp']:
        try:
            from panel import php2shell
            st = php2shell.status()
            rows = [{'name': r['name'], 'version': r['version'], 'status': r['status']}
                    for r in st['versions'] if r['status'] in ('vulnerable', 'nofix')]
            data = {'ok': True, 'worst': 'vulnerable' if rows else st['worst'], 'rows': rows,
                    'enabled': st['enabled']}
        except Exception as e:  # noqa: BLE001
            data = {'ok': True, 'worst': 'fixed', 'rows': [], 'enabled': True, 'error': str(e)[:200]}
        _p2s_cache.update(data=data, ts=now, fp=fp)
    return jsonify(_p2s_cache['data'])


# ---------------------------------------------------------------- disk usage by category
# What takes the space on / : websites and app folders, databases, backups, logs, Docker,
# mail, and the rest (operating system and other files). `du` over large trees takes a
# while, so it runs in the background at the lowest CPU and disk priority, at most once per
# 6 hours (one panel worker at a time), and the dashboard shows the last result at once.
DISK_CAT_FILE = '/opt/vortexpanel/data/disk_categories.json'
DISK_CAT_LOCK = '/opt/vortexpanel/data/disk_categories.lock'
DISK_CAT_MAX_AGE = 6 * 3600
DISK_CAT_LABELS = [('websites', 'Websites and apps'), ('databases', 'Databases'), ('backups', 'Backups'),
                   ('logs', 'Logs'), ('docker', 'Docker'), ('mail', 'Mail'), ('other', 'System and other')]


def _disk_cat_paths():
    """{category: [folders]} that exist on the same filesystem as /."""
    import glob, os
    sites = []
    try:
        from panel.routes.websites_core import list_sites
        sites = [s.get('path') for s in list_sites() if s.get('path')]
    except Exception:  # noqa: BLE001
        pass
    for mod, key in (('nodejs_projects', 'path'), ('go_projects', 'work_dir'), ('python_projects', 'path')):
        try:
            m = __import__(f'panel.routes.{mod}', fromlist=['load_projects'])
            for p in m.load_projects():
                v = p.get(key) or (os.path.dirname(p.get('exec_file') or '') if mod == 'go_projects' else '')
                if v:
                    sites.append(v)
        except Exception:  # noqa: BLE001
            pass
    cats = {
        'databases': ['/var/lib/mysql', '/var/lib/postgresql', '/var/lib/pgsql', '/var/lib/mongodb', '/var/lib/redis'],
        'docker': ['/var/lib/docker', '/var/lib/containerd'],
        'backups': ['/opt/vortexpanel/backups', '/www/backup', '/var/backups/vortexpanel'],
        'logs': ['/var/log', '/www/wwwlogs'],
        'mail': ['/var/vmail', '/var/mail', '/home/vmail'],
        'websites': ['/www/wwwroot', '/var/www'] + sites,
    }
    try:
        root_dev = os.stat('/').st_dev
    except OSError:
        return {}
    seen, out = [], {}
    for cat in ('databases', 'docker', 'backups', 'logs', 'mail', 'websites'):   # first match wins
        for p in cats[cat]:
            try:
                rp = os.path.realpath(p)
                if not os.path.isdir(rp) or os.stat(rp).st_dev != root_dev or rp == '/':
                    continue
            except OSError:
                continue
            if any(rp == s or rp.startswith(s + '/') for s in seen):
                continue                                   # inside a folder already counted
            out.setdefault(cat, []).append(rp)
            seen.append(rp)
    # a folder listed after one inside it: keep the outer one only
    for cat, lst in out.items():
        out[cat] = [p for p in lst if not any(p != q and p.startswith(q + '/') for c2 in out.values() for q in c2)]
    return out


def _disk_cat_compute():
    import fcntl, json, os, subprocess, shutil
    os.makedirs(os.path.dirname(DISK_CAT_FILE), exist_ok=True)
    lock = open(DISK_CAT_LOCK, 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return                                          # another worker is already measuring
    try:
        paths = _disk_cat_paths()
        sizes = {}
        argv = ['du', '-sx', '--block-size=1']
        prefix = ['nice', '-n', '19'] + (['ionice', '-c3'] if shutil.which('ionice') else [])
        for cat, lst in paths.items():
            total = 0
            for i in range(0, len(lst), 50):
                try:
                    r = subprocess.run(prefix + argv + lst[i:i + 50], capture_output=True, text=True, timeout=900)
                except subprocess.TimeoutExpired:
                    continue
                for line in r.stdout.splitlines():
                    try:
                        total += int(line.split('\t', 1)[0])
                    except ValueError:
                        pass
            sizes[cat] = total
        st = os.statvfs('/')
        total_b = st.f_blocks * st.f_frsize
        used_b = (st.f_blocks - st.f_bfree) * st.f_frsize
        sizes['other'] = max(0, used_b - sum(sizes.values()))
        data = {'t': int(time.time()), 'total': total_b, 'used': used_b,
                'cats': [{'key': k, 'label': lbl, 'bytes': sizes.get(k, 0)} for k, lbl in DISK_CAT_LABELS]}
        tmp = DISK_CAT_FILE + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(data, f)
        os.replace(tmp, DISK_CAT_FILE)
    finally:
        try:
            fcntl.flock(lock, fcntl.LOCK_UN)
        finally:
            lock.close()


@dashboard_bp.route('/api/dashboard/disk-categories')
def disk_categories():
    """The last measurement (at once), and a new one started in the background when it is
    older than 6 hours or ?refresh=1 was asked."""
    if not req(): return jsonify({'ok': False}), 401
    import json, threading
    from flask import request
    try:
        with open(DISK_CAT_FILE) as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = None
    stale = not data or time.time() - data.get('t', 0) > DISK_CAT_MAX_AGE or request.args.get('refresh') == '1'
    running = False
    if stale:
        import fcntl
        try:
            with open(DISK_CAT_LOCK, 'a') as lk:
                fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(lk, fcntl.LOCK_UN)
            threading.Thread(target=_disk_cat_compute, daemon=True).start()
        except OSError:
            pass                                          # a measurement is already running
        running = True
    return jsonify({'ok': True, 'data': data, 'measuring': running})


# CPU is measured as the change in /proc/stat between one poll and the next, not over a short
# in-request sleep. A short window (80 ms) is noisy and, worse, catches the panel's own polling
# work (reading stats, checking services), so an idle server looked like it was spiking to ~50%.
# The delta since this worker's previous reading averages over the real poll interval.
_CPU_PREV = {'idle': 0, 'total': 0}


def _get_stats():
    def _proc_stat():
        try:
            vals = [int(x) for x in open('/proc/stat').readline().split()[1:]]
            idle, total = (vals[3] if len(vals) > 3 else 0), sum(vals)
            d_idle, d_total = idle - _CPU_PREV['idle'], total - _CPU_PREV['total']
            if _CPU_PREV['total'] and d_total > 0:
                _CPU_PREV.update(idle=idle, total=total)
                return round(max(0.0, min(100.0, (1 - d_idle / d_total) * 100)), 1)
            # first reading since this worker started, or counters reset (reboot): take one short
            # sample so the value is sane, then seed the cache for delta measurement next time
            a = vals
            time.sleep(0.08)
            vals = [int(x) for x in open('/proc/stat').readline().split()[1:]]
            _CPU_PREV.update(idle=(vals[3] if len(vals) > 3 else 0), total=sum(vals))
            da = [vals[i] - a[i] for i in range(min(len(a), len(vals)))]
            tot = sum(da) or 1
            return round((1 - (da[3] if len(da) > 3 else 0) / tot) * 100, 1)
        except Exception:
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
                'php8.6-fpm', 'php8.5-fpm', 'php8.4-fpm', 'php8.3-fpm', 'php8.2-fpm',
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
    """Last 30 minutes of real samples (the old endpoint returned random
    numbers). Full history: /api/monitoring/history."""
    if not req(): return jsonify({'ok': False}), 401
    from panel import metrics
    pts = [{'time': p['ts'], 'cpu': p['cpu'], 'ram': p['mem']} for p in metrics.recent(30)]
    return jsonify({'ok': True, 'history': pts})
