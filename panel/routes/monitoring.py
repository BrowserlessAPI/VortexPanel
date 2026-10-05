from flask import Blueprint, jsonify, request
import subprocess, os, re, time

monitoring_bp = Blueprint('monitoring', __name__)
def req():
    from panel.routes.auth import check_ip_and_session
    return check_ip_and_session()
def sh(c):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL,timeout=20).strip()
    except: return ''


@monitoring_bp.route('/api/monitor/stats')
def monitor_stats_alias():
    return processes()

@monitoring_bp.route('/api/monitor/processes')
def monitor_processes_alias():
    return processes()

# NOTE: '/api/monitoring' is served by monitoring_overview() below (the
# aggregator the monitoring page actually calls). This alias previously also
# registered '/api/monitoring' and, being registered first, SHADOWED the
# overview handler — so the page only ever received a bare process list. Alias
# kept for '/api/monitor/*' spellings only.
def monitoring_root():
    return processes()

@monitoring_bp.route('/api/monitoring/processes')
def processes():
    if not req(): return jsonify({'ok':False}),401
    raw = sh("ps aux --sort=-%cpu | head -21 | awk 'NR>1{print $1,$2,$3,$4,$11}'")
    procs = []
    for line in raw.split('\n'):
        parts = line.strip().split(None,4)
        if len(parts)>=5:
            procs.append({'user':parts[0],'pid':parts[1],'cpu':parts[2],'mem':parts[3],'cmd':parts[4][:60]})
    return jsonify({'ok':True,'processes':procs})

@monitoring_bp.route('/api/monitoring/logs')
def logs():
    if not req(): return jsonify({'ok':False}),401
    log = request.args.get('log','nginx_error')
    # Each logical log maps to candidate paths (Debian first, RHEL second) —
    # pick the first that exists. On RHEL: messages/secure/maillog/mysqld.log.
    candidates = {
        'nginx_error':  ['/var/log/nginx/error.log'],
        'nginx_access': ['/var/log/nginx/access.log'],
        'mysql':        ['/var/log/mysql/error.log', '/var/log/mariadb/mariadb.log', '/var/log/mysqld.log'],
        'syslog':       ['/var/log/syslog', '/var/log/messages'],
        'auth':         ['/var/log/auth.log', '/var/log/secure'],
        'mail':         ['/var/log/mail.log', '/var/log/maillog'],
    }.get(log, ['/var/log/syslog', '/var/log/messages'])
    path = next((p for p in candidates if os.path.exists(p)), candidates[0])
    try:
        lines = max(1, min(int(request.args.get('lines', 100)), 5000))
    except (TypeError, ValueError):
        lines = 100
    content = sh(f'tail -n {lines} {path} 2>/dev/null')
    return jsonify({'ok':True,'content':content,'path':path})

@monitoring_bp.route('/api/monitoring/diskio')
def diskio():
    if not req(): return jsonify({'ok':False}),401
    # Was `iostat` (sysstat, usually not installed) with the columns read
    # off by one (reads = kB_wrtn/s). /proc/diskstats is always there.
    def snap():
        d = {}
        try:
            for line in open('/proc/diskstats'):
                f = line.split()
                if len(f) < 14 or re.match(r'^(loop|ram|zram|fd|sr)\d', f[2]):
                    continue
                d[f[2]] = (int(f[5]), int(f[9]))   # sectors read / written
        except Exception:
            pass
        return d
    a = snap(); time.sleep(1); b = snap()
    disks = []
    for dev, (r2, w2) in b.items():
        r1, w1 = a.get(dev, (r2, w2))
        disks.append({'device': dev, 'reads': round((r2 - r1) * 512 / 1024, 1),
                      'writes': round((w2 - w1) * 512 / 1024, 1)})   # kB/s
    return jsonify({'ok':True,'disks':disks})

@monitoring_bp.route('/api/monitoring/netstat')
def netstat():
    if not req(): return jsonify({'ok':False}),401
    raw = sh('ss -tlnp 2>/dev/null | head -30')
    return jsonify({'ok':True,'output':raw})

@monitoring_bp.route('/api/monitoring/fail2ban')
def fail2ban():
    if not req(): return jsonify({'ok':False}),401
    raw = sh('fail2ban-client status 2>/dev/null')
    return jsonify({'ok':True,'output':raw})

@monitoring_bp.route('/api/monitoring')
def monitoring_overview():
    """Aggregator endpoint for monitoringPage.load()"""
    if not req(): return jsonify({'ok': False}), 401
    import subprocess, re as _re

    # CPU: total busy % from /proc/stat. `top -bn1 ... $2` was only the user
    # share, the since-boot average, broke on comma-decimal locales and ran
    # with no timeout.
    try:
        def _t():
            v = [int(x) for x in open('/proc/stat').readline().split()[1:]]
            return v[3] + (v[4] if len(v) > 4 else 0), sum(v)
        i1, t1 = _t(); time.sleep(0.2); i2, t2 = _t()
        cpu = round((1 - (i2 - i1) / ((t2 - t1) or 1)) * 100, 1)
    except Exception: cpu = 0.0

    # RAM
    try:
        mem_out = subprocess.run("free -m | awk 'NR==2{print $2,$3}'",
                                  shell=True, capture_output=True, text=True, timeout=5).stdout.strip().split()
        ram_total = int(mem_out[0]) if len(mem_out)>0 else 0
        ram_used  = int(mem_out[1]) if len(mem_out)>1 else 0
        ram_pct   = round(ram_used/ram_total*100, 1) if ram_total else 0
        ram_str   = f"{ram_used} MB / {ram_total} MB"
    except: ram_pct=0; ram_str=''

    # Disk
    try:
        disk_out = subprocess.run("df / | awk 'NR==2{print $5}'",
                                   shell=True, capture_output=True, text=True, timeout=5).stdout.strip().rstrip('%')
        disk = int(disk_out) if disk_out.isdigit() else 0
    except: disk = 0

    # Uptime
    try:
        uptime = subprocess.run("uptime -p", shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
    except: uptime = ''

    # Load
    try:
        load = subprocess.run("cat /proc/loadavg", shell=True, capture_output=True, text=True, timeout=5).stdout.strip().split()
        load_str = ' '.join(load[:3]) if load else ''
    except: load_str = ''

    # Top processes
    processes = []
    try:
        proc_out = subprocess.run(
            "ps aux --sort=-%cpu | head -11 | tail -10",
            shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        for line in proc_out.split('\n'):
            parts = line.split(None, 10)
            if len(parts) >= 11:
                processes.append({
                    'pid':    parts[1],
                    'cpu':    parts[2]+'%',
                    'mem':    parts[3]+'%',
                    'status': parts[7],
                    'name':   parts[10][:40],
                })
    except: pass

    return jsonify({
        'ok':        True,
        'cpu':       cpu,
        'ram':       ram_str,
        'ram_pct':   ram_pct,
        'disk':      disk,
        'uptime':    uptime,
        'load':      load_str,
        'processes': processes,
    })

@monitoring_bp.route('/api/monitoring/processes/kill', methods=['POST'])
def kill_process():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    pid = str(d.get('pid','')).strip()
    if not pid.isdigit():
        return jsonify({'ok':False,'error':'Invalid PID'}),400
    if pid == '1' or int(pid) in (os.getpid(), os.getppid()):
        return jsonify({'ok':False,'error':'Refusing to kill init or the panel process itself'}),400
    # Other gunicorn workers of this panel are children of the same master.
    try:
        ppid = int(open(f'/proc/{pid}/stat').read().rsplit(')', 1)[1].split()[1])
        if ppid == os.getppid():
            return jsonify({'ok':False,'error':'Refusing to kill a VortexPanel worker process'}),400
    except Exception:
        pass
    import signal as _signal
    try:
        os.kill(int(pid), _signal.SIGKILL if d.get('force') else _signal.SIGTERM)
    except ProcessLookupError:
        return jsonify({'ok':False,'error':f'No process with PID {pid}'}),404
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)}),500
    return jsonify({'ok':True, 'output':''})
