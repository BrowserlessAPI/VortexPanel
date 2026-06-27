from flask import Blueprint, jsonify, request, session
import subprocess, os, re, time

monitoring_bp = Blueprint('monitoring', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
    except: return ''


@monitoring_bp.route('/api/monitor/stats')
def monitor_stats_alias():
    return processes()

@monitoring_bp.route('/api/monitor/processes')
def monitor_processes_alias():
    return processes()

@monitoring_bp.route('/api/monitoring')
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
    paths = {
        'nginx_error':  '/var/log/nginx/error.log',
        'nginx_access': '/var/log/nginx/access.log',
        'mysql':        '/var/log/mysql/error.log',
        'syslog':       '/var/log/syslog',
        'auth':         '/var/log/auth.log',
        'mail':         '/var/log/mail.log',
    }
    path = paths.get(log,'/var/log/syslog')
    lines = int(request.args.get('lines', 100))
    content = sh(f'tail -n {lines} {path} 2>/dev/null')
    return jsonify({'ok':True,'content':content,'path':path})

@monitoring_bp.route('/api/monitoring/diskio')
def diskio():
    if not req(): return jsonify({'ok':False}),401
    raw = sh('iostat -d 1 1 2>/dev/null | tail -n +4')
    disks = []
    for line in raw.split('\n'):
        parts = line.strip().split()
        if len(parts)>=6:
            disks.append({'device':parts[0],'reads':parts[3],'writes':parts[4]})
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

    # CPU
    try:
        cpu_out = subprocess.run("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'",
                                  shell=True, capture_output=True, text=True).stdout.strip()
        cpu = float(cpu_out) if cpu_out else 0.0
    except: cpu = 0.0

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
    if pid == '1' or int(pid) == os.getpid():
        return jsonify({'ok':False,'error':'Refusing to kill init or the panel process itself'}),400
    signal_arg = '-9' if d.get('force') else ''
    out = sh(f'kill {signal_arg} {pid} 2>&1')
    return jsonify({'ok':True, 'output':out})
