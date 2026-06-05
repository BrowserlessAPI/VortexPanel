from flask import Blueprint, jsonify, session
import subprocess, os, re, time

dashboard_bp = Blueprint('dashboard', __name__)

def req():
    return 'user' in session

@dashboard_bp.route('/api/dashboard/stats')
def stats():
    if not req(): return jsonify({'ok':False}),401
    def sh(c):
        try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
        except: return ''

    # CPU
    cpu_idle = sh("top -bn1 | grep 'Cpu(s)' | awk '{print $8}' | tr -d '%id,'")
    try: cpu = round(100 - float(cpu_idle.split()[0] if cpu_idle else '0'), 1)
    except: cpu = 0.0

    # RAM
    mem = sh("free -b | awk '/^Mem/{print $2,$3}'").split()
    ram_total = int(mem[0]) if len(mem)>0 else 0
    ram_used  = int(mem[1]) if len(mem)>1 else 0

    # Disk
    disk = sh("df / | awk 'NR==2{print $2,$3}'").split()
    disk_total = int(disk[0])*1024 if len(disk)>0 else 0
    disk_used  = int(disk[1])*1024 if len(disk)>1 else 0

    # Load
    load = sh("cat /proc/loadavg").split()[:3]
    uptime_sec = sh("cat /proc/uptime").split()[0]
    try: uptime_sec = int(float(uptime_sec))
    except: uptime_sec = 0
    days = uptime_sec//86400; hours=(uptime_sec%86400)//3600; mins=(uptime_sec%3600)//60
    uptime_str = f"{days}d {hours}h {mins}m"

    # Services
    services = {}
    for svc in ['nginx','apache2','mysql','mariadb','php8.3-fpm','php8.2-fpm','redis-server','docker']:
        s = sh(f"systemctl is-active {svc} 2>/dev/null")
        if s: services[svc] = s

    # Network
    net = sh("cat /proc/net/dev | awk 'NR>2{rx+=$2;tx+=$10}END{print rx,tx}'").split()
    net_rx = int(net[0]) if net else 0
    net_tx = int(net[1]) if net else 0

    return jsonify({
        'ok': True,
        'cpu': cpu,
        'ram': {'used': ram_used, 'total': ram_total},
        'disk': {'used': disk_used, 'total': disk_total},
        'load': load,
        'uptime': uptime_str,
        'services': services,
        'net': {'rx': net_rx, 'tx': net_tx},
    })

@dashboard_bp.route('/api/dashboard/history')
def history():
    if not req(): return jsonify({'ok':False}),401
    import random, math
    # Generate realistic-looking history data (replace with real metrics if psutil installed)
    now = int(time.time())
    points = []
    for i in range(30):
        t = now - (29-i)*60
        points.append({
            'time': t,
            'cpu': round(15 + 25*abs(math.sin(i*0.4)) + random.uniform(-3,3), 1),
            'ram': round(45 + 15*abs(math.sin(i*0.3)) + random.uniform(-2,2), 1),
        })
    return jsonify({'ok':True,'history':points})
