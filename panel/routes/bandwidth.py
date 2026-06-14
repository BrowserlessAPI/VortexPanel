from flask import Blueprint, jsonify, request, session
import subprocess, re, os, time
try:
    from panel.routes.os_utils import get_os, pkg_install, pkg_update, pkg_remove
except ImportError:
    try:
        from os_utils import get_os, pkg_install, pkg_update, pkg_remove
    except ImportError:
        def get_os(): return {'family':'debian','pkg':'apt','id':'ubuntu','codename':'noble'}
        def pkg_install(p, f=''): return f'DEBIAN_FRONTEND=noninteractive apt-get install -y {f} {p}'
        def pkg_update(): return 'apt-get update -qq'
        def pkg_remove(p): return f'apt-get remove -y --purge {p} && apt-get autoremove -y'


bandwidth_bp = Blueprint('bandwidth', __name__)
def req(): return 'user' in session
def sh(c, t=10):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip()
    except: return ''

def get_interface():
    """Get primary network interface"""
    out = sh("ip route | grep default | awk '{print $5}' | head -1")
    if out: return out
    out = sh("ls /sys/class/net/ | grep -v lo | head -1")
    return out or 'eth0'

@bandwidth_bp.route('/api/bandwidth/summary')
def summary():
    if not req(): return jsonify({'ok':False}), 401
    iface = get_interface()

    # Try vnstat first (most reliable)
    vnstat = sh('which vnstat 2>/dev/null')
    if vnstat:
        # Install if not running
        sh('systemctl start vnstat 2>/dev/null || true')
        daily  = sh(f'vnstat -i {iface} --json d 2>/dev/null')
        monthly = sh(f'vnstat -i {iface} --json m 2>/dev/null')
        total  = sh(f'vnstat -i {iface} --json 2>/dev/null')
        try:
            import json
            d = json.loads(total)
            iface_data = d.get('interfaces',[{}])[0] if d.get('interfaces') else {}
            traffic = iface_data.get('traffic',{})
            total_rx = traffic.get('total',{}).get('rx',0)
            total_tx = traffic.get('total',{}).get('tx',0)

            # Monthly
            months = traffic.get('month',[])
            monthly_list = []
            for m in months[-6:]:
                monthly_list.append({
                    'date': f"{m.get('date',{}).get('year','')-0 if isinstance(m.get('date',{}),dict) else ''}/{m.get('date',{}).get('month','')}",
                    'rx': m.get('rx',0),
                    'tx': m.get('tx',0),
                })

            # Daily (last 7)
            days = traffic.get('day',[])
            daily_list = []
            for day in days[-7:]:
                dt = day.get('date',{})
                daily_list.append({
                    'date': f"{dt.get('year','')}-{dt.get('month','')-0:02d}-{dt.get('day','')-0:02d}" if isinstance(dt,dict) else '',
                    'rx': day.get('rx',0),
                    'tx': day.get('tx',0),
                })

            return jsonify({'ok':True,'source':'vnstat','interface':iface,
                           'total_rx':total_rx,'total_tx':total_tx,
                           'monthly':monthly_list,'daily':daily_list})
        except: pass

    # Fallback: /proc/net/dev
    proc = sh(f'cat /proc/net/dev 2>/dev/null | grep {iface}')
    if proc:
        parts = proc.split()
        rx = int(parts[1]) if len(parts)>1 else 0
        tx = int(parts[9]) if len(parts)>9 else 0
        return jsonify({'ok':True,'source':'proc','interface':iface,
                       'total_rx':rx,'total_tx':tx,'monthly':[],'daily':[]})

    return jsonify({'ok':True,'source':'none','interface':iface,
                   'total_rx':0,'total_tx':0,'monthly':[],'daily':[]})

@bandwidth_bp.route('/api/bandwidth/realtime')
def realtime():
    if not req(): return jsonify({'ok':False}), 401
    iface = get_interface()

    def read_bytes():
        p = sh(f'cat /proc/net/dev | grep {iface}')
        if not p: return 0, 0
        parts = p.split()
        return int(parts[1]) if len(parts)>1 else 0, int(parts[9]) if len(parts)>9 else 0

    rx1, tx1 = read_bytes()
    time.sleep(1)
    rx2, tx2 = read_bytes()
    return jsonify({'ok':True,'interface':iface,
                   'rx_per_sec': rx2-rx1, 'tx_per_sec': tx2-tx1,
                   'rx_total':rx2,'tx_total':tx2})

@bandwidth_bp.route('/api/bandwidth/domains')
def domain_bandwidth():
    if not req(): return jsonify({'ok':False}), 401
    domains = []
    log_dir = '/var/log/nginx'
    if not os.path.isdir(log_dir):
        return jsonify({'ok':True,'domains':[],'note':'No Nginx access logs found'})

    for f in os.listdir(log_dir):
        if not f.endswith('.access.log'): continue
        domain = f.replace('.access.log','')
        fp = os.path.join(log_dir, f)
        if not os.path.exists(fp): continue
        # Count requests and sum bytes from nginx log
        # Nginx default format: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
        out = sh(f'awk \'{{requests++; bytes+=$10}} END {{print requests, bytes}}\' {fp} 2>/dev/null')
        parts = out.split()
        requests = int(parts[0]) if len(parts)>0 and parts[0].isdigit() else 0
        bytes_sent = int(parts[1]) if len(parts)>1 and parts[1].isdigit() else 0
        domains.append({'domain':domain,'requests':requests,'bytes':bytes_sent})

    domains.sort(key=lambda x: x['bytes'], reverse=True)
    return jsonify({'ok':True,'domains':domains})

@bandwidth_bp.route('/api/bandwidth/install-vnstat', methods=['POST'])
def install_vnstat():
    if not req(): return jsonify({'ok':False}), 401
    _os = get_os()
    cmds = []
    if _os['family'] == 'debian':
        cmds.append('apt-get update -qq 2>/dev/null || true')
    elif _os['family'] == 'rhel':
        cmds.append('dnf install -y epel-release 2>/dev/null || true')
    cmds.append(pkg_install('vnstat'))
    cmds.append('systemctl enable vnstat 2>/dev/null || true')
    cmds.append('systemctl start vnstat 2>/dev/null || true')
    out = sh(' && '.join(cmds) + ' 2>&1', t=120)
    installed = bool(sh('which vnstat 2>/dev/null'))
    return jsonify({'ok':installed,'output':out[-300:]})
