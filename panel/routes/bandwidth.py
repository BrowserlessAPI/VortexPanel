from flask import Blueprint, jsonify
import subprocess, re, os, time, shlex
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
def req():
    from panel.routes.auth import check_ip_and_session
    return check_ip_and_session()
def sh(c, t=10):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip()
    except: return ''

def get_interface():
    """Primary network interface: the one carrying the default route (IPv4,
    then IPv6 for v6-only hosts). `awk '{print $5}'` returned 'scope' or
    'proto' for routes without a 'via' hop (point-to-point / some VPS)."""
    for cmd in ('ip -4 route show default 2>/dev/null', 'ip -6 route show default 2>/dev/null'):
        m = re.search(r'\bdev\s+(\S+)', sh(cmd))
        if m:
            return m.group(1)
    try:
        for n in sorted(os.listdir('/sys/class/net')):
            if n != 'lo' and not n.startswith(('veth', 'docker', 'br-', 'virbr')):
                return n
    except Exception:
        pass
    return 'eth0'


def _iface_bytes(iface):
    """(rx, tx) for exactly this interface. `grep eth0` also matched veth0...
    lines, so the first (wrong) match could be used."""
    try:
        for line in open('/proc/net/dev').readlines()[2:]:
            name, _, rest = line.partition(':')
            if name.strip() == iface:
                f = rest.split()
                return int(f[0]), int(f[8])
    except Exception:
        pass
    return None

@bandwidth_bp.route('/api/bandwidth/summary')
def summary():
    if not req(): return jsonify({'ok':False}), 401
    iface = get_interface()

    # Try vnstat first (most reliable)
    vnstat = sh('which vnstat 2>/dev/null')
    if vnstat:
        # Install if not running
        sh('systemctl start vnstat 2>/dev/null || true')
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
    b = _iface_bytes(iface)
    if b:
        rx, tx = b
        return jsonify({'ok':True,'source':'proc','interface':iface,
                       'total_rx':rx,'total_tx':tx,'monthly':[],'daily':[]})

    return jsonify({'ok':True,'source':'none','interface':iface,
                   'total_rx':0,'total_tx':0,'monthly':[],'daily':[]})

@bandwidth_bp.route('/api/bandwidth/realtime')
def realtime():
    if not req(): return jsonify({'ok':False}), 401
    iface = get_interface()

    def read_bytes():
        return _iface_bytes(iface) or (0, 0)

    rx1, tx1 = read_bytes()
    time.sleep(1)
    rx2, tx2 = read_bytes()
    return jsonify({'ok':True,'interface':iface,
                   'rx_per_sec': rx2-rx1, 'tx_per_sec': tx2-tx1,
                   'rx_total':rx2,'tx_total':tx2})

@bandwidth_bp.route('/api/bandwidth/domains')
def domain_bandwidth():
    if not req(): return jsonify({'ok':False}), 401
    domains = {}
    # Per-site access logs written by the panel: nginx and Apache (both use
    # the "combined" format, where $10 is the response size).
    log_dirs = [d for d in ('/var/log/nginx', '/var/log/apache2', '/var/log/httpd') if os.path.isdir(d)]
    if not log_dirs:
        return jsonify({'ok':True,'domains':[],'note':'No Nginx/Apache access logs found'})

    for log_dir in log_dirs:
        for f in os.listdir(log_dir):
            if not f.endswith('.access.log'): continue
            domain = f[:-len('.access.log')]
            fp = os.path.join(log_dir, f)
            if not os.path.isfile(fp): continue
            # Only count numeric size fields: "-" (no body) and lines in a
            # non-combined format would otherwise be summed as garbage. awk
            # prints with %d so big totals are not shown as 1.2e+10.
            out = sh(f'awk \'{{requests++; if ($10 ~ /^[0-9]+$/) bytes+=$10}} END {{printf "%.0f %.0f\\n", requests, bytes}}\' '
                     f'{shlex.quote(fp)} 2>/dev/null', t=60)
            parts = out.split()
            requests = int(parts[0]) if len(parts)>0 and parts[0].isdigit() else 0
            bytes_sent = int(parts[1]) if len(parts)>1 and parts[1].isdigit() else 0
            e = domains.setdefault(domain, {'domain':domain,'requests':0,'bytes':0})
            e['requests'] += requests; e['bytes'] += bytes_sent
    domains = list(domains.values())

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
    out = sh(' && '.join(cmds) + ' 2>&1', t=600)
    installed = bool(sh('which vnstat 2>/dev/null'))
    return jsonify({'ok':installed,'output':out[-300:]})
