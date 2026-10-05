from flask import Blueprint, jsonify, request, session
import subprocess, re, os, json, shlex, shutil, ipaddress

try:
    from panel.routes.os_utils import get_os
except ImportError:
    try:
        from os_utils import get_os
    except ImportError:
        def get_os(): return {'family': 'debian'}

firewall_bp = Blueprint('firewall', __name__)


def req(): return 'user' in session


def sh(c, t=30):
    try: return subprocess.check_output(c, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=t).strip()
    except Exception: return ''


def sh3(c, t=60):
    """Run a command and return (stdout, stderr, rc) so failures can be reported."""
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return '', 'Timeout', 1
    except Exception as e:
        return '', str(e), 1


def _is_rhel_family():
    return get_os().get('family') in ('rhel', 'fedora')


def _which(name):
    return shutil.which(name) or next(
        (p for p in (f'/usr/sbin/{name}', f'/sbin/{name}', f'/usr/bin/{name}') if os.path.exists(p)), None)


def _backend():
    """Which firewall frontend to drive: 'ufw', 'firewalld', or None when neither
    is installed. Prefers the distro-native one but falls back to whichever exists
    (e.g. firewalld on Debian, ufw on Fedora)."""
    has_ufw = bool(_which('ufw'))
    has_fwd = bool(_which('firewall-cmd'))
    if _is_rhel_family():
        order = (('firewalld', has_fwd), ('ufw', has_ufw))
    else:
        order = (('ufw', has_ufw), ('firewalld', has_fwd))
    for name, present in order:
        if present:
            return name
    return None


_NO_BACKEND = ('No firewall manager is installed (neither ufw nor firewalld was found). '
               'Install ufw (Debian/Ubuntu) or firewalld (RHEL/Fedora) first.')


def _get_protocol(d):
    """Frontend sends 'protocol'; accept 'proto' too for older/other callers."""
    p = str(d.get('protocol') or d.get('proto') or 'tcp').lower().strip()
    return 'both' if p in ('both', 'any', 'all', 'tcp/udp') else p


def _validate_rule(d):
    """Validate user input before it reaches a shell. Returns (rule, error)."""
    port = str(d.get('port', '')).strip().replace(' ', '')
    m = re.fullmatch(r'(\d{1,5})(?:[:-](\d{1,5}))?', port)
    if not m:
        return None, 'Port must be a number (e.g. 8080) or a range (e.g. 6000-6100)'
    lo = int(m.group(1)); hi = int(m.group(2)) if m.group(2) else None
    if not (1 <= lo <= 65535) or (hi is not None and not (lo < hi <= 65535)):
        return None, 'Port must be between 1 and 65535 (range start below range end)'
    proto = _get_protocol(d)
    if proto not in ('tcp', 'udp', 'both'):
        return None, 'Protocol must be tcp, udp or both'
    action = str(d.get('action') or 'allow').lower().strip()
    if action not in ('allow', 'deny', 'reject', 'limit'):
        return None, 'Action must be allow, deny, reject or limit'
    src = str(d.get('from') or 'any').strip()
    if src.lower() in ('', 'any', 'anywhere'):
        src = 'any'
    else:
        try:
            net = ipaddress.ip_network(src, strict=False)
            src = str(net.network_address) if net.num_addresses == 1 else str(net)
        except ValueError:
            return None, 'Source must be "any", an IP address or a CIDR range'
    return {'lo': lo, 'hi': hi, 'proto': proto, 'action': action, 'from': src}, None


# ==============================================================================
# Lock-out protection: SSH + panel port must stay reachable
# ==============================================================================

def _ssh_ports():
    ports = set()
    out = sh('sshd -T 2>/dev/null | awk \'$1=="port"{print $2}\'', t=10)
    for p in out.split():
        if p.isdigit(): ports.add(int(p))
    if not ports:
        files = ['/etc/ssh/sshd_config']
        d = '/etc/ssh/sshd_config.d'
        if os.path.isdir(d):
            files += [os.path.join(d, f) for f in sorted(os.listdir(d)) if f.endswith('.conf')]
        for fp in files:
            try:
                for line in open(fp):
                    m = re.match(r'\s*Port\s+(\d+)', line, re.I)
                    if m: ports.add(int(m.group(1)))
            except Exception:
                pass
    return ports or {22}


def _panel_ports():
    ports = set()
    try:
        content = open('/etc/systemd/system/vortexpanel.service').read()
        for m in re.finditer(r'(?:--bind|-b)\s+\S*:(\d+)', content):
            ports.add(int(m.group(1)))
    except Exception:
        pass
    try:
        p = json.load(open('/opt/vortexpanel/config.json')).get('port')
        if p: ports.add(int(p))
    except Exception:
        pass
    return ports or {8888}


def _protected_ports():
    return _ssh_ports() | _panel_ports()


def _ports_in(text):
    """Every port number (incl. ranges) mentioned in a rule's 'to' field."""
    found = set()
    text = re.sub(r'\(v6\)', '', text or '')
    for a, b in re.findall(r'(?<![\d.])(\d{1,5})(?:[:-](\d{1,5}))?(?![\d.])', text):
        lo = int(a); hi = int(b) if b else lo
        if hi - lo > 70000: continue
        found.add((lo, hi))
    return found


def _rule_touches_protected(to_text, raw=''):
    t = f'{to_text} {raw}'.lower()
    if 'ssh' in t:
        return True
    prot = _protected_ports()
    for lo, hi in _ports_in(to_text):
        if any(lo <= p <= hi for p in prot):
            return True
    return False


# ==============================================================================
# UFW (Debian / Ubuntu)
# ==============================================================================

def _ufw_rules():
    raw = sh('ufw status numbered 2>/dev/null')
    status = 'active' if 'Status: active' in raw else 'inactive'
    lines = []
    for line in raw.split('\n'):
        m = re.match(r'\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)(\s+IN|\s+OUT|\s+FWD)?\s+(.*)', line)
        if m:
            lines.append({
                'num': int(m.group(1)),
                'to': m.group(2).strip(),
                'action': m.group(3),
                'from': m.group(5).strip(),
            })
    return status, lines


def _ufw_ipv6_fix():
    """ufw with IPV6=yes cannot be enabled when the kernel has IPv6 disabled
    (ipv6.disable=1: ip6tables-restore fails, "problem running ufw-init").
    Switch ufw to IPv4-only in that case. Returns a note or ''."""
    if os.path.exists('/proc/net/if_inet6'):
        return ''
    path = '/etc/default/ufw'
    try:
        with open(path) as f:
            txt = f.read()
    except OSError:
        return ''
    if not re.search(r'^\s*IPV6\s*=\s*"?yes"?\s*$', txt, re.M | re.I):
        return ''
    new = re.sub(r'^\s*IPV6\s*=.*$', 'IPV6=no', txt, flags=re.M | re.I)
    try:
        with open(path, 'w') as f:
            f.write(new)
    except OSError:
        return ''
    return 'IPv6 is disabled in this kernel: ufw was switched to IPv4-only (IPV6=no in /etc/default/ufw). '


def _ufw_set_status(enable):
    if enable:
        note = _ufw_ipv6_fix()
        # Allow SSH and the panel port BEFORE enabling: ufw's default incoming
        # policy is deny, so enabling on a fresh box would otherwise cut off the
        # admin's SSH session and this panel.
        for p in sorted(_protected_ports()):
            sh(f'ufw allow {p}/tcp')
        out, err, rc = sh3('ufw --force enable 2>&1')
        out = note + (out or err)
    else:
        out, err, rc = sh3('ufw --force disable 2>&1')
    status, _ = _ufw_rules()
    want = 'active' if enable else 'inactive'
    return status == want, (out or err)


def _ufw_add_rule(r):
    port = str(r['lo']) if r['hi'] is None else f"{r['lo']}:{r['hi']}"
    protos = ['tcp', 'udp'] if (r['proto'] == 'both' and r['hi'] is not None) else [r['proto']]
    for proto in protos:
        cmd = f"ufw {r['action']}"
        if r['from'] != 'any':
            cmd += f" from {shlex.quote(r['from'])}"
        cmd += f' to any port {port}'
        if proto != 'both':
            cmd += f' proto {proto}'
        out, err, rc = sh3(cmd + ' 2>&1')
        if rc != 0 or 'ERROR' in out:
            return False, out or err or 'ufw rejected the rule'
    return True, None


def _ufw_del_rule(num):
    out, err, rc = sh3(f'ufw --force delete {int(num)} 2>&1')
    if rc != 0:
        return False, out or err or 'ufw delete failed'
    return True, None


UFW_PRESETS = {
    'webserver':  ['ufw allow 22/tcp', 'ufw allow 80/tcp', 'ufw allow 443/tcp'],
    'mailserver': ['ufw allow 25/tcp', 'ufw allow 465/tcp', 'ufw allow 587/tcp', 'ufw allow 993/tcp', 'ufw allow 995/tcp'],
    'database':   ['ufw allow from 127.0.0.1 to any port 3306', 'ufw allow from 127.0.0.1 to any port 5432'],
}


def _ufw_apply_preset(preset):
    for cmd in UFW_PRESETS.get(preset, []):
        sh(cmd)


# ==============================================================================
# firewalld (Fedora / RHEL / AlmaLinux / Rocky / Oracle Linux / CentOS / CloudLinux)
# ==============================================================================

# Map common firewalld service names to a port/proto for display purposes.
_FW_SERVICE_PORTS = {
    'ssh': '22/tcp', 'http': '80/tcp', 'https': '443/tcp', 'ftp': '21/tcp',
    'smtp': '25/tcp', 'smtps': '465/tcp', 'imap': '143/tcp', 'imaps': '993/tcp',
    'pop3': '110/tcp', 'pop3s': '995/tcp', 'dns': '53/tcp',
    'mysql': '3306/tcp', 'postgresql': '5432/tcp',
    'dhcpv6-client': '546/udp', 'cockpit': '9090/tcp',
}

_FW_ACTION_MAP_REV = {'allow': 'accept', 'deny': 'drop', 'reject': 'reject', 'limit': 'accept'}


def _fw_active():
    return sh('firewall-cmd --state 2>/dev/null', t=15).strip() == 'running'


def _fw_cmd(running=None):
    """firewall-cmd needs the daemon running; firewall-offline-cmd edits the
    permanent config while it is stopped (used to pre-open ports before start)."""
    if running is None:
        running = _fw_active()
    if running:
        return 'firewall-cmd --permanent'
    if _which('firewall-offline-cmd'):
        return 'firewall-offline-cmd'
    return 'firewall-cmd --permanent'


def _fw_zone(running=None):
    if running is None:
        running = _fw_active()
    z = sh('firewall-cmd --get-default-zone 2>/dev/null' if running
           else 'firewall-offline-cmd --get-default-zone 2>/dev/null').strip()
    return z if re.fullmatch(r'[A-Za-z0-9_-]+', z or '') else 'public'


def _fw_list_combined(zone=None):
    """Return (items, zone). Each item: {num, to, action, from, _type, _raw}
    representing every currently-open port, service, and rich rule in the
    given zone (default zone if not specified)."""
    running = _fw_active()
    zone = zone or _fw_zone(running)
    base = 'firewall-cmd' if running else ('firewall-offline-cmd' if _which('firewall-offline-cmd') else 'firewall-cmd')
    items = []

    for p in sh(f'{base} --zone={zone} --list-ports 2>/dev/null').split():
        items.append({'to': p, 'action': 'ALLOW', 'from': 'Anywhere', '_type': 'port', '_raw': p})

    for svc in sh(f'{base} --zone={zone} --list-services 2>/dev/null').split():
        to = _FW_SERVICE_PORTS.get(svc, svc)
        items.append({'to': to, 'action': 'ALLOW', 'from': 'Anywhere', '_type': 'service', '_raw': svc})

    rich_out = sh(f'{base} --zone={zone} --list-rich-rules 2>/dev/null')
    for line in rich_out.split('\n'):
        line = line.strip()
        if not line:
            continue
        m_port = re.search(r'port\s+port="([^"]+)"\s+protocol="(tcp|udp)"', line)
        m_src  = re.search(r'source\s+address="([^"]+)"', line)
        if ' accept' in line:
            act = 'ALLOW'
        elif ' reject' in line:
            act = 'REJECT'
        elif ' drop' in line:
            act = 'DENY'
        else:
            act = 'ALLOW'
        to  = f'{m_port.group(1)}/{m_port.group(2)}' if m_port else line
        frm = m_src.group(1) if m_src else 'Anywhere'
        items.append({'to': to, 'action': act, 'from': frm, '_type': 'rich', '_raw': line})

    for i, it in enumerate(items, 1):
        it['num'] = i
    return items, zone


def _fw_set_status(enable):
    if enable:
        running = _fw_active()
        zone = _fw_zone(running)
        base = _fw_cmd(running)
        # Pre-open SSH + panel port in the permanent config (offline when the
        # daemon is stopped) so the admin is not locked out the moment it starts.
        for p in sorted(_protected_ports()):
            sh(f'{base} --zone={zone} --add-port={p}/tcp 2>/dev/null')
        out, err, rc = sh3('systemctl enable --now firewalld 2>&1')
        if _fw_active():
            for p in sorted(_protected_ports()):
                sh(f'firewall-cmd --zone={zone} --add-port={p}/tcp 2>/dev/null')
                sh(f'firewall-cmd --permanent --zone={zone} --add-port={p}/tcp 2>/dev/null')
        return _fw_active(), (out or err)
    out, err, rc = sh3('systemctl disable --now firewalld 2>&1')
    return not _fw_active(), (out or err)


def _fw_add_rule(r):
    running = _fw_active()
    zone = _fw_zone(running)
    base = _fw_cmd(running)
    fa = _FW_ACTION_MAP_REV.get(r['action'], 'accept')
    port = str(r['lo']) if r['hi'] is None else f"{r['lo']}-{r['hi']}"
    protos = ['tcp', 'udp'] if r['proto'] == 'both' else [r['proto']]
    src = r['from']

    for proto in protos:
        if fa == 'accept' and src == 'any':
            out, err, rc = sh3(f'{base} --zone={zone} --add-port={port}/{proto} 2>&1')
        else:
            if src != 'any':
                fam = 'ipv6' if ':' in src else 'ipv4'
                head = f'rule family="{fam}" source address="{src}" '
            else:
                # No family -> the rule applies to IPv4 AND IPv6.
                head = 'rule '
            rule = f'{head}port port="{port}" protocol="{proto}" {fa}'
            out, err, rc = sh3(f'{base} --zone={zone} --add-rich-rule={shlex.quote(rule)} 2>&1')
        if rc != 0:
            return False, out or err or 'firewalld rejected the rule'

    if running:
        sh('firewall-cmd --reload')
    return True, None


def _fw_del_rule(num, force=False):
    items, zone = _fw_list_combined()
    target = next((it for it in items if it['num'] == num), None)
    if not target:
        return False, 'Rule not found (the list may have changed - reload and try again)'
    if not force and target['action'] == 'ALLOW' and _rule_touches_protected(target['to'], target['_raw']):
        return False, ('Refusing to delete a rule that keeps SSH or the panel port reachable '
                       '(this could lock you out). Send force=true to override.')
    running = _fw_active()
    base = _fw_cmd(running)
    if target['_type'] == 'port':
        out, err, rc = sh3(f"{base} --zone={zone} --remove-port={shlex.quote(target['_raw'])} 2>&1")
    elif target['_type'] == 'service':
        out, err, rc = sh3(f"{base} --zone={zone} --remove-service={shlex.quote(target['_raw'])} 2>&1")
    else:
        out, err, rc = sh3(f"{base} --zone={zone} --remove-rich-rule={shlex.quote(target['_raw'])} 2>&1")
    if rc != 0:
        return False, out or err or 'firewalld delete failed'
    if running:
        sh('firewall-cmd --reload')
    return True, None


_FW_PRESETS = {
    'webserver': [('port', '22/tcp'), ('port', '80/tcp'), ('port', '443/tcp')],
    'mailserver': [('port', '25/tcp'), ('port', '465/tcp'), ('port', '587/tcp'), ('port', '993/tcp'), ('port', '995/tcp')],
    'database': [
        ('rich', 'rule family="ipv4" source address="127.0.0.1" port port="3306" protocol="tcp" accept'),
        ('rich', 'rule family="ipv4" source address="127.0.0.1" port port="5432" protocol="tcp" accept'),
    ],
}


def _fw_apply_preset(preset):
    running = _fw_active()
    zone = _fw_zone(running)
    base = _fw_cmd(running)
    for kind, val in _FW_PRESETS.get(preset, []):
        if kind == 'port':
            sh(f'{base} --zone={zone} --add-port={val}')
        else:
            sh(f"{base} --zone={zone} --add-rich-rule={shlex.quote(val)}")
    if running:
        sh('firewall-cmd --reload')


# ==============================================================================
# ROUTES -- dispatch based on the installed firewall manager
# ==============================================================================

def _listing():
    be = _backend()
    if be == 'firewalld':
        items, _ = _fw_list_combined()
        status = 'active' if _fw_active() else 'inactive'
        return be, status, [{'num': it['num'], 'to': it['to'], 'action': it['action'], 'from': it['from']} for it in items]
    if be == 'ufw':
        status, lines = _ufw_rules()
        return be, status, [{'num': l['num'], 'to': l['to'], 'action': l['action'], 'from': l['from']} for l in lines]
    return None, 'not installed', []


@firewall_bp.route('/api/firewall/rules')
def rules():
    if not req(): return jsonify({'ok': False}), 401
    be, status, items = _listing()
    out = [{'num': str(it['num']), 'rule': it['to'], 'action': it['action'],
            'direction': 'IN', 'from': it['from']} for it in items]
    return jsonify({'ok': True, 'status': status, 'backend': be, 'rules': out})


def _toggle(enable):
    be = _backend()
    if not be:
        return jsonify({'ok': False, 'error': _NO_BACKEND}), 400
    if be == 'firewalld':
        ok, out = _fw_set_status(enable)
        status = 'active' if _fw_active() else 'inactive'
    else:
        ok, out = _ufw_set_status(enable)
        status, _ = _ufw_rules()
    resp = {'ok': ok, 'output': out or '', 'enabled': status == 'active', 'backend': be}
    if not ok:
        resp['error'] = (out or 'Firewall state did not change') + (
            ' (on containers/VPSes without netfilter kernel modules the firewall cannot be enabled)' if enable else '')
    return jsonify(resp)


@firewall_bp.route('/api/firewall/status', methods=['POST'])
def set_status():
    if not req(): return jsonify({'ok': False}), 401
    enable = bool((request.get_json() or {}).get('enable', True))
    return _toggle(enable)


@firewall_bp.route('/api/firewall/rules', methods=['POST'])
def add_rule():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    if not str(d.get('port', '')).strip():
        return jsonify({'ok': False, 'error': 'Port required'}), 400
    r, err = _validate_rule(d)
    if err:
        return jsonify({'ok': False, 'error': err}), 400
    be = _backend()
    if not be:
        return jsonify({'ok': False, 'error': _NO_BACKEND}), 400
    if r['action'] in ('deny', 'reject') and r['from'] == 'any':
        prot = _protected_ports()
        hi = r['hi'] if r['hi'] is not None else r['lo']
        if any(r['lo'] <= p <= hi for p in prot) and not d.get('force'):
            return jsonify({'ok': False, 'error': 'Refusing to block SSH or the panel port for everyone (this would lock you out). Send force=true to override.'}), 400
    if be == 'firewalld':
        ok, err = _fw_add_rule(r)
    else:
        ok, err = _ufw_add_rule(r)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok': True})


@firewall_bp.route('/api/firewall/rules/<int:num>', methods=['DELETE'])
def del_rule(num):
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json(silent=True) or {}
    force = bool(d.get('force')) or request.args.get('force') in ('1', 'true')
    be = _backend()
    if not be:
        return jsonify({'ok': False, 'error': _NO_BACKEND}), 400
    if be == 'firewalld':
        ok, err = _fw_del_rule(num, force)
    else:
        status, lines = _ufw_rules()
        target = next((l for l in lines if l['num'] == num), None)
        if not target:
            return jsonify({'ok': False, 'error': 'Rule not found (the list may have changed - reload and try again)'}), 404
        if (not force and status == 'active' and target['action'] in ('ALLOW', 'LIMIT')
                and _rule_touches_protected(target['to'])):
            return jsonify({'ok': False, 'error': 'Refusing to delete a rule that keeps SSH or the panel port reachable (this could lock you out). Send force=true to override.'}), 400
        ok, err = _ufw_del_rule(num)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok': True})


@firewall_bp.route('/api/firewall/presets', methods=['POST'])
def apply_preset():
    if not req(): return jsonify({'ok': False}), 401
    preset = (request.get_json() or {}).get('preset', 'webserver')
    if preset not in UFW_PRESETS:
        return jsonify({'ok': False, 'error': 'Unknown preset'}), 400
    be = _backend()
    if not be:
        return jsonify({'ok': False, 'error': _NO_BACKEND}), 400
    if be == 'firewalld':
        _fw_apply_preset(preset)
    else:
        _ufw_apply_preset(preset)
    return jsonify({'ok': True})


@firewall_bp.route('/api/firewall')
def firewall_overview():
    """Aggregator: returns rules + status in one call for firewallPage.load()"""
    if not req(): return jsonify({'ok': False}), 401
    be, status, items = _listing()
    resp = {'ok': True, 'rules': items, 'status': status, 'backend': be}
    if not be:
        resp['error'] = _NO_BACKEND
    return jsonify(resp)


@firewall_bp.route('/api/firewall/toggle', methods=['POST'])
def toggle_ufw():
    if not req(): return jsonify({'ok': False}), 401
    enable = bool((request.get_json() or {}).get('enable', True))
    return _toggle(enable)
