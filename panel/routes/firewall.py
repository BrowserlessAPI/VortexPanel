from flask import Blueprint, jsonify, request, session
import subprocess, re

try:
    from panel.routes.os_utils import get_os
except ImportError:
    try:
        from os_utils import get_os
    except ImportError:
        def get_os(): return {'family': 'debian'}

firewall_bp = Blueprint('firewall', __name__)


def req(): return 'user' in session


def sh(c):
    try: return subprocess.check_output(c, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except: return ''


def _is_rhel_family():
    return get_os().get('family') in ('rhel', 'fedora')


def _get_protocol(d):
    """Frontend sends 'protocol'; accept 'proto' too for older/other callers."""
    return (d.get('protocol') or d.get('proto') or 'tcp').lower()


# ==============================================================================
# UFW (Debian / Ubuntu)
# ==============================================================================

def _ufw_rules():
    raw = sh('ufw status numbered 2>/dev/null')
    status = 'active' if 'Status: active' in raw else 'inactive'
    lines = []
    for line in raw.split('\n'):
        m = re.match(r'\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)(\s+IN|\s+OUT)?\s+(.*)', line)
        if m:
            lines.append({
                'num': int(m.group(1)),
                'to': m.group(2).strip(),
                'action': m.group(3),
                'from': m.group(5).strip(),
            })
    return status, lines


def _ufw_set_status(enable):
    if enable:
        sh('ufw --force enable')
    else:
        sh('ufw --force disable')


def _ufw_add_rule(d):
    action = d.get('action', 'allow')
    port   = d.get('port', '')
    proto  = _get_protocol(d)
    src    = d.get('from', 'any')
    if not port:
        return False, 'Port required'
    cmd = f'ufw {action}'
    if src and src != 'any':
        cmd += f' from {src}'
    cmd += f' to any port {port} proto {proto}'
    sh(cmd)
    return True, None


def _ufw_del_rule(num):
    sh(f'ufw --force delete {num}')
    return True


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


def _fw_zone():
    z = sh('firewall-cmd --get-default-zone 2>/dev/null').strip()
    return z or 'public'


def _fw_active():
    return sh('firewall-cmd --state 2>/dev/null').strip() == 'running'


def _fw_list_combined(zone=None):
    """Return (items, zone). Each item: {num, to, action, from, _type, _raw}
    representing every currently-open port, service, and rich rule in the
    given zone (default zone if not specified)."""
    zone = zone or _fw_zone()
    items = []

    for p in sh(f'firewall-cmd --zone={zone} --list-ports 2>/dev/null').split():
        items.append({'to': p, 'action': 'ALLOW', 'from': 'Anywhere', '_type': 'port', '_raw': p})

    for svc in sh(f'firewall-cmd --zone={zone} --list-services 2>/dev/null').split():
        to = _FW_SERVICE_PORTS.get(svc, svc)
        items.append({'to': to, 'action': 'ALLOW', 'from': 'Anywhere', '_type': 'service', '_raw': svc})

    rich_out = sh(f'firewall-cmd --zone={zone} --list-rich-rules 2>/dev/null')
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
        return sh('systemctl enable --now firewalld 2>&1')
    return sh('systemctl disable --now firewalld 2>&1')


def _fw_add_rule(d):
    port  = str(d.get('port', '')).strip()
    proto = _get_protocol(d)
    action = (d.get('action') or 'allow').lower()
    src    = d.get('from', 'any')
    if not port:
        return False, 'Port required'

    zone = _fw_zone()
    fa = _FW_ACTION_MAP_REV.get(action, 'accept')

    if fa == 'accept' and (not src or src == 'any'):
        sh(f'firewall-cmd --permanent --zone={zone} --add-port={port}/{proto}')
    else:
        src_part = f'source address="{src}" ' if src and src != 'any' else ''
        rule = f'rule family="ipv4" {src_part}port port="{port}" protocol="{proto}" {fa}'
        sh(f"firewall-cmd --permanent --zone={zone} --add-rich-rule='{rule}'")

    sh('firewall-cmd --reload')
    return True, None


def _fw_del_rule(num):
    items, zone = _fw_list_combined()
    target = next((it for it in items if it['num'] == num), None)
    if not target:
        return False
    if target['_type'] == 'port':
        sh(f"firewall-cmd --permanent --zone={zone} --remove-port={target['_raw']}")
    elif target['_type'] == 'service':
        sh(f"firewall-cmd --permanent --zone={zone} --remove-service={target['_raw']}")
    else:
        sh(f"firewall-cmd --permanent --zone={zone} --remove-rich-rule='{target['_raw']}'")
    sh('firewall-cmd --reload')
    return True


_FW_PRESETS = {
    'webserver': [('port', '22/tcp'), ('port', '80/tcp'), ('port', '443/tcp')],
    'mailserver': [('port', '25/tcp'), ('port', '465/tcp'), ('port', '587/tcp'), ('port', '993/tcp'), ('port', '995/tcp')],
    'database': [
        ('rich', 'rule family="ipv4" source address="127.0.0.1" port port="3306" protocol="tcp" accept'),
        ('rich', 'rule family="ipv4" source address="127.0.0.1" port port="5432" protocol="tcp" accept'),
    ],
}


def _fw_apply_preset(preset):
    zone = _fw_zone()
    for kind, val in _FW_PRESETS.get(preset, []):
        if kind == 'port':
            sh(f'firewall-cmd --permanent --zone={zone} --add-port={val}')
        else:
            sh(f"firewall-cmd --permanent --zone={zone} --add-rich-rule='{val}'")
    sh('firewall-cmd --reload')


# ==============================================================================
# ROUTES — dispatch based on detected OS family
# ==============================================================================

@firewall_bp.route('/api/firewall/rules')
def rules():
    if not req(): return jsonify({'ok': False}), 401
    if _is_rhel_family():
        items, _ = _fw_list_combined()
        status = 'active' if _fw_active() else 'inactive'
        out = [{'num': str(it['num']), 'rule': it['to'], 'action': it['action'],
                'direction': 'IN', 'from': it['from']} for it in items]
        return jsonify({'ok': True, 'status': status, 'rules': out})
    status, lines = _ufw_rules()
    out = [{'num': str(l['num']), 'rule': l['to'], 'action': l['action'],
            'direction': 'IN', 'from': l['from']} for l in lines]
    return jsonify({'ok': True, 'status': status, 'rules': out})


@firewall_bp.route('/api/firewall/status', methods=['POST'])
def set_status():
    if not req(): return jsonify({'ok': False}), 401
    enable = (request.get_json() or {}).get('enable', True)
    if _is_rhel_family():
        _fw_set_status(enable)
    else:
        _ufw_set_status(enable)
    return jsonify({'ok': True})


@firewall_bp.route('/api/firewall/rules', methods=['POST'])
def add_rule():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    if not d.get('port'):
        return jsonify({'ok': False, 'error': 'Port required'}), 400
    if _is_rhel_family():
        ok, err = _fw_add_rule(d)
    else:
        ok, err = _ufw_add_rule(d)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok': True})


@firewall_bp.route('/api/firewall/rules/<int:num>', methods=['DELETE'])
def del_rule(num):
    if not req(): return jsonify({'ok': False}), 401
    if _is_rhel_family():
        _fw_del_rule(num)
    else:
        _ufw_del_rule(num)
    return jsonify({'ok': True})


@firewall_bp.route('/api/firewall/presets', methods=['POST'])
def apply_preset():
    if not req(): return jsonify({'ok': False}), 401
    preset = (request.get_json() or {}).get('preset', 'webserver')
    if _is_rhel_family():
        _fw_apply_preset(preset)
    else:
        _ufw_apply_preset(preset)
    return jsonify({'ok': True})


@firewall_bp.route('/api/firewall')
def firewall_overview():
    """Aggregator: returns rules + status in one call for firewallPage.load()"""
    if not req(): return jsonify({'ok': False}), 401
    if _is_rhel_family():
        items, _ = _fw_list_combined()
        status = 'active' if _fw_active() else 'inactive'
        out = [{'num': it['num'], 'to': it['to'], 'action': it['action'], 'from': it['from']} for it in items]
        return jsonify({'ok': True, 'rules': out, 'status': status})
    status, lines = _ufw_rules()
    out = [{'num': l['num'], 'to': l['to'], 'action': l['action'], 'from': l['from']} for l in lines]
    return jsonify({'ok': True, 'rules': out, 'status': status})


@firewall_bp.route('/api/firewall/toggle', methods=['POST'])
def toggle_ufw():
    if not req(): return jsonify({'ok': False}), 401
    enable = (request.get_json() or {}).get('enable', True)
    if _is_rhel_family():
        out = _fw_set_status(enable)
        status = 'active' if _fw_active() else 'inactive'
    else:
        action = 'enable' if enable else 'disable'
        out = sh(f'echo "y" | ufw {action} 2>&1')
        status, _ = _ufw_rules()
    return jsonify({'ok': True, 'output': out or '', 'enabled': status == 'active'})
