from flask import Blueprint, jsonify, request, session
import subprocess, re

firewall_bp = Blueprint('firewall', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
    except: return ''

@firewall_bp.route('/api/firewall/rules')
def rules():
    if not req(): return jsonify({'ok':False}),401
    raw = sh('ufw status numbered 2>/dev/null')
    status = 'active' if 'Status: active' in raw else 'inactive'
    lines = []
    for line in raw.split('\n'):
        m = re.match(r'\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)?\s*(.*)', line)
        if m:
            lines.append({'num':m.group(1),'rule':m.group(2).strip(),'action':m.group(3),'direction':m.group(4) or 'IN','from':m.group(5).strip()})
    return jsonify({'ok':True,'status':status,'rules':lines})

@firewall_bp.route('/api/firewall/status', methods=['POST'])
def set_status():
    if not req(): return jsonify({'ok':False}),401
    enable = (request.get_json() or {}).get('enable', True)
    if enable:
        sh('ufw --force enable')
    else:
        sh('ufw --force disable')
    return jsonify({'ok':True})

@firewall_bp.route('/api/firewall/rules', methods=['POST'])
def add_rule():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    action = d.get('action','allow')
    port   = d.get('port','')
    proto  = d.get('proto','tcp')
    src    = d.get('from','any')
    if not port: return jsonify({'ok':False,'error':'Port required'}),400
    cmd = f'ufw {action}'
    if src != 'any': cmd += f' from {src}'
    cmd += f' to any port {port} proto {proto}'
    sh(cmd)
    return jsonify({'ok':True})

@firewall_bp.route('/api/firewall/rules/<int:num>', methods=['DELETE'])
def del_rule(num):
    if not req(): return jsonify({'ok':False}),401
    sh(f'ufw --force delete {num}')
    return jsonify({'ok':True})

@firewall_bp.route('/api/firewall/presets', methods=['POST'])
def apply_preset():
    if not req(): return jsonify({'ok':False}),401
    preset = (request.get_json() or {}).get('preset','webserver')
    presets = {
        'webserver': ['ufw allow 22/tcp','ufw allow 80/tcp','ufw allow 443/tcp'],
        'mailserver': ['ufw allow 25/tcp','ufw allow 465/tcp','ufw allow 587/tcp','ufw allow 993/tcp','ufw allow 995/tcp'],
        'database': ['ufw allow from 127.0.0.1 to any port 3306','ufw allow from 127.0.0.1 to any port 5432'],
    }
    for cmd in presets.get(preset,[]):
        sh(cmd)
    return jsonify({'ok':True})

@firewall_bp.route('/api/firewall')
def firewall_overview():
    """Aggregator: returns rules + status in one call for firewallPage.load()"""
    if not req(): return jsonify({'ok': False}), 401
    raw = sh('ufw status numbered 2>/dev/null')
    rules = []
    for line in raw.split('\n'):
        m = re.match(r'\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)(\s+IN|\s+OUT)?\s+(.*)', line)
        if m:
            rules.append({'num':int(m.group(1)), 'to':m.group(2).strip(),
                         'action':m.group(3), 'from':m.group(5).strip()})
    status = 'active' if 'Status: active' in raw else 'inactive'
    return jsonify({'ok': True, 'rules': rules, 'status': status})

@firewall_bp.route('/api/firewall/toggle', methods=['POST'])
def toggle_ufw():
    if not req(): return jsonify({'ok': False}), 401
    enable = (request.get_json() or {}).get('enable', True)
    action = 'enable' if enable else 'disable'
    out = sh(f'echo "y" | ufw {action} 2>&1')
    return jsonify({'ok': True, 'output': out, 'enabled': enable})
