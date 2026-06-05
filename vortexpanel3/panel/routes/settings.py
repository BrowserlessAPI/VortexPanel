from flask import Blueprint, jsonify, request, session
import subprocess, os, json, hashlib

settings_bp = Blueprint('settings', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
    except: return ''

CONFIG_FILE = '/opt/vortexpanel/config.json'

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f: return json.load(f)
    return {'panel_name':'VortexPanel','port':8888,'ssl_enabled':False,'auto_update':True,'timezone':'UTC'}

def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE,'w') as f: json.dump(cfg, f, indent=2)

@settings_bp.route('/api/settings')
def get_settings():
    if not req(): return jsonify({'ok':False}),401
    cfg = load_config()
    # System info
    hostname = sh('hostname')
    os_info  = sh('cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2').strip('"')
    kernel   = sh('uname -r')
    cpu_info = sh("cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d: -f2").strip()
    ip       = sh("hostname -I | awk '{print $1}'")
    return jsonify({'ok':True,'config':cfg,'system':{'hostname':hostname,'os':os_info,'kernel':kernel,'cpu':cpu_info,'ip':ip}})

@settings_bp.route('/api/settings', methods=['PUT'])
def save_settings():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    cfg = load_config()
    cfg.update({k:v for k,v in d.items() if k in ('panel_name','ssl_enabled','auto_update','timezone','smtp_host','smtp_port','smtp_user','smtp_pass')})
    save_config(cfg)
    return jsonify({'ok':True})

@settings_bp.route('/api/settings/password', methods=['POST'])
def change_password():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    new_pw = d.get('new_password','')
    if len(new_pw) < 6: return jsonify({'ok':False,'error':'Min 6 characters'}),400
    from panel.routes.auth import CREDS_FILE, get_credentials
    creds = get_credentials()
    creds['password_hash'] = hashlib.sha256(new_pw.encode()).hexdigest()
    os.makedirs(os.path.dirname(CREDS_FILE), exist_ok=True)
    with open(CREDS_FILE,'w') as f: json.dump(creds, f)
    return jsonify({'ok':True})

@settings_bp.route('/api/settings/hostname', methods=['POST'])
def set_hostname():
    if not req(): return jsonify({'ok':False}),401
    name = (request.get_json() or {}).get('hostname','').strip()
    if not name: return jsonify({'ok':False,'error':'Hostname required'}),400
    sh(f'hostnamectl set-hostname {name}')
    return jsonify({'ok':True})

@settings_bp.route('/api/settings/update', methods=['POST'])
def system_update():
    if not req(): return jsonify({'ok':False}),401
    import threading
    def do_update():
        sh('apt-get update -y && apt-get upgrade -y', t=300)
    threading.Thread(target=do_update, daemon=True).start()
    return jsonify({'ok':True,'message':'System update started in background'})

@settings_bp.route('/api/settings/reboot', methods=['POST'])
def reboot():
    if not req(): return jsonify({'ok':False}),401
    import threading
    threading.Thread(target=lambda: sh('sleep 3 && reboot'), daemon=True).start()
    return jsonify({'ok':True,'message':'Rebooting in 3 seconds...'})
