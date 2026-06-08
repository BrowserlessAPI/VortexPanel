from flask import Blueprint, jsonify, request, session
import subprocess, os, json, threading, time, requests as req_lib

ddns_bp = Blueprint('ddns', __name__)
def req(): return 'user' in session

DDNS_CONFIG = '/opt/vortexpanel/ddns_config.json'
DDNS_LOG    = '/opt/vortexpanel/ddns.log'
DDNS_PID    = '/opt/vortexpanel/ddns.pid'

def load_config():
    if os.path.exists(DDNS_CONFIG):
        try:
            with open(DDNS_CONFIG) as f: return json.load(f)
        except: pass
    return {'domains': [], 'enabled': False, 'interval': 300}

def save_config(cfg):
    os.makedirs('/opt/vortexpanel', exist_ok=True)
    with open(DDNS_CONFIG, 'w') as f: json.dump(cfg, f, indent=2)

def get_public_ip():
    for url in ['https://api.ipify.org', 'https://ifconfig.me/ip', 'https://icanhazip.com']:
        try:
            r = req_lib.get(url, timeout=5)
            if r.status_code == 200:
                return r.text.strip()
        except: pass
    return None

def update_cloudflare(domain_cfg, ip):
    token   = domain_cfg.get('api_token','')
    domain  = domain_cfg.get('domain','')
    email   = domain_cfg.get('email','')
    api_limit = domain_cfg.get('api_limit', False)

    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    if not api_limit and email:
        headers = {'X-Auth-Email': email, 'X-Auth-Key': token, 'Content-Type': 'application/json'}

    # Get zone ID
    try:
        root_domain = '.'.join(domain.split('.')[-2:])
        r = req_lib.get(f'https://api.cloudflare.com/client/v4/zones?name={root_domain}', headers=headers, timeout=10)
        zones = r.json().get('result', [])
        if not zones: return False, f'Zone not found for {root_domain}'
        zone_id = zones[0]['id']

        # Get DNS record
        r = req_lib.get(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={domain}', headers=headers, timeout=10)
        records = r.json().get('result', [])

        if records:
            record_id = records[0]['id']
            current_ip = records[0]['content']
            if current_ip == ip:
                return True, f'IP unchanged ({ip})'
            # Update record
            r = req_lib.put(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}',
                headers=headers, json={'type':'A','name':domain,'content':ip,'ttl':120,'proxied':False}, timeout=10)
            if r.json().get('success'):
                return True, f'Updated {domain} → {ip}'
            return False, r.json().get('errors', 'Update failed')
        else:
            # Create record
            r = req_lib.post(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records',
                headers=headers, json={'type':'A','name':domain,'content':ip,'ttl':120,'proxied':False}, timeout=10)
            if r.json().get('success'):
                return True, f'Created {domain} → {ip}'
            return False, r.json().get('errors', 'Create failed')
    except Exception as e:
        return False, str(e)

def write_log(msg):
    os.makedirs('/opt/vortexpanel', exist_ok=True)
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    with open(DDNS_LOG, 'a') as f: f.write(f'[{timestamp}] {msg}\n')
    # Keep last 1000 lines
    try:
        with open(DDNS_LOG) as f: lines = f.readlines()
        if len(lines) > 1000:
            with open(DDNS_LOG, 'w') as f: f.writelines(lines[-1000:])
    except: pass

# Background DDNS updater
_ddns_thread = None
_ddns_running = False

def ddns_loop():
    global _ddns_running
    write_log('DDNS service started')
    last_ip = None
    while _ddns_running:
        cfg = load_config()
        if not cfg.get('enabled'):
            time.sleep(10)
            continue
        ip = get_public_ip()
        if not ip:
            write_log('Failed to get public IP')
            time.sleep(60)
            continue
        if ip != last_ip:
            write_log(f'IP changed: {last_ip} → {ip}')
            for d in cfg.get('domains', []):
                provider = d.get('provider', 'cloudflare')
                if provider == 'cloudflare':
                    ok, msg = update_cloudflare(d, ip)
                    write_log(f'[{"OK" if ok else "ERR"}] {d.get("domain")}: {msg}')
            last_ip = ip
        time.sleep(cfg.get('interval', 300))
    write_log('DDNS service stopped')

def start_ddns():
    global _ddns_thread, _ddns_running
    if _ddns_running: return
    _ddns_running = True
    _ddns_thread = threading.Thread(target=ddns_loop, daemon=True)
    _ddns_thread.start()

def stop_ddns():
    global _ddns_running
    _ddns_running = False

# Auto-start if enabled
cfg = load_config()
if cfg.get('enabled'): start_ddns()

@ddns_bp.route('/api/ddns/domains')
def list_domains():
    if not req(): return jsonify({'ok':False}), 401
    cfg = load_config()
    return jsonify({'ok':True, 'domains': cfg.get('domains',[]), 'enabled': cfg.get('enabled', False)})

@ddns_bp.route('/api/ddns/domains', methods=['POST'])
def add_domain():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    domain    = d.get('domain','').strip()
    provider  = d.get('provider','cloudflare')
    email     = d.get('email','').strip()
    api_token = d.get('api_token','').strip()
    api_limit = d.get('api_limit', False)
    if not domain or not api_token:
        return jsonify({'ok':False, 'error':'Domain and API token required'})
    cfg = load_config()
    # Remove existing entry for same domain
    cfg['domains'] = [x for x in cfg['domains'] if x.get('domain') != domain]
    cfg['domains'].append({'domain':domain,'provider':provider,'email':email,'api_token':api_token,'api_limit':api_limit})
    save_config(cfg)
    return jsonify({'ok':True})

@ddns_bp.route('/api/ddns/domains/<domain>', methods=['DELETE'])
def delete_domain(domain):
    if not req(): return jsonify({'ok':False}), 401
    cfg = load_config()
    cfg['domains'] = [x for x in cfg['domains'] if x.get('domain') != domain]
    save_config(cfg)
    return jsonify({'ok':True})

@ddns_bp.route('/api/ddns/status')
def get_status():
    if not req(): return jsonify({'ok':False}), 401
    cfg = load_config()
    ip = get_public_ip()
    return jsonify({'ok':True, 'enabled': cfg.get('enabled', False),
        'running': _ddns_running, 'current_ip': ip or 'Unknown',
        'interval': cfg.get('interval', 300)})

@ddns_bp.route('/api/ddns/toggle', methods=['POST'])
def toggle():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    enable = d.get('enable', False)
    cfg = load_config()
    cfg['enabled'] = enable
    save_config(cfg)
    if enable: start_ddns()
    else: stop_ddns()
    return jsonify({'ok':True, 'enabled': enable})

@ddns_bp.route('/api/ddns/log')
def get_log():
    if not req(): return jsonify({'ok':False}), 401
    if not os.path.exists(DDNS_LOG):
        return jsonify({'ok':True, 'log': 'No log entries yet'})
    try:
        result = subprocess.check_output(f'tail -200 {DDNS_LOG}', shell=True, text=True)
        return jsonify({'ok':True, 'log': result})
    except:
        return jsonify({'ok':True, 'log': 'Could not read log'})

@ddns_bp.route('/api/ddns/test/<domain>', methods=['POST'])
def test_domain(domain):
    if not req(): return jsonify({'ok':False}), 401
    cfg = load_config()
    domain_cfg = next((d for d in cfg['domains'] if d['domain'] == domain), None)
    if not domain_cfg: return jsonify({'ok':False, 'error':'Domain not found'})
    ip = get_public_ip()
    if not ip: return jsonify({'ok':False, 'error':'Could not get public IP'})
    ok, msg = update_cloudflare(domain_cfg, ip)
    write_log(f'[MANUAL TEST] {domain}: {msg}')
    return jsonify({'ok':ok, 'message':msg, 'ip':ip})
