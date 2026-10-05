from flask import Blueprint, jsonify, request, session
import os, json, threading, time, ipaddress, fcntl, requests as req_lib

ddns_bp = Blueprint('ddns', __name__)
def req(): return 'user' in session

DDNS_CONFIG = '/opt/vortexpanel/ddns_config.json'
DDNS_LOG    = '/opt/vortexpanel/ddns.log'
DDNS_PID    = '/opt/vortexpanel/ddns.pid'
DDNS_LOCK   = '/opt/vortexpanel/ddns.lock'
CF_API      = 'https://api.cloudflare.com/client/v4'

def load_config():
    if os.path.exists(DDNS_CONFIG):
        try:
            with open(DDNS_CONFIG) as f: cfg = json.load(f)
            if isinstance(cfg, dict):
                cfg.setdefault('domains', [])
                return cfg
        except Exception: pass
    return {'domains': [], 'enabled': False, 'interval': 300}

def save_config(cfg):
    """Holds Cloudflare API tokens/keys: 0600, written atomically (it used to
    be created world-readable)."""
    os.makedirs('/opt/vortexpanel', exist_ok=True)
    tmp = DDNS_CONFIG + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f: json.dump(cfg, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, DDNS_CONFIG)

def _interval(cfg):
    try: return max(60, int(cfg.get('interval', 300)))
    except (TypeError, ValueError): return 300

def get_public_ip():
    """Public IPv4 only - these are A records. icanhazip / ifconfig.me answer
    with the IPv6 address on dual-stack hosts, which Cloudflare then rejects
    as A record content."""
    for url in ['https://api.ipify.org', 'https://ipv4.icanhazip.com', 'https://v4.ident.me']:
        try:
            r = req_lib.get(url, timeout=5)
            if r.status_code == 200:
                ip = r.text.strip()
                ipaddress.IPv4Address(ip)
                return ip
        except Exception: pass
    return None

def _cf_errors(resp_json, fallback):
    errs = (resp_json or {}).get('errors') or []
    msgs = []
    for e in errs:
        if isinstance(e, dict): msgs.append(f"{e.get('code', '')} {e.get('message', '')}".strip())
        else: msgs.append(str(e))
    return '; '.join(msgs) or fallback

def _cf_json(r):
    try: return r.json()
    except ValueError: return {'success': False, 'errors': [f'HTTP {r.status_code} (non-JSON response)']}

def update_cloudflare(domain_cfg, ip):
    token   = domain_cfg.get('api_token','')
    domain  = domain_cfg.get('domain','')
    email   = domain_cfg.get('email','')
    api_limit = domain_cfg.get('api_limit', False)

    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    if not api_limit and email:
        headers = {'X-Auth-Email': email, 'X-Auth-Key': token, 'Content-Type': 'application/json'}

    try:
        # Find the zone by walking up the labels (the old "last two labels"
        # guess failed for example.co.uk, example.com.au, ...).
        labels = domain.strip('.').split('.')
        zone_id = None
        for i in range(0, max(1, len(labels) - 1)):
            name = '.'.join(labels[i:])
            j = _cf_json(req_lib.get(f'{CF_API}/zones', params={'name': name}, headers=headers, timeout=15))
            if not j.get('success'):
                return False, 'Cloudflare API error: ' + _cf_errors(j, 'zone lookup failed (check the token/key)')
            if j.get('result'):
                zone_id = j["result"][0]["id"]
                break
        if not zone_id: return False, f'No Cloudflare zone found for {domain}'

        # Get DNS record
        j = _cf_json(req_lib.get(f'{CF_API}/zones/{zone_id}/dns_records',
                                 params={'type': 'A', 'name': domain}, headers=headers, timeout=15))
        if not j.get('success'):
            return False, 'Cloudflare API error: ' + _cf_errors(j, 'record lookup failed')
        records = j.get('result') or []

        if records:
            rec = records[0]
            if rec.get('content') == ip:
                return True, f'IP unchanged ({ip})'
            # Preserve the record's proxied (orange cloud) state and TTL.
            j = _cf_json(req_lib.put(f'{CF_API}/zones/{zone_id}/dns_records/{rec["id"]}',
                headers=headers, json={'type':'A','name':domain,'content':ip,'ttl':rec.get('ttl', 120),
                                       'proxied':rec.get('proxied', False)}, timeout=15))
            if j.get('success'):
                return True, f'Updated {domain} -> {ip}'
            return False, _cf_errors(j, 'Update failed')
        else:
            j = _cf_json(req_lib.post(f'{CF_API}/zones/{zone_id}/dns_records',
                headers=headers, json={'type':'A','name':domain,'content':ip,'ttl':120,'proxied':False}, timeout=15))
            if j.get('success'):
                return True, f'Created {domain} -> {ip}'
            return False, _cf_errors(j, 'Create failed')
    except Exception as e:
        return False, str(e)

def write_log(msg):
    try:
        os.makedirs('/opt/vortexpanel', exist_ok=True)
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        with open(DDNS_LOG, 'a') as f: f.write(f'[{timestamp}] {msg}\n')
        # Keep last 1000 lines
        with open(DDNS_LOG) as f: lines = f.readlines()
        if len(lines) > 1000:
            with open(DDNS_LOG, 'w') as f: f.writelines(lines[-1000:])
    except Exception: pass

# Background DDNS updater.
#
# gunicorn runs 4 worker processes and each one imports this module, so the
# old module-level auto-start ran four updater loops in parallel, and
# toggle/stop only affected the one worker that served the request. Now every
# worker starts a supervisor thread, but only the process holding an
# exclusive flock on DDNS_LOCK runs the loop; if that worker exits the lock is
# released and another worker takes over. Enabled/disabled is read from the
# config file on every cycle, so start/stop applies to whichever worker runs it.
_supervisor = None
_supervisor_lock = threading.Lock()
_holder = {'fd': None}

def _try_lock():
    try:
        fd = os.open(DDNS_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except OSError:
        os.close(fd)
        return None

def ddns_loop():
    write_log('DDNS service started')
    last_key = None
    while True:
        try:
            cfg = load_config()
            if not cfg.get('enabled'):
                last_key = None
                time.sleep(10)
                continue
            ip = get_public_ip()
            if not ip:
                write_log('Failed to get public IP')
                time.sleep(60)
                continue
            # Re-run when the IP OR the domain list changes (a newly added
            # domain used to wait until the next IP change).
            key = (ip, json.dumps(cfg.get('domains', []), sort_keys=True))
            if key != last_key:
                write_log(f'Checking records for IP {ip}')
                all_ok = True
                for d in cfg.get('domains', []):
                    provider = d.get('provider', 'cloudflare')
                    if provider == 'cloudflare':
                        ok, msg = update_cloudflare(d, ip)
                    else:
                        ok, msg = False, f'unsupported provider {provider}'
                    if not ok: all_ok = False
                    write_log(f'[{"OK" if ok else "ERR"}] {d.get("domain")}: {msg}')
                # Only remember the state when every update succeeded so a
                # transient API failure is retried next cycle.
                if all_ok:
                    last_key = key
                else:
                    write_log('One or more updates failed - will retry next cycle')
            time.sleep(_interval(cfg))
        except Exception as e:
            write_log(f'DDNS loop error: {e}')
            time.sleep(60)

def _supervise():
    while True:
        fd = _try_lock()
        if fd is not None:
            _holder['fd'] = fd
            ddns_loop()  # never returns
        time.sleep(30)

def start_ddns():
    global _supervisor
    with _supervisor_lock:
        if _supervisor is None or not _supervisor.is_alive():
            _supervisor = threading.Thread(target=_supervise, daemon=True, name='ddns-supervisor')
            _supervisor.start()

def stop_ddns():
    # The loop idles while the config says disabled; nothing else to do.
    pass

def ddns_running():
    """True if some worker holds the updater lock and DDNS is enabled."""
    if not load_config().get('enabled'):
        return False
    if _holder['fd'] is not None:
        return True
    fd = _try_lock()
    if fd is None:
        return True
    os.close(fd)  # nobody held it
    return False

# Auto-start if enabled
if load_config().get('enabled'): start_ddns()

def _public_domain(d):
    out = dict(d)
    tok = out.get('api_token') or ''
    out['api_token'] = (tok[:4] + '********') if tok else ''
    return out

@ddns_bp.route('/api/ddns/domains')
def list_domains():
    if not req(): return jsonify({'ok':False}), 401
    cfg = load_config()
    return jsonify({'ok':True, 'domains': [_public_domain(d) for d in cfg.get('domains',[])],
                    'enabled': cfg.get('enabled', False)})

@ddns_bp.route('/api/ddns/domains', methods=['POST'])
def add_domain():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    domain    = (d.get('domain','') or '').strip().strip('.').lower()
    provider  = d.get('provider','cloudflare') or 'cloudflare'
    email     = (d.get('email','') or '').strip()
    api_token = (d.get('api_token','') or '').strip()
    api_limit = bool(d.get('api_limit', False))
    if not domain or not api_token:
        return jsonify({'ok':False, 'error':'Domain and API token required'})
    if provider != 'cloudflare':
        return jsonify({'ok':False, 'error':'Only Cloudflare is supported'})
    if '.' not in domain or any(c.isspace() for c in domain):
        return jsonify({'ok':False, 'error':'Invalid domain'})
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
        'running': ddns_running(), 'current_ip': ip or 'Unknown',
        'interval': _interval(cfg)})

@ddns_bp.route('/api/ddns/toggle', methods=['POST'])
def toggle():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    enable = bool(d.get('enable', False))
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
        with open(DDNS_LOG, errors='replace') as f:
            return jsonify({'ok':True, 'log': ''.join(f.readlines()[-200:])})
    except OSError:
        return jsonify({'ok':True, 'log': 'Could not read log'})

@ddns_bp.route('/api/ddns/test/<domain>', methods=['POST'])
def test_domain(domain):
    if not req(): return jsonify({'ok':False}), 401
    cfg = load_config()
    domain_cfg = next((d for d in cfg['domains'] if d.get('domain') == domain), None)
    if not domain_cfg: return jsonify({'ok':False, 'error':'Domain not found'})
    ip = get_public_ip()
    if not ip: return jsonify({'ok':False, 'error':'Could not get public IPv4 address'})
    ok, msg = update_cloudflare(domain_cfg, ip)
    write_log(f'[MANUAL TEST] {domain}: {msg}')
    return jsonify({'ok':ok, 'message':msg, 'ip':ip, 'error': None if ok else msg})
