from flask import Blueprint, jsonify, request, session
import subprocess, re, os

dns_bp = Blueprint('dns', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
    except: return ''

ZONES_DIR = '/etc/bind/zones'

@dns_bp.route('/api/dns/zones')
def list_zones():
    if not req(): return jsonify({'ok':False}),401
    zones = []
    if os.path.isdir(ZONES_DIR):
        for f in os.listdir(ZONES_DIR):
            if f.startswith('db.'):
                domain = f[3:]
                zones.append({'domain':domain,'file':f})
    # Also check named.conf.local
    raw = sh('cat /etc/bind/named.conf.local 2>/dev/null || cat /etc/named/named.conf.local 2>/dev/null')
    for m in re.finditer(r'zone\s+"([^"]+)"', raw):
        d = m.group(1)
        if not any(z['domain']==d for z in zones):
            zones.append({'domain':d,'file':f'db.{d}'})
    return jsonify({'ok':True,'zones':zones})

@dns_bp.route('/api/dns/zones', methods=['POST'])
def create_zone():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    domain = d.get('domain','').strip().rstrip('.')
    ip     = d.get('ip','127.0.0.1')
    if not domain: return jsonify({'ok':False,'error':'Domain required'}),400
    os.makedirs(ZONES_DIR, exist_ok=True)
    zone_file = f'{ZONES_DIR}/db.{domain}'
    template = f"""$ORIGIN {domain}.
$TTL 3600
@   IN SOA  ns1.{domain}. admin.{domain}. (
        2024010101 ; Serial
        3600       ; Refresh
        900        ; Retry
        604800     ; Expire
        300 )      ; Minimum

@   IN NS   ns1.{domain}.
@   IN A    {ip}
ns1 IN A    {ip}
www IN A    {ip}
mail IN A   {ip}
@   IN MX 10 mail.{domain}.
"""
    with open(zone_file,'w') as f: f.write(template)
    sh(f'systemctl reload bind9 2>/dev/null || rndc reload 2>/dev/null')
    return jsonify({'ok':True,'domain':domain})

@dns_bp.route('/api/dns/zones/<domain>/records')
def get_records(domain):
    if not req(): return jsonify({'ok':False}),401
    zone_file = f'{ZONES_DIR}/db.{domain}'
    if not os.path.exists(zone_file):
        return jsonify({'ok':False,'error':'Zone not found'}),404
    with open(zone_file) as f: content = f.read()
    records = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith(';') or line.startswith('$'): continue
        m = re.match(r'^(\S+)\s+(?:IN\s+)?(\w+)\s+(.+)$', line)
        if m: records.append({'host':m.group(1),'type':m.group(2),'value':m.group(3)})
    return jsonify({'ok':True,'records':records,'content':content})

@dns_bp.route('/api/dns/zones/<domain>', methods=['DELETE'])
def delete_zone(domain):
    if not req(): return jsonify({'ok':False}), 401
    zone_file = f'{ZONES_DIR}/db.{domain}'
    try:
        if os.path.exists(zone_file): os.unlink(zone_file)
        # Remove from named.conf.local
        conf = '/etc/bind/named.conf.local'
        if os.path.exists(conf):
            with open(conf) as f: c = f.read()
            import re as _re
            c = _re.sub(rf'zone\s+"{re.escape(domain)}"[^}}]+}}\s*;?\s*', '', c, flags=_re.DOTALL)
            with open(conf,'w') as f: f.write(c)
        sh('rndc reload 2>/dev/null || systemctl reload bind9 2>/dev/null || systemctl reload named 2>/dev/null')
        return jsonify({'ok':True})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)})

@dns_bp.route('/api/dns/zones/<domain>/records', methods=['POST'])
def add_record(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    host  = d.get('host','@')
    rtype = d.get('type','A')
    value = d.get('value','').strip()
    ttl   = d.get('ttl','3600')
    if not value: return jsonify({'ok':False,'error':'Value required'})
    zone_file = f'{ZONES_DIR}/db.{domain}'
    if not os.path.exists(zone_file):
        return jsonify({'ok':False,'error':'Zone not found'})
    # Update serial
    import re as _re, time as _time
    with open(zone_file) as f: content = f.read()
    serial = str(int(_time.strftime('%Y%m%d')) * 100 + 1)
    content = _re.sub(r'(\d{10})\s*;\s*Serial', serial + ' ; Serial', content)
    # Add record
    record_line = f'{host}\tIN\t{rtype}\t{value}\n'
    if ttl and ttl != '3600':
        record_line = f'{host}\t{ttl}\tIN\t{rtype}\t{value}\n'
    content += record_line
    with open(zone_file,'w') as f: f.write(content)
    sh('rndc reload 2>/dev/null || systemctl reload bind9 2>/dev/null || systemctl reload named 2>/dev/null')
    return jsonify({'ok':True})

@dns_bp.route('/api/dns/zones/<domain>/records/delete', methods=['POST'])
def delete_record(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    idx = d.get('index', -1)
    zone_file = f'{ZONES_DIR}/db.{domain}'
    if not os.path.exists(zone_file):
        return jsonify({'ok':False,'error':'Zone not found'})
    with open(zone_file) as f: lines = f.readlines()
    # Find non-comment, non-directive records
    record_lines = [i for i,l in enumerate(lines) if l.strip() and not l.strip().startswith(';') and not l.strip().startswith('$') and 'IN' in l and 'SOA' not in l]
    if 0 <= idx < len(record_lines):
        del lines[record_lines[idx]]
        with open(zone_file,'w') as f: f.writelines(lines)
        sh('rndc reload 2>/dev/null || systemctl reload bind9 2>/dev/null || systemctl reload named 2>/dev/null')
    return jsonify({'ok':True})
