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
