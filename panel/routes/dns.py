from flask import Blueprint, jsonify, request, session
import subprocess, re, os

dns_bp = Blueprint('dns', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
    except: return ''

def _os_family():
    """'rhel' or 'debian' -- confirmed via real documentation that RHEL-family
    (RHEL/Fedora/CentOS/AlmaLinux/Rocky/Oracle/CloudLinux) installs BIND as
    the 'bind'+'bind-utils' packages with config at /etc/named.conf directly,
    while Debian/Ubuntu installs 'bind9'+'bind9utils' with config split into
    /etc/bind/named.conf (main) + /etc/bind/named.conf.local (an include
    file, present by default). RHEL-family has no such include file by
    default, so this module manages its own and ensures it's included."""
    id_like = sh(". /etc/os-release 2>/dev/null && echo $ID_LIKE || echo debian").lower()
    if re.search(r'rhel|fedora|centos', id_like):
        return 'rhel'
    return 'debian'

def _zones_dir():
    return '/var/named' if _os_family() == 'rhel' else '/etc/bind/zones'

def _main_conf():
    """The top-level file named-checkconf should validate."""
    return '/etc/named.conf' if _os_family() == 'rhel' else '/etc/bind/named.conf'

def _zones_conf():
    """The file this module writes zone declarations into. On Debian this
    is the include file already present by default. On RHEL-family there is
    no such file by default -- _ensure_rhel_include() creates and wires it
    up the first time it's needed."""
    if _os_family() == 'rhel':
        return '/etc/named/vortexpanel-zones.conf'
    return '/etc/bind/named.conf.local'

def _ensure_rhel_include():
    """RHEL-family's /etc/named.conf has no include for a separate zones
    file by default (unlike Debian, which ships with named.conf.local
    already included) -- add one the first time it's needed, immediately
    before the closing of the file so it doesn't land inside another
    block by accident."""
    if _os_family() != 'rhel':
        return
    main = _main_conf()
    zones_conf = _zones_conf()
    os.makedirs(os.path.dirname(zones_conf), exist_ok=True)
    if not os.path.exists(zones_conf):
        open(zones_conf, 'w').close()
    include_line = f'include "{zones_conf}";'
    existing = open(main).read() if os.path.exists(main) else ''
    if include_line not in existing:
        with open(main, 'a') as f:
            f.write(f'\n{include_line}\n')

def _reload_bind():
    sh('rndc reload 2>/dev/null || systemctl reload bind9 2>/dev/null || systemctl reload named 2>/dev/null')


@dns_bp.route('/api/dns/zones')
def list_zones():
    if not req(): return jsonify({'ok':False}),401
    zones_dir = _zones_dir()
    zones = []
    if os.path.isdir(zones_dir):
        for f in os.listdir(zones_dir):
            if f.startswith('db.'):
                domain = f[3:]
                zones.append({'domain':domain,'file':f})
    raw = sh(f'cat {_zones_conf()} 2>/dev/null')
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
    zones_dir = _zones_dir()
    os.makedirs(zones_dir, exist_ok=True)
    zone_file = f'{zones_dir}/db.{domain}'
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
    # Declare the zone to BIND -- without this, the zone file exists on disk
    # and is syntactically valid, but BIND has no idea it should serve it at
    # all. Confirmed via a real dig query returning nothing until this was
    # added (on Debian/Ubuntu). RHEL-family needs the same declaration, but
    # into a different file that isn't included by default, hence the
    # _ensure_rhel_include() call first.
    _ensure_rhel_include()
    conf = _zones_conf()
    stanza = f'\nzone "{domain}" {{\n    type master;\n    file "{zone_file}";\n}};\n'
    existing = open(conf).read() if os.path.exists(conf) else ''
    if f'zone "{domain}"' not in existing:
        with open(conf, 'a') as f: f.write(stanza)
    check = subprocess.run(f'named-checkconf {_main_conf()}', shell=True, capture_output=True, text=True)
    if check.returncode != 0:
        return jsonify({'ok':False,'error':f'BIND config validation failed: {check.stderr.strip() or check.stdout.strip()}'}), 500
    _reload_bind()
    return jsonify({'ok':True,'domain':domain})

@dns_bp.route('/api/dns/zones/<domain>/records')
def get_records(domain):
    if not req(): return jsonify({'ok':False}),401
    zone_file = f'{_zones_dir()}/db.{domain}'
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
    zone_file = f'{_zones_dir()}/db.{domain}'
    try:
        if os.path.exists(zone_file): os.unlink(zone_file)
        conf = _zones_conf()
        if os.path.exists(conf):
            with open(conf) as f: c = f.read()
            c = re.sub(rf'zone\s+"{re.escape(domain)}"[^}}]+}}\s*;?\s*', '', c, flags=re.DOTALL)
            with open(conf,'w') as f: f.write(c)
        _reload_bind()
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
    zone_file = f'{_zones_dir()}/db.{domain}'
    if not os.path.exists(zone_file):
        return jsonify({'ok':False,'error':'Zone not found'})
    import time as _time
    with open(zone_file) as f: content = f.read()
    serial = str(int(_time.strftime('%Y%m%d')) * 100 + 1)
    content = re.sub(r'(\d{10})\s*;\s*Serial', serial + ' ; Serial', content)
    record_line = f'{host}\tIN\t{rtype}\t{value}\n'
    if ttl and ttl != '3600':
        record_line = f'{host}\t{ttl}\tIN\t{rtype}\t{value}\n'
    content += record_line
    with open(zone_file,'w') as f: f.write(content)
    _reload_bind()
    return jsonify({'ok':True})

@dns_bp.route('/api/dns/zones/<domain>/records/delete', methods=['POST'])
def delete_record(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    idx = d.get('index', -1)
    zone_file = f'{_zones_dir()}/db.{domain}'
    if not os.path.exists(zone_file):
        return jsonify({'ok':False,'error':'Zone not found'})
    with open(zone_file) as f: lines = f.readlines()
    record_lines = [i for i,l in enumerate(lines) if l.strip() and not l.strip().startswith(';') and not l.strip().startswith('$') and 'IN' in l and 'SOA' not in l]
    if 0 <= idx < len(record_lines):
        del lines[record_lines[idx]]
        with open(zone_file,'w') as f: f.writelines(lines)
        _reload_bind()
    return jsonify({'ok':True})
