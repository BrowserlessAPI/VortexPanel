from flask import Blueprint, jsonify, request, session
import subprocess, re, os, time, ipaddress

dns_bp = Blueprint('dns', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.run(c, shell=True, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, timeout=30).stdout.strip()
    except Exception: return ''

def run(args, timeout=60):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, ((r.stdout or '') + (r.stderr or '')).strip()
    except FileNotFoundError:
        return 127, f'{args[0]} not found (install bind9-utils / bind-utils)'
    except subprocess.TimeoutExpired:
        return 124, f'{args[0]} timed out'

_DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9-]{2,63}$')
_HOST_RE   = re.compile(r'^(@|\*|(\*\.)?[A-Za-z0-9_]([A-Za-z0-9_.-]{0,252})?\.?)$')
_RTYPES    = ('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'PTR')

def _valid_domain(d):
    return bool(d) and bool(_DOMAIN_RE.match(d))

def _os_family():
    """'rhel' or 'debian' -- RHEL-family (RHEL/Fedora/CentOS/AlmaLinux/Rocky/
    Oracle/CloudLinux) installs BIND as 'bind' with config at /etc/named.conf
    and zones in /var/named; Debian/Ubuntu installs 'bind9' with
    /etc/bind/named.conf + the named.conf.local include. Fedora has ID=fedora
    and no ID_LIKE, so check both fields."""
    ids = sh(". /etc/os-release 2>/dev/null && echo \"$ID $ID_LIKE\" || echo debian").lower()
    if re.search(r'rhel|fedora|centos', ids) or (os.path.exists('/etc/named.conf') and not os.path.isdir('/etc/bind')):
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
    file by default -- add one the first time it's needed. Returns the
    previous content of named.conf (for rollback) or None if unchanged."""
    if _os_family() != 'rhel':
        return None
    main = _main_conf()
    zones_conf = _zones_conf()
    os.makedirs(os.path.dirname(zones_conf), exist_ok=True)
    if not os.path.exists(zones_conf):
        open(zones_conf, 'w').close()
        os.chmod(zones_conf, 0o644)
    include_line = f'include "{zones_conf}";'
    existing = open(main).read() if os.path.exists(main) else ''
    if include_line not in existing:
        with open(main, 'a') as f:
            f.write(f'\n{include_line}\n')
        return existing
    return None

def _named_mask(c):
    """named.conf text with comments blanked out (same length, so regex
    positions map 1:1 onto the original)."""
    def blank(m_):
        return re.sub(r'[^\n]', ' ', m_.group(0))
    return re.sub(r'/\*.*?\*/|//[^\n]*|#[^\n]*', blank, c, flags=re.S)

def _rhel_listen_public():
    """RHEL/Fedora's stock /etc/named.conf only listens on 127.0.0.1 / ::1,
    so a zone created here never answered anyone else. Widen ONLY those
    stock loopback-only listen-on / listen-on-v6 lists to 'any' -- validated
    with named-checkconf and restored on failure. The global allow-query
    { localhost; } is deliberately left alone: it keeps recursion closed
    (no open resolver); each panel zone gets its own allow-query { any; }.
    Returns (previous named.conf text or None if unchanged, error or None)."""
    main = _main_conf()
    try:
        old = open(main).read()
    except OSError as e:
        return None, str(e)
    masked = _named_mask(old)
    om = re.search(r'\boptions\s*\{', masked)
    if not om:
        return None, None
    # end of the options block (brace matching on the masked text)
    depth, i = 0, om.end() - 1
    while i < len(masked):
        if masked[i] == '{': depth += 1
        elif masked[i] == '}':
            depth -= 1
            if depth == 0: break
        i += 1
    opts_start, opts_end = om.end(), i
    new = old
    loop = {'v4': {'127.0.0.1', 'localhost'}, 'v6': {'::1', 'localhost'}}
    edits = []
    for kind, pat in (('v4', r'listen-on(\s+port\s+\d+)?\s*\{([^}]*)\}\s*;'),
                      ('v6', r'listen-on-v6(\s+port\s+\d+)?\s*\{([^}]*)\}\s*;')):
        if kind == 'v6' and not os.path.exists('/proc/net/if_inet6'):
            continue
        for m in re.finditer(pat, masked[opts_start:opts_end]):
            addrs = {a.strip() for a in m.group(2).split(';') if a.strip()}
            if addrs and addrs <= loop[kind]:
                a, b = opts_start + m.start(), opts_start + m.end()
                word = 'listen-on-v6' if kind == 'v6' else 'listen-on'
                edits.append((a, b, f'{word}{m.group(1) or ""} {{ any; }};'))
    if not edits:
        return None, None
    for a, b, text in sorted(edits, reverse=True):
        new = new[:a] + text + new[b:]
    with open(main, 'w') as f: f.write(new)
    err = _check_conf()
    if err:
        with open(main, 'w') as f: f.write(old)
        return None, err
    return old, None

def _dns_firewall_hint():
    """A note when an active firewall does not let DNS (53) in."""
    if sh('firewall-cmd --state 2>/dev/null') == 'running':
        if sh('firewall-cmd --query-service=dns 2>/dev/null') != 'yes' and \
                sh('firewall-cmd --query-port=53/udp 2>/dev/null') != 'yes':
            return 'The firewall (firewalld) does not allow DNS yet: open port 53 TCP and UDP on the Firewall page.'
    elif 'Status: active' in sh('ufw status 2>/dev/null'):
        if not re.search(r'^(53|DNS|Bind9)(/(udp|tcp))?\b.*ALLOW', sh('ufw status 2>/dev/null'), re.M):
            return 'The firewall (ufw) does not allow DNS yet: open port 53 TCP and UDP on the Firewall page.'
    return ''

def _reload_bind():
    rc, _ = run(['rndc', 'reload'], timeout=30)
    if rc != 0:
        sh('systemctl reload named 2>/dev/null || systemctl reload bind9 2>/dev/null')

def _named_unit():
    for u in ('named', 'bind9', 'named-chroot'):
        if run(['systemctl', 'cat', u], timeout=15)[0] == 0:
            return u
    return 'named'

def _check_conf():
    rc, out = run(['named-checkconf', _main_conf()])
    return None if rc == 0 else (out or 'named-checkconf failed')

def _check_zone(domain, zone_file):
    rc, out = run(['named-checkzone', domain, zone_file])
    return None if rc == 0 else (out or 'named-checkzone failed')

def _zone_file(domain):
    return f'{_zones_dir()}/db.{domain}'

def _remove_zone_block(text, domain):
    """Remove `zone "domain" { ... };` honouring nested braces (the old
    [^}]+ regex stopped at the first inner '}' and left a broken config
    behind for zones with allow-transfer { ... }; etc.)."""
    m = re.search(r'zone\s+"' + re.escape(domain) + r'"\s*(IN\s+)?\{', text)
    if not m: return text
    depth, i = 0, m.end() - 1
    while i < len(text):
        if text[i] == '{': depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0: break
        i += 1
    end = i + 1
    rest = re.match(r'\s*;?[ \t]*\n?', text[end:])
    end += rest.end() if rest else 0
    return text[:m.start()] + text[end:]

def _strip_comment(line):
    out, q = [], False
    for ch in line:
        if ch == '"': q = not q
        if ch == ';' and not q: break
        out.append(ch)
    return ''.join(out).rstrip()

def _parse_records(content):
    """Records in file order, each with 'line' = its line number in the zone
    file. Both UIs delete by position in this list ({index: i}); the old
    delete endpoint counted rows differently from the listing (the list
    included the SOA, the delete list did not), so deleting row N removed
    row N+1."""
    records = []
    owner = '@'
    in_paren = False
    for i, raw in enumerate(content.split('\n')):
        line = _strip_comment(raw)
        if in_paren:
            if ')' in line: in_paren = False
            continue
        if not line.strip() or line.lstrip().startswith('$'): continue
        toks = line.split()
        if raw[:1] in (' ', '\t'):
            host = owner
        else:
            host = toks.pop(0); owner = host
        ttl = ''
        if toks and re.match(r'^\d+[smhdwSMHDW]?$', toks[0]): ttl = toks.pop(0)
        if toks and toks[0].upper() in ('IN', 'CH', 'HS'): toks.pop(0)
        if toks and not ttl and re.match(r'^\d+[smhdwSMHDW]?$', toks[0]): ttl = toks.pop(0)
        if not toks: continue
        rtype = toks.pop(0).upper()
        value = ' '.join(toks)
        if rtype == 'SOA' and '(' in line and ')' not in line:
            in_paren = True
        records.append({'host': host, 'type': rtype, 'value': value, 'ttl': ttl, 'line': i})
    return records

def _bump_serial(content):
    """Monotonic RFC-1912 serial (YYYYMMDDnn), never going backwards."""
    today = int(time.strftime('%Y%m%d')) * 100
    cur_m = re.search(r'(\d{10})(\s*;\s*Serial)', content, re.I)
    if not cur_m: return content
    serial = str(max(today + 1, int(cur_m.group(1)) + 1))
    return content[:cur_m.start(1)] + serial + content[cur_m.end(1):]

def _write_zone_checked(domain, zone_file, new_content):
    """Write, validate with named-checkzone, restore the old file on failure."""
    old = open(zone_file).read() if os.path.exists(zone_file) else None
    with open(zone_file, 'w') as f: f.write(new_content)
    err = _check_zone(domain, zone_file)
    if err:
        if old is not None:
            with open(zone_file, 'w') as f: f.write(old)
        return err
    _reload_bind()
    return None


@dns_bp.route('/api/dns/zones')
def list_zones():
    if not req(): return jsonify({'ok':False}),401
    zones_dir = _zones_dir()
    zones = []
    if os.path.isdir(zones_dir):
        for f in sorted(os.listdir(zones_dir)):
            if f.startswith('db.') and not f.endswith(('.jnl', '.tmp')):
                domain = f[3:]
                zones.append({'domain':domain,'file':f})
    conf = _zones_conf()
    raw = open(conf).read() if os.path.exists(conf) else ''
    for m in re.finditer(r'zone\s+"([^"]+)"', raw):
        d = m.group(1)
        if not any(z['domain']==d for z in zones):
            zones.append({'domain':d,'file':f'db.{d}'})
    return jsonify({'ok':True,'zones':zones})

@dns_bp.route('/api/dns/zones', methods=['POST'])
def create_zone():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    domain = (d.get('domain','') or '').strip().rstrip('.').lower()
    ip     = (d.get('ip','') or '').strip() or '127.0.0.1'
    if not domain: return jsonify({'ok':False,'error':'Domain required'}),400
    if not _valid_domain(domain): return jsonify({'ok':False,'error':'Invalid domain'}),400
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return jsonify({'ok':False,'error':'Server IP must be an IPv4 address'}),400
    if not os.path.exists(_main_conf()):
        return jsonify({'ok':False,'error':'BIND is not installed (no ' + _main_conf() + ')'}),400
    zones_dir = _zones_dir()
    os.makedirs(zones_dir, exist_ok=True)
    zone_file = _zone_file(domain)
    if os.path.exists(zone_file):
        return jsonify({'ok':False,'error':'A zone for this domain already exists'}),400
    serial = time.strftime('%Y%m%d') + '01'
    template = f"""$ORIGIN {domain}.
$TTL 3600
@   IN SOA  ns1.{domain}. admin.{domain}. (
        {serial} ; Serial
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
    os.chmod(zone_file, 0o644)
    err = _check_zone(domain, zone_file)
    if err:
        os.unlink(zone_file)
        return jsonify({'ok':False,'error':f'Zone validation failed: {err}'}), 500
    # Declare the zone to BIND (Debian: named.conf.local, RHEL: our include).
    # allow-query { any; } per zone: authoritative answers for everyone even
    # where the global options only allow localhost (RHEL default), without
    # opening recursion.
    main_backup = _ensure_rhel_include()
    conf = _zones_conf()
    stanza = (f'\nzone "{domain}" {{\n    type master;\n    file "{zone_file}";\n'
              f'    allow-query {{ any; }};\n}};\n')
    existing = open(conf).read() if os.path.exists(conf) else ''
    if f'zone "{domain}"' not in existing:
        with open(conf, 'a') as f: f.write(stanza)

    def _undo():
        # Roll back - otherwise the next BIND restart fails on a bad config.
        with open(conf, 'w') as f: f.write(existing)
        if main_backup is not None:
            with open(_main_conf(), 'w') as f: f.write(main_backup)
        if os.path.exists(zone_file):
            os.unlink(zone_file)

    err = _check_conf()
    if err:
        _undo()
        return jsonify({'ok':False,'error':f'BIND config validation failed: {err}'}), 500
    notices = []
    listen_backup = None
    if _os_family() == 'rhel':
        listen_backup, lerr = _rhel_listen_public()
        if lerr:
            notices.append('named.conf only listens on localhost, and widening listen-on to all addresses '
                           f'failed validation ({lerr}) -- it was left unchanged, so this zone only answers '
                           'queries from this server. Set listen-on { any; }; in /etc/named.conf to publish it.')
        elif listen_backup is not None:
            notices.append('named.conf listened on localhost only (RHEL default): listen-on was changed to all '
                           'addresses so the zone answers publicly. Recursion stays limited to localhost.')
    if listen_backup is not None:
        # listen-on changes need a full restart to bind the new addresses.
        rc, out = run(['systemctl', 'restart', _named_unit()], timeout=120)
        if rc != 0 or sh(f'systemctl is-active {_named_unit()} 2>/dev/null') != 'active':
            with open(_main_conf(), 'w') as f: f.write(listen_backup)
            _undo()
            run(['systemctl', 'restart', _named_unit()], timeout=120)
            return jsonify({'ok':False,'error':'BIND did not start with the new configuration; every change was '
                                                f'rolled back and BIND restarted. {out[-400:]}'}), 500
    else:
        _reload_bind()
    hint = _dns_firewall_hint()
    if hint:
        notices.append(hint)
    return jsonify({'ok':True,'domain':domain,'notice':' '.join(notices)})

@dns_bp.route('/api/dns/zones/<domain>/records')
def get_records(domain):
    if not req(): return jsonify({'ok':False}),401
    if not _valid_domain(domain): return jsonify({'ok':False,'error':'Invalid domain'}),400
    zone_file = _zone_file(domain)
    if not os.path.exists(zone_file):
        return jsonify({'ok':False,'error':'Zone not found'}),404
    with open(zone_file) as f: content = f.read()
    return jsonify({'ok':True,'records':_parse_records(content),'content':content})

@dns_bp.route('/api/dns/zones/<domain>', methods=['DELETE'])
def delete_zone(domain):
    if not req(): return jsonify({'ok':False}), 401
    if not _valid_domain(domain): return jsonify({'ok':False,'error':'Invalid domain'}),400
    zone_file = _zone_file(domain)
    try:
        conf = _zones_conf()
        if os.path.exists(conf):
            with open(conf) as f: old = f.read()
            new = _remove_zone_block(old, domain)
            if new != old:
                with open(conf,'w') as f: f.write(new)
                err = _check_conf()
                if err:
                    with open(conf,'w') as f: f.write(old)
                    return jsonify({'ok':False,'error':f'BIND config validation failed: {err}'})
        for p in (zone_file, zone_file + '.jnl'):
            if os.path.exists(p): os.unlink(p)
        _reload_bind()
        return jsonify({'ok':True})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)})

@dns_bp.route('/api/dns/zones/<domain>/records', methods=['POST'])
def add_record(domain):
    if not req(): return jsonify({'ok':False}), 401
    if not _valid_domain(domain): return jsonify({'ok':False,'error':'Invalid domain'}),400
    d = request.get_json() or {}
    # The DNS page sends the owner as 'name'; it was ignored, so every
    # record landed on '@'.
    host  = (d.get('host') or d.get('name') or '@').strip() or '@'
    rtype = (d.get('type') or 'A').strip().upper()
    value = (d.get('value') or '').strip()
    ttl   = str(d.get('ttl') or '3600').strip()
    if not value: return jsonify({'ok':False,'error':'Value required'})
    if any(c in host + value + ttl for c in '\r\n'):
        return jsonify({'ok':False,'error':'Values must be a single line'})
    if rtype not in _RTYPES: return jsonify({'ok':False,'error':'Unsupported record type'})
    if not _HOST_RE.match(host): return jsonify({'ok':False,'error':'Invalid host name'})
    if not ttl.isdigit(): return jsonify({'ok':False,'error':'TTL must be a number'})
    try:
        if rtype == 'A': ipaddress.IPv4Address(value)
        elif rtype == 'AAAA': ipaddress.IPv6Address(value)
    except ValueError:
        return jsonify({'ok':False,'error':f'Invalid {rtype} address'})
    if rtype == 'MX' and not re.match(r'^\d+\s', value):
        value = '10 ' + value
    if rtype in ('CNAME', 'NS', 'MX', 'PTR', 'SRV'):
        # A target without a trailing dot is relative to the zone, so
        # "mail.example.com" would become mail.example.com.example.com.
        parts = value.split()
        if '.' in parts[-1] and not parts[-1].endswith('.'):
            parts[-1] += '.'
        value = ' '.join(parts)
    if rtype == 'TXT' and not value.startswith('"'):
        value = '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
    zone_file = _zone_file(domain)
    if not os.path.exists(zone_file):
        return jsonify({'ok':False,'error':'Zone not found'})
    with open(zone_file) as f: content = f.read()
    content = _bump_serial(content)
    if not content.endswith('\n'): content += '\n'
    record_line = f'{host}\tIN\t{rtype}\t{value}\n'
    if ttl and ttl != '3600':
        record_line = f'{host}\t{ttl}\tIN\t{rtype}\t{value}\n'
    content += record_line
    err = _write_zone_checked(domain, zone_file, content)
    if err: return jsonify({'ok':False,'error':f'Record rejected by named-checkzone: {err}'})
    return jsonify({'ok':True})

@dns_bp.route('/api/dns/zones/<domain>/records/delete', methods=['POST'])
def delete_record(domain):
    if not req(): return jsonify({'ok':False}), 401
    if not _valid_domain(domain): return jsonify({'ok':False,'error':'Invalid domain'}),400
    d = request.get_json() or {}
    try: idx = int(d.get('index', -1))
    except (TypeError, ValueError): idx = -1
    zone_file = _zone_file(domain)
    if not os.path.exists(zone_file):
        return jsonify({'ok':False,'error':'Zone not found'})
    with open(zone_file) as f: content = f.read()
    recs = _parse_records(content)
    rec = recs[idx] if 0 <= idx < len(recs) else None
    if not rec: return jsonify({'ok':False,'error':'Record not found - reload the zone'})
    if rec['type'] == 'SOA': return jsonify({'ok':False,'error':'The SOA record cannot be deleted'})
    lines = content.split('\n')
    del lines[rec['line']]
    err = _write_zone_checked(domain, zone_file, _bump_serial('\n'.join(lines)))
    if err: return jsonify({'ok':False,'error':f'Zone invalid after delete, not saved: {err}'})
    return jsonify({'ok':True})
