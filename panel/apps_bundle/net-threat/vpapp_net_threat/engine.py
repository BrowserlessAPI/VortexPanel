"""Network Threat Detection engine: threat-intelligence lists in the App's own
nftables table `inet vp_net_threat`.

Inbound   (input hook, priority -15)  packets FROM a listed address are counted per
                                       address and list; 'block' lists drop them.
Outbound  (output hook, priority -15) connections TO a botnet command server are
                                       counted (critical) and dropped when blocking.
Private, reserved, loopback and this server's own addresses are removed from every
list before loading, and whitelisted / admin addresses always pass.
"""
import ipaddress
import json
import os
import re
import time
import urllib.request

from panel import appkit

APP = 'net-threat'
TABLE = appkit.nft_table(APP)       # vp_net_threat
FH = 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/'

# id, name, category, risk, direction, default mode, url, description
LISTS = [
    ('firehol_l1', 'FireHOL Level 1', 'Attack networks', 'high', 'in', 'monitor', FH + 'firehol_level1.netset',
     'Spamhaus DROP/EDROP, DShield top attackers, hijacked and criminal networks. Very few false positives.'),
    ('et_compromised', 'Emerging Threats compromised', 'Compromised hosts', 'high', 'in', 'monitor', FH + 'et_compromised.ipset',
     'Hosts known to be compromised and used for attacks (Proofpoint Emerging Threats).'),
    ('blocklist_de', 'blocklist.de', 'Brute force & attacks', 'medium', 'in', 'monitor', FH + 'blocklist_de.ipset',
     'Addresses reported in the last 48 hours for SSH, mail, FTP and web login attacks.'),
    ('greensnow', 'GreenSnow', 'Scanners', 'low', 'in', 'monitor', FH + 'greensnow.ipset',
     'Port scanners and bruteforcers seen by the GreenSnow honeypot network.'),
    ('tor_exits', 'Tor exit nodes', 'Anonymisers', 'info', 'in', 'off', FH + 'tor_exits.ipset',
     'Tor exit relays. Not malicious by themselves; useful to see or block anonymous traffic.'),
    ('feodo_c2', 'abuse.ch Feodo Tracker', 'Botnet C&C servers', 'critical', 'out', 'block',
     'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',
     'Command servers of Emotet, Dridex, QakBot and similar botnets. A connection FROM this server to one means it is infected.'),
]
LIST_BY_ID = {x[0]: x for x in LISTS}
RISK_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
MAX_ENTRIES = 200000


def settings():
    s = appkit.read_json(APP, 'settings.json', {})
    modes = {x[0]: x[5] for x in LISTS}
    modes.update({k: v for k, v in (s.get('modes') or {}).items() if k in modes and v in ('off', 'monitor', 'block')})
    return {'enabled': bool(s.get('enabled', True)), 'modes': modes,
            'update_hours': appkit.clamp_int(s.get('update_hours'), 1, 168, 6),
            'notify': bool(s.get('notify', True)), 'retention_days': appkit.clamp_int(s.get('retention_days'), 1, 365, 30)}


def save_settings(s):
    appkit.write_json(APP, 'settings.json', s)


def whitelist():
    return appkit.read_json(APP, 'whitelist.json', {'items': []}).get('items', [])


def save_whitelist(items):
    appkit.write_json(APP, 'whitelist.json', {'items': items})


# -------------------------------------------------------------------- lists

def _own_addresses():
    out = set()
    rc, o, _ = appkit.run(['ip', '-o', 'addr'], timeout=10)
    for m in re.finditer(r'inet6? ([0-9a-fA-F:.]+)/', o or ''):
        out.add(m.group(1))
    return out


def clean_networks(lines):
    """Parse a list; drop private/reserved/loopback ranges and anything covering this server."""
    own = [ipaddress.ip_address(a) for a in _own_addresses() if appkit.parse_ip(a)]
    v4, v6 = [], []
    for raw in lines:
        t = raw.split('#', 1)[0].split(';', 1)[0].strip()
        if not t:
            continue
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            continue
        if net.is_private or net.is_reserved or net.is_loopback or net.is_multicast or net.is_link_local or net.is_unspecified:
            continue
        if net.prefixlen < (8 if net.version == 4 else 19):
            continue           # absurdly wide entries are never trusted
        if any(a.version == net.version and a in net for a in own):
            continue
        (v4 if net.version == 4 else v6).append(net)
    v4 = list(ipaddress.collapse_addresses(v4))[:MAX_ENTRIES]
    v6 = list(ipaddress.collapse_addresses(v6))[:MAX_ENTRIES]
    return [str(n) for n in v4], [str(n) for n in v6]


def list_file(lid):
    return os.path.join(appkit.data_dir(APP), f'list-{lid}.json')


def load_list(lid):
    try:
        with open(list_file(lid)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def download(lid):
    """Fetch one list, clean it and store it. (ok, message)."""
    x = LIST_BY_ID[lid]
    try:
        req = urllib.request.Request(x[6], headers={'User-Agent': 'VortexPanel-ThreatDetection'})
        with urllib.request.urlopen(req, timeout=60) as r:
            text = r.read(32 * 1024 * 1024).decode('utf-8', 'replace')
    except Exception as e:  # noqa: BLE001
        return False, f'{x[1]}: download failed ({e})'
    v4, v6 = clean_networks(text.splitlines())
    if not v4 and not v6 and lid != 'feodo_c2':
        return False, f'{x[1]}: the download contained no usable addresses (kept the previous copy)'
    data = {'t': int(time.time()), 'v4': v4, 'v6': v6, 'source': x[6]}
    tmp = list_file(lid) + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, list_file(lid))
    return True, f'{x[1]}: {len(v4) + len(v6)} networks'


def update_all(only_enabled=True):
    s = settings()
    msgs = []
    for x in LISTS:
        if only_enabled and s['modes'].get(x[0]) == 'off':
            continue
        ok, m = download(x[0])
        msgs.append((ok, m))
    appkit.write_json(APP, 'update.json', {'t': int(time.time()), 'results': [{'ok': ok, 'msg': m} for ok, m in msgs]})
    return msgs


# ---------------------------------------------------------------- nftables

def _el(vals):
    return '{ ' + ', '.join(vals) + ' }'


def build_ruleset(s):
    wl = [w['ip'] for w in whitelist() if w.get('ip')] + [ip for ip in appkit.admin_ips() if appkit.parse_ip(ip)]
    wl4 = [str(ipaddress.ip_network(w, strict=False)) for w in wl if ':' not in w]
    wl6 = [str(ipaddress.ip_network(w, strict=False)) for w in wl if ':' in w]
    L = [f'table inet {TABLE} {{',
         '  set allow4 { type ipv4_addr; flags interval; auto-merge; ' + (f'elements = {_el(wl4)}; ' if wl4 else '') + '}',
         '  set allow6 { type ipv6_addr; flags interval; auto-merge; ' + (f'elements = {_el(wl6)}; ' if wl6 else '') + '}']
    inb, outb = [], []
    for x in LISTS:
        lid, mode, direction = x[0], s['modes'].get(x[0], 'off'), x[4]
        if mode == 'off' or not s['enabled']:
            continue
        d = load_list(lid)
        v4, v6 = d.get('v4') or [], d.get('v6') or []
        L.append(f'  set l4_{lid} {{ type ipv4_addr; flags interval; auto-merge; ' + (f'elements = {_el(v4)}; ' if v4 else '') + '}')
        L.append(f'  set l6_{lid} {{ type ipv6_addr; flags interval; auto-merge; ' + (f'elements = {_el(v6)}; ' if v6 else '') + '}')
        L.append(f'  set h4_{lid} {{ type ipv4_addr; size 65536; flags dynamic,timeout; timeout 1h; }}')
        L.append(f'  set h6_{lid} {{ type ipv6_addr; size 65536; flags dynamic,timeout; timeout 1h; }}')
        L.append(f'  set p4_{lid} {{ type ipv4_addr . inet_service; size 65536; flags dynamic,timeout; timeout 1h; }}')
        L.append(f'  set p6_{lid} {{ type ipv6_addr . inet_service; size 65536; flags dynamic,timeout; timeout 1h; }}')
        verdict = ' drop' if mode == 'block' else ''
        k = 'saddr' if direction == 'in' else 'daddr'
        rules = [f'    ip {k} @l4_{lid} meta l4proto {{ tcp, udp }} update @h4_{lid} {{ ip {k} counter }} add @p4_{lid} {{ ip {k} . th dport }}{verdict}',
                 f'    ip {k} @l4_{lid} meta l4proto != {{ tcp, udp }} update @h4_{lid} {{ ip {k} counter }}{verdict}',
                 f'    ip6 {k} @l6_{lid} meta l4proto {{ tcp, udp }} update @h6_{lid} {{ ip6 {k} counter }} add @p6_{lid} {{ ip6 {k} . th dport }}{verdict}',
                 f'    ip6 {k} @l6_{lid} meta l4proto != {{ tcp, udp }} update @h6_{lid} {{ ip6 {k} counter }}{verdict}']
        (inb if direction == 'in' else outb).extend(rules)
    L += ['  chain input {', '    type filter hook input priority -15; policy accept;', '    iif "lo" accept',
          '    ip saddr @allow4 accept', '    ip6 saddr @allow6 accept', '    ct state established,related accept'] + inb + ['  }']
    L += ['  chain output {', '    type filter hook output priority -15; policy accept;', '    oif "lo" accept',
          '    ip daddr @allow4 accept', '    ip6 daddr @allow6 accept'] + outb + ['  }', '}']
    return '\n'.join(L) + '\n'


def table_exists():
    return appkit.run(['nft', 'list', 'table', 'inet', TABLE], timeout=10)[0] == 0


def apply(s=None):
    """Rebuild the table in one transaction. (ok, error)."""
    s = s or settings()
    script = f'table inet {TABLE}\ndelete table inet {TABLE}\n' + build_ruleset(s)
    return appkit.nft(script, timeout=120)


def remove():
    appkit.nft_drop_table(APP)


def hits():
    """[(list, ip, packets, [ports])] currently in the kernel's hit sets."""
    s = settings()
    out = []
    for x in LISTS:
        lid = x[0]
        if s['modes'].get(lid) == 'off':
            continue
        ports = {}
        for fam in ('p4_', 'p6_'):
            for e in appkit.nft_set_elements(TABLE, fam + lid):
                v = e['val']
                if isinstance(v, list) and len(v) == 2:
                    ports.setdefault(str(v[0]), set()).add(int(v[1]))
        for fam in ('h4_', 'h6_'):
            for e in appkit.nft_set_elements(TABLE, fam + lid):
                ip = str(e['val'])
                out.append((lid, ip, int(e.get('packets') or 0), sorted(ports.get(ip, ()))))
    return out
