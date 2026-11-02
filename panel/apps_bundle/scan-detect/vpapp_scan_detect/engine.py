"""Scan Detection engine: the nftables table, settings and block list.

Everything lives in its own table `inet vp_scan_detect` (priority -10 on the
input hook), so it never edits ufw/firewalld/the panel firewall, and removing
the table removes the App's whole footprint.

How a probe is counted (in the kernel, no log parsing):
  - loopback, whitelisted and established/related traffic is ignored
  - a NEW or INVALID TCP packet (SYN, FIN, NULL, XMAS scans) or a UDP packet
    to a port nothing on this server listens on is a probe
  - per source address the kernel keeps a packet counter (hits sets) and the
    distinct ports it touched (ports sets, entries expire after the window)
The service reads those sets every few seconds and blocks an address whose
probes in the sliding window, or distinct ports, pass the thresholds.
"""
import ipaddress
import re
import time

from panel import appkit

APP = 'scan-detect'
TABLE = appkit.nft_table(APP)          # vp_scan_detect

DEFAULTS = {
    'enabled': True,
    'window_min': 3,            # sliding window
    'scan_count': 100,          # probes in the window
    'port_count': 20,           # distinct closed ports in the window (0 = off)
    'block_minutes': 1440,      # 0 = permanent (until unblocked)
    'tcp': True,
    'udp': False,
    'detect_only': False,       # record, never block
    'ignore_private': True,     # LAN / private ranges are never counted
    'retention_days': 30,
    'notify': False,            # panel alerts on each block
}


def settings():
    s = dict(DEFAULTS)
    s.update({k: v for k, v in appkit.read_json(APP, 'settings.json', {}).items() if k in DEFAULTS})
    return s


def clean_settings(d):
    cur = settings()
    out = dict(cur)
    for k in ('enabled', 'tcp', 'udp', 'detect_only', 'ignore_private', 'notify'):
        if k in d:
            out[k] = bool(d[k])
    out['window_min'] = appkit.clamp_int(d.get('window_min', cur['window_min']), 1, 60, 3)
    out['scan_count'] = appkit.clamp_int(d.get('scan_count', cur['scan_count']), 5, 100000, 100)
    out['port_count'] = appkit.clamp_int(d.get('port_count', cur['port_count']), 0, 65535, 20)
    out['block_minutes'] = appkit.clamp_int(d.get('block_minutes', cur['block_minutes']), 0, 525600, 1440)
    out['retention_days'] = appkit.clamp_int(d.get('retention_days', cur['retention_days']), 1, 365, 30)
    if not out['tcp'] and not out['udp']:
        out['tcp'] = True
    return out


def save_settings(s):
    appkit.write_json(APP, 'settings.json', s)


# ------------------------------------------------------------------- whitelist

def whitelist():
    return appkit.read_json(APP, 'whitelist.json', {'items': []}).get('items', [])


def save_whitelist(items):
    appkit.write_json(APP, 'whitelist.json', {'items': items})


def _split_family(nets):
    v4, v6 = [], []
    for n in nets:
        try:
            net = ipaddress.ip_network(n, strict=False)
        except ValueError:
            continue
        (v4 if net.version == 4 else v6).append(str(net))
    return v4, v6


# -------------------------------------------------------------------- ruleset

def _ftp_passive():
    """Pure-FTPd passive data port range ('lo-hi') or ''. Each passive port listens for
    milliseconds only, so without this an FTP upload of 20+ files looked like a scan."""
    for p in ('/etc/pure-ftpd/conf/PassivePortRange', '/etc/pure-ftpd/pure-ftpd.conf', '/etc/pure-ftpd.conf'):
        try:
            txt = open(p).read()
        except OSError:
            continue
        m = re.search(r'^(?:\s*PassivePortRange\s+)?(\d{2,5})[\s:-]+(\d{2,5})\s*$', txt, re.M)
        if m and int(m.group(1)) < int(m.group(2)) <= 65535:
            return f'{int(m.group(1))}-{int(m.group(2))}'
    return '30000-50000' if appkit.have('pure-ftpd') else ''


def _open_ports():
    """Ports something listens on from outside (not loopback-only), plus the FTP passive range."""
    tcp, udp = set(), set()
    for proto, flag, dest in (('tcp', '-Hltn', tcp), ('udp', '-Hlun', udp)):
        rc, out, _ = appkit.run(['ss', flag], timeout=15)
        if rc != 0:
            continue
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3]
            host, _, port = local.rpartition(':')
            host = host.strip('[]').split('%')[0]
            if host in ('127.0.0.1', '::1') or host.startswith('127.'):
                continue
            if port.isdigit():
                dest.add(int(port))
    tcp = sorted(tcp)
    rng = _ftp_passive()
    if rng:
        lo, hi = (int(x) for x in rng.split('-'))
        tcp = [p for p in tcp if not lo <= p <= hi] + [rng]
    return tcp, sorted(udp)


def _ephemeral_low():
    try:
        return max(1024, int(open('/proc/sys/net/ipv4/ip_local_port_range').read().split()[0]))
    except (OSError, ValueError, IndexError):
        return 32768


def _elements(vals):
    return '{ ' + ', '.join(str(v) for v in vals) + ' }' if vals else ''


def _block_elems(entries):
    out = []
    for e in entries:
        if e.get('expires'):
            out.append(f"{e['val']} timeout {max(1, int(e['expires']))}s")
        else:
            out.append(str(e['val']))
    return out


def build_ruleset(s, wl4, wl6, block4, block6, tcp_open, udp_open):
    win = int(s['window_min']) * 60
    lines = [f'table inet {TABLE} {{',
             '  set block4 { type ipv4_addr; flags timeout; size 262144; ' + (f'elements = {_elements(block4)}; ' if block4 else '') + '}',
             '  set block6 { type ipv6_addr; flags timeout; size 262144; ' + (f'elements = {_elements(block6)}; ' if block6 else '') + '}',
             '  set allow4 { type ipv4_addr; flags interval; auto-merge; ' + (f'elements = {_elements(wl4)}; ' if wl4 else '') + '}',
             '  set allow6 { type ipv6_addr; flags interval; auto-merge; ' + (f'elements = {_elements(wl6)}; ' if wl6 else '') + '}',
             '  set open_tcp { type inet_service; flags interval; ' + (f'elements = {_elements(tcp_open)}; ' if tcp_open else '') + '}',
             '  set open_udp { type inet_service; ' + (f'elements = {_elements(udp_open)}; ' if udp_open else '') + '}',
             '  set hits4 { type ipv4_addr; size 65536; flags dynamic,timeout; timeout 15m; }',
             '  set hits6 { type ipv6_addr; size 65536; flags dynamic,timeout; timeout 15m; }',
             f'  set ports4 {{ type ipv4_addr . inet_service; size 131072; flags dynamic,timeout; timeout {win}s; }}',
             f'  set ports6 {{ type ipv6_addr . inet_service; size 131072; flags dynamic,timeout; timeout {win}s; }}',
             '  chain input {',
             '    type filter hook input priority -10; policy accept;',
             '    iif "lo" accept',
             '    ip saddr @allow4 accept',
             '    ip6 saddr @allow6 accept',
             '    ip saddr @block4 counter drop',
             '    ip6 saddr @block6 counter drop']
    if s['enabled']:
        lines.append('    ct state established,related accept')
        if s['ignore_private']:
            lines.append('    ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } accept')
            lines.append('    ip6 saddr { fc00::/7, fe80::/10 } accept')
        if s['tcp']:
            # SYN scans: a new connection to a closed port
            lines.append('    ct state new meta l4proto tcp tcp dport != @open_tcp jump probe_tcp')
            # FIN / NULL / XMAS scans: no SYN, ACK or RST, below the local ephemeral range
            # (late packets of finished connections land on ephemeral ports and are not scans)
            lines.append(f'    ct state invalid meta l4proto tcp tcp flags & (syn|ack|rst) == 0x0 '
                         f'tcp dport < {_ephemeral_low()} tcp dport != @open_tcp jump probe_tcp')
        if s['udp']:
            lines.append('    ct state new meta l4proto udp udp dport != @open_udp jump probe_udp')
    lines.append('  }')
    lines += ['  chain probe_tcp {',
              '    meta nfproto ipv4 update @hits4 { ip saddr counter }',
              '    meta nfproto ipv4 add @ports4 { ip saddr . tcp dport }',
              '    meta nfproto ipv6 update @hits6 { ip6 saddr counter }',
              '    meta nfproto ipv6 add @ports6 { ip6 saddr . tcp dport }',
              '  }',
              '  chain probe_udp {',
              '    meta nfproto ipv4 update @hits4 { ip saddr counter }',
              '    meta nfproto ipv4 add @ports4 { ip saddr . udp dport }',
              '    meta nfproto ipv6 update @hits6 { ip6 saddr counter }',
              '    meta nfproto ipv6 add @ports6 { ip6 saddr . udp dport }',
              '  }',
              '}']
    return '\n'.join(lines) + '\n'


def table_exists():
    return appkit.run(['nft', 'list', 'table', 'inet', TABLE], timeout=10)[0] == 0


def blocked_entries():
    out = []
    for fam in ('block4', 'block6'):
        for e in appkit.nft_set_elements(TABLE, fam):
            out.append({'ip': str(e['val']), 'expires': e.get('expires')})
    return out


def active():
    """{ip: until (0 = permanent)} - our own record of what should be blocked, so the
    block list survives `nft flush ruleset` (nftables/firewalld restarts) and reboots."""
    now = int(time.time())
    d = appkit.read_json(APP, 'active.json', {})
    return {ip: int(u) for ip, u in d.items() if not u or int(u) > now}


def _set_active(ip, until):
    def fn(d):
        now = int(time.time())
        d = {k: v for k, v in d.items() if not v or int(v) > now}
        if until is None:
            d.pop(ip, None)
        else:
            d[ip] = int(until)
        return d
    appkit.update_json(APP, 'active.json', fn)


def apply(s=None):
    """(Re)build the table in one transaction, keeping blocked addresses and their
    remaining time. (ok, error)."""
    s = s or settings()
    keep = blocked_entries() if table_exists() else []
    now = int(time.time())
    have_ips = {e['ip'] for e in keep}
    for ip, until in active().items():
        if ip not in have_ips:
            keep.append({'ip': ip, 'expires': (until - now) if until else None})
    b4 = [{'val': e['ip'], 'expires': e['expires']} for e in keep if ':' not in e['ip']]
    b6 = [{'val': e['ip'], 'expires': e['expires']} for e in keep if ':' in e['ip']]
    wl = [w['ip'] for w in whitelist() if w.get('ip')]
    # admins currently working on the panel are always allowed
    wl += [ip for ip in appkit.admin_ips() if appkit.parse_ip(ip)]
    wl4, wl6 = _split_family(wl)
    tcp, udp = _open_ports()
    script = build_ruleset(s, wl4, wl6, _block_elems(b4), _block_elems(b6), tcp, udp)
    pre = f'table inet {TABLE}\ndelete table inet {TABLE}\n'
    ok, err = appkit.nft(pre + script)
    return ok, err


def sync_open_ports():
    """Refresh the listening-port sets without touching anything else."""
    if not table_exists():
        return
    tcp, udp = _open_ports()
    script = (f'flush set inet {TABLE} open_tcp\nflush set inet {TABLE} open_udp\n'
              + (f'add element inet {TABLE} open_tcp {_elements(tcp)}\n' if tcp else '')
              + (f'add element inet {TABLE} open_udp {_elements(udp)}\n' if udp else ''))
    appkit.nft(script)


def sync_allow():
    """Refresh the whitelist sets (whitelist + signed-in admin addresses)."""
    if not table_exists():
        return
    wl = [w['ip'] for w in whitelist() if w.get('ip')] + [ip for ip in appkit.admin_ips() if appkit.parse_ip(ip)]
    wl4, wl6 = _split_family(wl)
    script = (f'flush set inet {TABLE} allow4\nflush set inet {TABLE} allow6\n'
              + (f'add element inet {TABLE} allow4 {_elements(wl4)}\n' if wl4 else '')
              + (f'add element inet {TABLE} allow6 {_elements(wl6)}\n' if wl6 else ''))
    appkit.nft(script)


# ---------------------------------------------------------------- block / unblock

def is_protected(ip, s=None):
    """Never block: whitelist, admins, loopback, (optionally) private ranges."""
    s = s or settings()
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if a.is_loopback or a.is_unspecified or a.is_multicast:
        return True
    if s.get('ignore_private') and (a.is_private or a.is_link_local):
        return True
    if ip in appkit.admin_ips():
        return True
    return appkit.ip_in(ip, [w['ip'] for w in whitelist() if w.get('ip')])


def block(ip, minutes, reason, mode='auto', ports=None, probes=0):
    """Add to the kernel block set and record it. (ok, error)."""
    ipn = appkit.parse_ip(ip)
    if not ipn or '/' in ipn:
        return False, 'Enter a single IP address'
    if is_protected(ipn):
        return False, f'{ipn} is whitelisted, private or a signed-in admin address; it is never blocked'
    if not table_exists():
        ok, err = apply()
        if not ok:
            return False, err
    fam = 'block6' if ':' in ipn else 'block4'
    t = f' timeout {int(minutes) * 60}s' if minutes and int(minutes) > 0 else ''
    # add (no-op if present) + delete + add in ONE transaction: re-blocking an address
    # must replace its expiry (a plain add keeps the old timeout on most kernels)
    ok, err = appkit.nft(f'add element inet {TABLE} {fam} {{ {ipn} }}\n'
                         f'delete element inet {TABLE} {fam} {{ {ipn} }}\n'
                         f'add element inet {TABLE} {fam} {{ {ipn}{t} }}\n')
    if not ok:
        return False, err
    now = int(time.time())
    _set_active(ipn, (now + int(minutes) * 60) if minutes else 0)
    appkit.append_jsonl(APP, 'blocks.jsonl', {
        't': now, 'ip': ipn, 'mode': mode, 'reason': str(reason)[:200], 'minutes': int(minutes or 0),
        'until': (now + int(minutes) * 60) if minutes else 0, 'ports': (ports or [])[:50], 'probes': int(probes)})
    return True, ''


def unblock(ip):
    ipn = appkit.parse_ip(ip)
    if not ipn:
        return False, 'Bad address'
    fam = 'block6' if ':' in ipn else 'block4'
    ok, err = appkit.nft(f'delete element inet {TABLE} {fam} {{ {ipn} }}\n')
    if not ok and 'no such' not in err.lower() and 'not exist' not in err.lower() and 'enoent' not in err.lower():
        return False, err
    _set_active(ipn, None)
    appkit.append_jsonl(APP, 'blocks.jsonl', {'t': int(time.time()), 'ip': ipn, 'mode': 'unblock',
                                              'reason': 'unblocked', 'minutes': 0, 'until': 0,
                                              'ports': [], 'probes': 0})
    return True, ''


def remove_table():
    appkit.nft_drop_table(APP)
