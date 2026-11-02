"""Scan Detection service (vortexpanel-app-scan-detect).

Every POLL seconds: read the kernel's per-address probe counters and port sets,
keep a sliding window per address, block what passes the thresholds, and write
the live view, the real-time probe log and today's statistics for the panel.
"""
import collections
import os
import signal
import sys
import time

from panel import appkit
from vpapp_scan_detect import engine

APP = engine.APP
POLL = 5
RT_MAX = 1000


class State:
    def __init__(self):
        self.hist = collections.defaultdict(collections.deque)   # ip -> deque[(t, delta)]
        self.last_pkts = {}                                        # ip -> cumulative counter seen
        self.seen_pairs = set()                                    # (ip, port) already in the rt log
        self.first = {}
        self.last = {}
        self.rt = appkit.read_json(APP, 'realtime.json', {'items': []}).get('items', [])[-RT_MAX:]
        self.day = time.strftime('%Y-%m-%d')
        self.stats = self._load_stats(self.day)

    def _load_stats(self, day):
        st = appkit.read_json(APP, f'stats-{day}.json', {})
        st.setdefault('probes', 0)
        st.setdefault('hourly', [0] * 24)
        st.setdefault('blocks', 0)
        st.setdefault('ips', {})
        return st


def _ports_by_ip():
    out = collections.defaultdict(set)
    for fam in ('ports4', 'ports6'):
        for e in appkit.nft_set_elements(engine.TABLE, fam):
            v = e['val']
            if isinstance(v, list) and len(v) == 2:
                try:
                    out[str(v[0])].add(int(v[1]))
                except (TypeError, ValueError):
                    continue
    return out


def _hits():
    out = {}
    for fam in ('hits4', 'hits6'):
        for e in appkit.nft_set_elements(engine.TABLE, fam):
            out[str(e['val'])] = int(e.get('packets') or 0)
    return out


def tick(st, s, now):
    if time.strftime('%Y-%m-%d', time.localtime(now)) != st.day:
        appkit.write_json(APP, f'stats-{st.day}.json', st.stats)
        st.day = time.strftime('%Y-%m-%d', time.localtime(now))
        st.stats = st._load_stats(st.day)
        st.seen_pairs.clear()

    win = int(s['window_min']) * 60
    hits = _hits()
    ports = _ports_by_ip()
    blocked = {e['ip'] for e in engine.blocked_entries()}
    hour = time.localtime(now).tm_hour
    new_probes = 0

    for ip, pk in hits.items():
        prev = st.last_pkts.get(ip, 0)
        delta = pk - prev if pk >= prev else pk          # counter reset when the entry expired
        st.last_pkts[ip] = pk
        if delta <= 0:
            continue
        new_probes += delta
        st.hist[ip].append((now, delta))
        st.first.setdefault(ip, now)
        st.last[ip] = now
        rec = st.stats['ips'].setdefault(ip, {'probes': 0, 'ports': [], 'first': now, 'last': now, 'blocked': 0})
        rec['probes'] += delta
        rec['last'] = now
        if len(st.stats['ips']) > 5000:       # keep the busiest
            keep = sorted(st.stats['ips'].items(), key=lambda kv: -kv[1]['probes'])[:4000]
            st.stats['ips'] = dict(keep)
    for ip in list(st.last_pkts):
        if ip not in hits:
            st.last_pkts.pop(ip, None)

    # real-time log: (ip, port) pairs not seen yet today
    for ip, ps in ports.items():
        rec = st.stats['ips'].get(ip)
        for p in sorted(ps):
            if rec is not None and p not in rec['ports'] and len(rec['ports']) < 200:
                rec['ports'].append(p)
            key = (ip, p)
            if key in st.seen_pairs:
                continue
            st.seen_pairs.add(key)
            st.rt.append({'t': now, 'ip': ip, 'port': p})
    if len(st.seen_pairs) > 200000:
        st.seen_pairs.clear()
    st.rt = st.rt[-RT_MAX:]

    st.stats['probes'] += new_probes
    st.stats['hourly'][hour] += new_probes

    live = []
    cutoff = now - win
    for ip, dq in list(st.hist.items()):
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if not dq:
            st.hist.pop(ip, None)
            continue
        probes = sum(d for _, d in dq)
        nports = len(ports.get(ip, ()))
        over = probes >= s['scan_count'] or (s['port_count'] and nports >= s['port_count'])
        is_blocked = ip in blocked
        if over and not is_blocked and not s['detect_only'] and s['enabled'] and not engine.is_protected(ip, s):
            why = (f'{probes} probes in {s["window_min"]} min' if probes >= s['scan_count']
                   else f'{nports} closed ports in {s["window_min"]} min')
            ok, _ = engine.block(ip, s['block_minutes'], why, 'auto', sorted(ports.get(ip, ()))[:50], probes)
            if ok:
                is_blocked = True
                st.stats['blocks'] += 1
                if ip in st.stats['ips']:
                    st.stats['ips'][ip]['blocked'] = now
                if s['notify']:
                    appkit.notify(APP, 'Port scanner blocked', f'{ip}: {why}')
        live.append({'ip': ip, 'probes': probes, 'ports': nports, 'first': st.first.get(ip, now),
                     'last': st.last.get(ip, now), 'blocked': is_blocked, 'over': bool(over),
                     'sample': sorted(ports.get(ip, ()))[:20]})
    live.sort(key=lambda r: (-r['probes'], r['ip']))
    appkit.write_json(APP, 'live.json', {'t': now, 'window_min': s['window_min'], 'items': live[:500]})
    appkit.write_json(APP, 'realtime.json', {'t': now, 'items': st.rt})
    appkit.write_json(APP, f'stats-{st.day}.json', st.stats)


def cleanup(s):
    keep_days = int(s['retention_days'])
    cutoff = time.time() - keep_days * 86400
    d = appkit.data_dir(APP)
    for fn in os.listdir(d):
        if fn.startswith('stats-') and fn.endswith('.json'):
            try:
                if time.mktime(time.strptime(fn[6:16], '%Y-%m-%d')) < cutoff:
                    os.remove(os.path.join(d, fn))
            except (ValueError, OSError):
                continue
    path = os.path.join(d, 'blocks.jsonl')
    with appkit.locked(APP, 'blocks.jsonl'):     # read + rewrite under one lock: no lost appends
        recs = appkit.read_jsonl(APP, 'blocks.jsonl', limit=50000, newest_first=False)
        keep = [r for r in recs if r.get('t', 0) >= cutoff]
        if len(keep) != len(recs):
            tmp = path + '.tmp'
            with open(tmp, 'w') as f:
                for r in keep:
                    f.write(__import__('json').dumps(r, separators=(',', ':')) + '\n')
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)


def main():
    running = {'on': True}
    signal.signal(signal.SIGTERM, lambda *_: running.update(on=False))
    st = State()
    settings_mtime = 0
    last_ports = last_allow = last_clean = 0
    sp = os.path.join(appkit.data_dir(APP), 'settings.json')
    wp = os.path.join(appkit.data_dir(APP), 'whitelist.json')
    wl_mtime = 0
    s = engine.settings()
    ok, err = engine.apply(s)
    print('ruleset applied' if ok else f'ruleset failed: {err}', flush=True)
    while running['on']:
        now = int(time.time())
        try:
            m = os.path.getmtime(sp) if os.path.exists(sp) else 0
            wm = os.path.getmtime(wp) if os.path.exists(wp) else 0
            if m != settings_mtime or not engine.table_exists():
                settings_mtime = m
                s = engine.settings()
                ok, err = engine.apply(s)
                if not ok:
                    print(f'ruleset failed: {err}', flush=True)
            if wm != wl_mtime or now - last_allow >= 60:
                wl_mtime, last_allow = wm, now
                engine.sync_allow()
            if now - last_ports >= 30:
                last_ports = now
                engine.sync_open_ports()
            rt_flag = os.path.join(appkit.data_dir(APP), '.clear-realtime')
            if os.path.exists(rt_flag):          # the page cleared the real-time log
                st.rt, st.seen_pairs = [], set()
                try:
                    os.remove(rt_flag)
                except OSError:
                    pass
            tick(st, s, now)
            if now - last_clean >= 3600:
                last_clean = now
                cleanup(s)
        except Exception as e:  # noqa: BLE001 - keep the service alive, log the reason
            print(f'tick error: {type(e).__name__}: {e}', flush=True)
        for _ in range(POLL * 2):
            if not running['on']:
                break
            time.sleep(0.5)
    return 0


if __name__ == '__main__':
    sys.exit(main())
