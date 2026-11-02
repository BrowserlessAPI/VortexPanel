"""Network Threat Detection service (vortexpanel-app-net-threat).

  every 10 s   read the kernel hit counters; a new address (or new activity after an
               hour of silence) becomes a threat event; keep today's statistics
  every N h    download fresh lists and reload the table
  on change    settings / whitelist edits rebuild the table
"""
import os
import signal
import sys
import time

from panel import appkit
from vpapp_net_threat import engine as E

APP = E.APP


def _stats(day):
    st = appkit.read_json(APP, f'stats-{day}.json', {})
    st.setdefault('hits', 0)
    st.setdefault('hourly', [0] * 24)
    st.setdefault('by_list', {})
    st.setdefault('ips', {})
    return st


def tick(state, now):
    day = time.strftime('%Y-%m-%d', time.localtime(now))
    if state.get('day') != day:
        state['day'] = day
        state['stats'] = _stats(day)
    st = state['stats']
    last = state.setdefault('last', {})          # (lid, ip) -> packets seen
    seen_t = state.setdefault('seen_t', {})      # (lid, ip) -> last activity time
    s = E.settings()
    hour = time.localtime(now).tm_hour
    live = []
    for lid, ip, pk, ports in E.hits():
        key = (lid, ip)
        prev = last.get(key, 0)
        delta = pk - prev if pk >= prev else pk
        last[key] = pk
        x = E.LIST_BY_ID[lid]
        live.append({'list': lid, 'ip': ip, 'packets': pk, 'ports': ports[:20]})
        if delta <= 0:
            continue
        st['hits'] += delta
        st['hourly'][hour] += delta
        st['by_list'][lid] = st['by_list'].get(lid, 0) + delta
        rec = st['ips'].setdefault(ip, {'list': lid, 'packets': 0, 'ports': [], 'first': now, 'last': now})
        if E.RISK_ORDER.get(x[3], 9) < E.RISK_ORDER.get(E.LIST_BY_ID.get(rec['list'], ('',) * 4)[3], 9):
            rec['list'] = lid          # an address on several lists shows its most serious one
        rec['packets'] += delta
        rec['last'] = now
        for p in ports:
            if p not in rec['ports'] and len(rec['ports']) < 50:
                rec['ports'].append(p)
        if now - seen_t.get(key, 0) > 3600:
            mode = s['modes'].get(lid, 'monitor')
            ev = {'t': now, 'ip': ip, 'list': lid, 'category': x[2], 'risk': x[3], 'direction': x[4],
                  'action': 'blocked' if mode == 'block' else 'detected', 'ports': ports[:20], 'packets': delta}
            appkit.append_jsonl(APP, 'events.jsonl', ev, 20000)
            if s['notify'] and x[3] in ('critical', 'high') and (x[4] == 'out' or x[3] == 'critical'):
                appkit.notify(APP, 'Threat detected', f"{'Outbound to' if x[4] == 'out' else 'From'} {ip} ({x[1]}: {x[2]})")
        seen_t[key] = now
    if len(st['ips']) > 20000:
        st['ips'] = dict(sorted(st['ips'].items(), key=lambda kv: -kv[1]['packets'])[:15000])
    if len(last) > 200000:
        last.clear()
    appkit.write_json(APP, f'stats-{day}.json', st)
    appkit.write_json(APP, 'live.json', {'t': now, 'items': live[:1000]})


def cleanup(s):
    cutoff = time.time() - s['retention_days'] * 86400
    d = appkit.data_dir(APP)
    for fn in os.listdir(d):
        if fn.startswith('stats-') and fn.endswith('.json'):
            try:
                if time.mktime(time.strptime(fn[6:16], '%Y-%m-%d')) < cutoff:
                    os.remove(os.path.join(d, fn))
            except (ValueError, OSError):
                continue


def main():
    running = {'on': True}
    signal.signal(signal.SIGTERM, lambda *_: running.update(on=False))
    d = appkit.data_dir(APP)
    marks = {}
    state = {}
    last_update = (appkit.read_json(APP, 'update.json', {}) or {}).get('t', 0)
    last_clean = 0
    while running['on']:
        now = int(time.time())
        s = E.settings()
        try:
            if now - last_update >= s['update_hours'] * 3600 or os.path.exists(os.path.join(d, '.update-now')):
                try:
                    os.remove(os.path.join(d, '.update-now'))
                except OSError:
                    pass
                for ok, m in E.update_all():
                    print(m, flush=True)
                last_update = now
                marks.clear()          # force a reload with the new lists
            m = tuple(os.path.getmtime(os.path.join(d, f)) if os.path.exists(os.path.join(d, f)) else 0
                      for f in ('settings.json', 'whitelist.json'))
            if marks.get('cfg') != m or not E.table_exists() or now - marks.get('allow', 0) > 300:
                ok, err = E.apply(s)
                print('table loaded' if ok else f'table failed: {err[:300]}', flush=True)
                marks['cfg'], marks['allow'] = m, now
            tick(state, now)
            if now - last_clean > 3600:
                cleanup(s)
                last_clean = now
        except Exception as e:  # noqa: BLE001
            print(f'tick error: {type(e).__name__}: {e}', flush=True)
        for _ in range(20):
            if not running['on']:
                break
            time.sleep(0.5)
    return 0


if __name__ == '__main__':
    sys.exit(main())
