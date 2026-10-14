"""Server monitoring history.

Every minute (vortexpanel-metrics.timer -> python3 -m panel.tasks metrics)
one sample is stored in data/metrics.db: CPU %, load, memory and swap use,
root disk use, network and disk throughput. Samples are kept for 3 days;
15-minute averages for 120 days. The Monitoring page draws charts from it
and the alert rules (panel/alerts.py) read the same samples.
"""
import json
import os
import shutil
import sqlite3
import time

DB_PATH = '/opt/vortexpanel/data/metrics.db'
STATE = '/opt/vortexpanel/data/metrics_state.json'
RAW_KEEP = 3 * 86400
ROLLUP_KEEP = 120 * 86400
FIELDS = ('cpu', 'load1', 'mem', 'swap', 'disk', 'net_rx', 'net_tx', 'io_r', 'io_w')


def _db():
    os.makedirs(os.path.dirname(DB_PATH), mode=0o700, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.execute('PRAGMA journal_mode=WAL')
    cols = ', '.join(f'{f} REAL' for f in FIELDS)
    con.executescript(f'''
        CREATE TABLE IF NOT EXISTS raw (ts INTEGER PRIMARY KEY, {cols});
        CREATE TABLE IF NOT EXISTS rollup (ts INTEGER PRIMARY KEY, {cols});
    ''')
    return con


def _cpu_times():
    with open('/proc/stat') as f:
        parts = f.readline().split()[1:]
    vals = [int(x) for x in parts]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    return sum(vals), idle


def _net_bytes():
    rx = tx = 0
    try:
        with open('/proc/net/dev') as f:
            for line in f.readlines()[2:]:
                name, data = line.split(':', 1)
                name = name.strip()
                if name == 'lo' or name.startswith(('veth', 'docker', 'br-', 'virbr')):
                    continue
                d = data.split()
                rx += int(d[0])
                tx += int(d[8])
    except Exception:
        pass
    return rx, tx


def _disk_bytes():
    r = w = 0
    try:
        with open('/proc/diskstats') as f:
            for line in f:
                p = line.split()
                name = p[2]
                # whole disks only (sda, vda, nvme0n1, xvda), no partitions
                if name.startswith(('loop', 'ram', 'dm-', 'sr', 'zram')):
                    continue
                if name[-1].isdigit() and not name.startswith('nvme') and not name.startswith('mmcblk'):
                    continue
                if (name.startswith('nvme') or name.startswith('mmcblk')) and 'p' in name[5:]:
                    continue
                r += int(p[5]) * 512
                w += int(p[9]) * 512
    except Exception:
        pass
    return r, w


def _mem():
    info = {}
    with open('/proc/meminfo') as f:
        for line in f:
            k, v = line.split(':', 1)
            info[k] = int(v.split()[0]) * 1024
    total = info.get('MemTotal', 1)
    avail = info.get('MemAvailable', info.get('MemFree', 0))
    st = info.get('SwapTotal', 0)
    sf = info.get('SwapFree', 0)
    return round((total - avail) * 100 / total, 1), (round((st - sf) * 100 / st, 1) if st else 0.0)


def sample():
    """One measurement. CPU is measured over one second; rates are per
    second since the previous run (stored in metrics_state.json)."""
    t1, i1 = _cpu_times()
    time.sleep(1)
    t2, i2 = _cpu_times()
    cpu = round(100 * (1 - (i2 - i1) / max(1, t2 - t1)), 1)
    load1 = os.getloadavg()[0]
    mem, swap = _mem()
    du = shutil.disk_usage('/')
    disk = round(du.used * 100 / du.total, 1)
    now = time.time()
    rx, tx = _net_bytes()
    dr, dw = _disk_bytes()
    try:
        prev = json.load(open(STATE))
    except Exception:
        prev = {}
    dt = now - prev.get('t', 0)
    rate = lambda cur, key: max(0.0, (cur - prev[key]) / dt) if prev.get(key) is not None and 0 < dt < 3600 and cur >= prev[key] else 0.0
    out = {'ts': int(now), 'cpu': cpu, 'load1': round(load1, 2), 'mem': mem, 'swap': swap, 'disk': disk,
           'net_rx': round(rate(rx, 'rx')), 'net_tx': round(rate(tx, 'tx')),
           'io_r': round(rate(dr, 'dr')), 'io_w': round(rate(dw, 'dw'))}
    try:
        with open(STATE + '.tmp', 'w') as f:
            json.dump({'t': now, 'rx': rx, 'tx': tx, 'dr': dr, 'dw': dw}, f)
        os.replace(STATE + '.tmp', STATE)
    except Exception:
        pass
    return out


def collect():
    s = sample()
    con = _db()
    with con:
        con.execute(f'INSERT OR REPLACE INTO raw (ts, {", ".join(FIELDS)}) VALUES (?{", ?" * len(FIELDS)})',
                    [s['ts']] + [s[f] for f in FIELDS])
        # 15-minute rollups for every finished bucket not rolled up yet.
        last = con.execute('SELECT MAX(ts) FROM rollup').fetchone()[0] or 0
        bucket_now = s['ts'] - s['ts'] % 900
        avgs = ', '.join(f'AVG({f})' for f in FIELDS)
        con.execute(f'INSERT OR REPLACE INTO rollup (ts, {", ".join(FIELDS)}) '
                    f'SELECT ts - ts % 900 AS b, {avgs} FROM raw WHERE ts >= ? AND ts < ? GROUP BY b',
                    (last + 900 if last else 0, bucket_now))
        con.execute('DELETE FROM raw WHERE ts < ?', (s['ts'] - RAW_KEEP,))
        con.execute('DELETE FROM rollup WHERE ts < ?', (s['ts'] - ROLLUP_KEEP,))
    con.close()
    return s


RANGES = {'1h': 3600, '6h': 6 * 3600, '24h': 86400, '3d': 3 * 86400, '7d': 7 * 86400, '30d': 30 * 86400,
          '90d': 90 * 86400}


def history(rng='1h', max_points=360):
    secs = RANGES.get(rng, 3600)
    since = int(time.time()) - secs
    if not os.path.exists(DB_PATH):
        return []
    con = _db()
    table = 'raw' if secs <= RAW_KEEP else 'rollup'
    rows = con.execute(f'SELECT ts, {", ".join(FIELDS)} FROM {table} WHERE ts >= ? ORDER BY ts', (since,)).fetchall()
    con.close()
    pts = [dict(zip(('ts',) + FIELDS, r)) for r in rows]
    if len(pts) > max_points:
        # Average into max_points buckets (keeps peaks visible as averages).
        step = (secs // max_points) or 1
        buckets = {}
        for p in pts:
            b = p['ts'] - p['ts'] % step
            buckets.setdefault(b, []).append(p)
        pts = [{'ts': b, **{f: round(sum((x[f] or 0) for x in g) / len(g), 2) for f in FIELDS}}
               for b, g in sorted(buckets.items())]
    return pts


def recent(minutes):
    """Raw samples of the last N minutes (for alert rules)."""
    if not os.path.exists(DB_PATH):
        return []
    con = _db()
    rows = con.execute(f'SELECT ts, {", ".join(FIELDS)} FROM raw WHERE ts >= ? ORDER BY ts',
                       (int(time.time()) - minutes * 60 - 30,)).fetchall()
    con.close()
    return [dict(zip(('ts',) + FIELDS, r)) for r in rows]
