"""Per-website traffic history.

Reads each site's access log incrementally (remembering the byte offset and
inode of every log, so a rotated log is finished before the new one is
started) and adds the bytes sent and the request count to hourly and daily
totals in a small SQLite database. Hours and days come from the timestamps in
the log lines, so traffic is counted at the time it happened even when the
collector runs late.

Runs every 5 minutes from the vortexpanel-tasks timer (panel/tasks.py) and on
demand from the Bandwidth page.
"""
import os, re, json, time, sqlite3, fcntl, calendar
from datetime import datetime, timezone

DB_PATH = '/opt/vortexpanel/data/bandwidth.db'
LOCK_PATH = '/opt/vortexpanel/data/.bandwidth.lock'
HOURLY_KEEP_DAYS = 35
# A first run on a big existing log reads at most this much of its tail.
FIRST_READ_MAX = 512 * 1024 * 1024
# Upper bound per run, so one huge log cannot hold the collector for long.
RUN_READ_MAX = 1024 * 1024 * 1024

# combined: ... [07/Oct/2026:01:30:00 +0000] "GET / HTTP/1.1" 200 1234 ...
_COMBINED = re.compile(rb'\[(\d{2}/\w{3}/\d{4}:\d{2}):\d{2}:\d{2} ([+-]\d{4})\] "(?:[^"\\]|\\.)*" \d{3} (\d+|-)')
_MONTHS = {m: i for i, m in enumerate(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug',
                                       'Sep', 'Oct', 'Nov', 'Dec'], 1)}


def _db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.execute('PRAGMA journal_mode=WAL')
    con.executescript('''
        CREATE TABLE IF NOT EXISTS offsets (path TEXT PRIMARY KEY, inode INTEGER, pos INTEGER);
        CREATE TABLE IF NOT EXISTS hourly (domain TEXT, hour INTEGER, bytes INTEGER, requests INTEGER,
                                           PRIMARY KEY (domain, hour));
        CREATE TABLE IF NOT EXISTS daily (domain TEXT, day TEXT, bytes INTEGER, requests INTEGER,
                                          PRIMARY KEY (domain, day));
        CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
    ''')
    return con


def _log_sources():
    """(domain, path, format) for every per-site access log the panel writes."""
    out = []
    for d in ('/var/log/nginx', '/var/log/apache2', '/var/log/httpd'):
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith('.access.log'):
                    out.append((f[:-len('.access.log')], os.path.join(d, f), 'combined'))
    d = '/var/log/openlitespeed'
    if os.path.isdir(d):
        for f in os.listdir(d):
            if f.endswith('.access_log'):
                out.append((f[:-len('.access_log')], os.path.join(d, f), 'combined'))
    d = '/var/log/caddy'
    if os.path.isdir(d):
        for f in os.listdir(d):
            if f.endswith('.log') and not f.startswith(('access', 'caddy')):
                out.append((f[:-len('.log')], os.path.join(d, f), 'caddy'))
    return [(dom.lower(), p, fmt) for dom, p, fmt in out
            if re.fullmatch(r'[a-z0-9.*_-]+', dom.lower()) and os.path.isfile(p)]


class _Acc:
    """Hour -> [bytes, requests] for one domain, plus a timestamp cache."""
    def __init__(self):
        self.hours = {}
        self._cache = {}

    def hour_of(self, stamp, tz):
        key = (stamp, tz)
        h = self._cache.get(key)
        if h is None:
            try:
                day, mon, rest = stamp.split(b'/')
                year, hour = rest.split(b':')
                t = calendar.timegm((int(year), _MONTHS[mon.decode()], int(day), int(hour), 0, 0))
                sign = -1 if tz[:1] == b'-' else 1
                off = sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
                h = (t - off) // 3600 * 3600
            except Exception:
                h = 0
            self._cache[key] = h
        return h

    def add(self, hour, nbytes):
        if not hour:
            return
        e = self.hours.get(hour)
        if e is None:
            self.hours[hour] = [nbytes, 1]
        else:
            e[0] += nbytes
            e[1] += 1


def _parse_combined(data, acc):
    for m in _COMBINED.finditer(data):
        size = m.group(3)
        acc.add(acc.hour_of(m.group(1), m.group(2)), int(size) if size != b'-' else 0)


def _parse_caddy(data, acc):
    for line in data.splitlines():
        if not line.startswith(b'{'):
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        ts = j.get('ts')
        if not isinstance(ts, (int, float)):
            continue
        acc.add(int(ts) // 3600 * 3600, int(j.get('size') or 0))


def _read_from(path, pos, limit):
    with open(path, 'rb') as f:
        f.seek(pos)
        data = f.read(limit)
    # Only whole lines: the rest is read on the next run.
    cut = data.rfind(b'\n')
    if cut < 0:
        return b'', pos
    return data[:cut + 1], pos + cut + 1


def collect():
    """Read new log lines of every site. Returns a short summary dict."""
    os.makedirs(os.path.dirname(LOCK_PATH), exist_ok=True)
    lockf = open(LOCK_PATH, 'w')
    try:
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return {'ok': True, 'skipped': 'another collection is running'}
    started = time.time()
    con = _db()
    budget = RUN_READ_MAX
    read_total = 0
    try:
        offs = {r[0]: (r[1], r[2]) for r in con.execute('SELECT path, inode, pos FROM offsets')}
        per_domain = {}
        for domain, path, fmt in _log_sources():
            try:
                st = os.stat(path)
            except OSError:
                continue
            parse = _parse_caddy if fmt == 'caddy' else _parse_combined
            acc = per_domain.setdefault(domain, _Acc())
            inode, pos = offs.get(path, (None, None))
            if inode is not None and inode != st.st_ino:
                # Rotated: finish the old file (now <log>.1) from where we stopped.
                old = path + '.1'
                try:
                    ost = os.stat(old)
                    if ost.st_ino == inode and ost.st_size > pos:
                        data, _ = _read_from(old, pos, min(ost.st_size - pos, budget))
                        parse(data, acc); budget -= len(data); read_total += len(data)
                except OSError:
                    pass
                pos = 0
            elif pos is None:
                pos = max(0, st.st_size - FIRST_READ_MAX)
                if pos:
                    # start at a line boundary
                    with open(path, 'rb') as f:
                        f.seek(pos)
                        f.readline()
                        pos = f.tell()
            elif st.st_size < pos:
                pos = 0  # truncated in place (copytruncate)
            if budget > 0 and st.st_size > pos:
                data, newpos = _read_from(path, pos, min(st.st_size - pos, budget))
                parse(data, acc)
                budget -= len(data); read_total += len(data)
                pos = newpos
            con.execute('INSERT OR REPLACE INTO offsets (path, inode, pos) VALUES (?, ?, ?)',
                        (path, st.st_ino, pos))

        rows = 0
        for domain, acc in per_domain.items():
            for hour, (nbytes, nreq) in acc.hours.items():
                rows += 1
                con.execute('''INSERT INTO hourly (domain, hour, bytes, requests) VALUES (?, ?, ?, ?)
                               ON CONFLICT(domain, hour) DO UPDATE SET bytes = bytes + excluded.bytes,
                               requests = requests + excluded.requests''', (domain, hour, nbytes, nreq))
                day = time.strftime('%Y-%m-%d', time.localtime(hour))
                con.execute('''INSERT INTO daily (domain, day, bytes, requests) VALUES (?, ?, ?, ?)
                               ON CONFLICT(domain, day) DO UPDATE SET bytes = bytes + excluded.bytes,
                               requests = requests + excluded.requests''', (domain, day, nbytes, nreq))
        con.execute('DELETE FROM hourly WHERE hour < ?', (int(time.time()) - HOURLY_KEEP_DAYS * 86400,))
        con.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('last_collect', ?)", (str(int(time.time())),))
        con.commit()
        return {'ok': True, 'read_bytes': read_total, 'rows': rows, 'seconds': round(time.time() - started, 2)}
    finally:
        con.close()
        try:
            fcntl.flock(lockf, fcntl.LOCK_UN)
        finally:
            lockf.close()


def last_collect():
    try:
        con = _db()
        r = con.execute("SELECT v FROM meta WHERE k='last_collect'").fetchone()
        con.close()
        return int(r[0]) if r else 0
    except Exception:
        return 0


def _periods(period):
    """Bucket list [(key, label, start_epoch, end_epoch)] for a period, oldest first."""
    now = time.time()
    lt = time.localtime(now)
    out = []
    if period == '24h':
        cur = int(now) // 3600 * 3600
        for i in range(23, -1, -1):
            s = cur - i * 3600
            out.append((s, time.strftime('%H:00', time.localtime(s)), s, s + 3600))
    elif period in ('7d', '30d'):
        n = 7 if period == '7d' else 30
        for i in range(n - 1, -1, -1):
            d = time.localtime(now - i * 86400)
            key = time.strftime('%Y-%m-%d', d)
            out.append((key, time.strftime('%b %d', d), None, None))
    else:  # 12m
        y, m = lt.tm_year, lt.tm_mon
        ms = []
        for _ in range(12):
            ms.append((y, m))
            m -= 1
            if m == 0:
                y, m = y - 1, 12
        for y, m in reversed(ms):
            out.append((f'{y:04d}-{m:02d}', datetime(y, m, 1).strftime('%b %Y'), None, None))
    return out


def series(period='7d', domain=None):
    """Traffic per bucket for one domain or all domains together."""
    if period not in ('24h', '7d', '30d', '12m'):
        period = '7d'
    buckets = _periods(period)
    con = _db()
    try:
        vals = {}
        args = []
        dom_sql = ''
        if domain:
            dom_sql = ' AND domain = ?'
            args = [domain]
        if period == '24h':
            start = buckets[0][2]
            for hour, b, r in con.execute('SELECT hour, SUM(bytes), SUM(requests) FROM hourly WHERE hour >= ?'
                                          + dom_sql + ' GROUP BY hour', [start] + args):
                vals[hour] = (b, r)
        elif period in ('7d', '30d'):
            start = buckets[0][0]
            for day, b, r in con.execute('SELECT day, SUM(bytes), SUM(requests) FROM daily WHERE day >= ?'
                                         + dom_sql + ' GROUP BY day', [start] + args):
                vals[day] = (b, r)
        else:
            start = buckets[0][0] + '-01'
            for mon, b, r in con.execute('SELECT substr(day, 1, 7) AS mon, SUM(bytes), SUM(requests) FROM daily '
                                         'WHERE day >= ?' + dom_sql + ' GROUP BY mon', [start] + args):
                vals[mon] = (b, r)
    finally:
        con.close()
    pts = [{'label': lbl, 'bytes': int(vals.get(k, (0, 0))[0] or 0), 'requests': int(vals.get(k, (0, 0))[1] or 0)}
           for k, lbl, _, _ in buckets]
    return {'period': period, 'points': pts,
            'bytes': sum(p['bytes'] for p in pts), 'requests': sum(p['requests'] for p in pts)}


def site_totals(period='30d'):
    """Per-domain totals over a period, with a small daily trend for each."""
    if period not in ('24h', '7d', '30d', '12m'):
        period = '30d'
    con = _db()
    try:
        out = {}
        # Same window as series() so the table adds up to the chart.
        first = _periods(period)[0]
        if period == '24h':
            start = first[2]
            for dom, b, r in con.execute('SELECT domain, SUM(bytes), SUM(requests) FROM hourly WHERE hour >= ? '
                                         'GROUP BY domain', (start,)):
                out[dom] = {'domain': dom, 'bytes': int(b or 0), 'requests': int(r or 0)}
        else:
            start = first[0] if period != '12m' else first[0] + '-01'
            for dom, b, r in con.execute('SELECT domain, SUM(bytes), SUM(requests) FROM daily WHERE day >= ? '
                                         'GROUP BY domain', (start,)):
                out[dom] = {'domain': dom, 'bytes': int(b or 0), 'requests': int(r or 0)}
        # 14-day trend for the sparkline
        tstart = time.strftime('%Y-%m-%d', time.localtime(time.time() - 13 * 86400))
        trend = {}
        for dom, day, b in con.execute('SELECT domain, day, bytes FROM daily WHERE day >= ?', (tstart,)):
            trend.setdefault(dom, {})[day] = int(b or 0)
    finally:
        con.close()
    keys = [time.strftime('%Y-%m-%d', time.localtime(time.time() - i * 86400)) for i in range(13, -1, -1)]
    for dom, e in out.items():
        e['trend'] = [trend.get(dom, {}).get(k, 0) for k in keys]
    return sorted(out.values(), key=lambda e: e['bytes'], reverse=True)
