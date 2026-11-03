"""Website Statistics storage: one SQLite database owned by this App
(data/apps/site-stats/stats.db). The core bandwidth collector keeps its own
database and log offsets; nothing here touches it."""
import os
import sqlite3
import time

from panel import appkit

APP = 'site-stats'
DEFAULTS = {
    'retention_days': 30,
    'exclude_ips': [],          # never counted (your office, uptime monitors)
    'exclude_paths': [],        # URL prefixes never counted (/wp-cron.php, /health)
    'sites': [],                # [] = every site
    'interval': 60,             # seconds between collector runs
    'top_keep': 500,            # rows kept per list per day after the day ends
    'own_domains_only': True,   # count a request only when its host is one of the site's names
}

TOP_KINDS = ('url', 'ref', 'search', 'spider', 'browser', 'os', 'device', 'status', 'url404', 'method', 'xhost')


def db_path():
    return os.path.join(appkit.data_dir(APP), 'stats.db')


def connect():
    path = db_path()
    con = sqlite3.connect(path, timeout=30)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA synchronous=NORMAL')
    con.executescript('''
        CREATE TABLE IF NOT EXISTS offsets (path TEXT PRIMARY KEY, inode INTEGER, pos INTEGER);
        CREATE TABLE IF NOT EXISTS hourly (site TEXT, hour INTEGER, req INTEGER, pv INTEGER, bytes INTEGER,
            spider INTEGER, s2 INTEGER, s3 INTEGER, s4 INTEGER, s5 INTEGER, rt_sum REAL, rt_n INTEGER,
            PRIMARY KEY (site, hour));
        CREATE TABLE IF NOT EXISTS vis (site TEXT, hour INTEGER, kind INTEGER, h INTEGER,
            PRIMARY KEY (site, hour, kind, h)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS top (site TEXT, day TEXT, kind TEXT, k TEXT, hits INTEGER, bytes INTEGER,
            PRIMARY KEY (site, day, kind, k)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS ips (site TEXT, day TEXT, ip TEXT, hits INTEGER, pv INTEGER, bytes INTEGER,
            first INTEGER, last INTEGER, country TEXT, spider TEXT, s4 INTEGER,
            PRIMARY KEY (site, day, ip)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS minute (site TEXT, minute INTEGER, req INTEGER, bytes INTEGER,
            PRIMARY KEY (site, minute)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
    ''')
    return con


def settings():
    s = dict(DEFAULTS)
    s.update({k: v for k, v in appkit.read_json(APP, 'settings.json', {}).items() if k in DEFAULTS})
    return s


def clean_settings(d):
    cur = settings()
    out = dict(cur)
    out['retention_days'] = appkit.clamp_int(d.get('retention_days', cur['retention_days']), 1, 400, 30)
    out['interval'] = appkit.clamp_int(d.get('interval', cur['interval']), 30, 3600, 60)
    out['top_keep'] = appkit.clamp_int(d.get('top_keep', cur['top_keep']), 50, 5000, 500)
    out['own_domains_only'] = bool(d.get('own_domains_only', cur.get('own_domains_only', True)))
    ips = []
    for tok in (d.get('exclude_ips', cur['exclude_ips']) or []):
        ip = appkit.parse_ip(tok)
        if ip:
            ips.append(ip)
    out['exclude_ips'] = ips[:500]
    paths = []
    for p in (d.get('exclude_paths', cur['exclude_paths']) or []):
        p = str(p).strip()
        if p.startswith('/') and len(p) < 200 and not any(c in p for c in '\r\n\t '):
            paths.append(p)
    out['exclude_paths'] = paths[:200]
    sites = d.get('sites', cur['sites']) or []
    out['sites'] = [str(x).lower() for x in sites if isinstance(x, str) and len(x) < 254][:2000]
    return out


def meta_get(con, k, default=''):
    r = con.execute('SELECT v FROM meta WHERE k=?', (k,)).fetchone()
    return r[0] if r else default


def meta_set(con, k, v):
    con.execute('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', (k, str(v)))


# ----------------------------------------------------------------- time ranges

def day_str(t):
    return time.strftime('%Y-%m-%d', time.localtime(t))


def day_start(t):
    lt = time.localtime(t)
    return int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1)))


def range_bounds(rng, now=None):
    """(start, end, step, label) for today | yesterday | 7d | 30d; end exclusive.
    step = 'hour' for single days, 'day' otherwise."""
    now = now or time.time()
    today = day_start(now)
    if rng == 'yesterday':
        y = day_start(today - 3600)
        return y, today, 'hour'
    tomorrow = day_start(today + 26 * 3600)          # DST-safe next midnight
    if rng == '7d':
        return day_start(today - 6 * 86400 + 3600), tomorrow, 'day'
    if rng == '30d':
        return day_start(today - 29 * 86400 + 3600), tomorrow, 'day'
    return today, tomorrow, 'hour'


def previous_bounds(start, end):
    span = end - start
    return day_start(start - span + 7200), start


def days_between(start, end):
    out, t = [], start
    while t < end:
        d = day_str(t)
        if not out or out[-1] != d:
            out.append(d)
        t += 3600
    return out
