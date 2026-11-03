"""Website Statistics collector (service vortexpanel-app-site-stats).

Reads every website's access log incrementally (own offsets, rotation-aware)
and adds requests, page views, visitors, traffic, spiders, status codes and the
top lists to stats.db. Nginx/Apache/OpenLiteSpeed write the "combined" format;
Caddy writes JSON (which also carries the response time).
"""
import calendar
import hashlib
import json
import os
import re
import signal
import sys
import time

from panel import appkit
from vpapp_site_stats import geo, hostguard, store

APP = store.APP
FIRST_READ_MAX = 64 * 1024 * 1024      # a brand-new log: only its tail
RUN_READ_MAX = 256 * 1024 * 1024       # per log per run

_FULL = re.compile(rb'^(\S+) \S+ \S+ \[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})\] '
                   rb'"(\S+) (\S+)[^"]*" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?(?: "([^"]*)")?', re.M)
_MONTHS = {m: i for i, m in enumerate([b'Jan', b'Feb', b'Mar', b'Apr', b'May', b'Jun', b'Jul', b'Aug',
                                       b'Sep', b'Oct', b'Nov', b'Dec'], 1)}
_ASSET = re.compile(r'\.(?:css|js|mjs|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|otf|eot|map|mp4|webm|mp3|ogg|'
                    r'pdf|zip|gz|txt|xml|json)$', re.I)

# name -> UA marker (checked in order; first match wins)
SPIDERS = [
    ('Googlebot', 'googlebot'), ('Google (other)', 'google'), ('Bingbot', 'bingbot'), ('Baiduspider', 'baiduspider'),
    ('YandexBot', 'yandex'), ('DuckDuckBot', 'duckduckbot'), ('Applebot', 'applebot'), ('Sogou', 'sogou'),
    ('360Spider', '360spider'), ('PetalBot', 'petalbot'), ('Bytespider', 'bytespider'), ('GPTBot', 'gptbot'),
    ('ChatGPT-User', 'chatgpt'), ('ClaudeBot', 'claudebot'), ('Claude-Web', 'claude-web'), ('PerplexityBot', 'perplexity'),
    ('CCBot', 'ccbot'), ('Meta (facebook)', 'facebookexternalhit'), ('Meta crawler', 'meta-externalagent'),
    ('AhrefsBot', 'ahrefsbot'), ('SemrushBot', 'semrushbot'), ('MJ12bot', 'mj12bot'), ('DotBot', 'dotbot'),
    ('Twitterbot', 'twitterbot'), ('LinkedInBot', 'linkedinbot'), ('Slackbot', 'slackbot'), ('Discordbot', 'discordbot'),
    ('UptimeRobot', 'uptimerobot'), ('Pingdom', 'pingdom'),
    ('Other bot', 'bot'), ('Other crawler', 'crawl'), ('Other spider', 'spider'), ('Scripts (curl, python...)', 'curl'),
    ('Scripts (curl, python...)', 'python-'), ('Scripts (curl, python...)', 'wget'), ('Scripts (curl, python...)', 'go-http'),
    ('Scripts (curl, python...)', 'java/'), ('Scripts (curl, python...)', 'libwww'), ('Scripts (curl, python...)', 'httpclient'),
    ('Headless browser', 'headless'),
]
SEARCH = {'google.': 'Google', 'bing.com': 'Bing', 'duckduckgo.com': 'DuckDuckGo', 'yahoo.': 'Yahoo',
          'yandex.': 'Yandex', 'baidu.com': 'Baidu', 'ecosia.org': 'Ecosia', 'search.brave.com': 'Brave',
          'naver.com': 'Naver', 'sogou.com': 'Sogou', 'so.com': '360'}


def spider_of(ua):
    if not ua or ua == '-':
        return 'Empty user agent'
    low = ua.lower()
    for name, mark in SPIDERS:
        if mark in low:
            return name
    return ''


def browser_of(ua):
    for name, pat in (('Edge', 'Edg/'), ('Opera', 'OPR/'), ('Samsung Internet', 'SamsungBrowser'), ('UC Browser', 'UCBrowser'),
                      ('Chrome', 'Chrome/'), ('Firefox', 'Firefox/'), ('Safari', 'Safari/')):
        if pat in ua:
            return name
    return 'Other'


def os_of(ua):
    for name, pat in (('Android', 'Android'), ('iOS', 'iPhone'), ('iOS', 'iPad'), ('Windows', 'Windows'),
                      ('macOS', 'Mac OS X'), ('ChromeOS', 'CrOS'), ('Linux', 'Linux')):
        if pat in ua:
            return name
    return 'Other'


def device_of(ua):
    if 'iPad' in ua or 'Tablet' in ua:
        return 'Tablet'
    if 'Mobi' in ua or 'Android' in ua or 'iPhone' in ua:
        return 'Mobile'
    return 'Desktop'


def _h(text):
    return int.from_bytes(hashlib.blake2b(text.encode('utf-8', 'replace'), digest_size=8).digest(), 'big') & 0x7fffffffffffffff


# --------------------------------------------------------------------- sources

def log_sources():
    """(site, path, fmt) for each per-site access log the panel writes."""
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
    seen, res = set(), []
    for site, p, fmt in out:
        site = site.lower()
        if re.fullmatch(r'[a-z0-9.*_-]{1,253}', site) and os.path.isfile(p) and site not in seen:
            seen.add(site)
            res.append((site, p, fmt))
    return sorted(res)


def error_log(site):
    for p in (f'/var/log/nginx/{site}.error.log', f'/var/log/apache2/{site}.error.log',
              f'/var/log/httpd/{site}.error.log', f'/var/log/openlitespeed/{site}.error_log'):
        if os.path.isfile(p):
            return p
    return ''


# ------------------------------------------------------------------- aggregate

class Agg:
    def __init__(self, site, s, names=None):
        self.site = site
        self.names = names or set()   # the site's own host names (empty: not known, nothing filtered)
        self.foreign = {}             # (day, host) -> [hits, bytes]: other domains pointed at this server
        import ipaddress
        self.ex_ips = set(x for x in s['exclude_ips'] if '/' not in x)
        self.ex_nets = [ipaddress.ip_network(x, strict=False) for x in s['exclude_ips'] if '/' in x]
        self._ex_cache = {}
        self.ex_paths = tuple(s['exclude_paths'])
        self.hourly = {}      # hour -> [req, pv, bytes, spider, s2, s3, s4, s5, rt_sum, rt_n]
        self.vis = set()      # (hour, kind, h)
        self.top = {}         # (day, kind, k) -> [hits, bytes]
        self.ips = {}         # (day, ip) -> [hits, pv, bytes, first, last, country, spider, s4]
        self.minute = {}      # minute -> [req, bytes]
        self._day = {}

    def _in_nets(self, ip):
        if not self.ex_nets:
            return False
        r = self._ex_cache.get(ip)
        if r is None:
            import ipaddress
            try:
                a = ipaddress.ip_address(ip)
                r = any(a.version == n.version and a in n for n in self.ex_nets)
            except ValueError:
                r = False
            self._ex_cache[ip] = r
        return r

    def day(self, hour):
        d = self._day.get(hour)
        if d is None:
            d = self._day[hour] = store.day_str(hour)
        return d

    def _top(self, day, kind, k, nbytes=0):
        e = self.top.get((day, kind, k))
        if e is None:
            self.top[(day, kind, k)] = [1, nbytes]
        else:
            e[0] += 1
            e[1] += nbytes

    def add(self, ts, ip, method, path, status, nbytes, ref, ua, rt=None, host=''):
        if ip in self.ex_ips or (self.ex_paths and path.startswith(self.ex_paths)) or self._in_nets(ip):
            return
        if host and self.names and not hostguard.host_matches(host, self.names):
            # a request for another domain that points at this server: not this site's traffic
            k = (self.day(ts - ts % 3600), host.lower().split(':')[0][:200])
            f = self.foreign.get(k)
            if f is None:
                f = self.foreign[k] = [0, 0]
            f[0] += 1
            f[1] += nbytes
            return
        hour = ts - ts % 3600
        day = self.day(hour)
        h = self.hourly.get(hour)
        if h is None:
            h = self.hourly[hour] = [0, 0, 0, 0, 0, 0, 0, 0, 0.0, 0]
        h[0] += 1
        h[2] += nbytes
        st = status // 100
        if 2 <= st <= 5:
            h[2 + st] += 1
        if rt is not None:
            h[8] += rt
            h[9] += 1
        m = ts - ts % 60
        mm = self.minute.get(m)
        if mm is None:
            self.minute[m] = [1, nbytes]
        else:
            mm[0] += 1
            mm[1] += nbytes
        upath = path.split('?', 1)[0][:300] or '/'
        spider = spider_of(ua)
        rec = self.ips.get((day, ip))
        if rec is None:
            rec = self.ips[(day, ip)] = [0, 0, 0, ts, ts, '', spider, 0]
        rec[0] += 1
        rec[2] += nbytes
        rec[4] = max(rec[4], ts)
        rec[3] = min(rec[3], ts)
        if st == 4:
            rec[7] += 1
        self.vis.add((hour, 1, _h(ip)))
        self._top(day, 'status', str(status))
        self._top(day, 'method', method[:10])
        if status == 404:
            self._top(day, 'url404', upath)
        if spider:
            h[3] += 1
            self._top(day, 'spider', spider, nbytes)
            return
        if method not in ('GET', 'POST') or st not in (2, 3) or _ASSET.search(upath):
            return
        # a page view by a person (an address that browses like a person is a person,
        # even if it also sent some script or bot requests)
        h[1] += 1
        rec[1] += 1
        rec[6] = ''
        self.vis.add((hour, 0, _h(ip + '|' + ua)))
        self._top(day, 'url', upath, nbytes)
        self._top(day, 'browser', browser_of(ua))
        self._top(day, 'os', os_of(ua))
        self._top(day, 'device', device_of(ua))
        if ref and ref != '-':
            mm2 = re.match(r'https?://([^/:?#]+)', ref)
            if mm2:
                host = mm2.group(1).lower()
                if host.startswith('www.'):
                    host = host[4:]
                if host != self.site and not host.endswith('.' + self.site) and self.site != host.split('.', 1)[-1]:
                    self._top(day, 'ref', host)
                    for mark, name in SEARCH.items():
                        if mark in host:
                            self._top(day, 'search', name)
                            break
        else:
            self._top(day, 'ref', '(direct)')


def _ts(m):
    """Epoch seconds from the log's own date and UTC offset."""
    try:
        t = calendar.timegm((int(m.group(4)), _MONTHS[m.group(3)], int(m.group(2)), int(m.group(5)),
                             int(m.group(6)), int(m.group(7))))
        tz = m.group(8)
        sign = -1 if tz[:1] == b'-' else 1
        return t - sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
    except (KeyError, ValueError, OverflowError):
        return 0


def parse_combined(data, agg):
    for m in _FULL.finditer(data):
        ts = _ts(m)
        if not ts:
            continue
        size = m.group(12)
        agg.add(ts, m.group(1).decode('ascii', 'replace'), m.group(9).decode('ascii', 'replace'),
                m.group(10).decode('utf-8', 'replace'), int(m.group(11)), int(size) if size != b'-' else 0,
                (m.group(13) or b'').decode('utf-8', 'replace'), (m.group(14) or b'').decode('utf-8', 'replace'),
                host=(m.group(15) or b'').decode('utf-8', 'replace'))


def parse_caddy(data, agg):
    for line in data.splitlines():
        if not line.startswith(b'{'):
            continue
        try:
            j = json.loads(line)
        except ValueError:
            continue
        ts = j.get('ts')
        rq = j.get('request') or {}
        if not isinstance(ts, (int, float)) or not isinstance(rq, dict):
            continue
        hdr = rq.get('headers') or {}
        ua = (hdr.get('User-Agent') or [''])[0]
        ref = (hdr.get('Referer') or [''])[0]
        ip = str(rq.get('client_ip') or rq.get('remote_ip') or '')
        dur = j.get('duration')
        agg.add(int(ts), ip, str(rq.get('method') or ''), str(rq.get('uri') or '/'), int(j.get('status') or 0),
                int(j.get('size') or 0), ref, ua, float(dur) if isinstance(dur, (int, float)) else None,
                host=str(rq.get('host') or ''))


# ----------------------------------------------------------------------- write

def flush(con, agg):
    con.executemany('''INSERT INTO hourly (site, hour, req, pv, bytes, spider, s2, s3, s4, s5, rt_sum, rt_n)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(site, hour) DO UPDATE SET req=req+excluded.req, pv=pv+excluded.pv,
        bytes=bytes+excluded.bytes, spider=spider+excluded.spider, s2=s2+excluded.s2, s3=s3+excluded.s3,
        s4=s4+excluded.s4, s5=s5+excluded.s5, rt_sum=rt_sum+excluded.rt_sum, rt_n=rt_n+excluded.rt_n''',
                    [(agg.site, hr, *v) for hr, v in agg.hourly.items()])
    con.executemany('INSERT OR IGNORE INTO vis (site, hour, kind, h) VALUES (?,?,?,?)',
                    [(agg.site, hr, k, h) for hr, k, h in agg.vis])
    con.executemany('''INSERT INTO top (site, day, kind, k, hits, bytes) VALUES (?,?,?,?,?,?)
        ON CONFLICT(site, day, kind, k) DO UPDATE SET hits=hits+excluded.hits, bytes=bytes+excluded.bytes''',
                    [(agg.site, d, kind, k, v[0], v[1]) for (d, kind, k), v in agg.top.items()])
    # countries are counted at query time from this table (one per visitor IP per day)
    rows = [(agg.site, d, ip, v[0], v[1], v[2], v[3], v[4], geo.country(ip), v[6], v[7])
            for (d, ip), v in agg.ips.items()]
    con.executemany('''INSERT INTO ips (site, day, ip, hits, pv, bytes, first, last, country, spider, s4)
        VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(site, day, ip) DO UPDATE SET hits=hits+excluded.hits,
        pv=pv+excluded.pv, bytes=bytes+excluded.bytes, first=min(first, excluded.first),
        last=max(last, excluded.last), country=excluded.country,
        spider=CASE WHEN ips.spider='' OR excluded.spider='' THEN '' ELSE excluded.spider END, s4=s4+excluded.s4''', rows)
    con.executemany('''INSERT INTO top (site, day, kind, k, hits, bytes) VALUES (?,?,?,?,?,?)
        ON CONFLICT(site, day, kind, k) DO UPDATE SET hits=hits+excluded.hits, bytes=bytes+excluded.bytes''',
                    [(agg.site, d, 'xhost', h, v[0], v[1]) for (d, h), v in agg.foreign.items()])
    con.executemany('''INSERT INTO minute (site, minute, req, bytes) VALUES (?,?,?,?)
        ON CONFLICT(site, minute) DO UPDATE SET req=req+excluded.req, bytes=bytes+excluded.bytes''',
                    [(agg.site, m, v[0], v[1]) for m, v in agg.minute.items()])


def _read(path, pos, limit):
    with open(path, 'rb') as f:
        f.seek(pos)
        data = f.read(limit)
    cut = data.rfind(b'\n')
    if cut < 0:
        return b'', pos
    return data[:cut + 1], pos + cut + 1


def collect(s=None):
    """One pass over every log. Returns {site: bytes read}. Serialised: the page's
    Refresh button and the service must never read the same log bytes twice."""
    with appkit.locked(APP, 'collect'):
        return _collect(s)


def _collect(s=None):
    s = s or store.settings()
    only = set(s['sites'])
    con = store.connect()
    done = {}
    try:
        offsets = {r[0]: (r[1], r[2]) for r in con.execute('SELECT path, inode, pos FROM offsets')}
        names = {}
        for site, path, fmt in log_sources():
            names[site] = hostguard.site_names(site) if s.get('own_domains_only', True) else set()
        for site, path, fmt in log_sources():
            if only and site not in only:
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            inode, pos = offsets.get(path, (None, None))
            if pos is None:
                pos = max(0, st.st_size - FIRST_READ_MAX)
                # start at a line boundary
                if pos:
                    with open(path, 'rb') as f:
                        f.seek(pos)
                        f.readline()
                        pos = f.tell()
            elif inode != st.st_ino or st.st_size < pos:
                # rotated: finish the rotated file (path.1) from where we were, then start the new one
                rotated = path + '.1'
                if inode is not None and os.path.exists(rotated) and os.stat(rotated).st_ino == inode:
                    data, _ = _read(rotated, pos, RUN_READ_MAX)
                    agg = Agg(site, s, names.get(site))
                    (parse_caddy if fmt == 'caddy' else parse_combined)(data, agg)
                    flush(con, agg)
                pos = 0
            data, newpos = _read(path, pos, RUN_READ_MAX)
            if data:
                agg = Agg(site, s, names.get(site))
                (parse_caddy if fmt == 'caddy' else parse_combined)(data, agg)
                flush(con, agg)
                done[site] = len(data)
            con.execute('INSERT INTO offsets (path, inode, pos) VALUES (?,?,?) ON CONFLICT(path) DO UPDATE '
                        'SET inode=excluded.inode, pos=excluded.pos', (path, st.st_ino, newpos))
            con.commit()
        store.meta_set(con, 'last_collect', int(time.time()))
        con.commit()
    finally:
        con.close()
    return done


def cleanup(s=None):
    s = s or store.settings()
    now = time.time()
    keep_from = store.day_start(now - (int(s['retention_days']) - 1) * 86400)
    keep_day = store.day_str(keep_from)
    today = store.day_str(now)
    con = store.connect()
    try:
        con.execute('DELETE FROM hourly WHERE hour < ?', (keep_from,))
        con.execute('DELETE FROM vis WHERE hour < ?', (keep_from,))
        con.execute('DELETE FROM top WHERE day < ?', (keep_day,))
        con.execute('DELETE FROM ips WHERE day < ?', (keep_day,))
        con.execute('DELETE FROM minute WHERE minute < ?', (int(now) - 3 * 3600,))
        # finished days keep only the busiest rows of each list (URLs can be endless)
        keep = int(s['top_keep'])
        for site, day, kind in con.execute('SELECT site, day, kind FROM top WHERE day < ? GROUP BY site, day, kind '
                                           'HAVING COUNT(*) > ?', (today, keep)).fetchall():
            con.execute('''DELETE FROM top WHERE site=? AND day=? AND kind=? AND k NOT IN
                (SELECT k FROM top WHERE site=? AND day=? AND kind=? ORDER BY hits DESC LIMIT ?)''',
                        (site, day, kind, site, day, kind, keep))
        for site, day in con.execute('SELECT site, day FROM ips WHERE day < ? GROUP BY site, day HAVING COUNT(*) > ?',
                                     (today, keep * 10)).fetchall():
            con.execute('''DELETE FROM ips WHERE site=? AND day=? AND ip NOT IN
                (SELECT ip FROM ips WHERE site=? AND day=? ORDER BY hits DESC LIMIT ?)''', (site, day, site, day, keep * 10))
        con.commit()
    finally:
        con.close()


def main():
    running = {'on': True}
    signal.signal(signal.SIGTERM, lambda *_: running.update(on=False))
    last_clean = 0
    flag = os.path.join(appkit.data_dir(APP), '.collect-now')
    while running['on']:
        s = store.settings()
        t0 = time.time()
        try:
            collect(s)
            try:
                os.remove(flag)          # tells a waiting Refresh request the pass is done
            except OSError:
                pass
            if t0 - last_clean > 3600:
                cleanup(s)
                last_clean = t0
                if s.get('own_domains_only', True):
                    try:
                        hostguard.apply_logging()     # websites added since the last hour
                    except Exception as e:  # noqa: BLE001
                        print(f'host logging: {e}', flush=True)
        except Exception as e:  # noqa: BLE001 - keep running, report why
            print(f'collect error: {type(e).__name__}: {e}', flush=True)
        wait = max(5, int(s['interval']) - int(time.time() - t0))
        for _ in range(wait * 2):
            if not running['on'] or os.path.exists(flag):
                break
            time.sleep(0.5)
    return 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'once':
        print(collect())
    else:
        sys.exit(main())
