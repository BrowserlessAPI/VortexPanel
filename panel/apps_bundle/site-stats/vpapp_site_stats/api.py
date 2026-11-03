"""Website Statistics API: /api/app/site-stats/..."""
import os
import re
import time

from flask import jsonify, request

from panel import appkit
from vpapp_site_stats import collector, geo, hostguard, store

APP = store.APP
SERVICE = appkit.unit_name(APP)
bp = appkit.blueprint(APP, __name__)
_SITE_RE = re.compile(r'^[a-z0-9.*_-]{1,253}$')


def _err(msg, code=400):
    return jsonify({'ok': False, 'error': msg}), code


def _site_arg():
    site = (request.args.get('site') or '').lower()
    if site and not _SITE_RE.match(site):
        return None
    return site      # '' = all sites


def _where(site):
    return ('site=?', (site,)) if site else ('1=1', ())


def _range():
    rng = request.args.get('range') or 'today'
    if rng not in ('today', 'yesterday', '7d', '30d'):
        rng = 'today'
    return (rng,) + store.range_bounds(rng)


def _totals(con, site, start, end):
    w, a = _where(site)
    r = con.execute(f'SELECT COALESCE(SUM(req),0), COALESCE(SUM(pv),0), COALESCE(SUM(bytes),0), COALESCE(SUM(spider),0), '
                    f'COALESCE(SUM(s2),0), COALESCE(SUM(s3),0), COALESCE(SUM(s4),0), COALESCE(SUM(s5),0), '
                    f'COALESCE(SUM(rt_sum),0), COALESCE(SUM(rt_n),0) FROM hourly WHERE {w} AND hour>=? AND hour<?',
                    a + (start, end)).fetchone()
    uv = con.execute(f'SELECT COUNT(*) FROM (SELECT DISTINCT site, h FROM vis WHERE {w} AND kind=0 AND hour>=? AND hour<?)',
                     a + (start, end)).fetchone()[0]
    ip = con.execute(f'SELECT COUNT(*) FROM (SELECT DISTINCT site, h FROM vis WHERE {w} AND kind=1 AND hour>=? AND hour<?)',
                     a + (start, end)).fetchone()[0]
    return {'req': r[0], 'pv': r[1], 'bytes': r[2], 'spider': r[3], 's2': r[4], 's3': r[5], 's4': r[6], 's5': r[7],
            'avg_ms': round(r[8] / r[9] * 1000, 1) if r[9] else None, 'uv': uv, 'ip': ip}


def _series(con, site, start, end, step):
    w, a = _where(site)
    rows = con.execute(f'SELECT hour, SUM(req), SUM(pv), SUM(bytes), SUM(spider), SUM(s4)+SUM(s5) FROM hourly '
                       f'WHERE {w} AND hour>=? AND hour<? GROUP BY hour', a + (start, end)).fetchall()
    uvr = con.execute(f'SELECT hour, COUNT(DISTINCT h) FROM vis WHERE {w} AND kind=0 AND hour>=? AND hour<? GROUP BY hour',
                      a + (start, end)).fetchall()
    ipr = con.execute(f'SELECT hour, COUNT(DISTINCT h) FROM vis WHERE {w} AND kind=1 AND hour>=? AND hour<? GROUP BY hour',
                      a + (start, end)).fetchall()
    by = {r[0]: r for r in rows}
    uvh, iph = dict(uvr), dict(ipr)
    out = []
    if step == 'hour':
        t = start
        while t < end:
            r = by.get(t)
            out.append({'t': t, 'label': time.strftime('%H:00', time.localtime(t)), 'req': r[1] if r else 0,
                        'pv': r[2] if r else 0, 'bytes': r[3] if r else 0, 'spider': r[4] if r else 0,
                        'err': r[5] if r else 0, 'uv': uvh.get(t, 0), 'ip': iph.get(t, 0)})
            t += 3600
        return out
    for day in store.days_between(start, end):
        d0 = store.day_start(time.mktime(time.strptime(day, '%Y-%m-%d')) + 3600)
        d1 = store.day_start(d0 + 26 * 3600)
        agg = {'req': 0, 'pv': 0, 'bytes': 0, 'spider': 0, 'err': 0}
        for t, r in by.items():
            if d0 <= t < d1:
                agg['req'] += r[1]; agg['pv'] += r[2]; agg['bytes'] += r[3]; agg['spider'] += r[4]; agg['err'] += r[5]
        uv = con.execute(f'SELECT COUNT(*) FROM (SELECT DISTINCT site, h FROM vis WHERE {w} AND kind=0 AND hour>=? AND hour<?)',
                         a + (d0, d1)).fetchone()[0]
        ip = con.execute(f'SELECT COUNT(*) FROM (SELECT DISTINCT site, h FROM vis WHERE {w} AND kind=1 AND hour>=? AND hour<?)',
                         a + (d0, d1)).fetchone()[0]
        out.append(dict(agg, t=d0, label=day[5:], uv=uv, ip=ip))
    return out


@bp.route('/sites')
def sites():
    """Every site with a log, with today's numbers (the 'Websites' table)."""
    rng, start, end, _ = _range()
    con = store.connect()
    try:
        last = int(store.meta_get(con, 'last_collect', '0') or 0)
        out = []
        for site, path, fmt in collector.log_sources():
            t = _totals(con, site, start, end)
            t.update(site=site, log=path, format=fmt)
            out.append(t)
    finally:
        con.close()
    s = store.settings()
    out.sort(key=lambda r: (-r['pv'], -r['req'], r['site']))
    return jsonify({'ok': True, 'sites': out, 'range': rng, 'last_collect': last, 'service': appkit.service_state(SERVICE),
                    'tracked': s['sites'], 'geo': geo.status(),
                    'scan_detect': os.path.isfile('/opt/vortexpanel/plugins/scan-detect/plugin.json')})


@bp.route('/summary')
def summary():
    site = _site_arg()
    if site is None:
        return _err('Bad site')
    rng, start, end, step = _range()
    cmp_ = request.args.get('compare') or ''
    con = store.connect()
    try:
        out = {'ok': True, 'site': site, 'range': rng, 'step': step,
               'totals': _totals(con, site, start, end), 'series': _series(con, site, start, end, step)}
        if cmp_ in ('prev', 'week'):
            if cmp_ == 'week' and step == 'hour':
                ps, pe = start - 7 * 86400, end - 7 * 86400
            else:
                ps, pe = store.previous_bounds(start, end)
            out['compare'] = {'totals': _totals(con, site, ps, pe), 'series': _series(con, site, ps, pe, step)}
        # live: requests per minute for the last 60 minutes
        w, a = _where(site)
        now = int(time.time())
        m0 = now - now % 60 - 59 * 60
        rows = dict(con.execute(f'SELECT minute, SUM(req) FROM minute WHERE {w} AND minute>=? GROUP BY minute', a + (m0,)).fetchall())
        out['live'] = [{'t': m0 + i * 60, 'req': rows.get(m0 + i * 60, 0)} for i in range(60)]
        last5 = sum(v for k, v in rows.items() if k >= now - now % 60 - 4 * 60)
        out['qps'] = round(last5 / 300, 2)
        out['last_collect'] = int(store.meta_get(con, 'last_collect', '0') or 0)
    finally:
        con.close()
    return jsonify(out)


@bp.route('/top')
def top():
    site = _site_arg()
    kind = request.args.get('kind') or 'url'
    if site is None or (kind not in store.TOP_KINDS and kind != 'country'):
        return _err('Bad request')
    rng, start, end, _ = _range()
    days = store.days_between(start, end)
    limit = appkit.clamp_int(request.args.get('limit'), 5, 500, 50)
    q = (request.args.get('q') or '').strip()
    w, a = _where(site)
    con = store.connect()
    try:
        ph = ','.join('?' * len(days))
        if kind == 'country':
            rows = con.execute(f'SELECT country, COUNT(*), SUM(bytes), SUM(pv) FROM ips WHERE {w} AND day IN ({ph}) '
                               f"AND spider='' GROUP BY country ORDER BY 2 DESC LIMIT ?", a + tuple(days) + (limit,)).fetchall()
            items = [{'k': r[0] or '', 'hits': r[1], 'bytes': r[2], 'pv': r[3]} for r in rows]
        else:
            extra, args = '', ()
            if q:
                extra, args = ' AND k LIKE ?', ('%' + q.replace('%', '') + '%',)
            rows = con.execute(f'SELECT k, SUM(hits), SUM(bytes) FROM top WHERE {w} AND day IN ({ph}) AND kind=?{extra} '
                               f'GROUP BY k ORDER BY 2 DESC LIMIT ?', a + tuple(days) + (kind,) + args + (limit,)).fetchall()
            items = [{'k': r[0], 'hits': r[1], 'bytes': r[2]} for r in rows]
        total = sum(i['hits'] for i in items) or 1
        for i in items:
            i['pct'] = round(i['hits'] * 100 / total, 1)
    finally:
        con.close()
    return jsonify({'ok': True, 'kind': kind, 'items': items, 'geo': geo.status() if kind == 'country' else None})


@bp.route('/visitors')
def visitors():
    site = _site_arg()
    if site is None:
        return _err('Bad site')
    rng, start, end, _ = _range()
    days = store.days_between(start, end)
    q = (request.args.get('q') or '').strip()
    kind = request.args.get('kind') or ''          # '' | people | spiders
    sort = request.args.get('sort') or 'hits'
    if sort not in ('hits', 'pv', 'bytes', 'last', 's4'):
        sort = 'hits'
    page = appkit.clamp_int(request.args.get('page'), 1, 100000, 1)
    size = appkit.clamp_int(request.args.get('size'), 10, 200, 50)
    w, a = _where(site)
    ph = ','.join('?' * len(days))
    cond, args = f'{w} AND day IN ({ph})', a + tuple(days)
    if q:
        cond += ' AND ip LIKE ?'
        args += ('%' + q.replace('%', '') + '%',)
    if kind == 'people':
        cond += " AND spider=''"
    elif kind == 'spiders':
        cond += " AND spider!=''"
    con = store.connect()
    try:
        total = con.execute(f'SELECT COUNT(DISTINCT ip) FROM ips WHERE {cond}', args).fetchone()[0]
        rows = con.execute(f'SELECT ip, SUM(hits) hits, SUM(pv) pv, SUM(bytes) bytes, MIN(first), MAX(last) last, '
                           f'MAX(country), MAX(spider), SUM(s4) s4, GROUP_CONCAT(DISTINCT site) FROM ips WHERE {cond} '
                           f'GROUP BY ip ORDER BY {sort} DESC LIMIT ? OFFSET ?', args + (size, (page - 1) * size)).fetchall()
    finally:
        con.close()
    items = [{'ip': r[0], 'hits': r[1], 'pv': r[2], 'bytes': r[3], 'first': r[4], 'last': r[5], 'country': r[6] or '',
              'spider': r[7] or '', 's4': r[8], 'sites': (r[9] or '').split(',')} for r in rows]
    return jsonify({'ok': True, 'items': items, 'total': total, 'page': page, 'size': size})


@bp.route('/errors')
def errors():
    site = _site_arg()
    if not site:
        return _err('Choose a website')
    path = collector.error_log(site)
    if not path:
        return jsonify({'ok': True, 'path': '', 'lines': [], 'groups': []})
    n = appkit.clamp_int(request.args.get('lines'), 50, 2000, 300)
    q = (request.args.get('q') or '').strip().lower()
    try:
        with open(path, 'rb') as f:
            f.seek(0, 2)
            sz = f.tell()
            f.seek(max(0, sz - 2 * 1024 * 1024))
            lines = f.read().decode('utf-8', 'replace').splitlines()[-n * 4:]
    except OSError as e:
        return _err(str(e))
    if q:
        lines = [ln for ln in lines if q in ln.lower()]
    lines = lines[-n:]
    groups = {}
    for ln in lines:
        m = re.search(r'\] \d+#\d+: (?:\*\d+ )?(.*?)(?:, client: |$)', ln) or re.search(r'\] \[[^\]]*\] (.*)$', ln)
        key = re.sub(r'\d+', 'N', (m.group(1) if m else ln)[:160])
        level = (re.search(r'\[(emerg|alert|crit|error|warn|notice|info)\]', ln) or [None, ''])[1]
        g = groups.setdefault(key, {'msg': key, 'n': 0, 'level': level, 'last': ''})
        g['n'] += 1
        g['last'] = ln[:19]
    return jsonify({'ok': True, 'path': path, 'lines': lines[::-1],
                    'groups': sorted(groups.values(), key=lambda g: -g['n'])[:50]})


@bp.route('/settings', methods=['GET', 'POST'])
def settings_route():
    if request.method == 'GET':
        return jsonify({'ok': True, 'settings': store.settings(), 'defaults': store.DEFAULTS, 'geo': geo.status(),
                        'sites': [s for s, _, _ in collector.log_sources()],
                        'db_size': os.path.getsize(store.db_path()) if os.path.exists(store.db_path()) else 0})
    old = store.settings()
    s = store.clean_settings(appkit.body())
    appkit.write_json(APP, 'settings.json', s)
    changed = ', '.join(k for k in s if s[k] != old.get(k))
    appkit.oplog(APP, 'settings', changed or 'no change')
    return jsonify({'ok': True, 'settings': s})


@bp.route('/collect', methods=['POST'])
def collect_now():
    """Ask the service for a pass now and wait briefly for it. A big log is never parsed
    inside a web request; only when the service is stopped does the request do it itself."""
    flag = os.path.join(appkit.data_dir(APP), '.collect-now')
    if appkit.service_state(appkit.unit_name(APP)) == 'active':
        open(flag, 'w').close()
        for _ in range(40):
            if not os.path.exists(flag):
                return jsonify({'ok': True, 'queued': False})
            time.sleep(0.5)
        return jsonify({'ok': True, 'queued': True})
    try:
        done = collector.collect()
    except Exception as e:  # noqa: BLE001
        return _err(f'{type(e).__name__}: {e}', 500)
    return jsonify({'ok': True, 'sites': len(done)})


@bp.route('/geo/install', methods=['POST'])
def geo_install():
    log = []
    ok, msg = geo.install(log.append)
    if ok and not geo.module_ok():
        rc, _, err = appkit.run([appkit.venv_python(), '-m', 'pip', 'install', '--quiet', '--disable-pip-version-check',
                                 'maxminddb>=2.5,<3'], timeout=300)
        if rc != 0:
            msg += '. The Python module maxminddb could not be installed: ' + err.strip()[-200:]
    appkit.oplog(APP, 'country database', msg)
    return jsonify({'ok': ok, 'message': msg, 'error': '' if ok else msg, 'log': log, 'geo': geo.status()})


@bp.route('/cleanup', methods=['POST'])
def cleanup():
    d = appkit.body()
    site = (d.get('site') or '').lower()
    if site and not _SITE_RE.match(site):
        return _err('Bad site')
    con = store.connect()
    try:
        for t in ('hourly', 'vis', 'top', 'ips', 'minute'):
            if site:
                con.execute(f'DELETE FROM {t} WHERE site=?', (site,))
            else:
                con.execute(f'DELETE FROM {t}')
        con.commit()
        con.execute('VACUUM')
    finally:
        con.close()
    appkit.oplog(APP, 'data cleanup', site or 'all websites')
    return jsonify({'ok': True})


@bp.route('/oplog')
def oplog():
    return jsonify({'ok': True, 'items': appkit.read_jsonl(APP, 'oplog.jsonl', 300)})


@bp.route('/service', methods=['POST'])
def service():
    action = appkit.body().get('action')
    if action not in ('restart', 'start', 'stop'):
        return _err('Unknown action')
    rc, _, err = appkit.run(['systemctl', action, SERVICE], timeout=60)
    appkit.oplog(APP, f'service {action}', '' if rc == 0 else err[-200:])
    return jsonify({'ok': rc == 0, 'error': err.strip()[-300:], 'service': appkit.service_state(SERVICE)})

@bp.route('/hosts')
def hosts():
    """Other domains that reached the websites, and the two controls for them."""
    site = _site_arg()
    if site is None:
        return _err('Bad request')
    rng, start, end, _ = _range()
    days = store.days_between(start, end)
    w, a = _where(site)
    con = store.connect()
    try:
        ph = ','.join('?' * len(days))
        rows = con.execute(f"SELECT k, SUM(hits), SUM(bytes) FROM top WHERE {w} AND day IN ({ph}) AND kind='xhost' "
                           f'GROUP BY k ORDER BY 2 DESC LIMIT 50', a + tuple(days)).fetchall()
    finally:
        con.close()
    return jsonify({'ok': True, 'items': [{'k': r[0], 'hits': r[1], 'bytes': r[2]} for r in rows],
                    'logging': hostguard.logging_status(), 'catchall': hostguard.catchall_status(),
                    'own_domains_only': store.settings().get('own_domains_only', True)})


@bp.route('/hosts/catchall', methods=['POST'])
def hosts_catchall():
    ok, msg = hostguard.set_catchall(bool(appkit.body().get('on')))
    return jsonify({'ok': ok, 'message': msg, 'error': '' if ok else msg, 'catchall': hostguard.catchall_status()})


@bp.route('/hosts/logging', methods=['POST'])
def hosts_logging():
    on = bool(appkit.body().get('on'))
    s = store.settings()
    s['own_domains_only'] = on
    appkit.write_json(APP, 'settings.json', s)
    ok, msg = hostguard.apply_logging() if on else (True, 'All requests in the logs are counted.')
    appkit.oplog(APP, 'own domains only', 'on' if on else 'off')
    return jsonify({'ok': ok, 'message': msg, 'error': '' if ok else msg, 'logging': hostguard.logging_status()})
