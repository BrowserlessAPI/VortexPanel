"""Scan Detection API: /api/app/scan-detect/..."""
import os
import time

from flask import jsonify, request

from panel import appkit
from vpapp_scan_detect import engine

APP = engine.APP
SERVICE = appkit.unit_name(APP)
bp = appkit.blueprint(APP, __name__)


def _err(msg, code=400):
    return jsonify({'ok': False, 'error': msg}), code


def _days(n):
    out = []
    for i in range(n - 1, -1, -1):
        day = time.strftime('%Y-%m-%d', time.localtime(time.time() - i * 86400))
        st = appkit.read_json(APP, f'stats-{day}.json', {})
        out.append({'day': day, 'probes': st.get('probes', 0), 'ips': len(st.get('ips', {})),
                    'blocks': st.get('blocks', 0)})
    return out


@bp.route('/overview')
def overview():
    s = engine.settings()
    today = time.strftime('%Y-%m-%d')
    st = appkit.read_json(APP, f'stats-{today}.json', {})
    live = appkit.read_json(APP, 'live.json', {})
    act = engine.active()
    ips = st.get('ips', {})
    top = sorted(({'ip': ip, **r, 'ports_n': len(r.get('ports') or []), 'ports': (r.get('ports') or [])[:30]}
                  for ip, r in ips.items()), key=lambda r: -r['probes'])[:200]
    return jsonify({
        'ok': True, 'settings': s,
        'service': appkit.service_state(SERVICE), 'table': engine.table_exists(),
        'today': {'probes': st.get('probes', 0), 'ips': len(ips), 'blocks': st.get('blocks', 0),
                  'hourly': st.get('hourly', [0] * 24)},
        'blocked_now': len(act),
        'live': live.get('items', [])[:200], 'live_at': live.get('t', 0),
        'scanners': top, 'trend': _days(7),
        'whitelist_n': len(engine.whitelist()),
        'admin_ips': sorted(appkit.admin_ips()),
    })


@bp.route('/toggle', methods=['POST'])
def toggle():
    on = bool(appkit.body().get('enabled'))
    s = engine.settings()
    s['enabled'] = on
    engine.save_settings(s)
    ok, err = engine.apply(s)
    appkit.oplog(APP, 'enable' if on else 'disable', 'scan detection ' + ('on' if on else 'off'))
    return jsonify({'ok': ok, 'error': err, 'settings': s})


@bp.route('/settings', methods=['GET', 'POST'])
def settings_route():
    if request.method == 'GET':
        return jsonify({'ok': True, 'settings': engine.settings(), 'defaults': engine.DEFAULTS})
    old = engine.settings()
    s = engine.clean_settings(appkit.body())
    engine.save_settings(s)
    ok, err = engine.apply(s)
    if not ok:
        engine.save_settings(old)
        engine.apply(old)
        return _err('The firewall rejected the new settings (old settings kept): ' + err[-300:])
    changed = ', '.join(f'{k}={s[k]}' for k in s if s[k] != old.get(k))
    appkit.oplog(APP, 'settings', changed or 'no change')
    return jsonify({'ok': True, 'settings': s})


@bp.route('/blocks')
def blocks():
    q = (request.args.get('q') or '').strip()
    mode = request.args.get('mode') or ''
    page = appkit.clamp_int(request.args.get('page'), 1, 10000, 1)
    size = appkit.clamp_int(request.args.get('size'), 10, 200, 50)

    def m(r):
        if q and q not in r.get('ip', ''):
            return False
        if mode and r.get('mode') != mode:
            return False
        return True
    recs = appkit.read_jsonl(APP, 'blocks.jsonl', limit=20000, match=m)
    act = engine.active()
    now = int(time.time())
    for r in recs:
        r['active'] = r.get('mode') != 'unblock' and r['ip'] in act and act[r['ip']] == (r.get('until') or 0)
    kernel = {e['ip']: e['expires'] for e in engine.blocked_entries()}
    active_list = sorted(({'ip': ip, 'until': u, 'left': (u - now) if u else None, 'in_kernel': ip in kernel}
                          for ip, u in act.items()), key=lambda r: r['ip'])
    return jsonify({'ok': True, 'total': len(recs), 'items': recs[(page - 1) * size: page * size],
                    'page': page, 'size': size, 'active': active_list})


@bp.route('/block', methods=['POST'])
def block():
    d = appkit.body()
    ips = d.get('ips') if isinstance(d.get('ips'), list) else [d.get('ip')]
    minutes = appkit.clamp_int(d.get('minutes', engine.settings()['block_minutes']), 0, 525600, 1440)
    done, errors = [], []
    for ip in ips[:500]:
        ok, err = engine.block(str(ip or ''), minutes, d.get('reason') or 'blocked by admin', 'manual')
        (done if ok else errors).append(ip if ok else f'{ip}: {err}')
    if done:
        appkit.oplog(APP, 'block', f'{", ".join(map(str, done[:20]))} for ' + (f'{minutes} min' if minutes else 'ever'))
    return jsonify({'ok': bool(done) or not errors, 'blocked': done, 'errors': errors,
                    'error': '; '.join(errors[:3])})


@bp.route('/unblock', methods=['POST'])
def unblock():
    d = appkit.body()
    ips = d.get('ips') if isinstance(d.get('ips'), list) else [d.get('ip')]
    done, errors = [], []
    for ip in ips[:5000]:
        ok, err = engine.unblock(str(ip or ''))
        (done if ok else errors).append(ip if ok else f'{ip}: {err}')
    if done:
        appkit.oplog(APP, 'unblock', ', '.join(map(str, done[:20])) + (f' (+{len(done) - 20})' if len(done) > 20 else ''))
    return jsonify({'ok': not errors, 'unblocked': done, 'errors': errors, 'error': '; '.join(errors[:3])})


@bp.route('/unblock-all', methods=['POST'])
def unblock_all():
    ips = list(engine.active())
    for ip in ips:
        engine.unblock(ip)
    appkit.oplog(APP, 'unblock all', f'{len(ips)} address(es)')
    return jsonify({'ok': True, 'count': len(ips)})


@bp.route('/realtime')
def realtime():
    since = appkit.clamp_int(request.args.get('since'), 0, 2 ** 31, 0)
    q = (request.args.get('q') or '').strip()
    items = appkit.read_json(APP, 'realtime.json', {}).get('items', [])
    items = [i for i in items if i.get('t', 0) > since and (not q or q in i.get('ip', '') or q == str(i.get('port')))]
    return jsonify({'ok': True, 'items': items[-500:][::-1], 'now': int(time.time()),
                    'service': appkit.service_state(SERVICE)})


@bp.route('/oplog')
def oplog():
    return jsonify({'ok': True, 'items': appkit.read_jsonl(APP, 'oplog.jsonl', 500)})


@bp.route('/whitelist', methods=['GET', 'POST', 'DELETE'])
def whitelist_route():
    items = engine.whitelist()
    if request.method == 'GET':
        return jsonify({'ok': True, 'items': items, 'admin_ips': sorted(appkit.admin_ips())})
    d = appkit.body()
    if request.method == 'DELETE':
        ip = appkit.parse_ip(d.get('ip'))
        items = [w for w in items if w.get('ip') != ip]
        engine.save_whitelist(items)
        engine.sync_allow()
        appkit.oplog(APP, 'whitelist remove', ip or '')
        return jsonify({'ok': True, 'items': items})
    raw = d.get('ip') or ''
    added, bad = [], []
    for tok in str(raw).replace(',', '\n').split():
        ip = appkit.parse_ip(tok)
        if not ip:
            bad.append(tok)
            continue
        if any(w.get('ip') == ip for w in items):
            continue
        items.append({'ip': ip, 'note': str(d.get('note') or '')[:120], 't': int(time.time())})
        added.append(ip)
    if bad:
        return _err('Not an IP address or network: ' + ', '.join(bad[:5]))
    if len(items) > 2000:
        return _err('The whitelist is limited to 2000 entries')
    engine.save_whitelist(items)
    engine.sync_allow()
    # anything now whitelisted must not stay blocked
    for ip in list(engine.active()):
        if appkit.ip_in(ip, added):
            engine.unblock(ip)
    appkit.oplog(APP, 'whitelist add', ', '.join(added))
    return jsonify({'ok': True, 'items': items, 'added': added})


@bp.route('/cleanup', methods=['POST'])
def cleanup():
    d = appkit.body()
    what = d.get('what') or 'history'
    days = appkit.clamp_int(d.get('older_than'), 0, 365, 0)
    cutoff = time.time() - days * 86400
    dd = appkit.data_dir(APP)
    removed = 0
    today = time.strftime('%Y-%m-%d')
    if what in ('history', 'all'):
        for fn in os.listdir(dd):
            if fn.startswith('stats-') and fn.endswith('.json'):
                try:
                    t = time.mktime(time.strptime(fn[6:16], '%Y-%m-%d'))
                except ValueError:
                    continue
                if (days == 0 and fn[6:16] != today) or (days and t < cutoff):
                    os.remove(os.path.join(dd, fn))
                    removed += 1
    if what in ('records', 'all'):
        path = os.path.join(dd, 'blocks.jsonl')
        if days == 0:
            with appkit.locked(APP, 'blocks.jsonl'):
                open(path, 'w').close()
        else:
            with appkit.locked(APP, 'blocks.jsonl'):
                recs = appkit.read_jsonl(APP, 'blocks.jsonl', 50000, newest_first=False)
                keep = [r for r in recs if r.get('t', 0) >= cutoff]
                with open(path, 'w') as f:
                    for r in keep:
                        f.write(__import__('json').dumps(r) + '\n')
            removed += len(recs) - len(keep)
    if what in ('realtime', 'all'):
        appkit.write_json(APP, 'realtime.json', {'items': []})
        open(os.path.join(dd, '.clear-realtime'), 'w').close()   # the service drops its copy too
    appkit.oplog(APP, 'data cleanup', f'{what}, older than {days} day(s)' if days else what)
    return jsonify({'ok': True, 'removed': removed})


@bp.route('/service', methods=['POST'])
def service():
    action = appkit.body().get('action')
    if action not in ('restart', 'start', 'stop'):
        return _err('Unknown action')
    rc, _, err = appkit.run(['systemctl', action, SERVICE], timeout=60)
    appkit.oplog(APP, f'service {action}', '' if rc == 0 else err[-200:])
    return jsonify({'ok': rc == 0, 'error': err.strip()[-300:], 'service': appkit.service_state(SERVICE)})
