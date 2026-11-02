"""Network Threat Detection API: /api/app/net-threat/..."""
import os
import time

from flask import jsonify, request

from panel import appkit
from vpapp_net_threat import engine as E, suricata

APP = E.APP
SERVICE = appkit.unit_name(APP)
bp = appkit.blueprint(APP, __name__)


def _err(msg, code=400):
    return jsonify({'ok': False, 'error': msg}), code


def _lists_view(s):
    upd = appkit.read_json(APP, 'update.json', {})
    out = []
    for x in E.LISTS:
        d = E.load_list(x[0])
        out.append({'id': x[0], 'name': x[1], 'category': x[2], 'risk': x[3], 'direction': x[4], 'default': x[5],
                    'desc': x[7], 'mode': s['modes'].get(x[0], 'off'), 'entries': len(d.get('v4') or []) + len(d.get('v6') or []),
                    'updated': d.get('t', 0)})
    return out, upd


@bp.route('/overview')
def overview():
    s = E.settings()
    today = time.strftime('%Y-%m-%d')
    st = appkit.read_json(APP, f'stats-{today}.json', {})
    lists, upd = _lists_view(s)
    names = {x[0]: x for x in E.LISTS}
    ips = st.get('ips', {})
    threats = sorted(({'ip': ip, **r, 'name': names.get(r['list'], ('', '?'))[1], 'category': names.get(r['list'], ('', '', '?'))[2],
                       'risk': names.get(r['list'], ('',) * 4)[3] or 'low', 'direction': names.get(r['list'], ('',) * 5)[4] or 'in'}
                      for ip, r in ips.items()), key=lambda r: (E.RISK_ORDER.get(r['risk'], 9), -r['packets']))
    by_risk = {k: 0 for k in E.RISK_ORDER}
    for t in threats:
        by_risk[t['risk']] = by_risk.get(t['risk'], 0) + 1
    trend = []
    for i in range(6, -1, -1):
        day = time.strftime('%Y-%m-%d', time.localtime(time.time() - i * 86400))
        d = appkit.read_json(APP, f'stats-{day}.json', {})
        trend.append({'day': day, 'hits': d.get('hits', 0), 'ips': len(d.get('ips', {}))})
    return jsonify({'ok': True, 'settings': s, 'service': appkit.service_state(SERVICE), 'table': E.table_exists(),
                    'today': {'hits': st.get('hits', 0), 'hourly': st.get('hourly', [0] * 24), 'ips': len(ips),
                              'by_list': st.get('by_list', {})},
                    'by_risk': by_risk, 'outbound': [t for t in threats if t['direction'] == 'out'][:50],
                    'threats': threats[:300], 'lists': lists, 'update': upd, 'trend': trend,
                    'whitelist_n': len(E.whitelist()),
                    'protected_entries': sum(l['entries'] for l in lists if l['mode'] != 'off'),
                    'scan_detect': os.path.isfile('/opt/vortexpanel/plugins/scan-detect/plugin.json')})


@bp.route('/toggle', methods=['POST'])
def toggle():
    s = E.settings()
    s['enabled'] = bool(appkit.body().get('enabled'))
    E.save_settings(s)
    ok, err = E.apply(s)
    appkit.oplog(APP, 'enable' if s['enabled'] else 'disable', '')
    return jsonify({'ok': ok, 'error': err})


@bp.route('/list', methods=['POST'])
def set_list():
    d = appkit.body()
    lid, mode = d.get('id'), d.get('mode')
    if lid not in E.LIST_BY_ID or mode not in ('off', 'monitor', 'block'):
        return _err('Unknown list or mode')
    s = E.settings()
    old = s['modes'].get(lid)
    s['modes'][lid] = mode
    if mode != 'off' and not E.load_list(lid):
        ok, msg = E.download(lid)
        if not ok:
            return _err(msg)
    E.save_settings(s)
    ok, err = E.apply(s)
    if not ok:
        s['modes'][lid] = old
        E.save_settings(s)
        E.apply(s)
        return _err('The firewall rejected the change: ' + err[-300:])
    appkit.oplog(APP, 'list', f'{lid}: {mode}')
    return jsonify({'ok': True, 'lists': _lists_view(s)[0]})


@bp.route('/update', methods=['POST'])
def update_now():
    msgs = E.update_all()
    ok, err = E.apply()
    appkit.oplog(APP, 'lists updated', '; '.join(m for _, m in msgs)[:400])
    return jsonify({'ok': ok and all(x for x, _ in msgs), 'results': [{'ok': x, 'msg': m} for x, m in msgs],
                    'error': err or '; '.join(m for x, m in msgs if not x)})


@bp.route('/events')
def events():
    q = (request.args.get('q') or '').strip()
    risk = request.args.get('risk') or ''
    direction = request.args.get('direction') or ''
    page = appkit.clamp_int(request.args.get('page'), 1, 10000, 1)
    size = appkit.clamp_int(request.args.get('size'), 10, 200, 50)
    recs = appkit.read_jsonl(APP, 'events.jsonl', 20000, match=lambda r: (not q or q in r.get('ip', '')) and
                             (not risk or r.get('risk') == risk) and (not direction or r.get('direction') == direction))
    return jsonify({'ok': True, 'total': len(recs), 'items': recs[(page - 1) * size: page * size], 'page': page, 'size': size})


@bp.route('/lookup')
def lookup():
    ip = appkit.parse_ip(request.args.get('ip'))
    if not ip or '/' in ip:
        return _err('Enter an IP address')
    import ipaddress
    a = ipaddress.ip_address(ip)
    found = []
    for x in E.LISTS:
        d = E.load_list(x[0])
        for n in (d.get('v4') or []) + (d.get('v6') or []):
            net = ipaddress.ip_network(n)
            if net.version == a.version and a in net:
                found.append({'list': x[1], 'category': x[2], 'risk': x[3], 'network': n})
                break
    hist = appkit.read_jsonl(APP, 'events.jsonl', 50, match=lambda r: r.get('ip') == ip)
    return jsonify({'ok': True, 'ip': ip, 'lists': found, 'events': hist,
                    'whitelisted': appkit.ip_in(ip, [w['ip'] for w in E.whitelist()])})


@bp.route('/whitelist', methods=['GET', 'POST', 'DELETE'])
def whitelist_route():
    items = E.whitelist()
    if request.method == 'GET':
        return jsonify({'ok': True, 'items': items})
    d = appkit.body()
    if request.method == 'DELETE':
        ip = appkit.parse_ip(d.get('ip'))
        items = [w for w in items if w.get('ip') != ip]
    else:
        added = []
        for tok in str(d.get('ip') or '').replace(',', '\n').split():
            ip = appkit.parse_ip(tok)
            if not ip:
                return _err(f'Not an IP address or network: {tok}')
            if not any(w['ip'] == ip for w in items):
                items.append({'ip': ip, 'note': str(d.get('note') or '')[:120], 't': int(time.time())})
                added.append(ip)
    E.save_whitelist(items[:2000])
    E.apply()
    appkit.oplog(APP, 'whitelist ' + ('remove' if request.method == 'DELETE' else 'add'), str(d.get('ip'))[:200])
    return jsonify({'ok': True, 'items': items})


@bp.route('/settings', methods=['POST'])
def settings_route():
    d = appkit.body()
    s = E.settings()
    raw = appkit.read_json(APP, 'settings.json', {})
    raw['modes'] = s['modes']
    raw['enabled'] = s['enabled']
    if 'update_hours' in d:
        raw['update_hours'] = appkit.clamp_int(d['update_hours'], 1, 168, 6)
    if 'retention_days' in d:
        raw['retention_days'] = appkit.clamp_int(d['retention_days'], 1, 365, 30)
    if 'notify' in d:
        raw['notify'] = bool(d['notify'])
    E.save_settings(raw)
    appkit.oplog(APP, 'settings', ', '.join(f'{k}={raw.get(k)}' for k in ('update_hours', 'retention_days', 'notify')))
    return jsonify({'ok': True, 'settings': E.settings()})


@bp.route('/ids')
def ids_status():
    return jsonify(dict(suricata.status(), ok=True))


@bp.route('/ids/alerts')
def ids_alerts():
    return jsonify({'ok': True, 'items': suricata.alerts(500, (request.args.get('q') or '').strip())})


@bp.route('/ids/<action>', methods=['POST'])
def ids_action(action):
    if action == 'install':
        ok, msg = suricata.start_install()
    elif action == 'update-rules':
        ok, msg = suricata.update_rules()
    elif action in ('start', 'stop', 'restart'):
        rc, _, err = appkit.run(['systemctl', action, 'suricata'], timeout=120)
        ok, msg = rc == 0, err.strip()
    else:
        return _err('Unknown action')
    appkit.oplog(APP, f'suricata {action}', 'ok' if ok else msg[:200])
    return jsonify({'ok': ok, 'error': '' if ok else msg})


@bp.route('/oplog')
def oplog():
    return jsonify({'ok': True, 'items': appkit.read_jsonl(APP, 'oplog.jsonl', 300)})


@bp.route('/service', methods=['POST'])
def service():
    action = appkit.body().get('action')
    if action not in ('restart', 'start', 'stop'):
        return _err('Unknown action')
    rc, _, err = appkit.run(['systemctl', action, SERVICE], timeout=60)
    return jsonify({'ok': rc == 0, 'error': err.strip()[-300:], 'service': appkit.service_state(SERVICE)})
