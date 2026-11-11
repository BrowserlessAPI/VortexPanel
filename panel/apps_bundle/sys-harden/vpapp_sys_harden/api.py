"""System Hardening API: /api/app/sys-harden/..."""
import os
import time

from flask import jsonify, request

from panel import appkit
from vpapp_sys_harden import audit, compliance, guard, integrity, procguard

APP = guard.APP
SERVICE = appkit.unit_name(APP)
bp = appkit.blueprint(APP, __name__)

# Never offered as a custom protected path: locking these stops the server or the panel
DENY = ('/', '/proc', '/sys', '/dev', '/run', '/tmp', '/var/tmp', '/var/log', '/var/lib', '/var/run', '/var/cache',
        '/var/spool', '/opt/vortexpanel', '/home', '/etc', '/usr', '/bin', '/sbin', '/lib', '/lib64', '/boot', '/root', '/var',
        '/opt', '/srv', '/mnt', '/media', '/snap', '/www', '/var/www')


def _err(msg, code=400):
    return jsonify({'ok': False, 'error': msg}), code


def _areas_view(cfg):
    st = appkit.read_json(APP, 'scan_state.json', {})
    lk = guard.locked()
    since = time.time() - 86400
    ev = appkit.read_jsonl(APP, 'events.jsonl', 2000, match=lambda r: r.get('t', 0) >= since)
    out = []
    for aid in guard.all_areas(cfg):
        d = guard.AREAS.get(aid) or {}
        custom = aid.startswith('custom:')
        note = ''
        if custom:
            note = next((c.get('note', '') for c in cfg['custom'] if 'custom:' + c['path'] == aid), '')
        out.append({
            'id': aid, 'label': d.get('label') or aid[7:], 'icon': d.get('icon') or 'folder', 'custom': custom, 'note': note,
            'desc': d.get('desc') or 'Your own protected path', 'paths': d.get('paths') or [aid[7:]],
            'lockable': d.get('lockable', True), 'lock_warn': d.get('lock_warn') or
            'While locked nothing can create, change or delete files here (including updates of this software).',
            'mode': guard.area_mode(aid, cfg), 'severity': d.get('severity', 'high'),
            'files': (st.get(aid) or {}).get('files', 0), 'scanned': (st.get(aid) or {}).get('t', 0),
            'locked': sum(1 for a in lk.values() if a == aid), 'events_24h': sum(1 for e in ev if e.get('area') == aid),
        })
    return out


@bp.route('/overview')
def overview():
    cfg = guard.config()
    since = time.time() - 86400
    ev24 = appkit.read_jsonl(APP, 'events.jsonl', 5000, match=lambda r: r.get('t', 0) >= since)
    ack = appkit.read_json(APP, 'ack.json', {}).get('t', 0)
    comp = appkit.read_json(APP, 'compliance.json', {})
    procs = appkit.read_json(APP, 'processes.json', {})
    return jsonify({
        'ok': True, 'service': appkit.service_state(SERVICE), 'config': cfg, 'paused': cfg['paused_until'] > time.time(),
        'areas': _areas_view(cfg),
        'events_24h': len(ev24), 'unread': sum(1 for e in appkit.read_jsonl(APP, 'events.jsonl', 5000) if e.get('t', 0) > ack),
        'by_severity': {s: sum(1 for e in ev24 if e.get('severity') == s) for s in ('critical', 'high', 'medium', 'low')},
        'recent': appkit.read_jsonl(APP, 'events.jsonl', 8),
        'score': comp.get('score'), 'score_t': comp.get('t', 0),
        'compliance_fail': sum(1 for c in comp.get('checks', []) if c.get('status') == 'fail'),
        'processes': procs.get('items', []), 'processes_t': procs.get('t', 0),
        'scan_detect': os.path.isfile('/opt/vortexpanel/plugins/scan-detect/plugin.json'),
    })


@bp.route('/area', methods=['POST'])
def set_area():
    d = appkit.body()
    aid, mode = str(d.get('id') or ''), d.get('mode')
    cfg = guard.config()
    if aid not in guard.all_areas(cfg) or mode not in guard.MODES:
        return _err('Unknown area or mode')
    lockable = guard.AREAS.get(aid, {}).get('lockable', True)
    if mode == 'lock' and not lockable:
        return _err('This area can only be monitored: locking it would stop package updates and the panel from working.')
    c = appkit.read_json(APP, 'config.json', {})
    if aid.startswith('custom:'):
        for x in c.get('custom') or []:
            if 'custom:' + x.get('path', '') == aid:
                x['mode'] = mode
    else:
        c.setdefault('modes', {})[aid] = mode
    guard.save_config(c)
    msg = ''
    if mode == 'lock' and not guard.paused():
        n, errs = guard.lock_area(aid)
        if errs:
            return jsonify({'ok': False, 'error': 'Could not lock everything: ' + '; '.join(errs)[:400]})
        msg = f'{n} file(s) and folder(s) locked'
    elif mode != 'lock':
        n, errs = guard.unlock_area(aid)
        msg = f'{n} lock(s) removed' if n else ''
    if mode != 'off' and guard.load_baseline(aid) is None:
        guard.save_baseline(aid, guard.snapshot(aid))
    appkit.oplog(APP, 'protection', f'{aid}: {mode}' + (f' ({msg})' if msg else ''))
    return jsonify({'ok': True, 'message': msg, 'areas': _areas_view(guard.config())})


@bp.route('/pause', methods=['POST'])
def pause():
    minutes = appkit.clamp_int(appkit.body().get('minutes'), 0, 1440, 0)
    guard.pause(minutes)
    if not minutes:
        guard.enforce_locks()
    appkit.oplog(APP, 'locks paused' if minutes else 'locks resumed', f'{minutes} min' if minutes else '')
    return jsonify({'ok': True, 'paused_until': guard.config()['paused_until']})


@bp.route('/rebaseline', methods=['POST'])
def rebaseline():
    aid = str(appkit.body().get('id') or '')
    cfg = guard.config()
    ids = guard.all_areas(cfg) if aid == '*' else [aid]
    for a in ids:
        if a not in guard.all_areas(cfg):
            return _err('Unknown area')
        guard.save_baseline(a, guard.snapshot(a, cfg=cfg))
    appkit.oplog(APP, 'accept current state', aid)
    return jsonify({'ok': True})


@bp.route('/scan', methods=['POST'])
def scan_now():
    open(os.path.join(appkit.data_dir(APP), '.scan-now'), 'w').close()
    return jsonify({'ok': True, 'message': 'A scan starts within a few seconds.'})


@bp.route('/integrity', methods=['GET', 'POST'])
def integrity_route():
    if request.method == 'POST':
        res = appkit.read_json(APP, 'integrity.json', {})
        if res.get('running') and time.time() - (res.get('started') or 0) < 3600:
            return jsonify({'ok': True, 'message': 'The integrity check is already running.'})
        if appkit.service_state(SERVICE) == 'active':
            open(os.path.join(appkit.data_dir(APP), '.integrity-now'), 'w').close()
        else:
            import threading
            from vpapp_sys_harden import worker
            threading.Thread(target=worker.run_integrity, daemon=True).start()
        appkit.oplog(APP, 'integrity check', 'started')
        return jsonify({'ok': True, 'message': 'The integrity check has started. It takes a few minutes.'})
    res = appkit.read_json(APP, 'integrity.json', {})
    if res.get('running') and time.time() - (res.get('started') or 0) > 3600:
        res['running'] = False          # a run that died with the service
    res['pending'] = os.path.exists(os.path.join(appkit.data_dir(APP), '.integrity-now'))
    res['sections_info'] = [{'id': i, 'label': l, 'desc': d} for i, l, d in integrity.SECTIONS]
    return jsonify(dict(res, ok=True))


@bp.route('/integrity/repair', methods=['POST'])
def integrity_repair():
    paths = [str(p) for p in (appkit.body().get('paths') or []) if isinstance(p, str)][:500]
    if not paths:
        return _err('Nothing selected')
    try:
        fixed, errors = integrity.repair_panel(paths)
    except ValueError as e:
        return _err(str(e))
    appkit.oplog(APP, 'integrity repair', f'{len(fixed)} restored or quarantined' + (f'; {len(errors)} refused' if errors else ''))
    try:
        integrity.run(only={'panel', 'apps'})
    except Exception:  # noqa: BLE001
        pass
    restart = bool(fixed)
    if restart:
        # the running panel still has the old code in memory: restart it once this reply is sent
        rc, _, _ = appkit.run(['systemd-run', '--on-active=3', '--unit', f'vp-integrity-restart-{int(time.time())}',
                               'systemctl', 'restart', 'vortexpanel'], timeout=30)
        restart = rc == 0
    return jsonify({'ok': True, 'fixed': fixed, 'errors': errors, 'restarting': restart,
                    'message': f'{len(fixed)} file(s) restored from the signed release or moved to quarantine.'
                               + (' The panel restarts in a few seconds to load the clean code.' if restart else
                                  ' Restart the panel service (systemctl restart vortexpanel) to load the clean code.'
                                  if fixed else '')})


@bp.route('/files')
def files():
    aid = request.args.get('id') or ''
    if aid not in guard.all_areas():
        return _err('Unknown area')
    q = (request.args.get('q') or '').lower()
    lk = guard.locked()
    base = guard.load_baseline(aid) or {}
    items = [{'path': p, 'size': v[0], 'mtime': v[1] // 1_000_000_000, 'mode': oct(v[2] & 0o7777), 'locked': p in lk}
             for p, v in sorted(base.items()) if not q or q in p.lower()]
    return jsonify({'ok': True, 'total': len(items), 'items': items[:500]})


@bp.route('/custom', methods=['POST', 'DELETE'])
def custom():
    d = appkit.body()
    path = os.path.normpath(str(d.get('path') or '').strip())
    c = appkit.read_json(APP, 'config.json', {})
    items = [x for x in (c.get('custom') or []) if isinstance(x, dict)]
    if request.method == 'DELETE':
        guard.unlock_area('custom:' + path)
        c['custom'] = [x for x in items if x.get('path') != path]
        guard.save_config(c)
        appkit.oplog(APP, 'custom path removed', path)
        return jsonify({'ok': True})
    if not path.startswith('/') or path in DENY or path.count('/') < 2 or '\0' in path:
        return _err('Choose a specific folder or file (for example a website\'s wp-includes folder). '
                    'Whole system folders such as /etc, /usr, /var/www or /home cannot be locked here.')
    if any(path == x or path.startswith(x + '/') for x in ('/proc', '/sys', '/dev', '/run', '/opt/vortexpanel', '/var/lib',
                                                           '/var/log', '/tmp', '/var/tmp')):
        return _err('This location is used by the system or the panel and cannot be protected.')
    if not os.path.exists(path):
        return _err('That path does not exist.')
    if any(x.get('path') == path for x in items):
        return _err('Already protected.')
    mode = d.get('mode') if d.get('mode') in ('monitor', 'lock') else 'monitor'
    items.append({'path': path, 'mode': mode, 'note': str(d.get('note') or '')[:120], 't': int(time.time())})
    if len(items) > 100:
        return _err('Up to 100 protected paths.')
    c['custom'] = items
    guard.save_config(c)
    aid = 'custom:' + path
    guard.save_baseline(aid, guard.snapshot(aid))
    if mode == 'lock' and not guard.paused():
        guard.lock_area(aid)
    appkit.oplog(APP, 'custom path added', f'{path} ({mode})')
    return jsonify({'ok': True})


@bp.route('/events')
def events():
    sev = request.args.get('severity') or ''
    area = request.args.get('area') or ''
    q = (request.args.get('q') or '').lower()
    page = appkit.clamp_int(request.args.get('page'), 1, 10000, 1)
    size = appkit.clamp_int(request.args.get('size'), 10, 200, 50)
    recs = appkit.read_jsonl(APP, 'events.jsonl', 5000, match=lambda r: (not sev or r.get('severity') == sev) and
                             (not area or r.get('area') == area) and (not q or q in (r.get('path', '') + r.get('detail', '')).lower()))
    ack = appkit.read_json(APP, 'ack.json', {}).get('t', 0)
    for r in recs:
        r['new'] = r.get('t', 0) > ack
    return jsonify({'ok': True, 'total': len(recs), 'items': recs[(page - 1) * size: page * size], 'page': page, 'size': size})


@bp.route('/events/ack', methods=['POST'])
def events_ack():
    appkit.write_json(APP, 'ack.json', {'t': int(time.time())})
    return jsonify({'ok': True})


@bp.route('/processes')
def processes():
    cfg = guard.config()
    items = procguard.scan(cfg['proc_whitelist'])
    return jsonify({'ok': True, 'items': items, 'whitelist': cfg['proc_whitelist'], 'auto_kill': cfg['auto_kill'],
                    'quarantine': sorted(os.listdir(procguard.quarantine_dir()))[-50:]})


@bp.route('/processes/kill', methods=['POST'])
def kill():
    pid = appkit.clamp_int(appkit.body().get('pid'), 2, 2 ** 22, 0)
    if not pid:
        return _err('Bad process id')
    if pid == os.getpid() or pid == os.getppid():
        return _err('That is the panel itself')
    ok, detail = procguard.kill(pid)
    appkit.oplog(APP, 'kill process', detail)
    return jsonify({'ok': ok, 'message': detail, 'error': '' if ok else detail})


@bp.route('/processes/whitelist', methods=['POST', 'DELETE'])
def proc_whitelist():
    path = str(appkit.body().get('path') or '').replace(' (deleted)', '').strip()
    if not path.startswith('/') or len(path) > 300:
        return _err('Give the program path')
    c = appkit.read_json(APP, 'config.json', {})
    wl = [p for p in (c.get('proc_whitelist') or []) if p != path]
    if request.method == 'POST':
        wl.append(path)
    c['proc_whitelist'] = wl[:200]
    guard.save_config(c)
    appkit.oplog(APP, 'process whitelist ' + ('add' if request.method == 'POST' else 'remove'), path)
    return jsonify({'ok': True, 'whitelist': wl})


@bp.route('/compliance')
def compliance_route():
    res = compliance.run_all()
    res['t'] = int(time.time())
    appkit.write_json(APP, 'compliance.json', res)
    return jsonify(dict(res, ok=True))


@bp.route('/compliance/fix', methods=['POST'])
def compliance_fix():
    cid = str(appkit.body().get('id') or '')
    ok, err = compliance.fix(cid)
    appkit.oplog(APP, 'compliance fix', f'{cid}: ' + ('done' if ok else err))
    res = compliance.run_all()
    res['t'] = int(time.time())
    appkit.write_json(APP, 'compliance.json', res)
    return jsonify(dict(res, ok=ok, error=err))


@bp.route('/audit')
def audit_route():
    kind = request.args.get('kind') or ''
    q = (request.args.get('q') or '').strip()
    evs, source = audit.events(kind, q, 500)
    return jsonify({'ok': True, 'items': evs, 'source': source})


@bp.route('/audit/summary')
def audit_summary():
    return jsonify(dict(audit.summary(), ok=True))


@bp.route('/settings', methods=['POST'])
def settings():
    d = appkit.body()
    c = appkit.read_json(APP, 'config.json', {})
    if 'scan_minutes' in d:
        c['scan_minutes'] = appkit.clamp_int(d['scan_minutes'], 1, 1440, 5)
    for k in ('notify', 'auto_kill'):
        if k in d:
            c[k] = bool(d[k])
    guard.save_config(c)
    appkit.oplog(APP, 'settings', ', '.join(f'{k}={c.get(k)}' for k in ('scan_minutes', 'notify', 'auto_kill') if k in d))
    return jsonify({'ok': True, 'config': guard.config()})


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
