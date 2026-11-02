"""PHP Security API: /api/app/php-guard/..."""
import os
import time

from flask import jsonify, request

from panel import appkit
from vpapp_php_guard import engine, rules as R

APP = engine.APP
bp = appkit.blueprint(APP, __name__)


def _err(msg, code=400):
    return jsonify({'ok': False, 'error': msg}), code


def _rules_view(s):
    return [{'id': r[0], 'title': r[1], 'desc': r[2], 'group': r[3], 'default': r[4], 'note': r[5],
             'can_log': r[6], 'mode': s['modes'].get(r[0], r[4])} for r in R.RULES]


@bp.route('/overview')
def overview():
    s = engine.settings()
    evs = engine.read_events(5000)
    day = time.time() - 86400
    ev24 = [e for e in evs if e['t'] >= day]
    hours = [0] * 24
    now = int(time.time())
    for e in ev24:
        idx = 23 - int((now - e['t']) // 3600)
        if 0 <= idx < 24:
            hours[idx] += 1
    by_feature, by_file = {}, {}
    for e in ev24:
        k = e.get('rule') or e['feature']
        by_feature[k] = by_feature.get(k, 0) + 1
        if e['file']:
            by_file[e['file']] = by_file.get(e['file'], 0) + 1
    return jsonify({
        'ok': True, 'versions': engine.all_status(), 'rules': _rules_view(s), 'trusted': s['trusted'],
        'blocked_24h': sum(1 for e in ev24 if e['action'] == 'drop'), 'logged_24h': sum(1 for e in ev24 if e['action'] != 'drop'),
        'hours': hours, 'recent': evs[:8],
        'top_reasons': sorted(({'k': k, 'n': v} for k, v in by_feature.items()), key=lambda r: -r['n'])[:8],
        'top_files': sorted(({'k': k, 'n': v} for k, v in by_file.items()), key=lambda r: -r['n'])[:8],
        'build': engine.build_progress(), 'build_running': engine.build_running(),
        'engine': {'name': 'Snuffleupagus', 'version': engine.SRC_TAG},
    })


@bp.route('/rules', methods=['POST'])
def set_rules():
    d = appkit.body()
    s = engine.settings()
    old = dict(s['modes'])
    for k, v in (d.get('modes') or {}).items():
        if k in R.RULE_IDS and v in ('block', 'log', 'off'):
            s['modes'][k] = v
    engine.save_settings(s)
    ok, err = engine.apply_rules(s)
    if not ok:
        s['modes'] = old
        engine.save_settings(s)
        return _err(err)
    changed = ', '.join(f'{k}={v}' for k, v in s['modes'].items() if old.get(k) != v)
    appkit.oplog(APP, 'rules', changed or 'no change')
    return jsonify({'ok': True, 'rules': _rules_view(s)})


@bp.route('/preset', methods=['POST'])
def preset():
    name = appkit.body().get('name')
    s = engine.settings()
    if name == 'recommended':
        s['modes'] = dict(R.DEFAULT_MODES)
    elif name == 'strict':
        s['modes'] = {k: ('off' if k == 'mail_params' else 'block') for k in R.RULE_IDS}
    elif name == 'test':
        s['modes'] = {k: ('log' if v == 'block' and dict((r[0], r[6]) for r in R.RULES)[k] else v)
                      for k, v in R.DEFAULT_MODES.items()}
    else:
        return _err('Unknown preset')
    engine.save_settings(s)
    ok, err = engine.apply_rules(s)
    appkit.oplog(APP, 'preset', name + ('' if ok else ' (failed: ' + err[:200] + ')'))
    return jsonify({'ok': ok, 'error': err, 'rules': _rules_view(s)})


@bp.route('/trusted', methods=['POST', 'DELETE'])
def trusted():
    d = appkit.body()
    path = os.path.normpath(str(d.get('path') or '').strip()) if d.get('path') else ''
    s = engine.settings()
    if request.method == 'DELETE':
        s['trusted'] = [t for t in s['trusted'] if t != path]
    else:
        if not path.startswith('/') or path.count('/') < 2 or any(c in path for c in '"\n\r\\'):
            return _err('Give a folder such as /var/www/example.com/wp-content/plugins/backup-plugin')
        if not os.path.isdir(path):
            return _err('That folder does not exist')
        if path not in s['trusted']:
            s['trusted'].append(path)
    engine.save_settings(s)
    ok, err = engine.apply_rules(s)
    if not ok:
        return _err(err)
    appkit.oplog(APP, 'trusted folder ' + ('removed' if request.method == 'DELETE' else 'added'), path)
    return jsonify({'ok': True, 'trusted': s['trusted']})


@bp.route('/version/<ver>/<action>', methods=['POST'])
def version_action(ver, action):
    if action not in ('build', 'enable', 'disable') or not engine._php().valid_php_ver(ver):
        return _err('Bad request')
    if action == 'build':
        ok, msg = engine.start_build(ver, enable=bool(appkit.body().get('enable', True)))
        if ok:
            appkit.oplog(APP, 'build started', f'PHP {ver}')
        return jsonify({'ok': ok, 'error': '' if ok else msg})
    ok, msg = engine.enable(ver) if action == 'enable' else engine.disable(ver)
    appkit.oplog(APP, f'PHP {ver} {action}', 'ok' if ok else msg[:200])
    return jsonify({'ok': ok, 'error': '' if ok else msg, 'versions': engine.all_status()})


@bp.route('/build')
def build_status():
    return jsonify({'ok': True, 'build': engine.build_progress(), 'running': engine.build_running()})


@bp.route('/events')
def events():
    q = (request.args.get('q') or '').strip().lower()
    action = request.args.get('action') or ''
    page = appkit.clamp_int(request.args.get('page'), 1, 10000, 1)
    size = appkit.clamp_int(request.args.get('size'), 10, 200, 50)
    evs = [e for e in engine.read_events(5000) if (not action or (e['action'] == 'drop') == (action == 'drop'))
           and (not q or q in (e['msg'] + ' ' + e['file'] + ' ' + e['ip']).lower())]
    return jsonify({'ok': True, 'total': len(evs), 'items': evs[(page - 1) * size: page * size], 'page': page, 'size': size})


@bp.route('/rules-file')
def rules_file():
    s = engine.settings()
    return jsonify({'ok': True, 'path': engine.RULES_FILE, 'text': R.build(s['modes'], s['trusted'])})


@bp.route('/oplog')
def oplog():
    return jsonify({'ok': True, 'items': appkit.read_jsonl(APP, 'oplog.jsonl', 300)})
