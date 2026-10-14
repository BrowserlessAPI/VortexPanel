"""Monitoring history charts and alert settings."""
from flask import Blueprint, jsonify, request

from panel import alerts, metrics
from panel.routes.auth import require_admin, check_ip_and_session, audit_event

alerts_bp = Blueprint('alerts', __name__)


@alerts_bp.route('/api/monitoring/history')
def monitoring_history():
    if not check_ip_and_session():
        return jsonify({'ok': False}), 401
    rng = request.args.get('range', '1h')
    if rng not in metrics.RANGES:
        return jsonify({'ok': False, 'error': 'Unknown range'}), 400
    try:
        from panel.tasks import timer_status
        active = timer_status().get('vortexpanel-metrics', {}).get('active', False)
    except Exception:
        active = False
    return jsonify({'ok': True, 'range': rng, 'points': metrics.history(rng), 'collector_active': active})


@alerts_bp.route('/api/alerts')
def get_alerts():
    e = require_admin()
    if e:
        return e
    return jsonify({'ok': True, 'settings': alerts.public(alerts.load()), 'history': alerts.history(50)})


@alerts_bp.route('/api/alerts/history')
def get_history():
    if not check_ip_and_session():
        return jsonify({'ok': False}), 401
    return jsonify({'ok': True, 'history': alerts.history(200)})


def _validate(cfg):
    r = cfg['rules']
    for k in ('cpu', 'mem', 'disk'):
        t = float(r[k].get('threshold', 90))
        if not 10 <= t <= 100:
            return f'{k} threshold must be 10-100%'
        r[k]['threshold'] = t
    for k in ('cpu', 'mem'):
        r[k]['minutes'] = max(1, min(60, int(r[k].get('minutes', 5))))
    r['ssl']['days'] = max(1, min(60, int(r['ssl'].get('days', 14))))
    r['logins']['failures'] = max(3, min(1000, int(r['logins'].get('failures', 20))))
    r['logins']['minutes'] = max(1, min(1440, int(r['logins'].get('minutes', 10))))
    r['sites']['timeout'] = max(3, min(60, int(r['sites'].get('timeout', 10))))
    cfg['repeat_minutes'] = max(10, min(10080, int(cfg.get('repeat_minutes', 180))))
    em = cfg['channels']['email']
    em['port'] = int(em.get('port') or 587)
    if em.get('security') not in ('starttls', 'ssl', 'none'):
        return 'Email security must be starttls, ssl or none'
    if cfg['channels']['webhook'].get('format') not in ('json', 'slack', 'discord'):
        return 'Webhook format must be json, slack or discord'
    return ''


@alerts_bp.route('/api/alerts', methods=['PUT'])
def save_alerts():
    e = require_admin()
    if e:
        return e
    try:
        cfg = alerts.update_from(alerts.load(), request.get_json(silent=True) or {})
        err = _validate(cfg)
    except (TypeError, ValueError, KeyError) as ex:
        err = f'Invalid value: {ex}'
    if err:
        return jsonify({'ok': False, 'error': err}), 400
    alerts.save(cfg)
    audit_event('alert settings saved')
    return jsonify({'ok': True, 'settings': alerts.public(cfg)})


@alerts_bp.route('/api/alerts/test', methods=['POST'])
def test_alert():
    e = require_admin()
    if e:
        return e
    ch = (request.get_json(silent=True) or {}).get('channel')
    if ch not in ('email', 'telegram', 'webhook'):
        return jsonify({'ok': False, 'error': 'Unknown channel'}), 400
    host = alerts.server_name()
    res = alerts.send(f'[{host}] Test alert from VortexPanel',
                      'Alerts from this server reach you here. No action is needed.',
                      only=ch, event={'event': 'test', 'server': host})
    err = res.get(ch, 'not sent')
    return jsonify({'ok': not err, 'error': err})
