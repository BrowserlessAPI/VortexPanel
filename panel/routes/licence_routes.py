"""Hosting Module page: licence status, buying, activating, installing the module."""
import re
import time

from flask import Blueprint, jsonify, request

from panel import licence, module_install
from panel.utils.authctx import authed, is_admin

licence_bp = Blueprint('licence', __name__)
EMAIL_RE = re.compile(r"^[^@\s\"'<>]+@[^@\s\"'<>]+\.[A-Za-z]{2,}$")
_plans_cache = {'at': 0, 'data': None, 'error': ''}


def _guard():
    if not authed():
        return jsonify({'ok': False}), 401
    if not is_admin():
        return jsonify({'ok': False, 'error': 'Administrators only'}), 403
    return None


def _err(e):
    return jsonify({'ok': False, 'error': str(e), 'code': getattr(e, 'code', 'error')}), getattr(e, 'status', 400)


def _plans(force=False):
    if force or time.time() - _plans_cache['at'] > 600 or _plans_cache['data'] is None:
        try:
            _plans_cache.update(data=licence.plans(), error='', at=time.time())
        except licence.LicenceError as e:
            _plans_cache.update(error=str(e), at=time.time() - 540)   # retry after a minute
    return _plans_cache['data'], _plans_cache['error']


def _auto_link():
    """No licence here yet: ask for the one linked to this server's IP (throttled in licence.link).
    Installs the module when a licence arrives and the module is not installed."""
    cur = licence.current()
    co = cur.get('checkout') or {}
    if cur['licensed'] or (co and co.get('status') not in ('failed', 'cancelled', 'refunded')):
        return None
    try:
        payload = licence.link()
    except licence.LicenceError:
        return None
    if payload and payload.get('valid') and not licence.installed_module_version() and not module_install.running():
        module_install.start()
    return payload


def _status(with_plans=True):
    if with_plans:
        # opening the page checks in when the last answer is a few minutes old, so a licence that
        # was revoked, refunded, renewed or ended on the licence server shows its real state
        licence.refresh_stale(licence.STALE_VIEW)
    linked = _auto_link() if with_plans else None
    cur = licence.current()
    out = {'ok': True, 'licence': cur, 'installed_version': licence.installed_module_version(), 'linked_now': bool(linked),
           'install': module_install.progress(), 'install_running': module_install.running(),
           'server': licence.trust()['server'], 'server_id': licence.identity()['server_id']}
    try:
        from panel import plugins
        e = plugins.REGISTRY.get('hosting') or {}
        out['plugin_status'] = e.get('status') or ''
        out['plugin_error'] = e.get('error') or ''
    except Exception:  # noqa: BLE001
        pass
    if with_plans:
        data, error = _plans()
        out['plans'] = (data or {}).get('plans') or []
        out['features'] = (data or {}).get('features') or []
        out['links'] = (data or {}).get('links') or {}
        out['selling'] = bool((data or {}).get('selling'))
        out['offer'] = (data or {}).get('offer') or {}
        out['module_latest'] = cur.get('module_latest') or (data or {}).get('module_latest') or ''
        out['plans_error'] = error
        for k in ('refund_days', 'support_email', 'refund_email', 'currency'):
            out[k] = (data or {}).get(k)
        try:
            import subprocess
            out['virt'] = subprocess.run(['systemd-detect-virt'], capture_output=True, text=True, timeout=5).stdout.strip()
        except Exception:  # noqa: BLE001
            out['virt'] = ''
    return out


@licence_bp.route('/api/licence/status')
def status():
    g = _guard()
    if g:
        return g
    return jsonify(_status())


@licence_bp.route('/api/licence/order', methods=['POST'])
def order():
    """New licences (this server plus optional other servers' IPs) or a renewal of this server's."""
    g = _guard()
    if g:
        return g
    d = request.get_json(silent=True) or {}
    kind = 'renew' if d.get('kind') == 'renew' else 'new'
    email = str(d.get('email') or '').strip()
    if kind == 'new' and not EMAIL_RE.match(email):
        return jsonify({'ok': False, 'error': 'Enter a valid email address.'}), 400
    try:
        months = int(d.get('months') or 0)
        quantity = int(d.get('quantity') or 1)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Choose the length and the number of servers.'}), 400
    ips = [str(x).strip()[:64] for x in (d.get('ips') or []) if isinstance(x, str)][:500]
    try:
        data = licence.order(email, months, quantity, ips, kind)
    except licence.LicenceError as e:
        return _err(e)
    return jsonify({'ok': True, 'approve_url': data['approve_url'], 'total': data.get('total'),
                    'currency': data.get('currency')})


@licence_bp.route('/api/licence/checkout/cancel', methods=['POST'])
def checkout_cancel():
    g = _guard()
    if g:
        return g
    licence.cancel_checkout()
    return jsonify({'ok': True})


@licence_bp.route('/api/licence/claim', methods=['POST'])
def claim():
    """Polled by the page while a checkout is open. Installs the module once paid."""
    g = _guard()
    if g:
        return g
    try:
        r = licence.claim()
    except licence.LicenceError as e:
        return _err(e)
    if r.get('paid') and r.get('bound') and not licence.installed_module_version() and not module_install.running():
        ok, msg = module_install.start()
        r['install_started'] = ok
        r['install_message'] = msg
    return jsonify(dict(r, ok=True))


@licence_bp.route('/api/licence/activate', methods=['POST'])
def activate():
    g = _guard()
    if g:
        return g
    d = request.get_json(silent=True) or {}
    try:
        licence.activate(d.get('key'), bool(d.get('move')))
    except licence.LicenceError as e:
        return _err(e)
    out = _status(with_plans=False)
    if out['licence']['licensed'] and not out['installed_version']:
        ok, msg = module_install.start()
        out.update(install_started=ok, install_message=msg)
    return jsonify(out)


@licence_bp.route('/api/licence/check', methods=['POST'])
def check():
    g = _guard()
    if g:
        return g
    try:
        checked = licence.check()
    except licence.LicenceError as e:
        if e.code not in ('wrong_ip', 'not_bound', 'bound_elsewhere', 'identity', 'not_found'):
            return _err(e)
        checked = None
        try:
            checked = licence.link(force=True)      # the licence for this server's IP, if there is one
        except licence.LicenceError:
            pass
        if not checked:
            return _err(e)
    if checked is None:
        try:
            licence.link(force=True)
        except licence.LicenceError as e:
            return _err(e)
    _plans(force=True)
    out = _status()
    if out['licence']['licensed'] and not out['installed_version'] and not module_install.running():
        ok, msg = module_install.start()
        out.update(install_started=ok, install_message=msg)
    return jsonify(out)


@licence_bp.route('/api/licence/install', methods=['POST'])
def install():
    g = _guard()
    if g:
        return g
    if not licence.current()['licensed']:
        return jsonify({'ok': False, 'error': 'An active licence is needed to download the Hosting Module.'}), 403
    ok, msg = module_install.start()
    return (jsonify({'ok': True, 'message': msg}) if ok else (jsonify({'ok': False, 'error': msg}), 409))


@licence_bp.route('/api/licence/deactivate', methods=['POST'])
def deactivate():
    g = _guard()
    if g:
        return g
    try:
        licence.deactivate()
    except licence.LicenceError as e:
        return _err(e)
    return jsonify(_status(with_plans=False))
