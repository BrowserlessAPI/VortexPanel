"""Website SSL: provider accounts and business certificate orders (see panel/ssl_orders.py).

VortexPanel has no direct or indirect relation with the buying or selling of SSL
certificates: orders are placed with the customer's own provider account and paid
there.
"""
import re

from flask import Blueprint, jsonify, request

from panel import ssl_accounts as A
from panel import ssl_orders as O
from panel.utils.authctx import authed as _vp_authed

ssl_business_bp = Blueprint('ssl_business', __name__)

DISCLAIMER = ('VortexPanel has no direct or indirect relation with the buying or selling of SSL certificates. '
              'Orders, payments, refunds and support are between you and the certificate provider.')
_KEY = re.compile(r'[A-Za-z0-9_\-=]{3,200}')
_EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')

# ZeroSSL paid certificates (one product list for every account; the plan decides what is allowed)
ZEROSSL_PRODUCTS = [
    {'id': 'zerossl-annual', 'name': 'ZeroSSL annual', 'brand': 'ZeroSSL', 'level': 'DV', 'wildcard': True, 'years': [1]},
]


def req():
    return _vp_authed()


def _site(domain):
    from panel.routes.websites_core import is_valid_domain, _find_site_config
    if not is_valid_domain(domain):
        return None, 'Invalid domain'
    fp, ws = _find_site_config(domain)
    if not fp:
        return None, 'Website not found'
    if ws not in ('nginx', 'apache'):
        return None, f'Business certificates are installed automatically on nginx and Apache websites ({domain} is served by {ws}).'
    return ws, ''


@ssl_business_bp.route('/api/ssl/accounts')
def accounts():
    if not req(): return jsonify({'ok': False}), 401
    return jsonify({'ok': True, 'accounts': {n: A.public(n) for n in ('zerossl', 'digicert')},
                    'disclaimer': DISCLAIMER})


@ssl_business_bp.route('/api/ssl/accounts/<name>', methods=['POST', 'DELETE'])
def account_save(name):
    if not req(): return jsonify({'ok': False}), 401
    if name not in ('zerossl', 'digicert'):
        return jsonify({'ok': False, 'error': 'Unknown provider'}), 400
    if request.method == 'DELETE':
        A.delete(name)
        return jsonify({'ok': True})
    d = request.get_json() or {}
    acct = A.get(name)
    api_key = str(d.get('api_key') or '').strip()
    if api_key and not _KEY.fullmatch(api_key):
        return jsonify({'ok': False, 'error': 'The API key contains characters that are not allowed'}), 400
    if name == 'zerossl':
        email = str(d.get('email') or '').strip()
        if email and not _EMAIL.fullmatch(email):
            return jsonify({'ok': False, 'error': 'Enter a valid e-mail address'}), 400
        for k in ('eab_kid', 'eab_hmac'):
            v = str(d.get(k) or '').strip()
            if v and not _KEY.fullmatch(v):
                return jsonify({'ok': False, 'error': 'The EAB keys contain characters that are not allowed'}), 400
            if v:
                acct[k] = v
        if email:
            acct['email'] = email
    if api_key:
        try:
            info = O.zerossl_verify_key(api_key) if name == 'zerossl' else O.digicert_verify_key(api_key)
        except O.ApiError as e:
            return jsonify({'ok': False, 'error': f'The key was not accepted: {e}'}), 400
        acct['api_key'] = api_key
        acct['account_name'] = info.get('name', '')
    A.save(name, acct)
    return jsonify({'ok': True, 'account': A.public(name)})


@ssl_business_bp.route('/api/ssl/business/catalog')
def catalog():
    if not req(): return jsonify({'ok': False}), 401
    provider = request.args.get('provider', '')
    key = A.get(provider).get('api_key') if provider in ('zerossl', 'digicert') else ''
    if not key:
        return jsonify({'ok': True, 'connected': False, 'products': [], 'organizations': []})
    if provider == 'zerossl':
        return jsonify({'ok': True, 'connected': True, 'products': ZEROSSL_PRODUCTS, 'organizations': [], 'balance': ''})
    try:
        return jsonify({'ok': True, 'connected': True, **O.digicert_catalog(key)})
    except O.ApiError as e:
        return jsonify({'ok': False, 'error': str(e)}), 502


def _names(domain, kind, extra):
    if kind == 'wildcard':
        return [domain, f'*.{domain}']
    names = [domain] + ([f'www.{domain}'] if domain.count('.') == 1 else [])
    if kind == 'multi':
        from panel.routes.websites_core import is_valid_domain
        for n in extra or []:
            n = str(n).strip().lower()
            if n and is_valid_domain(n) and n not in names:
                names.append(n)
    return names[:50]


@ssl_business_bp.route('/api/websites/<domain>/ssl/business/orders', methods=['GET', 'POST'])
def orders(domain):
    if not req(): return jsonify({'ok': False}), 401
    ws, err = _site(domain)
    if err:
        return jsonify({'ok': False, 'error': err}), 400
    if request.method == 'GET':
        return jsonify({'ok': True, 'orders': [O.public(o) for o in O.all_orders(domain)][:20],
                        'disclaimer': DISCLAIMER})
    d = request.get_json() or {}
    provider = d.get('provider', '')
    product = str(d.get('product') or '')
    if not re.fullmatch(r'[a-z0-9_\-]{2,64}', product):
        return jsonify({'ok': False, 'error': 'Choose a product'}), 400
    org = d.get('organization') or None
    if org is not None and not isinstance(org, dict):
        return jsonify({'ok': False, 'error': 'Invalid organization'}), 400
    try:
        o = O.place(domain, provider, product, _names(domain, d.get('kind', 'single'), d.get('extra_names')),
                    years=int(d.get('years') or 1), dcv=d.get('dcv', 'http'), org=org,
                    payment=d.get('payment', 'balance'), email=str(d.get('email') or ''))
    except O.ApiError as e:
        return jsonify({'ok': False, 'error': str(e)}), 400
    return jsonify({'ok': True, 'order': O.public(o)})


@ssl_business_bp.route('/api/ssl/business/orders/<oid>/check', methods=['POST'])
def order_check(oid):
    if not req(): return jsonify({'ok': False}), 401
    try:
        o = O.check(oid)
    except ValueError:
        return jsonify({'ok': False, 'error': 'Invalid order'}), 400
    if not o:
        return jsonify({'ok': False, 'error': 'Order not found'}), 404
    return jsonify({'ok': True, 'order': O.public(o)})


@ssl_business_bp.route('/api/websites/<domain>/ssl/business/import', methods=['POST'])
def order_import(domain):
    if not req(): return jsonify({'ok': False}), 401
    ws, err = _site(domain)
    if err:
        return jsonify({'ok': False, 'error': err}), 400
    d = request.get_json() or {}
    num = str(d.get('order') or '').strip()
    if not re.fullmatch(r'[A-Za-z0-9_\-]{1,64}', num):
        return jsonify({'ok': False, 'error': 'Enter the order number'}), 400
    try:
        o = O.import_order(domain, d.get('provider', ''), num, d.get('key', ''))
    except O.ApiError as e:
        return jsonify({'ok': False, 'error': str(e)}), 400
    if o.get('status') != 'installed':
        return jsonify({'ok': False, 'error': o.get('error') or 'Not installed', 'order': O.public(o)}), 400
    return jsonify({'ok': True, 'order': O.public(o)})


@ssl_business_bp.route('/api/websites/<domain>/ssl/csr', methods=['POST'])
def csr(domain):
    """Key + CSR for a certificate bought on a provider's website (Sectigo and others)."""
    if not req(): return jsonify({'ok': False}), 401
    ws, err = _site(domain)
    if err:
        return jsonify({'ok': False, 'error': err}), 400
    d = request.get_json() or {}
    try:
        o, text = O.make_csr_only(domain, _names(domain, d.get('kind', 'single'), d.get('extra_names')),
                                  d.get('organization') or None)
    except O.ApiError as e:
        return jsonify({'ok': False, 'error': str(e)}), 400
    return jsonify({'ok': True, 'csr': text, 'order': O.public(o)})
