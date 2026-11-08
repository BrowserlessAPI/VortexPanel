"""Business (paid) certificates ordered with the customer's own provider account.

VortexPanel does not sell certificates. The customer connects their own account at
the certificate provider (an API key created on the provider's website) and the
panel uses it to:

  1. create the private key and the CSR on this server (the key never leaves it),
  2. place the order through the provider's API (charged to that account),
  3. prove domain control (a file in the website, a DNS record, or the provider's
     e-mail), adding the file or record itself where it can,
  4. check the order every 10 minutes (vortexpanel-ssl-orders.timer) and install the
     certificate on the website as soon as it is issued.

Providers with an ordering API for their own customers:
  zerossl   ZeroSSL REST API (api.zerossl.com, access key). Paid ZeroSSL plans.
  digicert  DigiCert CertCentral Services API (X-DC-DEVKEY). DigiCert and GeoTrust
            products in that account, paid from the account balance or its saved card.
Sectigo sells to end customers through its own shop and resellers only (its ordering
API is for resellers), so a Sectigo certificate is bought there: the panel creates the
CSR to paste into the order and installs the certificate that comes back.

    python -m panel.ssl_orders poll     (the timer)
"""
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from panel import ssl_accounts as A

ORDERS = os.environ.get('VP_SSL_ORDERS', '/etc/vortexpanel/ssl-orders')
ZEROSSL_API = os.environ.get('VP_ZEROSSL_API', 'https://api.zerossl.com')
DIGICERT_API = os.environ.get('VP_DIGICERT_API', 'https://www.digicert.com/services/v2')
FINAL = ('installed', 'failed', 'cancelled')
DCV_METHODS = ('http', 'dns', 'email')
PROVIDERS = {'zerossl': 'ZeroSSL', 'digicert': 'DigiCert'}


class ApiError(Exception):
    pass


# ---------------------------------------------------------------- HTTP

def _http(method, url, headers=None, data=None, form=False, t=30):
    body = None
    hdrs = {'User-Agent': 'VortexPanel', 'Accept': 'application/json'}
    hdrs.update(headers or {})
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
        else:
            body = json.dumps(data).encode()
            hdrs['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=t) as r:
            raw = r.read()
            status = r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    except (urllib.error.URLError, OSError) as e:
        raise ApiError(f'Could not reach the provider: {getattr(e, "reason", e)}')
    if not raw:
        return status, {}
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, {'_text': raw.decode(errors='replace')[:500]}


# ---------------------------------------------------------------- ZeroSSL

def _zs(method, path, key, data=None, params=None):
    q = urllib.parse.urlencode(dict(params or {}, access_key=key))
    status, js = _http(method, f'{ZEROSSL_API}{path}?{q}', data=data, form=True)
    if isinstance(js, dict) and js.get('success') is False or status >= 400:
        err = (js.get('error') or {}) if isinstance(js, dict) else {}
        kind = err.get('type') or err.get('info') or js.get('_text') or f'HTTP {status}'
        raise ApiError(f'ZeroSSL: {kind}'.replace('_', ' '))
    return js


def zerossl_verify_key(key):
    _zs('GET', '/certificates', key, params={'limit': 1})
    return {'name': 'ZeroSSL account'}


# ---------------------------------------------------------------- DigiCert

def _dc(method, path, key, data=None):
    status, js = _http(method, f'{DIGICERT_API}{path}', headers={'X-DC-DEVKEY': key}, data=data)
    if status >= 400:
        errs = js.get('errors') if isinstance(js, dict) else None
        msg = '; '.join(e.get('message', '') for e in errs) if errs else (js.get('_text') if isinstance(js, dict) else '')
        raise ApiError(f'DigiCert: {msg or "HTTP " + str(status)}')
    return js


def digicert_verify_key(key):
    me = _dc('GET', '/user/me', key)
    acct = (me.get('container') or {}).get('name') or me.get('email') or 'DigiCert account'
    return {'name': acct}


def digicert_catalog(key):
    """Products of the account (DigiCert and GeoTrust TLS), organizations and balance."""
    prods = []
    for p in (_dc('GET', '/product', key).get('products') or []):
        nid = p.get('name_id', '')
        if (p.get('type') or '').lower() not in ('ssl_certificate', 'ssl', '') and 'ssl' not in nid:
            continue
        if any(x in nid for x in ('private', 'client', 'code_signing', 'document', 'smime', 'vmc', 'cds')):
            continue
        brand = 'GeoTrust' if 'geotrust' in nid else ('RapidSSL' if 'rapidssl' in nid else
                ('Thawte' if 'thawte' in nid else 'DigiCert'))
        level = 'EV' if '_ev' in nid or 'ev_' in nid else ('DV' if '_dv' in nid or 'dv_' in nid else 'OV')
        prods.append({'id': nid, 'name': p.get('name') or nid, 'brand': brand, 'level': level,
                      'wildcard': 'wildcard' in nid or bool(p.get('allowed_wildcard')) or 'flex' in nid or 'basic' in nid,
                      'years': p.get('allowed_validity_years') or [1]})
    orgs = [{'id': o.get('id'), 'name': o.get('name') or o.get('display_name'),
             'status': o.get('status')} for o in (_dc('GET', '/organization', key).get('organizations') or [])]
    try:
        bal = _dc('GET', '/finance/balance', key)
        balance = f'{bal.get("balance")} {bal.get("currency") or ""}'.strip()
    except ApiError:
        balance = ''
    return {'products': prods, 'organizations': orgs, 'balance': balance}


# ---------------------------------------------------------------- storage

def _odir(oid):
    if not re.fullmatch(r'o[0-9a-f]{12}', oid or ''):
        raise ValueError('invalid order')
    return os.path.join(ORDERS, oid)


def load(oid):
    try:
        with open(os.path.join(_odir(oid), 'order.json')) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save(o):
    d = _odir(o['id'])
    os.makedirs(d, mode=0o700, exist_ok=True)
    o['updated'] = int(time.time())
    tmp = os.path.join(d, 'order.json.tmp')
    with open(tmp, 'w') as f:
        json.dump(o, f, indent=1)
    os.replace(tmp, os.path.join(d, 'order.json'))


def all_orders(domain=None):
    out = []
    try:
        names = os.listdir(ORDERS)
    except OSError:
        return out
    for oid in names:
        try:
            o = load(oid)
        except ValueError:
            continue
        if o and (domain is None or o.get('domain') == domain):
            out.append(o)
    return sorted(out, key=lambda o: o.get('created', 0), reverse=True)


def public(o):
    """An order as the browser sees it (no key material)."""
    keep = ('id', 'domain', 'provider', 'provider_name', 'product', 'product_name', 'names', 'years', 'dcv',
            'status', 'created', 'updated', 'provider_order', 'records', 'log', 'error', 'expires_on', 'kind',
            'payment', 'emails')
    return {k: o.get(k) for k in keep if k in o}


def installed_order(domain, cert_path):
    """The order whose certificate is installed at cert_path (for the SSL tab)."""
    if '/business/' not in (cert_path or ''):
        return None
    for o in all_orders(domain):
        if o.get('status') == 'installed':
            return public(o)
    return None


def _log(o, line):
    o.setdefault('log', []).append({'t': int(time.time()), 'm': line})
    o['log'] = o['log'][-60:]


# ---------------------------------------------------------------- key and CSR

def _secret_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(data)


def make_key_csr(oid, names, org=None):
    """RSA 2048 key and CSR for `names` (first = common name), stored with the order."""
    d = _odir(oid)
    os.makedirs(d, mode=0o700, exist_ok=True)
    keyp, csrp = os.path.join(d, 'key.pem'), os.path.join(d, 'csr.pem')
    r = subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', keyp],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise ApiError('Could not create the private key: ' + r.stderr[-200:])
    os.chmod(keyp, 0o600)

    def clean(v):
        return re.sub(r'[/\\=+,"<>;#]', ' ', str(v or '')).strip()[:64]
    subj = f'/CN={names[0]}'
    if org:
        for k, f in (('C', 'country'), ('ST', 'state'), ('L', 'city'), ('O', 'name')):
            v = clean(org.get(f))
            if v:
                subj += f'/{k}={v}'
    san = ','.join(f'DNS:{n}' for n in names)
    r = subprocess.run(['openssl', 'req', '-new', '-key', keyp, '-out', csrp, '-subj', subj,
                        '-addext', f'subjectAltName={san}', '-sha256'], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise ApiError('Could not create the CSR: ' + r.stderr[-200:])
    return open(csrp).read()


def key_for_cert(cert_pem):
    """A private key created by the panel (business order or CSR) that matches this certificate."""
    def pub(args, data):
        r = subprocess.run(['openssl'] + args, input=data, capture_output=True, timeout=20)
        return r.stdout.strip() if r.returncode == 0 else b''
    cpub = pub(['x509', '-noout', '-pubkey'], cert_pem.encode())
    if not cpub:
        return ''
    for o in all_orders():
        kp = os.path.join(_odir(o['id']), 'key.pem')
        if os.path.exists(kp):
            key = open(kp).read()
            if pub(['pkey', '-pubout'], key.encode()) == cpub:
                return key
    return ''


# ---------------------------------------------------------------- domain proof

def _site_root(domain):
    from panel.routes.acme import _nginx_root
    from panel.routes.websites_core import _get_site_path
    for r in (_nginx_root(domain), _get_site_path(domain)):
        if r and os.path.isdir(r):
            return r
    return ''


def _put_file(domain, url_path, content):
    """Place a validation file in the website folder. Returns '' or an error."""
    root = _site_root(domain)
    if not root:
        return f'The folder of {domain} was not found'
    rel = urllib.parse.urlparse(url_path).path if '://' in url_path else url_path
    if not rel.startswith('/.well-known/pki-validation/') or '..' in rel:
        return 'Unexpected validation file path from the provider'
    path = os.path.join(root, rel.lstrip('/'))
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    for p in (os.path.join(root, '.well-known'), os.path.dirname(path)):
        os.chmod(p, 0o755)
    with open(path, 'w') as f:
        f.write(content)
    os.chmod(path, 0o644)
    return ''


def _remove_files(o):
    """After issue: remove the validation files and the TXT records the panel added."""
    root = _site_root(o['domain'])
    for r in o.get('records') or []:
        if r.get('type') == 'TXT' and r.get('auto'):
            try:
                from panel import acme_dns
                acme_dns.change('rm', r['name'], r['value'])
            except Exception:
                pass
        if r.get('type') == 'FILE' and root:
            p = os.path.join(root, r['name'].lstrip('/'))
            if p.startswith(root + '/.well-known/pki-validation/') and os.path.exists(p):
                os.remove(p)


def _cf_token():
    try:
        from panel.routes.acme import _load_providers
        return (_load_providers().get('cloudflare') or {}).get('CF_Token', '')
    except Exception:
        return ''


def _cf_add(name, rtype, content):
    """Add a DNS record through Cloudflare (token saved under SSL through your DNS provider)."""
    tok = _cf_token()
    if not tok:
        return False
    labels = name.rstrip('.').split('.')
    hdr = {'Authorization': f'Bearer {tok}'}
    for i in range(len(labels) - 1):
        zone = '.'.join(labels[i:])
        st, js = _http('GET', 'https://api.cloudflare.com/client/v4/zones?' + urllib.parse.urlencode({'name': zone}), headers=hdr)
        res = (js or {}).get('result') or []
        if res:
            st, js = _http('POST', f'https://api.cloudflare.com/client/v4/zones/{res[0]["id"]}/dns_records', headers=hdr,
                           data={'type': rtype, 'name': name.rstrip('.'), 'content': content, 'ttl': 120, 'proxied': False})
            return bool((js or {}).get('success'))
    return False


def _local_txt(name, value):
    try:
        from panel import acme_dns
        from panel.routes.acme import _zone_covers
        if not _zone_covers(name):
            return False
        return acme_dns.change('add', name, value) == 0
    except Exception:
        return False


def _add_dns(o, rec):
    """Try to add a DNS record automatically; mark it on the record."""
    ok = False
    if rec['type'] == 'TXT':
        ok = _local_txt(rec['name'], rec['value'])
    if not ok:
        ok = _cf_add(rec['name'], rec['type'], rec['value'])
    rec['auto'] = ok
    _log(o, f'{rec["type"]} record {rec["name"]}: ' + ('added automatically' if ok else 'add it at your DNS provider'))


# ---------------------------------------------------------------- order

def place(domain, provider, product, names, years=1, dcv='http', org=None, payment='balance', email=''):
    """Create key + CSR, place the order and set up domain proof. Returns the order dict."""
    if provider not in PROVIDERS:
        raise ApiError('Unknown provider')
    if dcv not in DCV_METHODS:
        raise ApiError('Unknown domain proof method')
    acct = A.get(provider)
    key = acct.get('api_key')
    if not key:
        raise ApiError(f'Connect your {PROVIDERS[provider]} account first')
    if any('*' in n for n in names) and dcv == 'http':
        raise ApiError('A wildcard certificate is proven with a DNS record or e-mail, not a file')
    oid = 'o' + uuid.uuid4().hex[:12]
    o = {'id': oid, 'domain': domain, 'provider': provider, 'provider_name': PROVIDERS[provider], 'product': product,
         'names': names, 'years': int(years or 1), 'dcv': dcv, 'payment': payment, 'status': 'placing',
         'created': int(time.time()), 'records': [], 'log': [], 'kind': 'order'}
    save(o)
    try:
        csr = make_key_csr(oid, names, org)
        _log(o, 'Private key and CSR created on this server (RSA 2048).')
        if provider == 'zerossl':
            _zerossl_place(o, key, csr, email)
        else:
            _digicert_place(o, key, csr, org, payment)
        o['status'] = 'validating'
        save(o)
        ensure_timer()
    except Exception as e:
        o['status'], o['error'] = 'failed', str(e)
        _log(o, 'The order was not placed: ' + str(e))
        save(o)
        raise
    return o


def _zerossl_place(o, key, csr, email):
    js = _zs('POST', '/certificates', key, data={
        'certificate_domains': ','.join(o['names']), 'certificate_csr': csr,
        'certificate_validity_days': 200 if o['product'] != 'zerossl-90' else 90, 'strict_domains': 1})
    o['provider_order'] = js.get('id')
    o['product_name'] = {'4': 'ZeroSSL annual', '5': 'ZeroSSL annual wildcard', '6': 'ZeroSSL annual multi-domain'}.get(
        str(js.get('type')), 'ZeroSSL certificate')
    _log(o, f'Order {js.get("id")} placed with ZeroSSL.')
    val = js.get('validation') or {}
    method = {'http': 'HTTP_CSR_HASH', 'dns': 'CNAME_CSR_HASH', 'email': 'EMAIL'}[o['dcv']]
    data = {'validation_method': method}
    if o['dcv'] == 'http':
        for name, m in (val.get('other_methods') or {}).items():
            content = '\n'.join(m.get('file_validation_content') or [])
            path = urllib.parse.urlparse(m.get('file_validation_url_http', '')).path
            rec = {'type': 'FILE', 'name': path, 'value': content, 'host': name}
            err = _put_file(o['domain'], path, content)
            rec['auto'] = not err
            o['records'].append(rec)
            _log(o, f'Validation file for {name}: ' + ('placed in the website' if not err else err))
    elif o['dcv'] == 'dns':
        for name, m in (val.get('other_methods') or {}).items():
            rec = {'type': 'CNAME', 'name': m.get('cname_validation_p1', ''), 'value': m.get('cname_validation_p2', ''), 'host': name}
            _add_dns(o, rec)
            o['records'].append(rec)
    else:
        emails = []
        for name, opts in (val.get('email_validation') or {}).items():
            pick = next((e for e in opts if e.lower() == (email or '').lower()), None) or \
                next((e for e in opts if e.startswith('admin@')), opts[0] if opts else '')
            emails.append(pick)
        data['validation_email'] = ','.join(emails)
        o['emails'] = emails
        _log(o, 'ZeroSSL sends an approval e-mail to ' + ', '.join(emails))
    save(o)
    _zs('POST', f'/certificates/{o["provider_order"]}/challenges', key, data=data)
    _log(o, 'Domain check requested.')


def _digicert_place(o, key, csr, org, payment):
    dcv = {'http': 'http-token', 'dns': 'dns-txt-token', 'email': 'email'}[o['dcv']]
    body = {'certificate': {'common_name': o['names'][0], 'dns_names': o['names'][1:], 'csr': csr,
                            'signature_hash': 'sha256', 'server_platform': {'id': -1}},
            'order_validity': {'years': o['years']}, 'dcv_method': dcv,
            'payment_method': payment if payment in ('balance', 'profile') else 'balance', 'skip_approval': True}
    if org and org.get('id'):
        body['organization'] = {'id': int(org['id'])}
    elif org and org.get('name'):
        body['organization'] = {k: v for k, v in {
            'name': org.get('name'), 'address': org.get('address'), 'city': org.get('city'), 'state': org.get('state'),
            'zip': org.get('zip'), 'country': (org.get('country') or '').lower(), 'telephone': org.get('phone'),
            'contacts': [{'contact_type': 'organization_contact', 'first_name': org.get('first_name'),
                          'last_name': org.get('last_name'), 'email': org.get('email'), 'telephone': org.get('phone'),
                          'job_title': org.get('job_title') or 'Administrator'}]}.items() if v}
    js = _dc('POST', f'/order/certificate/{o["product"]}', key, data=body)
    o['provider_order'] = js.get('id')
    o['product_name'] = o['product']
    _log(o, f'Order {js.get("id")} placed with DigiCert and charged to your account '
            f'({"balance" if body["payment_method"] == "balance" else "saved card"}).')
    if js.get('certificate_chain'):
        o['chain_ready'] = True
    token = js.get('dcv_random_value') or ''
    for d in js.get('domains') or []:
        t = d.get('dcv_token') or {}
        tok = t.get('token') or token
        if o['dcv'] == 'http' and tok:
            url = t.get('http_token_url') or f'http://{d.get("name")}/.well-known/pki-validation/fileauth.txt'
            path = urllib.parse.urlparse(url).path
            rec = {'type': 'FILE', 'name': path, 'value': tok, 'host': d.get('name')}
            err = _put_file(o['domain'], path, tok)
            rec['auto'] = not err
            o['records'].append(rec)
            _log(o, f'Validation file for {d.get("name")}: ' + ('placed in the website' if not err else err))
        elif o['dcv'] == 'dns' and tok:
            host = d.get('name', '')
            rec = {'type': 'TXT', 'name': host[2:] if host.startswith('*.') else host, 'value': tok, 'host': host}
            _add_dns(o, rec)
            o['records'].append(rec)
    if o['dcv'] == 'email':
        _log(o, 'DigiCert sends the approval e-mail to the domain\'s contacts.')
    save(o)


def check(oid):
    """Advance one order: ask the provider, install when issued. Returns the order."""
    o = load(oid)
    if not o or o.get('status') in FINAL:
        return o
    key = A.get(o['provider']).get('api_key')
    if not key:
        o['error'] = f'The {o["provider_name"]} account is no longer connected'
        save(o)
        return o
    o.pop('error', None)
    try:
        cert = _saved_cert(o) if o.get('status') == 'issued' else ''
        if not cert:
            cert = _zerossl_check(o, key) if o['provider'] == 'zerossl' else _digicert_check(o, key)
        if cert:
            with open(os.path.join(_odir(o['id']), 'issued.pem'), 'w') as f:
                f.write(cert + '\n')      # kept: the certificate is paid for
            install(o, cert)
    except ApiError as e:
        o['error'] = str(e)
    o['checked'] = int(time.time())
    save(o)
    return o


def _saved_cert(o):
    p = os.path.join(_odir(o['id']), 'issued.pem')
    return open(p).read() if os.path.exists(p) else ''


def _zerossl_check(o, key):
    js = _zs('GET', f'/certificates/{o["provider_order"]}', key)
    st = js.get('status')
    if st in ('cancelled', 'revoked', 'expired'):
        o['status'] = 'failed'
        _log(o, f'ZeroSSL reports the certificate as {st}.')
        return ''
    if st != 'issued':
        return ''
    dl = _zs('GET', f'/certificates/{o["provider_order"]}/download/return', key)
    return (dl.get('certificate.crt', '').strip() + '\n' + dl.get('ca_bundle.crt', '').strip()).strip()


def _digicert_check(o, key):
    js = _dc('GET', f'/order/certificate/{o["provider_order"]}', key)
    st = (js.get('status') or '').lower()
    if st in ('rejected', 'canceled', 'cancelled', 'revoked'):
        o['status'] = 'failed'
        _log(o, f'DigiCert reports the order as {st}.')
        return ''
    if st != 'issued':
        if o['dcv'] in ('http', 'dns') and not o.get('dcv_requested'):
            try:
                _dc('PUT', f'/order/certificate/{o["provider_order"]}/check-dcv', key)
                o['dcv_requested'] = int(time.time())
                _log(o, 'Asked DigiCert to check the domain proof.')
                js = _dc('GET', f'/order/certificate/{o["provider_order"]}', key)   # DV is often issued at once
                st = (js.get('status') or '').lower()
            except ApiError:
                pass
        elif o.get('dcv_requested') and time.time() - o['dcv_requested'] > 1800:
            o.pop('dcv_requested', None)       # ask again every 30 minutes
        if st != 'issued':
            return ''
    cid = (js.get('certificate') or {}).get('id')
    if not cid:
        return ''
    # PEM text, not JSON: read the whole body
    req = urllib.request.Request(f'{DIGICERT_API}/certificate/{cid}/download/format/pem_noroot',
                                 headers={'X-DC-DEVKEY': key, 'User-Agent': 'VortexPanel', 'Accept': '*/*'})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            pem = r.read().decode(errors='replace')
    except Exception as e:
        raise ApiError(f'DigiCert: the certificate could not be downloaded ({e})')
    if '-----BEGIN CERTIFICATE-----' not in pem:
        raise ApiError('DigiCert: the download did not contain a certificate')
    return pem.strip()


def install(o, cert):
    """Install an issued certificate on the website (checked first, previous kept)."""
    from flask import Flask
    from panel.routes.websites_ssl import install_manual_cert, prepare_cert
    key = open(os.path.join(_odir(o['id']), 'key.pem')).read()
    cert, chk = prepare_cert(o['domain'], cert, key)
    if chk.get('error'):
        # issued (and paid): never give up on it - keep it and try again on the next check
        o['status'] = 'issued'
        o['error'] = chk['error']
        _log(o, 'Issued, but not installed yet: ' + chk['error'])
        return
    with Flask(__name__).app_context():
        resp = install_manual_cert(o['domain'], cert, key, subdir='business', source=f'business:{o["provider"]}')
        res = (resp[0] if isinstance(resp, tuple) else resp).get_json() or {}
    if not res.get('ok'):
        o['status'] = 'issued'
        o['error'] = res.get('error') or 'install failed'
        _log(o, 'Issued, but the web server did not accept it: ' + o['error'] + ' (it will be tried again)')
        return
    with open(os.path.join(_odir(o['id']), 'cert.pem'), 'w') as f:
        f.write(cert + '\n')
    o['status'] = 'installed'
    o['expires_on'] = chk.get('expires_on')
    _log(o, f'Issued and installed on {o["domain"]}.')
    _remove_files(o)
    try:
        from panel.alerts import notify_event
        notify_event('ssl', f'SSL certificate installed on {o["domain"]}',
                     f'{o["provider_name"]} issued the certificate for {", ".join(o["names"])}; it was installed '
                     f'and is valid until {o.get("expires_on")}.')
    except Exception:
        pass


def import_order(domain, provider, provider_order, key_pem=''):
    """A certificate ordered on the provider's website: fetch it by its order number
    and install it (the key made here for its CSR, or one given now)."""
    acct = A.get(provider)
    key = acct.get('api_key')
    if not key:
        raise ApiError(f'Connect your {PROVIDERS.get(provider, provider)} account first')
    oid = 'o' + uuid.uuid4().hex[:12]
    o = {'id': oid, 'domain': domain, 'provider': provider, 'provider_name': PROVIDERS[provider],
         'provider_order': str(provider_order), 'names': [domain], 'dcv': 'imported', 'status': 'validating',
         'created': int(time.time()), 'records': [], 'log': [], 'kind': 'import', 'product': 'imported'}
    cert = _zerossl_check(o, key) if provider == 'zerossl' else _digicert_check(o, key)
    if not cert:
        raise ApiError(f'Order {provider_order} has no issued certificate yet')
    key_pem = (key_pem or '').strip() or key_for_cert(cert)
    if not key_pem:
        raise ApiError('The private key for this certificate is not on this server. Paste it with the import.')
    os.makedirs(_odir(oid), mode=0o700, exist_ok=True)
    _secret_write(os.path.join(_odir(oid), 'key.pem'), key_pem + '\n')
    _log(o, f'Imported order {provider_order} from {PROVIDERS[provider]}.')
    install(o, cert)
    save(o)
    return o


def make_csr_only(domain, names, org=None):
    """Key + CSR for a certificate bought elsewhere (for example Sectigo's shop)."""
    oid = 'o' + uuid.uuid4().hex[:12]
    o = {'id': oid, 'domain': domain, 'provider': 'other', 'provider_name': 'Bought elsewhere', 'names': names,
         'dcv': 'n/a', 'status': 'csr', 'created': int(time.time()), 'records': [], 'log': [], 'kind': 'csr',
         'product': 'csr'}
    csr = make_key_csr(oid, names, org)
    _log(o, 'Private key and CSR created on this server.')
    save(o)
    return o, csr


# ---------------------------------------------------------------- timer

TIMER_SERVICE = '''[Unit]
Description=VortexPanel: check business SSL orders and install issued certificates

[Service]
Type=oneshot
WorkingDirectory=/opt/vortexpanel
ExecStart=/opt/vortexpanel/venv/bin/python -m panel.ssl_orders poll
'''
TIMER_UNIT = '''[Unit]
Description=VortexPanel: check business SSL orders every 10 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
'''


def ensure_timer():
    unit, timer = '/etc/systemd/system/vortexpanel-ssl-orders.service', '/etc/systemd/system/vortexpanel-ssl-orders.timer'
    try:
        if os.path.exists(timer) and open(unit).read() == TIMER_SERVICE:
            return
        with open(unit, 'w') as f:
            f.write(TIMER_SERVICE)
        with open(timer, 'w') as f:
            f.write(TIMER_UNIT)
        subprocess.run('systemctl daemon-reload && systemctl enable --now vortexpanel-ssl-orders.timer',
                       shell=True, capture_output=True, timeout=60)
    except OSError:
        pass


def poll():
    for o in all_orders():
        if o.get('kind') == 'order' and o.get('status') not in FINAL:
            check(o['id'])


if __name__ == '__main__':
    if sys.argv[1:] == ['poll']:
        poll()
    else:
        print(__doc__)
