"""Hosting Module licence (client side).

The Hosting Module is sold through the licence server. This file only:
  - gives this server an identity (server_id + a secret, created once in data/licence/)
  - places a PayPal order (new licences or a renewal), picks up the licence after payment,
    asks for the licence linked to this server's IP, activates a key, checks in
  - keeps the last signed answer and checks its Ed25519 signature offline against the
    public key(s) shipped in panel/trust/licence.json, so the panel keeps working for
    the grace period when the licence server cannot be reached
  - downloads the signed module package and hands it to panel/module_install.py

A licence problem never stops customer websites: the Hosting Module only locks its own
admin actions (new accounts, packages) when `hosting_licensed()` is False.

    python3 -m panel.licence status | check | install-module
"""
import base64
import fcntl
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time

PANEL_DIR = '/opt/vortexpanel'
STATE_DIR = os.path.join(PANEL_DIR, 'data', 'licence')
IDENTITY = os.path.join(STATE_DIR, 'identity.json')
STATE = os.path.join(STATE_DIR, 'state.json')
LOCK = os.path.join(STATE_DIR, '.lock')
TRUST = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'trust', 'licence.json')
TIMEOUT = 20
MODULE = 'hosting'
CHECK_EVERY = 3600       # the panel checks in at least hourly, so a revoked or ended licence shows soon
STALE_VIEW = 120         # opening the Hosting Module page checks in when the last answer is older than this
STALE_USE = 600          # a Hosting Module admin action checks in when the last answer is older than this


class LicenceError(Exception):
    def __init__(self, message, code='error', status=400):
        super().__init__(message)
        self.code = code
        self.status = status


# ---------------------------------------------------------------- files
def _ensure_dir():
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(STATE_DIR, 0o700)
    except OSError:
        pass


def _read(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write(path, data):
    _ensure_dir()
    fd, tmp = tempfile.mkstemp(dir=STATE_DIR, prefix='.tmp-')
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


class _Lock:
    def __enter__(self):
        _ensure_dir()
        self.f = open(LOCK, 'w')
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


def trust():
    """{"server": url, "keys": [base64 Ed25519 public keys]} shipped with the panel code."""
    t = _read(TRUST, {})
    server = os.environ.get('VP_LICENCE_SERVER') or t.get('server') or ''
    return {'server': server.rstrip('/'), 'keys': [k for k in t.get('keys') or [] if k]}


def identity():
    """This server's id and secret, created once. Copying the data folder to another
    server copies them too; the licence server notices two servers using one identity."""
    with _Lock():
        ident = _read(IDENTITY, None)
        if not ident or not ident.get('server_id') or len(ident.get('server_secret') or '') < 32:
            ident = {'server_id': 'vp-' + secrets.token_hex(16), 'server_secret': secrets.token_urlsafe(36),
                     'created_at': int(time.time())}
            _write(IDENTITY, ident)
    return ident


def load_state():
    return _read(STATE, {})


def _save_state(**changes):
    with _Lock():
        st = _read(STATE, {})
        st.update(changes)
        for k in [k for k, v in changes.items() if v is None]:
            st.pop(k, None)
        _write(STATE, st)
        return st


# ---------------------------------------------------------------- token check (offline)
def _b64u_dec(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def verify_token(token):
    """The token's payload when it is signed by a trusted key, else None."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        prefix, body, sig = str(token or '').split('.')
        if prefix != 'vpl1':
            return None
        msg = f'{prefix}.{body}'.encode()
        for k in trust()['keys']:
            try:
                Ed25519PublicKey.from_public_bytes(base64.b64decode(k)).verify(_b64u_dec(sig), msg)
                return json.loads(_b64u_dec(body))
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        return None
    return None


def verify_release(module, version, sha256, signature):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    msg = f'vortexpanel-release\n{module}\n{version}\n{sha256}'.encode()
    for k in trust()['keys']:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(k)).verify(_b64u_dec(signature), msg)
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


def current(now=None):
    """What the panel knows right now, from the stored signed token (no network)."""
    now = now or time.time()
    st = load_state()
    payload = verify_token(st.get('token')) if st.get('token') else None
    ident = _read(IDENTITY, {}) or {}
    out = {'has_key': bool(st.get('key')), 'key_last4': (st.get('key') or '')[-4:], 'licensed': False,
           'status': 'none', 'status_text': 'No licence', 'kind': '', 'period': '', 'period_end': 0,
           'valid_until': 0, 'refresh_after': 0, 'email': '', 'module_latest': '',
           'last_ok': st.get('last_ok') or 0, 'last_error': st.get('last_error') or '',
           'last_error_at': st.get('last_error_at') or 0, 'offline': False, 'checkout': st.get('checkout') or None,
           'linked_ip': '', 'months': 0, 'source': ''}
    if not payload:
        if st.get('token'):
            out.update(status='invalid', status_text='The stored licence is not signed by the licence server')
        elif st.get('key') and st.get('lost'):
            # the licence server took the licence back from this server (revoked and released,
            # moved, deleted): say so instead of a bare "No licence"
            lost = st['lost']
            out.update(status='lost', status_text=lost.get('text') or 'The licence server no longer lists this licence for this server',
                       lost_code=lost.get('code') or '', lost_at=lost.get('at') or 0)
        return out
    if payload.get('server_id') != ident.get('server_id'):
        out.update(status='other_server', status_text='The stored licence belongs to another server')
        return out
    out.update(status=payload.get('status') or '', status_text=payload.get('status_text') or '',
               kind=payload.get('kind') or '', period=payload.get('period') or '',
               period_end=payload.get('period_end') or 0, valid_until=payload.get('valid_until') or 0,
               refresh_after=payload.get('refresh_after') or 0, email=payload.get('email') or '',
               module_latest=payload.get('module_latest') or '', linked_ip=payload.get('linked_ip') or '',
               months=payload.get('months') or 0, source=payload.get('source') or '')
    in_time = now < (payload.get('valid_until') or 0)
    end = payload.get('period_end') or 0
    out['licensed'] = bool(payload.get('valid')) and in_time and MODULE in (payload.get('features') or [])
    if payload.get('valid') and end and now >= end and payload.get('source') != 'dodo':
        # a prepaid licence ends at its period end even when the last answer still said "Active"
        out['licensed'] = False
        out.update(status='expired', status_text='Expired: the paid period has ended')
    elif payload.get('valid') and not in_time:
        out.update(status='offline_expired',
                   status_text='The licence server has not been reached for too long; check-in needed')
    out['offline'] = bool(payload.get('valid')) and now > (payload.get('refresh_after') or 0) + 3600
    return out


def hosting_licensed():
    """For the Hosting Module: may the admin side create accounts and change packages?"""
    try:
        refresh_stale(STALE_USE)
    except Exception:  # noqa: BLE001
        pass
    try:
        return current()['licensed']
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------- talking to the licence server
def _server_info():
    try:
        virt = subprocess.run(['systemd-detect-virt'], capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:  # noqa: BLE001
        virt = ''
    try:
        from panel.plugins import core_version
        panel_version = core_version()
    except Exception:  # noqa: BLE001
        panel_version = ''
    module_version = ''
    try:
        module_version = _read(os.path.join(PANEL_DIR, 'plugins', MODULE, 'plugin.json'), {}).get('version', '')
    except Exception:  # noqa: BLE001
        pass
    ident = identity()
    return {'server_id': ident['server_id'], 'server_secret': ident['server_secret'],
            'hostname': socket.getfqdn()[:255], 'virt': virt or 'unknown', 'panel_version': panel_version,
            'module_version': module_version}


_V4 = threading.local()


def _ipv4_first():
    """Licences are linked to the address this server connects from. When the licence server has
    an IPv4 address, talk to it over IPv4 so a dual-stack server always shows the same address
    (only for this thread's requests to the licence server)."""
    try:
        import urllib3.util.connection as uc
        if not getattr(uc, '_vp_licence_patch', False):
            orig = uc.allowed_gai_family

            def family():
                return socket.AF_INET if getattr(_V4, 'on', False) else orig()
            uc.allowed_gai_family = family
            uc._vp_licence_patch = True
        from urllib.parse import urlsplit
        host = urlsplit(trust()['server']).hostname or ''
        _V4.on = bool(host) and bool(socket.getaddrinfo(host, 443, socket.AF_INET))
    except Exception:  # noqa: BLE001 - no IPv4 address (IPv6-only): the normal order applies
        _V4.on = False


def _call(method, path, body=None, timeout=TIMEOUT):
    import requests
    server = trust()['server']
    _ipv4_first()
    if not server.startswith(('https://', 'http://127.0.0.1', 'http://localhost')):
        raise LicenceError('The licence server address is not set in this panel version.', 'no_server', 503)
    try:
        r = requests.request(method, server + path, json=body, timeout=timeout,
                             headers={'User-Agent': 'VortexPanel-Licence/1'})
    except requests.RequestException as e:
        raise LicenceError('The licence server could not be reached. Try again in a few minutes.',
                           'unreachable', 503) from e
    try:
        data = r.json()
    except ValueError:
        raise LicenceError(f'The licence server answered HTTP {r.status_code}.', 'bad_answer', 502)
    if r.status_code >= 400 or not data.get('ok', False):
        raise LicenceError(data.get('error') or f'HTTP {r.status_code}', data.get('code') or 'error',
                           r.status_code if r.status_code >= 400 else 400)
    return data


def _store_token(data, key=None):
    payload = verify_token(data.get('token'))
    if not payload:
        raise LicenceError('The licence server\'s answer is not signed with a trusted key.', 'signature', 502)
    if payload.get('server_id') != identity()['server_id']:
        raise LicenceError('The licence server answered for another server.', 'identity', 502)
    changes = {'token': data['token'], 'last_ok': int(time.time()), 'last_error': None, 'last_error_at': None,
               'lost': None}
    if key:
        changes['key'] = key
    _save_state(**changes)
    return payload


def plans():
    return _call('GET', '/api/v1/plans')


def order(email, months, quantity=1, ips=None, kind='new'):
    """Place a PayPal order on the licence server. Returns its answer (approve_url, total ...)."""
    body = dict(_server_info(), email=email, months=months, quantity=quantity, ips=list(ips or [])[:500],
                kind='renew' if kind == 'renew' else 'new')
    data = _call('POST', '/api/v1/order', body)
    from urllib.parse import urlsplit
    url = str(data.get('approve_url') or '')
    if urlsplit(url).scheme != 'https' or urlsplit(url).hostname not in ('www.paypal.com', 'www.sandbox.paypal.com'):
        raise LicenceError('The licence server sent an unexpected payment address.', 'bad_answer', 502)
    _save_state(checkout={'order_id': data['order_id'], 'approve_url': url, 'kind': data.get('kind') or kind,
                          'total': data.get('total'), 'currency': data.get('currency'),
                          'quantity': data.get('quantity'), 'months': data.get('months'),
                          'started': int(time.time()), 'status': 'created', 'note': ''})
    return data


def claim():
    """After a checkout: is it paid? Stores the key and token when it is."""
    st = load_state()
    co = st.get('checkout') or {}
    info = _server_info()
    if co.get('order_id'):
        data = _call('POST', '/api/v1/claim', {'order_id': co['order_id'], 'server_id': info['server_id'],
                                               'server_secret': info['server_secret']})
        status = data.get('order_status') or ''
        if not data.get('paid'):
            if status in ('failed', 'cancelled', 'refunded') or status != co.get('status') or data.get('note') != co.get('note'):
                _save_state(checkout=dict(co, status=status, note=data.get('note') or ''))
            return {'paid': False, 'pending': status in ('created', 'pending'), 'status': status,
                    'note': data.get('note') or ''}
        if data.get('bound') and data.get('token'):
            _store_token(data, data.get('key'))
            _save_state(checkout=None)
            return {'paid': True, 'bound': True, 'kind': co.get('kind')}
        _save_state(checkout=None)
        return {'paid': True, 'bound': False, 'kind': co.get('kind')}
    if not co.get('intent_id'):
        return {'paid': False, 'pending': False}
    data = _call('POST', '/api/v1/claim', {'intent_id': co['intent_id'], 'server_id': info['server_id'],
                                           'server_secret': info['server_secret']})
    if not data.get('paid'):
        return {'paid': False, 'pending': True}
    if data.get('bound') and data.get('token'):
        _store_token(data, data.get('key'))
        _save_state(checkout=None)
        return {'paid': True, 'bound': True}
    # paid, but this server already had another licence: keep the new key for the owner
    _save_state(checkout=None, spare_key=data.get('key'))
    return {'paid': True, 'bound': False, 'key': data.get('key')}


def cancel_checkout():
    _save_state(checkout=None)


def link(force=False):
    """Ask the licence server for the licence linked to this server's IP address (bought for this
    server from another panel or the licence account). Returns the token payload, or None.
    Without force it asks at most once every 5 minutes."""
    st = load_state()
    now = int(time.time())
    if not force and now - int(st.get('last_link') or 0) < 300:
        return None
    _save_state(last_link=now)
    data = _call('POST', '/api/v1/link', dict(_server_info()))
    if not data.get('found'):
        return None
    return _store_token(data, data.get('key'))


def activate(key, move=False):
    key = re.sub(r'[^A-Za-z0-9-]', '', str(key or '')).upper()
    if len(key) < 10:
        raise LicenceError('Enter the licence key.', 'bad_key')
    data = _call('POST', '/api/v1/activate', dict(_server_info(), key=key, move=bool(move)))
    return _store_token(data, key)


def check(timeout=TIMEOUT):
    st = load_state()
    if not st.get('key'):
        return None
    _save_state(last_try=int(time.time()))
    try:
        data = _call('POST', '/api/v1/check', dict(_server_info(), key=st['key']), timeout=timeout)
    except LicenceError as e:
        now = int(time.time())
        _save_state(last_error=str(e), last_error_at=now)
        if e.code in ('not_found', 'bound_elsewhere', 'identity', 'not_bound'):
            # the licence server says this server no longer holds the licence: drop the token
            # ('wrong_ip' keeps it: it runs out within 3 days by itself, so a short change of the
            # outgoing address does not lock the module at once)
            text = {'not_bound': 'Released from this server on the licence server',
                    'bound_elsewhere': 'The licence is now active on another server',
                    'not_found': 'The licence key no longer exists on the licence server',
                    'identity': "This server's identity no longer matches the licence"}.get(e.code, str(e))
            _save_state(token=None, lost={'code': e.code, 'text': text, 'at': now})
        raise
    return _store_token(data)


def refresh_stale(max_age=STALE_VIEW, timeout=8):
    """Check in now when the last answer is older than max_age seconds (a revoked, refunded or
    ended licence then shows when the page is opened or the module is used, not hours later).
    At most one try per max_age, and none within 2 minutes of a failed one. Never raises."""
    st = load_state()
    if not st.get('key'):
        return None
    now = time.time()
    last = max(int(st.get('last_ok') or 0), int(st.get('last_try') or 0))
    if now - last < max_age or now - int(st.get('last_error_at') or 0) < 120:
        return None
    try:
        check(timeout=timeout)
        return 'checked'
    except LicenceError as e:
        return f'check failed: {e}'


def refresh_if_due():
    """Called every few minutes by the backups timer; only talks to the server when due."""
    st = load_state()
    if not st.get('key') or not st.get('token'):
        # no licence here (or the licence server took it back): a licence linked to this server's
        # IP activates by itself; asked every 6 hours
        if time.time() - int(st.get('last_link') or 0) >= 6 * 3600:
            try:
                if link(force=True):
                    return 'linked'
            except LicenceError:
                pass
    if not st.get('key'):
        return 'no licence'
    cur = current()
    now = time.time()
    due_at = int(st.get('last_ok') or 0) + CHECK_EVERY
    if cur['refresh_after']:
        due_at = min(due_at, cur['refresh_after'])
    end = cur.get('period_end') or 0
    if end and now >= end and int(st.get('last_ok') or 0) < end:
        due_at = 0          # the paid period ended since the last answer: ask (a renewal may have come in)
    if now < due_at:
        return 'not due'
    last_err = st.get('last_error_at') or 0
    if last_err and now - last_err < 15 * 60:
        return 'waiting after an error'
    try:
        check()
        return 'checked'
    except LicenceError as e:
        return f'check failed: {e}'


def deactivate():
    st = load_state()
    if not st.get('key'):
        raise LicenceError('This server has no licence.', 'no_licence')
    info = _server_info()
    _call('POST', '/api/v1/deactivate', dict(info, key=st['key']))
    _save_state(token=None, key=None, lost=None)


# ---------------------------------------------------------------- module package
def download_module(dest_dir, version=None):
    """Download and verify the signed module package. Returns (path, meta)."""
    import requests
    st = load_state()
    if not st.get('key'):
        raise LicenceError('This server has no licence.', 'no_licence')
    body = dict(_server_info(), key=st['key'])
    if version:
        body['version'] = version
    meta = _call('POST', '/api/v1/module/release', body)
    if not re.fullmatch(r'\d+\.\d+\.\d+([.-][A-Za-z0-9]+)?', str(meta.get('version') or '')):
        raise LicenceError('The licence server sent an invalid version.', 'bad_answer', 502)
    if version and meta['version'] != version:
        raise LicenceError(f'The licence server sent version {meta["version"]} instead of {version}.', 'bad_answer', 502)
    cur = installed_module_version()
    if cur and not version:
        from panel.plugins import _vtuple
        if _vtuple(meta['version']) < _vtuple(cur):
            raise LicenceError(f'The newest release ({meta["version"]}) is older than the installed module '
                               f'({cur}); nothing to install.', 'older', 409)
    if not verify_release(MODULE, meta['version'], meta['sha256'], meta['signature']):
        raise LicenceError('The module package is not signed with a trusted key.', 'signature', 502)
    # Always download from the trusted licence server: only the path of the answer is used, so a
    # wrong public address on the licence server (or a proxy in front of it) cannot redirect the panel.
    from urllib.parse import urlsplit
    dl_path = urlsplit(str(meta.get('url') or '')).path
    if not re.fullmatch(r'/api/v1/module/download/[A-Za-z0-9_.\-]+', dl_path):
        raise LicenceError('The licence server sent an invalid download address.', 'bad_answer', 502)
    url = trust()['server'] + dl_path
    _ipv4_first()
    path = os.path.join(dest_dir, f'hosting-{meta["version"]}.tar.gz')
    h = hashlib.sha256()
    try:
        with requests.get(url, stream=True, timeout=120) as r:
            if r.status_code != 200:
                raise LicenceError(f'The download failed (HTTP {r.status_code}).', 'download', 502)
            with open(path, 'wb') as f:
                for chunk in r.iter_content(65536):
                    h.update(chunk)
                    f.write(chunk)
    except requests.RequestException as e:
        raise LicenceError('The download failed. Try again.', 'download', 503) from e
    if h.hexdigest() != meta['sha256']:
        os.remove(path)
        raise LicenceError('The downloaded package does not match its signature.', 'signature', 502)
    return path, meta


def installed_module_version():
    return _read(os.path.join(PANEL_DIR, 'plugins', MODULE, 'plugin.json'), {}).get('version', '')


def main(argv):
    cmd = argv[1] if len(argv) > 1 else 'status'
    if cmd == 'status':
        print(json.dumps(dict(current(), identity=identity()['server_id'], trust=trust()['server']), indent=2))
        return 0
    if cmd == 'check':
        try:
            p = check()
            print('no licence on this server' if p is None else f'{p.get("status_text")} (valid: {p.get("valid")})')
            return 0
        except LicenceError as e:
            print(f'check failed: {e}')
            return 1
    if cmd == 'install-module':
        from panel import module_install
        return module_install.run(argv[2] if len(argv) > 2 else None)
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.path.insert(0, PANEL_DIR) if os.path.isdir(PANEL_DIR) else None
    sys.exit(main(sys.argv))
