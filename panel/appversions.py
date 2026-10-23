"""Tested App Store versions from the VortexPanel licence server.

The licence server publishes the list of app versions the VortexPanel team
has installed and tested, signed with its Ed25519 key (the public key ships
in panel/trust/licence.json). Every panel fetches it once a day. It is free:
no licence, key or account is involved, and nothing is sent but the request.

What the list may change, per app:
  - relabel   labels, recommended, end of life, notices; only the versions this
              panel already knows (the install script decides what a value does)
  - track     also new version tracks (PHP 8.6, PostgreSQL 19, ...) whose value
              matches the app's pattern; the panel's install script takes the value
  - pinned    exact releases with their download addresses and SHA-256 checksums
              (Adminer, phpMyAdmin, Roundcube, Anubis); only https addresses on the
              hosts listed here, and the install checks the checksum

It never contains commands: install scripts stay in the panel code. When the
list cannot be fetched, is not signed by a trusted key, is older than the one
already stored, or does not match these rules, the panel keeps what it has
(the previous list, or its built-in versions).

    python3 -m panel.appversions refresh     fetch now
    python3 -m panel.appversions status      what is in use
"""
import base64
import json
import os
import re
import threading
import time
import urllib.request

INSTALL_DIR = '/opt/vortexpanel'
CACHE = os.path.join(INSTALL_DIR, 'data', 'app_versions_signed.json')
PATH = '/api/v1/app-versions'
MAX_AGE = 86400
RETRY = 3 * 3600
PREFIX = 'vpc1'
FORMAT = 1

# app id -> (mode, value pattern)
RULES = {
    'php':        ('track', r'(7\.4|8\.[0-9]|9\.[0-9])'),
    'postgresql': ('track', r'(1[3-9]|2[0-9])'),
    'nodejs':     ('track', r'(2[0-9]|3[0-9])'),
    'python':     ('track', r'3\.(1[0-9]|2[0-9])'),
    'mariadb':    ('track', r'(10\.11|1[1-9]\.[0-9]{1,2})'),
    'mongodb':    ('track', r'([6-9]|1[0-9])\.[0-9]'),
    'redis':      ('track', r'([7-9]|1[0-9])\.[0-9]{1,2}'),
    'caddy':      ('track', r'2\.[0-9]{1,2}\.[0-9]{1,2}'),
    'adminer':    ('pinned', r'[4-9]\.[0-9]{1,2}\.[0-9]{1,2}'),
    'phpmyadmin': ('pinned', r'[5-9]\.[0-9]{1,2}\.[0-9]{1,2}'),
    'roundcube':  ('pinned', r'1\.[0-9]{1,2}\.[0-9]{1,2}'),
    'anubis':     ('pinned', r'[1-9]\.[0-9]{1,2}\.[0-9]{1,2}'),
    'nginx': ('relabel', None), 'apache2': ('relabel', None), 'openlitespeed': ('relabel', None),
    'mysql': ('relabel', None), 'bind9': ('relabel', None), 'docker': ('relabel', None),
    'composer': ('relabel', None), 'pure-ftpd': ('relabel', None), 'fail2ban': ('relabel', None),
    'postfix': ('relabel', None), 'clamav': ('relabel', None), 'supervisor': ('relabel', None),
    'memcached': ('relabel', None), 'modsecurity': ('relabel', None),
}
# files a pinned app needs, and where they may come from
PINNED_FILES = {
    'adminer':    {'adminer', 'mongo'},
    'phpmyadmin': {'tarball'},
    'roundcube':  {'tarball'},
    'anubis':     {'amd64', 'arm64'},
}
HOSTS = {'github.com', 'raw.githubusercontent.com', 'files.phpmyadmin.net'}
# the download addresses each pinned app accepts (host, characters, file type)
URL_RULES = {
    'adminer':    r'https://(github\.com|raw\.githubusercontent\.com)/[A-Za-z0-9._/-]+\.php',
    'phpmyadmin': r'https://(files\.phpmyadmin\.net|github\.com)/[A-Za-z0-9._/-]+\.tar\.gz',
    'roundcube':  r'https://github\.com/[A-Za-z0-9._/-]+\.tar\.gz',
    'anubis':     r'https://github\.com/[A-Za-z0-9._/-]+\.tar\.gz',
}

_lock = threading.Lock()
_busy = {'on': False}


# ------------------------------------------------------------------ signature
def _b64u_dec(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def _trust():
    try:
        from panel.licence import trust
        return trust()
    except Exception:  # noqa: BLE001
        return {'server': '', 'keys': []}


def verify(token):
    """The list when the token is signed by a trusted key and well formed, else None."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        prefix, body, sig = str(token or '').split('.')
        if prefix != PREFIX:
            return None
        msg = f'{prefix}.{body}'.encode()
        for k in _trust()['keys']:
            try:
                Ed25519PublicKey.from_public_bytes(base64.b64decode(k)).verify(_b64u_dec(sig), msg)
            except Exception:  # noqa: BLE001
                continue
            data = json.loads(_b64u_dec(body))
            if not isinstance(data, dict) or data.get('format') != FORMAT or not isinstance(data.get('apps'), dict):
                return None
            if not isinstance(data.get('serial'), int):
                return None
            return data
    except Exception:  # noqa: BLE001
        return None
    return None


def _panel_version():
    for p in (os.path.join(INSTALL_DIR, 'VERSION'),
              os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'VERSION')):
        try:
            return open(p).read().strip()
        except OSError:
            continue
    return '0'


def _vt(v):
    try:
        return tuple(int(x) for x in re.findall(r'\d+', str(v))[:3])
    except Exception:  # noqa: BLE001
        return ()


# ------------------------------------------------------------------ cache
def _read():
    try:
        with open(CACHE) as f:
            d = json.load(f)
    except Exception:  # noqa: BLE001
        return {}
    if not isinstance(d, dict):
        return {}
    try:
        d['checked'] = int(d.get('checked') or 0)
    except (TypeError, ValueError):
        d['checked'] = 0
    return d


def _write(d):
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    tmp = CACHE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(d, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, CACHE)


def load():
    """The verified list in use, or None. Checked on every load (cheap), so a
    hand-edited cache file is ignored."""
    st = _read()
    data = verify(st.get('token'))
    if not data:
        return None
    if _vt(data.get('min_core') or '0') > _vt(_panel_version()):
        return None
    return data


def status():
    st = _read()
    data = load()
    return {'in_use': bool(data), 'serial': (data or {}).get('serial', 0), 'issued': (data or {}).get('issued', ''),
            'checked': st.get('checked', 0), 'error': st.get('error', ''), 'server': _trust()['server']}


def refresh(force=False):
    """Fetch the list (at most once a day unless forced). -> status()"""
    st = _read()
    if not force and time.time() - st.get('checked', 0) < (MAX_AGE if not st.get('error') else RETRY):
        return status()
    with _lock:
        server = _trust()['server']
        err = ''
        try:
            if not server.startswith('https://') and not os.environ.get('VP_ALLOW_DEV_TRUST'):
                raise ValueError('no licence server address in panel/trust/licence.json')
            req = urllib.request.Request(server + PATH, headers={
                'User-Agent': f'VortexPanel/{_panel_version()} (app versions)', 'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=20) as r:
                body = json.loads(r.read(2_000_000).decode())
            token = body.get('token') if isinstance(body, dict) else None
            data = verify(token)
            if not data:
                raise ValueError('the list is not signed by a trusted key')
            if _vt(data.get('min_core') or '0') > _vt(_panel_version()):
                # meant for newer panels: keep the list this panel can use
                raise ValueError(f'list #{data["serial"]} needs VortexPanel {data.get("min_core")} or newer')
            cur = verify(st.get('token'))
            if cur and data['serial'] < cur['serial']:
                raise ValueError(f'older list (#{data["serial"]}) than the one in use (#{cur["serial"]})')
            if not cur or data['serial'] != cur['serial']:
                st['token'] = token
                st['fetched'] = int(time.time())
        except Exception as e:  # noqa: BLE001
            err = str(e)[:300]
        st['checked'] = int(time.time())
        st['error'] = err
        try:
            _write(st)
        except OSError:
            pass
    try:
        from panel import panel_cache
        panel_cache.invalidate('modules_list')
    except Exception:  # noqa: BLE001
        pass
    return status()


def refresh_async():
    st = _read()
    if _busy['on'] or time.time() - st.get('checked', 0) < (MAX_AGE if not st.get('error') else RETRY):
        return
    _busy['on'] = True

    def run():
        try:
            refresh()
        finally:
            _busy['on'] = False
    threading.Thread(target=run, daemon=True).start()


# ------------------------------------------------------------------ merging
_LABEL_BAD = re.compile(r'[\x00-\x1f<>`]')


def _label(v):
    v = str(v or '').strip()
    return v[:140] if v and not _LABEL_BAD.search(v) else ''


def _file_ok(f, app=''):
    if not isinstance(f, dict):
        return None
    url, sha = str(f.get('url') or ''), str(f.get('sha256') or '').lower()
    m = re.fullmatch(r'https://([a-z0-9.-]+)(/[A-Za-z0-9._~/%+-]*)', url)
    if not m or m.group(1) not in HOSTS or '..' in url or not re.fullmatch(r'[0-9a-f]{64}', sha):
        return None
    if app in URL_RULES and not re.fullmatch(URL_RULES[app], url):
        return None
    return {'url': url, 'sha256': sha}


def entries(mod_id, builtin, data=None):
    """The app's versions from the signed list, checked against the rules, or None
    (use the built-in list). Each entry: value, label, recommended, eol, lts, version,
    files (pinned apps), tested."""
    data = data if data is not None else load()
    app = ((data or {}).get('apps') or {}).get(mod_id)
    rule = RULES.get(mod_id)
    if not isinstance(app, dict) or not rule or not isinstance(app.get('versions'), list):
        return None
    mode, pattern = rule
    known = {str(v.get('value')): v for v in builtin or []}
    out, seen = [], set()
    for e in app['versions'][:20]:
        if not isinstance(e, dict):
            continue
        value = str(e.get('value') or '')
        if value in seen:
            continue
        if mode == 'relabel':
            if value not in known:
                continue
        elif mode == 'track':
            if value not in known and not re.fullmatch(pattern, value):
                continue
        elif not re.fullmatch(pattern, value):        # pinned
            continue
        label = _label(e.get('label')) or (known.get(value) or {}).get('label') or value
        item = {'value': value, 'label': label, 'tested': True}
        for flag in ('recommended', 'eol', 'lts'):
            if e.get(flag) is True:
                item[flag] = True
        ver = str(e.get('version') or '')
        if re.fullmatch(r'[0-9][0-9A-Za-z.+-]{0,30}', ver):
            item['version'] = ver
        if mode == 'pinned':
            files = e.get('files') if isinstance(e.get('files'), dict) else {}
            need = PINNED_FILES.get(mod_id, set())
            checked = {k: _file_ok(files.get(k), mod_id) for k in need}
            if not all(checked.values()):
                continue
            item['files'] = checked
        out.append(item)
        seen.add(value)
    if not out:
        return None
    if not any(x.get('recommended') for x in out):
        out[0]['recommended'] = True
    return out


def notice(mod_id, data=None):
    data = data if data is not None else load()
    app = ((data or {}).get('apps') or {}).get(mod_id)
    if isinstance(app, dict):
        return _label(app.get('notice'))[:140] if app.get('notice') else ''
    return ''


if __name__ == '__main__':
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'status'
    print(json.dumps(refresh(force=True) if cmd == 'refresh' else status(), indent=1))
