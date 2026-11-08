"""Accounts at certificate providers (ZeroSSL, DigiCert), stored on this server only.

The file is readable by root only. It holds what the customer pasted from the
provider's own website: an e-mail address and EAB keys for ZeroSSL's free ACME
certificates, and API keys for paid orders. The panel never stores the password
of a provider account.
"""
import json
import os

PATH = os.environ.get('VP_SSL_ACCOUNTS', '/etc/vortexpanel/ssl-accounts.json')

# fields that are secret: never sent back to the browser
SECRET = {'eab_hmac', 'api_key'}


def _load():
    try:
        with open(PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(data):
    os.makedirs(os.path.dirname(PATH), mode=0o700, exist_ok=True)
    tmp = PATH + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, PATH)


def get(name):
    return dict(_load().get(name) or {})


def save(name, values):
    data = _load()
    data[name] = {k: v for k, v in (values or {}).items() if v not in (None, '')}
    _write(data)


def delete(name):
    data = _load()
    if data.pop(name, None) is not None:
        _write(data)


def public(name):
    """The account as the browser may see it: secrets replaced by a flag."""
    acct = get(name)
    out = {k: v for k, v in acct.items() if k not in SECRET}
    for k in SECRET:
        if acct.get(k):
            out[k + '_saved'] = True
    out['connected'] = bool(acct)
    return out
