"""Country lookup from a local MMDB file (DB-IP Lite or MaxMind GeoLite2 Country).
Optional: without the `maxminddb` module or a database, regions show as unknown."""
import gzip
import os
import shutil
import tempfile
import time

DB_PATHS = ['/usr/share/GeoIP/GeoLite2-Country.mmdb', '/var/lib/GeoIP/GeoLite2-Country.mmdb',
            '/usr/share/GeoIP/dbip-country-lite.mmdb', '/etc/nginx/modsec/GeoLite2-Country.mmdb']
INSTALL_PATH = '/usr/share/GeoIP/dbip-country-lite.mmdb'      # shared with the WAF's region rules

_reader = None
_reader_path = None
_cache = {}


def db_path():
    for p in DB_PATHS:
        if os.path.exists(p) and os.path.getsize(p) > 0:
            return p
    return ''


def module_ok():
    try:
        import maxminddb  # noqa: F401
        return True
    except ImportError:
        return False


def status():
    return {'module': module_ok(), 'db': db_path()}


def _open():
    global _reader, _reader_path
    p = db_path()
    if not p:
        return None
    if _reader is not None and _reader_path == p:
        return _reader
    try:
        import maxminddb
        _reader = maxminddb.open_database(p)
        _reader_path = p
    except Exception:  # noqa: BLE001
        _reader = None
    return _reader


def country(ip):
    """ISO code ('DE') or '' when unknown/private."""
    if not ip:
        return ''
    c = _cache.get(ip)
    if c is not None:
        return c
    r = _open()
    code = ''
    if r is not None:
        try:
            rec = r.get(ip) or {}
            code = ((rec.get('country') or {}).get('iso_code') or
                    (rec.get('registered_country') or {}).get('iso_code') or '')
        except Exception:  # noqa: BLE001
            code = ''
    if len(_cache) > 200000:
        _cache.clear()
    _cache[ip] = code
    return code


def install(log=print):
    """Download the free DB-IP country database (CC BY 4.0). (ok, message)."""
    import urllib.request
    os.makedirs(os.path.dirname(INSTALL_PATH), exist_ok=True)
    lt = time.localtime()
    months = [time.strftime('%Y-%m', lt)]
    prev = time.localtime(time.mktime((lt.tm_year, lt.tm_mon, 1, 0, 0, 0, 0, 0, -1)) - 86400)
    months.append(time.strftime('%Y-%m', prev))
    for ym in months:
        url = f'https://download.db-ip.com/free/dbip-country-lite-{ym}.mmdb.gz'
        fd, tmp = tempfile.mkstemp(suffix='.mmdb.gz')
        os.close(fd)
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'VortexPanel'})
            with urllib.request.urlopen(req, timeout=120) as r, open(tmp, 'wb') as f:
                shutil.copyfileobj(r, f)
            with gzip.open(tmp, 'rb') as src, open(INSTALL_PATH + '.tmp', 'wb') as dst:
                shutil.copyfileobj(src, dst)
            os.replace(INSTALL_PATH + '.tmp', INSTALL_PATH)
            log(f'DB-IP country lite {ym} installed')
            global _reader
            _reader = None
            _cache.clear()
            return True, f'Country database {ym} installed (IP geolocation by DB-IP, CC BY 4.0)'
        except Exception as e:  # noqa: BLE001
            log(f'{ym}: {e}')
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return False, 'Could not download the country database (no internet access to download.db-ip.com?)'
