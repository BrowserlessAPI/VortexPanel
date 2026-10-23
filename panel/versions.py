"""Live version information for the App Store.

The catalog in panel/routes/modules.py carries version *tracks* (PHP 8.4,
PostgreSQL 18, Node.js 24, ...). Their labels used to hard-code patch
numbers ("8.4.26") that went stale between panel releases, and new tracks
(PostgreSQL 19, Python 3.15) only appeared after a panel update.

This module asks endoflife.date (a public, community-maintained API that
tracks release cycles, latest patch versions and end-of-life dates) at most
once a day, caches the answer in data/versions_live.json, and:
  - rewrites each known track's label with its current latest patch version
    and support status (LTS, security fixes only, end of life);
  - adds newer tracks the catalog does not list yet, for apps whose install
    script accepts any track number;
  - marks one track as recommended (the newest LTS, or the newest supported
    track for apps without LTS releases).
When the API cannot be reached the static catalog is used unchanged.
"""
import json
import os
import re
import threading
import time
import urllib.request
from datetime import date

CACHE = '/opt/vortexpanel/data/versions_live.json'
MAX_AGE = 86400
API_V1 = 'https://endoflife.date/api/v1/products/{}/'
API_LEGACY = 'https://endoflife.date/api/{}.json'

# mod_id -> (endoflife.date product, how a cycle maps to the catalog value,
#            may new cycles be added, prefer LTS for the recommendation)
PRODUCTS = {
    'php':        ('php', None, True, False),
    'postgresql': ('postgresql', None, True, False),
    'nodejs':     ('nodejs', None, True, True),
    'python':     ('python', None, True, False),
    'mariadb':    ('mariadb', None, True, True),
    'mysql':      ('mysql', None, False, True),
    'mongodb':    ('mongodb', None, False, False),
    'redis':      ('redis', None, False, False),
    'apache2':    ('apache-http-server', None, False, False),
    'docker':     ('docker-engine', None, False, False),
    'nginx':      ('nginx', None, False, False),       # branches: see _nginx_labels()
}
# Oldest cycle worth offering per app when new cycles are added.
_MIN_NEW = {'python': (3, 10), 'php': (8, 1), 'postgresql': (13,), 'nodejs': (20,), 'mariadb': (10, 11)}

_lock = threading.Lock()
_refreshing = {'on': False}


def _vt(v):
    try:
        return tuple(int(x) for x in str(v).split('.'))
    except Exception:
        return ()


def _get_json(url, timeout=12):
    req = urllib.request.Request(url, headers={'User-Agent': 'VortexPanel (version check)',
                                               'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _fetch(product):
    """Normalised list of cycles: name, latest, lts, eol (bool), eol_date,
    security_only (bool), released."""
    today = date.today().isoformat()
    out = []
    try:
        d = _get_json(API_V1.format(product))
        for r in (d.get('result') or {}).get('releases') or []:
            eol_from = r.get('eolFrom') or ''
            out.append({
                'name': str(r.get('name')), 'latest': ((r.get('latest') or {}).get('name') or ''),
                'lts': bool(r.get('isLts')), 'eol': bool(r.get('isEol')), 'eol_date': eol_from,
                'security_only': bool(r.get('isMaintained')) and not r.get('isEol') and
                                 bool(r.get('eoasFrom')) and str(r.get('eoasFrom')) <= today,
                'released': r.get('releaseDate') or '',
            })
        if out:
            return out
    except Exception:
        pass
    d = _get_json(API_LEGACY.format(product))
    for r in d:
        eol = r.get('eol')
        support = r.get('support')
        eol_bool = eol is True or (isinstance(eol, str) and eol <= today)
        out.append({
            'name': str(r.get('cycle')), 'latest': str(r.get('latest') or ''),
            'lts': bool(r.get('lts')), 'eol': eol_bool, 'eol_date': eol if isinstance(eol, str) else '',
            'security_only': (not eol_bool) and isinstance(support, str) and support <= today,
            'released': r.get('releaseDate') or '',
        })
    return out


def load():
    try:
        with open(CACHE) as f:
            return json.load(f)
    except Exception:
        return {}


def refresh(force=False):
    """Fetch every product (skipped when the cache is fresh). Returns the cache."""
    cur = load()
    if not force and time.time() - cur.get('at', 0) < MAX_AGE:
        return cur
    with _lock:
        data = {'at': int(time.time()), 'products': {}, 'errors': {}}
        for mod_id, (product, *_rest) in PRODUCTS.items():
            try:
                data['products'][mod_id] = _fetch(product)
            except Exception as e:
                data['errors'][mod_id] = str(e)[:200]
                if mod_id in (cur.get('products') or {}):
                    data['products'][mod_id] = cur['products'][mod_id]
        if not data['products'] and cur.get('products'):
            # Offline: keep the old data, retry in an hour.
            cur['at'] = int(time.time()) - MAX_AGE + 3600
            data = cur
        try:
            os.makedirs(os.path.dirname(CACHE), exist_ok=True)
            tmp = CACHE + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(data, f)
            os.replace(tmp, CACHE)
        except Exception:
            pass
        return data


def refresh_async():
    if _refreshing['on'] or time.time() - load().get('at', 0) < MAX_AGE:
        return
    _refreshing['on'] = True

    def run():
        try:
            refresh()
        finally:
            _refreshing['on'] = False
    threading.Thread(target=run, daemon=True).start()


def _status(c):
    if c['eol']:
        return 'end of life - no security fixes'
    if c['security_only']:
        return 'security fixes only'
    return ''


def _nginx_labels(versions, cycles):
    """nginx installs by branch ('stable' / 'mainline' from nginx.org), not by
    version: the newest even minor is the stable branch, the newest odd minor
    the mainline branch."""
    rel = [c for c in cycles if len(_vt(c['name'])) >= 2 and not c['eol']]
    even = [c for c in rel if _vt(c['name'])[1] % 2 == 0]
    odd = [c for c in rel if _vt(c['name'])[1] % 2 == 1]
    pick = {'stable': max(even, key=lambda c: _vt(c['name']), default=None),
            'mainline': max(odd, key=lambda c: _vt(c['name']), default=None)}
    for v in versions:
        c = pick.get(v['value'])
        if c and c.get('latest'):
            # the version first: the App Store compares it with the installed one
            v['label'] = (f"{c['latest']} Stable (nginx.org stable branch)" if v['value'] == 'stable'
                          else f"{c['latest']} Mainline (nginx.org newest features)")
    return versions


def apply(mod, live=None):
    """Return a copy of the catalog entry's version list with live labels,
    new tracks and a 'recommended' flag."""
    versions = [dict(v) for v in (mod.get('versions') or [])]
    spec = PRODUCTS.get(mod.get('id'))
    live = live if live is not None else load()
    if mod.get('id') == 'nginx':
        return _nginx_labels(versions, (live.get('products') or {}).get('nginx') or [])
    cycles = ((live.get('products') or {}).get(mod.get('id')) or []) if spec else []
    today = time.strftime('%Y-%m-%d')
    cycles = [c for c in cycles
              if not re.search(r'(a|b|rc|alpha|beta|dev)\d*$', c.get('latest') or '', re.I)
              and (c.get('released') or '') <= today]
    if cycles:
        _, _, can_add, prefer_lts = spec
        for v in versions:          # live data decides the recommendation
            v.pop('recommended', None)
        by_name = {c['name']: c for c in cycles}
        values = {v['value'] for v in versions}
        newest = max((c for c in cycles if _vt(c['name'])), key=lambda c: _vt(c['name']), default=None)
        if can_add:
            floor = _MIN_NEW.get(mod['id'], ())
            for c in sorted(cycles, key=lambda c: _vt(c['name']), reverse=True):
                if c['name'] in values or c['eol'] or not _vt(c['name']) or _vt(c['name']) < floor:
                    continue
                if versions and _vt(c['name']) < max((_vt(v['value']) for v in versions if _vt(v['value'])), default=()):
                    continue     # only add tracks newer than the catalog's newest
                versions.insert(0, {'value': c['name'], 'label': c['name'], 'added_live': True})
                values.add(c['name'])
        if all(_vt(v['value']) for v in versions):
            versions.sort(key=lambda v: _vt(v['value']), reverse=True)
        for v in versions:
            c = by_name.get(v['value'])
            if not c:
                v['label'] = re.sub(r'\s*\(latest\)', '', v['label'])
                continue
            tags = []
            if newest and c['name'] == newest['name']:
                tags.append('latest')
            if c['lts']:
                tags.append('LTS')
            st = _status(c)
            if st:
                tags.append(st)
            head = c['latest'] or c['name']
            v['label'] = head + (f' ({", ".join(tags)})' if tags else '')
            v['eol'] = c['eol']
            v['lts'] = c['lts']
        if not any(v.get('recommended') for v in versions):
            ok = [v for v in versions if v['value'] in by_name and not by_name[v['value']]['eol']
                  and not by_name[v['value']]['security_only']]
            pick = None
            if prefer_lts:
                lts = [v for v in ok if by_name[v['value']]['lts']]
                if lts:
                    pick = max(lts, key=lambda v: _vt(v['value']))
            if not pick and ok:
                # Newest supported track, but not one released in the last
                # 60 days (let the first bug-fix releases land first).
                cutoff = time.strftime('%Y-%m-%d', time.gmtime(time.time() - 60 * 86400))
                settled = [v for v in ok if (by_name[v['value']]['released'] or '0') <= cutoff] or ok
                pick = max(settled, key=lambda v: _vt(v['value']))
            if pick:
                pick['recommended'] = True
    if versions and not any(v.get('recommended') for v in versions):
        versions[0]['recommended'] = True
    for v in versions:
        if v.get('recommended') and 'recommended' not in v['label'].lower():
            v['label'] += ' - recommended'
    return versions
