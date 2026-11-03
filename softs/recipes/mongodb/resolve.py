"""Which MongoDB release tarball fits each system, from MongoDB's own download index
(downloads.mongodb.org/full.json: every release, its per-distribution archives and their
SHA-256). A system MongoDB builds nothing for is "not offered" (it keeps the OS packages)."""
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'pipeline'))
import common as C  # noqa: E402

_INDEX = {}

# own distribution name first, then binaries known to run there (same glibc/OpenSSL 3
# generation or older); the container test on the real system decides in the end
PREFER = {
    'el8': [r'rhel8\d*'], 'el9': [r'rhel9\d*'], 'el10': [r'rhel10\d*', r'rhel9\d*'],
    'ubuntu22': [r'ubuntu2204'], 'ubuntu24': [r'ubuntu2404', r'ubuntu2204'],
    'debian12': [r'debian12'], 'debian13': [r'debian13', r'debian12'],
}


def _index():
    if 'v' not in _INDEX:
        _INDEX['v'] = C.http_json('https://downloads.mongodb.org/full.json', timeout=120)
    return _INDEX['v']


def _num(t):
    m = re.search(r'(\d+)$', t)
    return int(m.group(1)) if m else 0


def resolve(item, target, arch):
    rel = next((r for r in _index().get('versions', []) if r.get('version') == item['version']), None)
    if rel is None:
        raise RuntimeError(f'MongoDB {item["version"]} is not in the download index yet')
    found = {}
    for d in rel.get('downloads', []):
        url = ((d.get('archive') or {}).get('url') or '')
        if d.get('arch') != arch or '/linux/mongodb-linux-' not in url or 'enterprise' in url \
                or d.get('edition') not in (None, 'base', 'targeted'):
            continue
        found[d.get('target', '')] = d['archive']
    for pat in PREFER.get(target, []):
        names = sorted((t for t in found if re.fullmatch(pat, t)), key=_num, reverse=True)
        if names:
            a = found[names[0]]
            out = {'VP_URL': a['url'], 'VP_MONGO_TARGET': names[0]}
            if re.fullmatch(r'[0-9a-f]{64}', str(a.get('sha256') or '')):
                out['VP_SHA256'] = a['sha256']
            return out
    return None
