"""Which libmodsecurity the ModSecurity module is compiled against: the newest version
published as stable (and active) for this system in the catalog, so the module never needs
library symbols newer than what servers can install. Without one, build.sh uses the
newest release tag. Every system is built either way."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'pipeline'))
import common as C  # noqa: E402

_CAT = {}


def _catalog():
    if 'c' not in _CAT:
        try:
            _CAT['c'] = C.load_catalog()
        except Exception:  # noqa: BLE001 - no download server yet (first runs, local tests)
            _CAT['c'] = {}
    return _CAT['c']


def resolve(item, target, arch):
    key = f'{target}-{arch}'
    best = None
    for r in C.releases(_catalog(), 'libmodsecurity'):
        if r.get('channel') != 'stable' or r.get('status', 'active') != 'active':
            continue
        if key not in (r.get('files') or {}):
            continue
        if best is None or C.vt(r['version']) > C.vt(best):
            best = r['version']
    return {'VP_MODSEC_VERSION': best} if best else {}
