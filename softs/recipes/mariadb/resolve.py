"""x86_64: the systemd binary tarball and its SHA-256 from the release's sha256sums.txt.
aarch64: the release's source tarball (compiled per system). A missing file means
"not offered" for that processor."""
import os
import re
import sys
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'pipeline'))
import common as C  # noqa: E402

BASE = 'https://archive.mariadb.org/mariadb-{v}'


def _sums(url):
    try:
        return C.http_get(url, timeout=60)
    except urllib.error.HTTPError as e:
        if e.code in (404, 410):
            return None
        raise


def resolve(item, target, arch):
    v = item['version']
    if arch == 'x86_64':
        name = f'mariadb-{v}-linux-systemd-x86_64.tar.gz'
        d = BASE.format(v=v) + '/bintar-linux-systemd-x86_64'
    else:
        name = f'mariadb-{v}.tar.gz'
        d = BASE.format(v=v) + '/source'
    txt = _sums(d + '/sha256sums.txt')
    if txt is None:
        return None
    for line in txt.splitlines():
        p = line.split()
        if len(p) >= 2 and p[-1].lstrip('*').lstrip('./') == name and re.fullmatch(r'[0-9a-f]{64}', p[0]):
            return {'VP_URL': f'{d}/{name}', 'VP_SHA256': p[0]}
    return None
