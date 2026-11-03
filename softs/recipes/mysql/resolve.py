"""Oracle's generic Linux tarball for each processor: the first of the known download
locations that has it. None of them having it means "not offered" for that processor."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'pipeline'))
import common as C  # noqa: E402


def resolve(item, target, arch):
    v = item['version']
    ser = '.'.join(v.split('.')[:2])
    for flav in (f'glibc2.28-{arch}-minimal', f'glibc2.28-{arch}'):
        name = f'mysql-{v}-linux-{flav}.tar.xz'
        for base in (f'https://cdn.mysql.com/Downloads/MySQL-{ser}', f'https://cdn.mysql.com/archives/mysql-{ser}'):
            if C.url_exists(f'{base}/{name}', not_found_403=True):
                out = {'VP_URL': f'{base}/{name}'}
                return out
    return None
