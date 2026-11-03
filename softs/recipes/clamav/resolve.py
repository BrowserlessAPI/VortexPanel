"""Cisco Talos' Linux release package for each processor, from the release's own asset
list. A processor without a package is "not offered" (it keeps the OS packages)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'pipeline'))
import common as C  # noqa: E402


def resolve(item, target, arch):
    assets = item.get('assets')
    if not assets:
        r = C.http_json(f'https://api.github.com/repos/Cisco-Talos/clamav/releases/tags/clamav-{item["version"]}')
        assets = {a['name']: a['browser_download_url'] for a in r.get('assets', [])}
    for name in (f'clamav-{item["version"]}.linux.{arch}.deb',
                 f'clamav-{item["version"]}.linux.{"arm64" if arch == "aarch64" else "amd64"}.deb'):
        if name in assets:
            return {'VP_URL': assets[name]}
    return None
