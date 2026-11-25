"""Build an offline bundle (and optionally a servable mirror tree) of VortexPanel server
software and VortexPanel Apps.

Run this on any machine with internet. Transfer the bundle to an air-gapped or
restricted-network panel and import it there (App Store > Offline & mirrors > Import bundle,
or `vortexpanel offline import <file>`). A bundle is just the signed catalog / App index plus
the package files you chose; the panel verifies every signature and checksum on import, so
nothing in the bundle has to be trusted and it cannot smuggle in modified software.

No dependencies and no credentials: it reads the public download URLs.

    python3 bundle.py --out vp-bundle.tar \
        --catalog-url https://dl.vortexpanel.dev --apps-url https://apps.vortexpanel.dev \
        --apps all --software nginx,php,mariadb --targets ubuntu24-x86_64,el9-x86_64

Options:
    --apps all|<id,...>        VortexPanel Apps to include (default: none)
    --software all|<id,...>    server software to include (default: none)
    --pinned all|<id,...>      pinned tools (phpMyAdmin, Adminer, ...) to include (default: none)
    --targets <t-arch,...>     software variants to include (default: every variant in the catalog)
    --channel stable|beta      which release of each item (default: stable)
    --all-versions             include every kept release, not just the newest
    --mirror-dir DIR           also write a mirror tree you can serve over HTTP and point a
                               panel's mirror setting at (software at DIR/, Apps at DIR/apps/)
"""
import argparse
import hashlib
import json
import os
import sys
import tarfile
import tempfile
import urllib.request

UA = 'VortexPanel-bundle'


def fetch(url, cap=16 << 30):
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=300) as r:
        data = r.read(cap + 1)
    if len(data) > cap:
        raise SystemExit(f'{url} is unexpectedly large')
    return data


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def pick(ids_arg, available):
    if not ids_arg:
        return []
    if ids_arg == 'all':
        return sorted(available)
    want = [x.strip() for x in ids_arg.split(',') if x.strip()]
    missing = [x for x in want if x not in available]
    if missing:
        raise SystemExit(f'not in the catalog: {", ".join(missing)} (available: {", ".join(sorted(available))})')
    return want


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--catalog-url', default='https://dl.vortexpanel.dev')
    ap.add_argument('--apps-url', default='')
    ap.add_argument('--apps', default='')
    ap.add_argument('--software', default='')
    ap.add_argument('--pinned', default='')
    ap.add_argument('--targets', default='')
    ap.add_argument('--channel', default='stable', choices=['stable', 'beta'])
    ap.add_argument('--all-versions', action='store_true')
    ap.add_argument('--mirror-dir', default='')
    a = ap.parse_args()
    if not (a.apps or a.software or a.pinned):
        raise SystemExit('nothing selected: pass --software, --apps and/or --pinned')

    catalog_url = a.catalog_url.rstrip('/')
    apps_url = a.apps_url.rstrip('/')
    targets = [t.strip() for t in a.targets.split(',') if t.strip()]
    staged = {}          # key -> bytes (verified)
    files = {}           # json name in bundle -> (bytes, sig bytes)

    def want_release(r, newest):
        if r.get('status', 'active') != 'active':
            return False
        if a.channel == 'stable' and r.get('channel', 'stable') != 'stable':
            return False
        return a.all_versions or r is newest

    # --- server software + pinned tools (one signed catalog) -----------------
    if a.software or a.pinned:
        raw = fetch(f'{catalog_url}/catalog.json')
        cat = json.loads(raw)
        sig = fetch(f'{catalog_url}/catalog.json.sig')
        files['catalog.json'] = (raw, sig)   # the original signed bytes, never re-serialized
        for section, arg in (('apps', a.software), ('pinned', a.pinned)):
            entries = cat.get(section) or {}
            for sid in pick(arg, set(entries)):
                rels = sorted(entries[sid].get('releases') or [],
                              key=lambda r: tuple(int(x) if x.isdigit() else -1 for x in r.get('version', '0').replace('-', '.').split('.')),
                              reverse=True)
                newest = next((r for r in rels if r.get('status', 'active') == 'active'
                               and (a.channel != 'stable' or r.get('channel', 'stable') == 'stable')), None)
                for r in rels:
                    if not want_release(r, newest):
                        continue
                    for variant, f in (r.get('files') or {}).items():
                        if targets and variant not in targets:
                            continue
                        key = str(f['key']).lstrip('/')
                        print(f'  software {sid} {r["version"]} [{variant}]', file=sys.stderr)
                        data = fetch(f'{catalog_url}/{key}')
                        if sha256(data) != f['sha256']:
                            raise SystemExit(f'checksum mismatch for {key}')
                        staged[key] = data

    # --- VortexPanel Apps (one signed index) ---------------------------------
    if a.apps:
        if not apps_url:
            raise SystemExit('--apps needs --apps-url (the Apps R2 domain)')
        raw = fetch(f'{apps_url}/index.json')
        idx = json.loads(raw)
        sig = fetch(f'{apps_url}/index.json.sig')
        files['apps-index.json'] = (raw, sig)   # the original signed bytes, never re-serialized
        entries = idx.get('apps') or {}
        for aid in pick(a.apps, set(entries)):
            rels = sorted(entries[aid].get('releases') or [],
                          key=lambda r: tuple(int(x) if x.isdigit() else -1 for x in r.get('version', '0').replace('-', '.').split('.')),
                          reverse=True)
            newest = next((r for r in rels if r.get('status', 'active') == 'active'
                           and (a.channel != 'stable' or r.get('channel', 'stable') == 'stable')), None)
            for r in rels:
                if not want_release(r, newest):
                    continue
                f = r.get('file') or {}
                key = str(f['key']).lstrip('/')
                print(f'  app {aid} {r["version"]}', file=sys.stderr)
                data = fetch(f'{apps_url}/{key}')
                if sha256(data) != f['sha256']:
                    raise SystemExit(f'checksum mismatch for {key}')
                staged[key] = data

    if not staged:
        raise SystemExit('no files matched the selection (check --channel / --targets)')

    # --- write the bundle tar ------------------------------------------------
    manifest = {'tool': 'vortexpanel-bundle', 'files': len(staged),
                'catalog': 'catalog.json' in files, 'apps_index': 'apps-index.json' in files}
    with tempfile.TemporaryDirectory() as tmp:
        def add(tf, arcname, data):
            p = os.path.join(tmp, 'blob')
            with open(p, 'wb') as fh:
                fh.write(data)
            tf.add(p, arcname=arcname)
        with tarfile.open(a.out, 'w') as tf:
            for name, (raw, sg) in files.items():
                add(tf, name, raw)
                add(tf, name + '.sig', sg)
            for key, data in staged.items():
                add(tf, f'files/{key}', data)
            add(tf, 'manifest.json', json.dumps(manifest, indent=1).encode())
    size = os.path.getsize(a.out)
    print(f'wrote {a.out} ({size // 1024 // 1024} MB, {len(staged)} file(s))', file=sys.stderr)

    # --- optional servable mirror tree ---------------------------------------
    if a.mirror_dir:
        d = a.mirror_dir
        for name, (raw, sg) in files.items():
            # software catalog serves at the root; the App index serves under apps/ as index.json
            sub = 'apps' if name == 'apps-index.json' else ''
            base = os.path.join(d, sub)
            os.makedirs(base, exist_ok=True)
            out_name = 'index.json' if name == 'apps-index.json' else name
            open(os.path.join(base, out_name), 'wb').write(raw)
            open(os.path.join(base, out_name + '.sig'), 'wb').write(sg)
        for key, data in staged.items():
            sub = 'apps' if key.startswith('apps/') else ''
            p = os.path.join(d, sub, key)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, 'wb').write(data)
        print(f'wrote mirror tree to {d}/  (serve it, then add {d} as a software mirror and '
              f'{d}/apps as an App mirror)', file=sys.stderr)


if __name__ == '__main__':
    main()
