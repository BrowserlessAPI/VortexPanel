"""Publish VortexPanel Apps (panel/apps_bundle/<id>) to the download server.

Runs on every push that changes an App and every day. An App whose plugin.json
version is not in the catalog yet is checked (manifest, every .py compiles, every
.json parses, pages/static present), packed into a zip and published; panels then
offer "Update to vX" without a panel release.

    python3 panel_apps.py [--only site-stats] [--dry-run]
"""
import argparse
import json
import os
import py_compile
import re
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C  # noqa: E402

BUNDLE = os.path.join(os.path.dirname(C.ROOT), 'panel', 'apps_bundle')
LISTING = ('name', 'category', 'summary', 'description', 'icon', 'color', 'features', 'engines', 'order',
           'conflicts', 'pages')


def check(d, man):
    """Raise on anything that would not load in a panel."""
    if man.get('kind') != 'app' or man.get('id') != os.path.basename(d) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,40}', man['id']):
        raise ValueError('plugin.json: kind must be "app" and id the folder name')
    if not re.fullmatch(r'\d+\.\d+\.\d+', str(man.get('version', ''))):
        raise ValueError('plugin.json: version must be X.Y.Z')
    for root, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x != '__pycache__']
        for fn in files:
            p = os.path.join(root, fn)
            if os.path.islink(p):
                raise ValueError(f'symbolic link not allowed: {p}')
            if fn.endswith('.py'):
                py_compile.compile(p, cfile=os.path.join(tempfile.gettempdir(), 'vp-check.pyc'), doraise=True)
            elif fn.endswith('.json'):
                json.load(open(p))
    for pg in man.get('pages') or []:
        if pg.get('template') and not os.path.exists(os.path.join(d, pg['template'])):
            raise ValueError(f'page template missing: {pg["template"]}')


def pack(d, man, out_dir):
    path = os.path.join(out_dir, f'app-{man["id"]}-{man["version"]}.zip')
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(d):
            dirs[:] = sorted(x for x in dirs if x != '__pycache__')
            for fn in sorted(files):
                if fn.endswith('.pyc'):
                    continue
                p = os.path.join(root, fn)
                zi = zipfile.ZipInfo(os.path.relpath(p, d), date_time=(2026, 1, 1, 0, 0, 0))
                zi.external_attr = 0o644 << 16
                zi.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(zi, open(p, 'rb').read())
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only', default='')
    ap.add_argument('--dry-run', action='store_true')
    a = ap.parse_args()
    only = [x for x in a.only.split(',') if x]
    cat = C.empty_catalog() if a.dry_run else C.load_catalog()
    section = cat.setdefault('panel_apps', {})
    done, failed = [], []
    out_dir = tempfile.mkdtemp(prefix='vp-apps-')
    for aid in sorted(os.listdir(BUNDLE)):
        d = os.path.join(BUNDLE, aid)
        if not os.path.isfile(os.path.join(d, 'plugin.json')) or (only and aid not in only):
            continue
        man = json.load(open(os.path.join(d, 'plugin.json')))
        entry = section.setdefault(aid, {'releases': []})
        if any(r['version'] == man.get('version') for r in entry['releases']):
            continue
        try:
            check(d, man)
            path = pack(d, man, out_dir)
        except Exception as e:  # noqa: BLE001
            failed.append(f'{aid} {man.get("version")}: {e}')
            continue
        sha = C.sha256_file(path)
        key = f'panel-apps/{aid}/{man["version"]}/{sha[:16]}/{os.path.basename(path)}'
        if not a.dry_run and not C.exists(key):
            C.upload(path, key)
        entry['name'] = man.get('name', aid)
        entry['releases'] = [r for r in entry['releases'] if r['version'] != man['version']]
        entry['releases'].append({
            'version': man['version'], 'channel': 'beta', 'status': 'active', 'released': int(time.time()),
            'requires_core': man.get('requires_core', ''), 'notes': str(man.get('changes') or '')[:1500],
            'manifest': {k: man[k] for k in LISTING if k in man},
            'file': {'key': key, 'sha256': sha, 'size': os.path.getsize(path)},
        })
        entry['releases'].sort(key=lambda r: C.vt(r['version']), reverse=True)
        entry['releases'] = entry['releases'][:5]
        done.append(f'{aid} {man["version"]}')
    if done and not a.dry_run:
        C.save_catalog(cat)
    summary = '\n'.join(['Panel Apps published:'] + [f'- {x}' for x in done] + ['', 'Failed checks:'] + [f'- {x}' for x in failed])
    print(summary)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        open(os.environ['GITHUB_STEP_SUMMARY'], 'a').write(summary + '\n')
    if failed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
