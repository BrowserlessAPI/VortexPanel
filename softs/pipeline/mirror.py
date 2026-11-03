"""Mirror upstream release files into R2 ("kind": "mirror" recipes).

For tools the panel installs from a released file rather than a build (phpMyAdmin,
Adminer, Roundcube, Anubis, ffmpeg): the newest release of each followed track is
downloaded, checked against the upstream checksum where one is published, stored
in R2 and listed in the signed catalog's "pinned" section. Panels then install
only these copies (catalog URL + SHA-256), never straight from upstream.

    python3 mirror.py [--only phpmyadmin,adminer] [--dry-run]
"""
import argparse
import json
import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C  # noqa: E402
import watch as W  # noqa: E402


def _fmt(tpl, item):
    v = item['version']
    return tpl.format(version=v, track=item.get('track', ''), tag=item.get('tag', ''), under=v.replace('.', '_'),
                      major=v.split('.')[0], suffix=item.get('suffix', ''), branch=item.get('branch', ''))


def _upstream_sha(spec, item, url):
    """The checksum upstream publishes for this file, or '' when there is none."""
    if spec.get('sha256_url'):
        txt = C.http_get(_fmt(spec['sha256_url'], item), timeout=60)
        m = re.search(r'\b([0-9a-f]{64})\b', txt)
        return m.group(1) if m else ''
    if spec.get('sha256_list'):          # one checksums file for all assets: "<sha>  <name>"
        txt = C.http_get(_fmt(spec['sha256_list'], item), timeout=60)
        name = url.rsplit('/', 1)[-1]
        for line in txt.splitlines():
            p = line.split()
            if len(p) >= 2 and p[-1].lstrip('*') == name and re.fullmatch(r'[0-9a-f]{64}', p[0]):
                return p[0]
    return ''


def mirror_one(app, recipe, item, tmp, dry):
    files = {}
    for name, spec in recipe['files'].items():
        url = (item.get('assets') or {}).get(_fmt(spec['asset'], item)) if spec.get('asset') else _fmt(spec['url'], item)
        if not url:
            raise RuntimeError(f'{name}: no upstream file for {item["version"]}')
        want = _upstream_sha(spec, item, url)
        dest = os.path.join(tmp, f'{app}-{name}-{os.path.basename(url.split("?")[0])}')
        got = C.download(url, dest, want or None)
        key = f'pinned/{app}/{item["version"]}/{got[:16]}/{os.path.basename(url.split("?")[0])}'
        if not dry and not C.exists(key):
            C.upload(dest, key, content_type='application/octet-stream')
        files[name] = {'key': key, 'sha256': got, 'size': os.path.getsize(dest), 'upstream': url,
                       'checked': 'upstream checksum' if want else 'TLS download'}
        os.remove(dest)
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only', default='')
    ap.add_argument('--dry-run', action='store_true')
    a = ap.parse_args()
    only = [x for x in a.only.split(',') if x]
    cat = C.empty_catalog() if a.dry_run else C.load_catalog()
    section = cat.setdefault('pinned', {})
    done, failed = [], []
    tmp = tempfile.mkdtemp(prefix='vp-mirror-')
    for app, r in C.recipes(kind='mirror').items():
        if only and app not in only:
            continue
        try:
            found = W.SOURCES[r['watch']['type']](r['watch'])
        except Exception as e:  # noqa: BLE001
            failed.append(f'{app}: cannot read releases: {e}')
            continue
        entry = section.setdefault(app, {'name': r.get('name', app), 'panel_id': r.get('panel_id', app), 'releases': []})
        have = {x['version'] for x in entry['releases']}
        for item in W.pick(r, found):
            if item['version'] in have:
                continue
            try:
                files = mirror_one(app, r, item, tmp, a.dry_run)
            except Exception as e:  # noqa: BLE001
                failed.append(f'{app} {item["version"]}: {e}')
                continue
            entry['releases'].append({'version': item['version'], 'track': item['track'], 'channel': 'stable',
                                      'status': 'active', 'released': int(time.time()), 'files': files})
            done.append(f'{app} {item["version"]}')
        entry['releases'].sort(key=lambda x: C.vt(x['version']), reverse=True)
        keep, seen = [], {}
        for x in entry['releases']:          # newest 2 per track
            seen[x['track']] = seen.get(x['track'], 0) + 1
            if seen[x['track']] <= 2:
                keep.append(x)
        entry['releases'] = keep
    if done and not a.dry_run:
        C.save_catalog(cat)
    summary = '\n'.join(['Mirrored:'] + [f'- {x}' for x in done] + ['', 'Failed:'] + [f'- {x}' for x in failed])
    print(summary)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        open(os.environ['GITHUB_STEP_SUMMARY'], 'a').write(summary + '\n')
    if failed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
