"""Upload tested zips to R2 and publish them in the signed catalog.

    python3 publish.py dist/ [--plan plan.json] [--review review.json] [--notes notes/]

Each build that passed its test is published; a server whose system has no passing
build simply is not offered that version (it keeps the version it has). Builds that
failed are listed in the run summary and the run is marked failed, so you get
GitHub's failure e-mail; re-run with force=app=version to add them later (files are
merged into the existing release). Security releases go straight to "stable"; others
start on "beta" and promote.py moves them to stable after SOFTS_PROMOTE_HOURS.
"""
import argparse
import glob
import json
import os
import sys
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dist')
    ap.add_argument('--plan', default='plan.json')
    ap.add_argument('--review', default='review.json')
    ap.add_argument('--notes', default='notes')
    ap.add_argument('--approve', default='', help='app=version,...: publish although the AI review held it')
    a = ap.parse_args()
    plan = json.load(open(a.plan)) if os.path.exists(a.plan) else []
    review = json.load(open(a.review)) if os.path.exists(a.review) else {}
    rs = C.recipes()
    zips = {}
    for p in glob.glob(os.path.join(a.dist, '**', '*.zip'), recursive=True):
        with zipfile.ZipFile(p) as z:
            m = json.loads(z.read('manifest.json'))
        zips[(m['app'], m['version'], m['target'], m['arch'])] = (p, m)

    cat = C.load_catalog()
    published, skipped, retried = [], [], []
    for item in plan:
        app, ver = item['app'], item['version']
        rv = review.get(f'{app}-{ver}') or {}
        approved = f'{app}={ver}' in [x.strip() for x in a.approve.split(',')]
        if rv.get('hold') and approved:
            C.log(f'{app} {ver}: held by the AI review, published because it was approved')
        if rv.get('hold') and not approved:
            skipped.append(f'{app} {ver}: held by the AI review ({"; ".join(rv.get("breaking") or [])[:300]})')
            continue
        old_rel = C.find_release(cat, app, ver) or {}
        files = dict(old_rel.get('files') or {})
        # this run's systems: all of them for a new release, only the retried/rechecked
        # ones for a published release (the others are already in `files`)
        planned = [(t, ar) for t, ar in C.build_matrix(rs[app])
                   if not item.get('only_targets') or f'{t}-{ar}' in item['only_targets']]
        not_offered_now = set(item.get('unavailable') or [])
        want = [(t, ar) for t, ar in planned if f'{t}-{ar}' not in not_offered_now]
        built = {f'{t}-{ar}' for t, ar in want if (app, ver, t, ar) in zips}
        missing = [f'{t}-{ar}' for t, ar in want if f'{t}-{ar}' not in built]
        if missing:
            skipped.append(f'{app} {ver}: no passing build for {", ".join(missing)}')
        if not built:
            if old_rel and missing:          # a retry that failed again: count it, keep the rest
                old_rel['retries'] = int(old_rel.get('retries') or 0) + 1
                old_rel['recipe_rev'] = C.recipe_rev(app)
                retried.append(f'{app} {ver}')
            continue
        for t, ar in want:
            if (app, ver, t, ar) not in zips:
                continue
            path, man = zips[(app, ver, t, ar)]
            sha = C.sha256_file(path)
            key = C.key_for(app, ver, t, ar, sha)
            if not C.exists(key):
                C.upload(path, key)
            files[f'{t}-{ar}'] = {'key': key, 'sha256': sha, 'size': os.path.getsize(path),
                                  'run_deps': len((man.get('run_deps') or {}).get(man.get('family') or 'deb', [])),
                                  'needs_glibc': man.get('needs_glibc', '')}
        still_missing = sorted((set(old_rel.get('missing') or []) - set(files)) | (set(missing) - set(files)))
        notes_path = os.path.join(a.notes, f'{app}-{ver}.md')
        notes = open(notes_path).read().strip() if os.path.exists(notes_path) else ''
        if notes:
            C.r2().put_object(Bucket=C.bucket(), Key=f'{app}/{ver}/notes.md', Body=notes.encode(),
                              ContentType='text/markdown; charset=utf-8')
        security = bool(rv.get('security'))
        a_entry = cat['apps'].setdefault(app, {'name': rs[app].get('name', app), 'panel_id': rs[app].get('panel_id', app),
                                               'releases': []})
        a_entry['name'] = rs[app].get('name', app)
        a_entry['panel_id'] = rs[app].get('panel_id', app)
        a_entry['coexist'] = bool(rs[app].get('coexist'))
        a_entry['releases'] = [r for r in a_entry['releases'] if r['version'] != ver]
        a_entry['releases'].append({
            'version': ver, 'track': item['track'],
            'channel': old_rel.get('channel') or ('stable' if security else 'beta'),
            'status': old_rel.get('status') or 'active', 'released': old_rel.get('released') or int(time.time()),
            'security': security or bool(old_rel.get('security')), 'cves': rv.get('cves') or old_rel.get('cves') or [],
            'breaking': rv.get('breaking') or old_rel.get('breaking') or [], 'notes': (notes or old_rel.get('notes') or '')[:1500],
            'files': files,
            **({'plugin': item['plugin']} if item.get('plugin') else ({'plugin': old_rel['plugin']} if old_rel.get('plugin') else {})),
            'missing': still_missing,
            # upstream has no file for these systems (they keep the OS packages; checked again for 14 days)
            'not_offered': sorted((set(old_rel.get('not_offered') or []) | not_offered_now) - set(files) - set(still_missing)),
            'retries': (int(old_rel.get('retries') or 0) + 1) if (old_rel and still_missing) else 0,
            'recipe_rev': C.recipe_rev(app),     # a recipe change makes failed systems retry
        })
        a_entry['releases'].sort(key=lambda r: C.vt(r['version']), reverse=True)
        published.append(f'{app} {ver} ({"stable, security" if security else "beta"}, {len(files)} systems'
                         + (f', not offered upstream: {", ".join(sorted(not_offered_now))}' if not_offered_now else '') + ')')

    if published or retried:
        C.save_catalog(cat)
    summary = '\n'.join(['Published:'] + [f'- {x}' for x in published] + ['', 'Not published:'] + [f'- {x}' for x in skipped])
    print(summary)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        open(os.environ['GITHUB_STEP_SUMMARY'], 'a').write(summary + '\n')
    C.gh_output('published', len(published))
    C.gh_output('skipped', len(skipped))


if __name__ == '__main__':
    main()
