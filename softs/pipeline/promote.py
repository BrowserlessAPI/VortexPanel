"""Catalog maintenance (runs daily after the build, or on demand):

  - beta releases older than SOFTS_PROMOTE_HOURS (default 24) become stable
  - withdraw:  python3 promote.py --withdraw nginx=1.31.8   (panels offer a rollback)
  - restore:   python3 promote.py --restore nginx=1.31.8
  - prune:     keeps the newest SOFTS_KEEP_PER_TRACK (default 3) releases per track;
               older zips are deleted from R2
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--withdraw', default='')
    ap.add_argument('--restore', default='')
    ap.add_argument('--promote-now', default='', help='app=version: move to stable now')
    a = ap.parse_args()
    hours = float(os.environ.get('SOFTS_PROMOTE_HOURS', '24'))
    keep = int(os.environ.get('SOFTS_KEEP_PER_TRACK', '3'))
    cat = C.load_catalog()
    changed = []
    now = time.time()

    def pairs(s):
        return [x.split('=', 1) for x in s.split(',') if '=' in x]

    def find(app, ver):
        # "app:site-stats=1.1.0" names a VortexPanel App, anything else server software
        if app.startswith('app:'):
            return next((r for r in ((cat.get('panel_apps') or {}).get(app[4:]) or {}).get('releases') or []
                         if r['version'] == ver), None)
        return C.find_release(cat, app, ver)

    for app, ver in pairs(a.withdraw):
        r = find(app, ver)
        if r and r.get('status') != 'withdrawn':
            r.update(status='withdrawn', withdrawn=int(now))
            changed.append(f'withdrew {app} {ver}')
    for app, ver in pairs(a.restore):
        r = find(app, ver)
        if r and r.get('status') == 'withdrawn':
            r['status'] = 'active'
            r.pop('withdrawn', None)
            changed.append(f'restored {app} {ver}')
    for app, ver in pairs(a.promote_now):
        r = find(app, ver)
        if r and r.get('channel') != 'stable':
            r.update(channel='stable', promoted=int(now))
            changed.append(f'promoted {app} {ver}')

    for app, entry in (cat.get('apps') or {}).items():
        for r in entry.get('releases') or []:
            if r.get('channel') == 'beta' and r.get('status') == 'active' and now - r.get('released', now) >= hours * 3600:
                r.update(channel='stable', promoted=int(now))
                changed.append(f'promoted {app} {r["version"]} to stable')
        # prune old releases per track (never the newest stable of a track)
        by_track = {}
        for r in entry.get('releases') or []:
            by_track.setdefault(r['track'], []).append(r)
        kept = []
        for track, rels in by_track.items():
            rels.sort(key=lambda r: C.vt(r['version']), reverse=True)
            newest_stable = next((r for r in rels if r.get('channel') == 'stable' and r.get('status') == 'active'), None)
            for i, r in enumerate(rels):
                if i < keep or r is newest_stable or (r.get('status') == 'withdrawn' and i < keep + 1):
                    kept.append(r)
                else:
                    for f in (r.get('files') or {}).values():
                        try:
                            C.r2().delete_object(Bucket=C.bucket(), Key=f['key'])
                        except Exception:  # noqa: BLE001
                            pass
                    changed.append(f'pruned {app} {r["version"]}')
        entry['releases'] = sorted(kept, key=lambda r: C.vt(r['version']), reverse=True)

    for aid, entry in (cat.get('panel_apps') or {}).items():
        for r in entry.get('releases') or []:
            if r.get('channel') == 'beta' and r.get('status') == 'active' and now - r.get('released', now) >= hours * 3600:
                r.update(channel='stable', promoted=int(now))
                changed.append(f'promoted App {aid} {r["version"]} to stable')

    if cat.get('apps') or cat.get('panel_apps'):
        C.save_catalog(cat)          # daily re-sign: new serial and expiry even when nothing changed
    print('\n'.join(changed) or 'nothing changed; catalog re-signed')


if __name__ == '__main__':
    main()
