"""Find new upstream releases. Runs every 24 hours.

For every recipe it reads the official release source, keeps the newest version of
each version track the recipe follows, and compares it with the published catalog.
Output: plan.json = [{app, version, track, sources...}] for the build stage, and a
GitHub Actions matrix (app, version, target, arch).

    python3 watch.py [--only nginx,php] [--force app=version] [--offline-catalog file]
"""
import argparse
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C  # noqa: E402


# --------------------------------------------------------------- upstream sources

def _gh_paged(url, pages=4):
    out = []
    for p in range(1, pages + 1):
        sep = '&' if '?' in url else '?'
        chunk = C.http_json(f'{url}{sep}per_page=100&page={p}')
        out += chunk
        if len(chunk) < 100:
            break
    return out


def src_github_tags(w):
    rx = re.compile(w['regex'])
    out = []
    for t in _gh_paged(f"https://api.github.com/repos/{w['repo']}/tags", w.get('pages', 4)):
        m = rx.match(t['name'])
        if m:
            out.append({'version': _norm(m, w), 'tag': t['name']})
    return out


def src_github_releases(w):
    rx = re.compile(w['regex'])
    out = []
    for r in _gh_paged(f"https://api.github.com/repos/{w['repo']}/releases", w.get('pages', 2)):
        if r.get('draft') or (r.get('prerelease') and not w.get('prerelease')):
            continue
        m = rx.match(r['tag_name'])
        if m:
            out.append({'version': _norm(m, w), 'tag': r['tag_name'],
                        'assets': {a['name']: a['browser_download_url'] for a in r.get('assets', [])},
                        'notes_text': (r.get('body') or '')[:20000]})
    return out


def _norm(m, w):
    v = m.group(1)
    if w.get('sep'):                      # REL_17_6 -> 17.6
        v = v.replace(w['sep'], '.')
    return v


def src_php_net(w):
    out = []
    for major in w.get('majors', ['8']):
        data = C.http_json(f'https://www.php.net/releases/index.php?json&max=200&version={major}')
        for v, info in data.items():
            if re.fullmatch(r'\d+\.\d+\.\d+', v):
                src = next((s for s in info.get('source', []) if s.get('filename', '').endswith('.tar.xz')), None)
                if src:
                    out.append({'version': v, 'url': f"https://www.php.net/distributions/{src['filename']}",
                                'sha256': src.get('sha256', '')})
    return out


def src_nodejs(w):
    out = []
    for r in C.http_json('https://nodejs.org/dist/index.json'):
        v = r['version'].lstrip('v')
        major = int(v.split('.')[0])
        if major % 2 == 1 and not w.get('odd'):
            continue                       # odd majors never become LTS
        out.append({'version': v, 'lts': r.get('lts') or False, 'security': bool(r.get('security'))})
    return out


def src_python_standalone(w):
    """astral-sh/python-build-standalone: relocatable CPython builds (any glibc >= 2.17)."""
    rx = re.compile(r'cpython-(3\.\d+\.\d+)\+(\d+)-(x86_64|aarch64)-unknown-linux-gnu-install_only\.tar\.gz$')
    best = {}
    for r in _gh_paged('https://api.github.com/repos/astral-sh/python-build-standalone/releases', 2):
        for a in r.get('assets', []):
            m = rx.match(a['name'])
            if not m:
                continue
            v, build, arch = m.groups()
            cur = best.setdefault(v, {'version': v, 'build': build, 'assets': {}})
            if build >= cur['build']:
                if build > cur['build']:
                    cur.update(build=build, assets={})
                cur['assets'][arch] = a['browser_download_url']
    return [x for x in best.values() if len(x['assets']) == 2]


def src_composer(w):
    d = C.http_json('https://getcomposer.org/versions')
    out = []
    for ch in ('stable', '2.2'):
        for e in d.get(ch, []):
            out.append({'version': e['version'], 'url': 'https://getcomposer.org' + e['path']})
    return out


def src_url_regex(w):
    text = C.http_get(w['url'])
    return [{'version': v} for v in sorted(set(re.findall(w['regex'], text)), key=C.vt)]


def src_btbn(w):
    """BtbN/FFmpeg-Builds 'latest': one item per release branch, versioned by build date."""
    r = C.http_json('https://api.github.com/repos/BtbN/FFmpeg-Builds/releases/tags/latest')
    date = (r.get('published_at') or r.get('created_at') or '')[:10].replace('-', '')
    assets = {a['name']: a['browser_download_url'] for a in r.get('assets', [])}
    out = []
    for branch, suffix in (w.get('branches') or {}).items():
        if any(n.startswith(f'ffmpeg-{branch}-latest-') for n in assets):
            out.append({'version': f'{suffix}.{date}', 'branch': branch, 'suffix': suffix, 'assets': assets})
    return out


SOURCES = {'github-tags': src_github_tags, 'github-releases': src_github_releases, 'php-net': src_php_net,
           'nodejs': src_nodejs, 'python-standalone': src_python_standalone, 'composer': src_composer,
           'url-regex': src_url_regex, 'btbn': src_btbn}


# ---------------------------------------------------------------- track policy

def pick(recipe, found):
    """Newest version of each followed track."""
    w = recipe['watch']
    depth = w.get('track_depth', 2)
    floor = C.vt(w.get('min_track', '0'))
    by_track = {}
    for f in found:
        v = f['version']
        if not re.fullmatch(r'\d+(\.\d+)*', v) or C.vt(v) < floor:
            continue
        if any(re.search(x, v) for x in w.get('exclude', [])):
            continue
        t = C.track_of(v, depth)
        if t not in by_track or C.vt(v) > C.vt(by_track[t]['version']):
            by_track[t] = dict(f, track=t)
    tracks = sorted(by_track, key=C.vt, reverse=True)
    keep = w.get('keep_tracks', 3)
    if w.get('tracks'):                       # explicit list (e.g. PHP's supported branches)
        tracks = [t for t in tracks if t in w['tracks']]
    else:
        tracks = tracks[:keep]
    return [by_track[t] for t in tracks]


RECHECK_DAYS = 14


def plugin_version(item, plugin, rels):
    """Program version + module release (Caddy WAF = Caddy + caddy-waf).
      - program version not published yet: build it with the newest module release
      - published, same module release: keep that version (the normal retry/recheck rules apply)
      - published with an older module release: rebuild as a fourth number, 2.11.8 -> 2.11.8.1
      - published before module releases were recorded: left as it is (the next program
        release records it)"""
    base = item['version']
    same = sorted((x for x in rels.values() if '.'.join(x['version'].split('.')[:3]) == base),
                  key=lambda x: C.vt(x['version']), reverse=True)
    if not same:
        return dict(item, plugin=plugin)
    newest = same[0]
    if newest.get('plugin') is None:
        return None
    if newest['plugin'] == plugin:
        return dict(item, version=newest['version'], plugin=plugin)
    parts = newest['version'].split('.')
    n = int(parts[3]) + 1 if len(parts) > 3 else 1
    return dict(item, version=f'{base}.{n}', plugin=plugin)

def availability(recipe, item):
    """Ask the recipe which systems upstream really offers this version for.
    resolved: {target-arch: env}, unavailable: [target-arch] (not built, not a failure)."""
    resolved, unavailable = {}, []
    for t, a in C.build_matrix(recipe):
        key = f'{t}-{a}'
        if item.get('only_targets') and key not in item['only_targets']:
            continue
        env = C.resolve(recipe, item, t, a)
        if env is None:
            unavailable.append(key)
        else:
            resolved[key] = env
    return dict(item, resolved=resolved, unavailable=unavailable)


def plan(only=None, force=None, catalog=None):
    cat = catalog if catalog is not None else C.load_catalog()
    out = []
    for app, r in C.recipes().items():
        if only and app not in only:
            continue
        if r.get('disabled'):
            continue
        try:
            found = SOURCES[r['watch']['type']](r['watch'])
        except Exception as e:  # noqa: BLE001 - one broken source must not stop the others
            C.log(f'{app}: cannot read releases: {e}')
            continue
        rels = {x['version']: x for x in C.releases(cat, app)}
        plugin = None
        if r['watch'].get('plugin'):
            # a module built into the program (Caddy WAF): its newest release is part of the build
            try:
                plugin = max((p['tag'] for p in src_github_tags(r['watch']['plugin'])), key=lambda t: C.vt(t.lstrip('v')))
            except Exception as e:  # noqa: BLE001
                C.log(f'{app}: cannot read the module releases: {e}')
                continue
        for item in pick(r, found):
            if plugin:
                item = plugin_version(item, plugin, rels)
                if item is None:
                    continue
            v = item['version']
            forced = bool(force and force.get(app) == v)
            rel = rels.get(v)
            if rel and not forced:
                # published: build again only for systems that failed (3 tries) and, for 14
                # days, check again the systems upstream had no file for (it may be uploaded later)
                todo = list(rel.get('missing') or []) if int(rel.get('retries') or 0) < 3 else []
                young = time.time() - int(rel.get('released') or 0) < RECHECK_DAYS * 86400
                recheck = [t for t in rel.get('not_offered') or [] if t not in todo] if young else []
                if not todo and not recheck:
                    continue
                item['only_targets'] = todo + recheck
                item['recheck'] = recheck
            elif not rel and not forced:
                # never publish a version older than one already on the same track
                newest_same = max((x['version'] for x in rels.values() if x.get('track') == item['track']),
                                  key=C.vt, default=None)
                if newest_same and C.vt(v) <= C.vt(newest_same):
                    continue
            item.pop('notes_text', None) if len(json.dumps(item)) > 60000 else None
            try:
                item = availability(r, item)
            except Exception as e:  # noqa: BLE001 - upstream index unreachable: try again next run
                C.log(f'{app} {v}: cannot check which systems upstream offers ({e}); next run')
                continue
            if not item.get('resolved'):
                if not item.get('recheck'):
                    C.log(f'{app} {v}: upstream offers no file for any supported system; skipped')
                continue
            out.append(dict(item, app=app))
            C.log(f'{app}: {"systems to build again for " if item.get("only_targets") else "new "}{v}'
                  + (f' ({", ".join(sorted(item["resolved"]))})' if item.get('only_targets') else f' (track {item["track"]})'))
    for app, v in (force or {}).items():
        if app not in C.recipes() or not re.fullmatch(r'\d+(\.\d+){1,3}', v):
            raise SystemExit(f'force: invalid app or version: {app}={v}')
        if not any(p['app'] == app and p['version'] == v for p in out):
            r = C.recipes()[app]
            fi = {'app': app, 'version': v, 'track': C.track_of(v, r['watch'].get('track_depth', 2))}
            try:
                fi = availability(r, fi)
            except Exception as e:  # noqa: BLE001 - one app's upstream must not stop the others
                C.log(f'force {app} {v}: cannot check which systems upstream offers ({e})')
                continue
            if fi.get('resolved'):
                out.append(fi)
    return out


def matrix(pl):
    rs = C.recipes()
    rows = []
    for p in pl:
        for target, arch in C.build_matrix(rs[p['app']]):
            if p.get('only_targets') and f'{target}-{arch}' not in p['only_targets']:
                continue
            if 'resolved' in p and f'{target}-{arch}' not in p['resolved']:
                continue                    # upstream offers nothing for this system
            rows.append({'app': p['app'], 'version': p['version'], 'target': target, 'arch': arch,
                         'runner': C.TARGETS['arches'][arch]['runner'] if arch in C.TARGETS['arches'] else 'ubuntu-24.04',
                         'image': (C.TARGETS['targets'].get(target) or {}).get('image', 'ubuntu:24.04')})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only', default='')
    ap.add_argument('--force', default='', help='app=version,app=version')
    ap.add_argument('--offline-catalog', default='')
    ap.add_argument('--max', type=int, default=int(os.environ.get('SOFTS_MAX_BUILDS', '12')),
                    help='at most this many new versions per run (the rest come next run)')
    a = ap.parse_args()
    only = [x for x in a.only.split(',') if x]
    force = dict(x.split('=', 1) for x in a.force.split(',') if '=' in x)
    cat = json.load(open(a.offline_catalog)) if a.offline_catalog else None
    pl = plan(only, force, cat)[:a.max]
    while pl and len(matrix(pl)) > 250:      # GitHub allows 256 jobs per matrix
        pl.pop()
    json.dump(pl, open('plan.json', 'w'), indent=1)
    mx = matrix(pl)
    C.gh_output('count', len(pl))
    C.gh_output('matrix', json.dumps({'include': mx}) if mx else '{"include":[]}')
    print(json.dumps(pl, indent=1))


if __name__ == '__main__':
    main()
