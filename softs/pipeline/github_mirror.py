"""Copy the server software in the signed catalog to GitHub Releases (second download source).

Panels download from R2 (dl.vortexpanel.dev) and fall back to these copies when R2 cannot
be reached. Nothing here is trusted by the panel: every file is checked against the SHA-256
in the signed catalog, and the catalog against its signature, wherever they come from.

    one release per app version   tag "nginx-1.31.8", assets "<sha16>-<file name>"
    the catalog                   tag "catalog", assets catalog.json + catalog.json.sig

VortexPanel's own Apps are never copied (they come only from their own R2 bucket).
Files no longer in the catalog are removed. GitHub limits how fast releases and files may be
created, so the first copy (about 22 GB) runs over several days within --minutes per run;
every run continues where the last stopped.

    SOFTS_MIRROR_TOKEN=... SOFTS_GITHUB_REPO=BrowserlessAPI/vortexpanel-softs \
        python3 github_mirror.py [--minutes 330] [--dry-run]
"""
import argparse
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C  # noqa: E402

API = os.environ.get('GITHUB_API_URL_MIRROR', 'https://api.github.com')
UPLOADS = os.environ.get('GITHUB_UPLOADS_URL_MIRROR', 'https://uploads.github.com')
PACE = float(os.environ.get('SOFTS_MIRROR_PACE', '7.5'))    # seconds between creations (GitHub: ~500/hour)
CATALOG_TAG = 'catalog'


class GitHub:
    def __init__(self, repo, token):
        self.repo, self.token, self.last_write = repo, token, 0.0

    def _pace(self):
        wait = self.last_write + PACE - time.time()
        if wait > 0:
            time.sleep(wait)
        self.last_write = time.time()

    def call(self, method, url, body=None, data=None, ctype=None, size=None, ok404=False):
        if not url.startswith('http'):
            url = f'{API}/repos/{self.repo}{url}'
        if method != 'GET':
            self._pace()
        for attempt in range(6):
            h = {'Authorization': f'Bearer {self.token}', 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': C.UA}
            payload = None
            if body is not None:
                payload = json.dumps(body).encode()
                h['Content-Type'] = 'application/json'
            elif data is not None:
                payload = open(data, 'rb')
                h['Content-Type'] = ctype or 'application/octet-stream'
                h['Content-Length'] = str(size)
            req = urllib.request.Request(url, data=payload, method=method, headers=h)
            try:
                with urllib.request.urlopen(req, timeout=1800) as r:
                    raw = r.read()
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as e:
                text = e.read().decode('utf-8', 'replace')[:400]
                if e.code == 404 and ok404:
                    return None
                limited = e.code == 429 or (e.code == 403 and ('rate limit' in text.lower() or e.headers.get('retry-after')))
                if limited or e.code >= 500:
                    wait = int(e.headers.get('retry-after') or 0)
                    reset = int(e.headers.get('x-ratelimit-reset') or 0)
                    if not wait and reset and e.headers.get('x-ratelimit-remaining') == '0':
                        wait = max(reset - int(time.time()), 1)
                    wait = min(wait or 60 * (attempt + 1), 3600)
                    C.log(f'GitHub {e.code} on {method} {url.split("?")[0]}: waiting {wait}s')
                    time.sleep(wait)
                    continue
                raise RuntimeError(f'GitHub {e.code} on {method} {url.split("?")[0]}: {text}') from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                C.log(f'network error on {method} {url.split("?")[0]}: {e}; retrying')
                time.sleep(30 * (attempt + 1))
            finally:
                if hasattr(payload, 'close'):
                    payload.close()
        raise RuntimeError(f'GitHub kept failing on {method} {url.split("?")[0]}')

    def pages(self, path):
        out, page = [], 1
        while True:
            sep = '&' if '?' in path else '?'
            got = self.call('GET', f'{path}{sep}per_page=100&page={page}') or []
            out += got
            if len(got) < 100:
                return out
            page += 1

    def releases(self):
        """{tag: {"id": n, "assets": {name: {"id": n, "size": n}}}}"""
        out = {}
        for r in self.pages('/releases'):
            assets = r.get('assets') or []
            if len(assets) >= 100:              # the list may be cut; ask for all of them
                assets = self.pages(f'/releases/{r["id"]}/assets')
            out[r['tag_name']] = {'id': r['id'], 'assets': {a['name']: {'id': a['id'], 'size': a['size'], 'state': a.get('state')}
                                                         for a in assets}}
        return out

    def create_release(self, tag, name, body):
        r = self.call('POST', '/releases', {'tag_name': tag, 'name': name, 'body': body, 'draft': False,
                                            'prerelease': False, 'make_latest': 'false'})
        return {'id': r['id'], 'assets': {}}

    def upload(self, rel_id, name, path, ctype='application/octet-stream'):
        q = urllib.parse.urlencode({'name': name})
        return self.call('POST', f'{UPLOADS}/repos/{self.repo}/releases/{rel_id}/assets?{q}', data=path,
                         ctype=ctype, size=os.path.getsize(path))

    def delete_asset(self, asset_id):
        self.call('DELETE', f'/releases/assets/{asset_id}', ok404=True)

    def delete_release(self, tag, rel_id):
        self.call('DELETE', f'/releases/{rel_id}', ok404=True)
        self.call('DELETE', f'/git/refs/tags/{urllib.parse.quote(tag)}', ok404=True)


def _notes(tag):
    return (f'VortexPanel build: {tag}.\n\nInstall it from the VortexPanel App Store. These files are a copy of '
            'dl.vortexpanel.dev; the panel checks every file against the SHA-256 in its signed catalog, so a '
            'file changed here is refused.')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--minutes', type=int, default=330, help='stop copying new files after this long')
    ap.add_argument('--dry-run', action='store_true')
    a = ap.parse_args()
    repo = os.environ.get('SOFTS_GITHUB_REPO', '').strip()
    token = os.environ.get('SOFTS_MIRROR_TOKEN', '').strip()
    if not repo or not token:
        print('GitHub mirror not set up (SOFTS_GITHUB_REPO / SOFTS_MIRROR_TOKEN): skipped')
        return
    stop_at = time.time() + a.minutes * 60
    gh = GitHub(repo, token)
    cat_obj = C.r2().get_object(Bucket=C.bucket(), Key='catalog.json')
    cat_raw = cat_obj['Body'].read()
    sig_raw = C.r2().get_object(Bucket=C.bucket(), Key='catalog.json.sig')['Body'].read()
    cat = json.loads(cat_raw)
    files = C.catalog_files(cat)
    if not files:
        raise SystemExit('the catalog lists no files; nothing is changed on GitHub')
    want = {}
    for key, sha, size in files:
        tag, name = C.gh_location(key)
        want.setdefault(tag, {})[name] = (key, sha, size)
    have = gh.releases()
    C.log(f'{len(files)} files in {len(want)} releases wanted; {len(have)} releases on GitHub')
    if a.dry_run:
        missing = sum(1 for t, fs in want.items() for n in fs if n not in (have.get(t) or {}).get('assets', {}))
        print(f'dry run: {missing} files to copy')
        return

    tmp = tempfile.mkdtemp(prefix='vp-ghm-')
    copied, removed, left, failed = 0, 0, 0, []
    # 1. the catalog first: panels need it to use any of the files (it is re-signed daily)
    rel = have.get(CATALOG_TAG) or gh.create_release(CATALOG_TAG, 'Signed catalog',
                                                     'The signed catalog of VortexPanel builds (catalog.json, '
                                                     'catalog.json.sig). Panels verify its signature.')
    for name, raw, ctype in (('catalog.json', cat_raw, 'application/json'), ('catalog.json.sig', sig_raw, 'text/plain')):
        p = os.path.join(tmp, name)
        open(p, 'wb').write(raw)
        old = rel['assets'].get(name)
        if old:
            gh.delete_asset(old['id'])
        gh.upload(rel['id'], name, p, ctype)
    C.log(f'catalog {cat.get("serial")} copied')

    # 2. files of the catalog, smallest releases first so most apps are complete early
    for tag in sorted(want, key=lambda t: sum(s for _, _, s in want[t].values())):
        rel = have.get(tag)
        todo = [(n, v) for n, v in sorted(want[tag].items())
                if not (rel and n in rel['assets'] and rel['assets'][n]['size'] == v[2]
                        and rel['assets'][n].get('state') in (None, 'uploaded'))]
        if not todo:
            continue
        if time.time() > stop_at:
            left += len(todo)
            continue
        if rel is None:
            rel = have[tag] = gh.create_release(tag, tag, _notes(tag))
        for name, (key, sha, size) in todo:
            if time.time() > stop_at:
                left += 1
                continue
            p = os.path.join(tmp, 'f')
            try:
                C.r2().download_file(C.bucket(), key, p)
                got = C.sha256_file(p)
                if got != sha:
                    raise RuntimeError(f'R2 copy does not match the catalog ({got[:16]} != {sha[:16]})')
                old = rel['assets'].get(name)
                if old:                         # a broken earlier upload
                    gh.delete_asset(old['id'])
                gh.upload(rel['id'], name, p)
                rel['assets'][name] = {'size': size}
                copied += 1
            except Exception as e:  # noqa: BLE001
                failed.append(f'{key}: {e}')
            finally:
                if os.path.exists(p):
                    os.remove(p)

    # 3. remove what the catalog no longer lists (withdrawn files stay listed, pruned ones go)
    for tag, rel in sorted(have.items()):
        if tag == CATALOG_TAG:
            continue
        if tag not in want:
            gh.delete_release(tag, rel['id'])
            removed += 1
            continue
        for name, asset in rel['assets'].items():
            if name not in want[tag] and asset.get('id'):
                gh.delete_asset(asset['id'])
                removed += 1

    summary = (f'GitHub mirror ({repo}): {copied} files copied, {removed} removed, {left} left for the next run'
               + ('' if not failed else '\nFailed:\n' + '\n'.join(f'- {x}' for x in failed)))
    print(summary)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        open(os.environ['GITHUB_STEP_SUMMARY'], 'a').write(summary + '\n')
    if failed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
