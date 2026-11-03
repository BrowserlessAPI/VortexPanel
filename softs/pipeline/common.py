"""Shared helpers for the VortexPanel software pipeline (runs in GitHub Actions).

Layout in the R2 bucket (public at SOFTS_BASE_URL):

    catalog.json                      every app, release, file, checksum (signed)
    catalog.json.sig                  Ed25519 signature of catalog.json (base64)
    <app>/<version>/<app>-<version>-<target>-<arch>.zip
    <app>/<version>/notes.md          release note shown in the panel

A release is published to the "beta" channel first and promoted to "stable"
(promote.py); security releases go straight to stable. A withdrawn release stays
in the catalog with status "withdrawn" so panels that installed it offer a rollback.
"""
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))     # softs/
RECIPES = os.path.join(ROOT, 'recipes')
TARGETS = json.load(open(os.path.join(ROOT, 'targets.json')))
UA = 'VortexPanel-softs-pipeline'


def log(*a):
    print('[softs]', *a, file=sys.stderr, flush=True)


# ------------------------------------------------------------------ versions

def vt(v):
    """'1.31.8' -> (1, 31, 8); non-numeric parts sort first."""
    return tuple(int(x) if x.isdigit() else -1 for x in re.split(r'[.+-]', str(v)) if x != '')


def track_of(v, depth=2):
    return '.'.join(str(v).split('.')[:depth])


# ------------------------------------------------------------------- recipes

def recipes(kind='build'):
    """Recipes of one kind: 'build' (compiled or repacked per system, tested in a
    container) or 'mirror' (an upstream release file stored in R2 as it is)."""
    out = {}
    for name in sorted(os.listdir(RECIPES)):
        p = os.path.join(RECIPES, name, 'recipe.json')
        if os.path.isfile(p):
            r = json.load(open(p))
            if r.get('kind', 'build') != kind:
                continue
            r['id'] = name
            r['dir'] = os.path.join(RECIPES, name)
            out[name] = r
    return out


def build_matrix(recipe):
    """[(target, arch)] a recipe is built for. universal_arches: those processors get one
    build for every Linux (an upstream binary), the others one build per system (compiled)."""
    arches = recipe.get('arches') or list(TARGETS['arches'])
    if recipe.get('universal'):
        # also_targets: systems the universal binary cannot run on (e.g. older glibc) get their
        # own build; a server takes its own system's build first (panel/softs.py file_keys)
        return [('linux', a) for a in arches] + [(t, a) for t in recipe.get('also_targets') or [] for a in arches]
    tg = recipe.get('targets') or list(TARGETS['targets'])
    uni = recipe.get('universal_arches') or []
    return [('linux', a) for a in arches if a in uni] + [(t, a) for t in tg for a in arches if a not in uni]


def resolve(recipe, item, target, arch):
    """The exact upstream file for one system, from the recipe's resolve.py:
    {VP_URL, VP_SHA256, ...}, or None when upstream offers nothing for that system
    (then it is not built, and that system keeps its operating system packages).
    Without resolve.py every system is built. Network errors raise: the release is
    then planned again on the next run instead of being marked not offered."""
    path = os.path.join(recipe['dir'], 'resolve.py')
    if not os.path.isfile(path):
        return {}
    import importlib.util
    spec = importlib.util.spec_from_file_location(f'resolve_{recipe["id"].replace("-", "_")}', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.resolve(item, target, arch)


def file_name(app, version, target, arch):
    return f'{app}-{version}-{target}-{arch}.zip'


def key_for(app, version, target, arch, sha256):
    """Content-addressed: a rebuilt zip gets a new key, so a cached or published file
    can never disagree with the checksum in the catalog."""
    return f'{app}/{version}/{sha256[:16]}/{file_name(app, version, target, arch)}'


# ---------------------------------------------------------------------- http

def http_get(url, timeout=60, headers=None, binary=False):
    h = {'User-Agent': UA}
    if 'api.github.com' in url and os.environ.get('GITHUB_TOKEN'):
        h['Authorization'] = 'Bearer ' + os.environ['GITHUB_TOKEN']
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    return data if binary else data.decode('utf-8', 'replace')


def url_exists(url, timeout=30, not_found_403=False):
    """True on 2xx, False on 404/410 (upstream does not have it); anything else raises,
    so a network problem is never mistaken for "not offered"."""
    import urllib.error
    for method in ('HEAD', 'GET'):
        req = urllib.request.Request(url, method=method, headers={'User-Agent': UA, 'Range': 'bytes=0-0'})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return 200 <= r.status < 300
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                return False
            if e.code in (403, 405) and method == 'HEAD':
                continue                     # some mirrors refuse HEAD
            if e.code == 403 and method == 'GET' and not_found_403:
                return False                 # CDNs (S3/CloudFront style) answer 403 for a missing object
            raise
    return False


def http_json(url, **kw):
    return json.loads(http_get(url, **kw))


def download(url, dest, sha256=None):
    h = hashlib.sha256()
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=600) as r, open(dest + '.part', 'wb') as f:
        while True:
            b = r.read(1 << 20)
            if not b:
                break
            h.update(b)
            f.write(b)
    if sha256 and h.hexdigest() != sha256.lower():
        os.remove(dest + '.part')
        raise RuntimeError(f'checksum mismatch for {url}')
    os.replace(dest + '.part', dest)
    return h.hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


# ------------------------------------------------------------------- catalog

def canonical(obj):
    """Exact bytes that are signed: sorted keys, no spaces, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def empty_catalog():
    return {'format': 1, 'serial': 0, 'generated': '', 'apps': {}}


def sign(data_bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    raw = base64.b64decode(os.environ['SOFTS_SIGNING_KEY'].strip())
    return base64.b64encode(Ed25519PrivateKey.from_private_bytes(raw).sign(data_bytes)).decode()


def public_key_b64():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    raw = base64.b64decode(os.environ['SOFTS_SIGNING_KEY'].strip())
    pub = Ed25519PrivateKey.from_private_bytes(raw).public_key()
    return base64.b64encode(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def releases(catalog, app):
    return ((catalog.get('apps') or {}).get(app) or {}).get('releases') or []


def find_release(catalog, app, version):
    return next((r for r in releases(catalog, app) if r['version'] == version), None)


# ----------------------------------------------------------------------- R2

def r2():
    import boto3
    from botocore.config import Config
    return boto3.client(
        's3', endpoint_url=f"https://{os.environ['R2_ACCOUNT_ID']}.r2.cloudflarestorage.com",
        aws_access_key_id=os.environ['R2_ACCESS_KEY_ID'], aws_secret_access_key=os.environ['R2_SECRET_ACCESS_KEY'],
        region_name='auto', config=Config(retries={'max_attempts': 5, 'mode': 'standard'}))


def bucket():
    return os.environ['R2_BUCKET']


def load_catalog():
    """The published catalog (read through the S3 API: always current, no cache)."""
    try:
        obj = r2().get_object(Bucket=bucket(), Key='catalog.json')
        return json.loads(obj['Body'].read())
    except Exception as e:  # noqa: BLE001
        if 'NoSuchKey' in str(e) or '404' in str(e):
            return empty_catalog()
        raise


def save_catalog(cat):
    """Write catalog.json + catalog.json.sig. The serial only goes up, so a panel
    never accepts an older (replayed) catalog."""
    cat['format'] = 1
    cat['serial'] = max(int(cat.get('serial') or 0) + 1, int(time.time()))
    cat['generated'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    # panels refuse an expired catalog (someone serving a stale copy); the daily
    # maintain job re-signs it, so it never expires while the pipeline runs
    cat['expires'] = int(time.time()) + int(os.environ.get('SOFTS_CATALOG_DAYS', '7')) * 86400
    data = canonical(cat)
    sig = sign(data)
    c = r2()
    # signature first would let a panel see a new sig with the old catalog for a moment;
    # the panel retries on a mismatch, so order does not matter for safety.
    c.put_object(Bucket=bucket(), Key='catalog.json', Body=data, ContentType='application/json',
                 CacheControl='public, max-age=300')
    c.put_object(Bucket=bucket(), Key='catalog.json.sig', Body=sig.encode(), ContentType='text/plain',
                 CacheControl='public, max-age=300')
    log(f'catalog published: serial {cat["serial"]}, {sum(len(a.get("releases", [])) for a in cat["apps"].values())} releases')
    return cat


def upload(path, key, content_type='application/zip'):
    r2().upload_file(path, bucket(), key, ExtraArgs={'ContentType': content_type,
                                                     'CacheControl': 'public, max-age=31536000, immutable'})
    log('uploaded', key)


def exists(key):
    try:
        r2().head_object(Bucket=bucket(), Key=key)
        return True
    except Exception:  # noqa: BLE001
        return False


def gh_output(name, value):
    p = os.environ.get('GITHUB_OUTPUT')
    if p:
        with open(p, 'a') as f:
            f.write(f'{name}={value}\n')
    else:
        print(f'{name}={value}')
