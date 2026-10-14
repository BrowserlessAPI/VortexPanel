"""Backup destinations (Backups > Storage).

  s3       S3-compatible storage (AWS, Backblaze B2, Wasabi, DigitalOcean
           Spaces, MinIO, ...) - the existing "Cloud Storage" settings,
           exposed here as the target with id "s3".
  ftp      FTP or explicit FTPS server (Python ftplib, no extra software).
  rclone   any rclone remote: Google Drive, OneDrive, Dropbox, SFTP, pCloud,
           Mega, ... The remote's configuration is pasted from
           `rclone config show <name>` (for Google Drive: run
           `rclone authorize "drive"` on a computer with a browser and paste
           the token). rclone itself is downloaded from its GitHub release
           and checked against the release's SHA256SUMS.

Every target supports upload / list / delete / download of files under a
folder (prefix). Settings: data/backup_targets.json (0600).
"""
import ftplib
import hashlib
import io
import json
import os
import platform
import re
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.request
import uuid

TARGETS_FILE = '/opt/vortexpanel/data/backup_targets.json'
RCLONE_BIN = '/opt/vortexpanel/bin/rclone'
RCLONE_CONF_DIR = '/opt/vortexpanel/data/rclone'
TYPES = {'s3': 'S3-compatible storage', 'ftp': 'FTP / FTPS server',
         'rclone': 'Google Drive, OneDrive, Dropbox, SFTP and more (rclone)'}
_SECRETS = ('password', 'secret_key', 'config')


class StorageError(Exception):
    pass


# --- target settings -----------------------------------------------------------------
def _read():
    try:
        with open(TARGETS_FILE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _write(d):
    os.makedirs(os.path.dirname(TARGETS_FILE), mode=0o700, exist_ok=True)
    tmp = TARGETS_FILE + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(d, f, indent=2)
    os.replace(tmp, TARGETS_FILE)


def _s3_target():
    try:
        from panel.routes.cloud_backup import load_config
        cfg = load_config()
    except Exception:
        cfg = {}
    if not cfg.get('bucket'):
        return None
    return {'id': 's3', 'type': 's3', 'name': f'{cfg.get("provider", "s3").upper()} bucket {cfg["bucket"]}',
            'prefix': cfg.get('prefix', 'vortexpanel-backups/'), 'legacy': True}


def list_targets():
    out = []
    s3 = _s3_target()
    if s3:
        out.append(s3)
    out += _read().get('targets', [])
    return out


def get_target(tid):
    for t in list_targets():
        if t['id'] == tid:
            return t
    return None


def public(t):
    p = {k: v for k, v in t.items() if k not in _SECRETS}
    for k in _SECRETS:
        if k in t:
            p[k + '_set'] = bool(t[k])
    return p


def save_target(d, tid=None):
    typ = d.get('type')
    if typ not in ('ftp', 'rclone'):
        raise StorageError('Unknown storage type')
    name = str(d.get('name') or '').strip()[:60]
    if not name:
        raise StorageError('Give the destination a name')
    data = _read()
    targets = data.get('targets', [])
    cur = next((t for t in targets if t['id'] == tid), None) if tid else None
    t = dict(cur or {'id': uuid.uuid4().hex[:10], 'type': typ, 'created': int(time.time())})
    t['name'] = name
    t['prefix'] = str(d.get('prefix') or 'vortexpanel-backups').strip().strip('/') + '/'
    if typ == 'ftp':
        host = str(d.get('host') or '').strip()
        if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}|\[?[0-9a-fA-F:]+\]?', host):
            raise StorageError('Enter the FTP server host name')
        t.update(host=host, port=int(d.get('port') or 21), username=str(d.get('username') or ''),
                 tls=bool(d.get('tls', True)), passive=bool(d.get('passive', True)))
        if d.get('password'):
            t['password'] = d['password']
    else:
        if d.get('config'):
            conf = str(d['config']).strip()
            if not re.search(r'^\s*type\s*=', conf, re.M):
                raise StorageError('Paste the remote\'s settings as shown by "rclone config show NAME" '
                                   '(they include a "type = ..." line)')
            # one section only, named by us
            body = '\n'.join(l for l in conf.splitlines() if not l.strip().startswith('['))
            t['config'] = body
            t['remote_type'] = re.search(r'^\s*type\s*=\s*(\S+)', conf, re.M).group(1)
        if not t.get('config'):
            raise StorageError('Paste the rclone remote settings')
    if cur:
        targets = [t if x['id'] == tid else x for x in targets]
    else:
        targets.append(t)
    data['targets'] = targets
    _write(data)
    return t


def delete_target(tid):
    data = _read()
    data['targets'] = [t for t in data.get('targets', []) if t['id'] != tid]
    _write(data)


# --- S3 ----------------------------------------------------------------------------------
def _s3():
    from panel.routes.cloud_backup import load_config, get_client
    cfg = load_config()
    if not cfg.get('bucket'):
        raise StorageError('S3 storage is not configured')
    return get_client(cfg), cfg['bucket']


# --- FTP ---------------------------------------------------------------------------------
def _ftp(t):
    try:
        if t.get('tls', True):
            f = ftplib.FTP_TLS(timeout=30, context=ssl.create_default_context())
        else:
            f = ftplib.FTP(timeout=30)
        f.connect(t['host'], int(t.get('port') or 21))
        f.login(t.get('username') or 'anonymous', t.get('password') or '')
        if t.get('tls', True):
            f.prot_p()
        f.set_pasv(bool(t.get('passive', True)))
        return f
    except ftplib.all_errors as e:
        raise StorageError(f'FTP connection to {t.get("host")} failed: {e}')


def _ftp_cd(f, prefix, create=True):
    for part in [p for p in prefix.strip('/').split('/') if p]:
        try:
            f.cwd(part)
        except ftplib.error_perm:
            if not create:
                raise
            f.mkd(part)
            f.cwd(part)


# --- rclone ------------------------------------------------------------------------------
def rclone_installed():
    return os.access(RCLONE_BIN, os.X_OK)


def install_rclone(log=print):
    """Download the latest rclone release from GitHub and verify its SHA-256."""
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'armv7l': 'arm-v7'}.get(platform.machine(), 'amd64')
    # The latest tag: github.com redirects /releases/latest to /releases/tag/vX
    # (works where api.github.com is rate-limited or blocked).
    req = urllib.request.Request('https://github.com/rclone/rclone/releases/latest',
                                 headers={'User-Agent': 'VortexPanel'})
    with urllib.request.urlopen(req, timeout=20) as r:
        tag = r.geturl().rstrip('/').rsplit('/', 1)[-1]
    if not re.fullmatch(r'v\d+\.\d+\.\d+', tag):
        raise StorageError('Could not find the latest rclone release on GitHub')
    zname = f'rclone-{tag}-linux-{arch}.zip'
    base = f'https://github.com/rclone/rclone/releases/download/{tag}/'
    assets = {zname: base + zname, 'SHA256SUMS': base + 'SHA256SUMS'}
    log(f'Downloading rclone {tag}...')
    tmp = tempfile.mkdtemp(prefix='rclone-', dir='/opt/vortexpanel/data/tmp' if os.path.isdir('/opt/vortexpanel/data/tmp') else None)
    try:
        zpath = os.path.join(tmp, zname)
        urllib.request.urlretrieve(assets[zname], zpath)
        with urllib.request.urlopen(assets['SHA256SUMS'], timeout=20) as r:
            sums = r.read().decode()
        want = next((l.split()[0] for l in sums.splitlines() if l.strip().endswith(zname)), '')
        got = hashlib.sha256(open(zpath, 'rb').read()).hexdigest()
        if not want or want != got:
            raise StorageError('The rclone download does not match its published SHA-256 checksum')
        import zipfile
        with zipfile.ZipFile(zpath) as z:
            member = next(n for n in z.namelist() if n.endswith('/rclone'))
            os.makedirs(os.path.dirname(RCLONE_BIN), exist_ok=True)
            with z.open(member) as src, open(RCLONE_BIN + '.new', 'wb') as dst:
                shutil.copyfileobj(src, dst)
        os.chmod(RCLONE_BIN + '.new', 0o755)
        os.replace(RCLONE_BIN + '.new', RCLONE_BIN)
        log(f'rclone {tag} installed (checksum verified)')
        return tag
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _rclone(t, args, timeout=3600):
    if not rclone_installed():
        raise StorageError('rclone is not installed yet (Backups > Storage > Install rclone)')
    os.makedirs(RCLONE_CONF_DIR, mode=0o700, exist_ok=True)
    conf = os.path.join(RCLONE_CONF_DIR, f'{t["id"]}.conf')
    fd = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(f'[vp]\n{t["config"]}\n')
    r = subprocess.run([RCLONE_BIN, '--config', conf, '--retries', '3', '--low-level-retries', '5'] + args,
                       capture_output=True, text=True, timeout=timeout)
    # rclone refreshes OAuth tokens and writes them back to the config file:
    # keep the refreshed token.
    try:
        new = open(conf).read().split('\n', 1)[1].strip()
        if new and new != t['config'].strip():
            data = _read()
            for x in data.get('targets', []):
                if x['id'] == t['id']:
                    x['config'] = new
            _write(data)
            t['config'] = new
    except Exception:
        pass
    if r.returncode != 0:
        raise StorageError((r.stderr or r.stdout).strip()[-400:] or 'rclone failed')
    return r.stdout


# --- operations --------------------------------------------------------------------------
def upload(tid, path, name=None, log=None):
    log = log or (lambda m: None)
    t = get_target(tid)
    if not t:
        raise StorageError('This backup destination no longer exists')
    name = name or os.path.basename(path)
    if t['type'] == 's3':
        client, bucket = _s3()
        log(f'Uploading to {t["name"]}...')
        client.upload_file(path, bucket, t['prefix'] + name)
    elif t['type'] == 'ftp':
        log(f'Uploading to FTP {t["host"]}...')
        f = _ftp(t)
        try:
            _ftp_cd(f, t['prefix'])
            with open(path, 'rb') as fh:
                f.storbinary(f'STOR {name}.part', fh, blocksize=1 << 20)
            try:
                f.delete(name)
            except ftplib.error_perm:
                pass
            f.rename(f'{name}.part', name)
        finally:
            try:
                f.quit()
            except Exception:
                pass
    else:
        log(f'Uploading to {t["name"]} ({t.get("remote_type", "rclone")})...')
        _rclone(t, ['copyto', path, f'vp:{t["prefix"]}{name}'])
    log(f'Uploaded to {t["name"]}')


def list_files(tid, startswith=''):
    """[{name, size, time}] newest first."""
    t = get_target(tid)
    if not t:
        raise StorageError('This backup destination no longer exists')
    out = []
    if t['type'] == 's3':
        client, bucket = _s3()
        for page in client.get_paginator('list_objects_v2').paginate(Bucket=bucket, Prefix=t['prefix'] + startswith):
            for o in page.get('Contents', []):
                out.append({'name': o['Key'][len(t['prefix']):], 'size': o['Size'],
                            'time': int(o['LastModified'].timestamp())})
    elif t['type'] == 'ftp':
        f = _ftp(t)
        try:
            try:
                _ftp_cd(f, t['prefix'], create=False)
            except ftplib.error_perm:
                return []
            try:
                for name, facts in f.mlsd(facts=['size', 'modify', 'type']):
                    if facts.get('type') == 'file' and name.startswith(startswith) and not name.endswith('.part'):
                        ts = time.mktime(time.strptime(facts['modify'][:14], '%Y%m%d%H%M%S')) if facts.get('modify') else 0
                        out.append({'name': name, 'size': int(facts.get('size') or 0), 'time': int(ts)})
            except ftplib.error_perm:
                for name in f.nlst():
                    if name.startswith(startswith) and not name.endswith('.part'):
                        out.append({'name': name, 'size': 0, 'time': 0})
        finally:
            try:
                f.quit()
            except Exception:
                pass
    else:
        raw = _rclone(t, ['lsjson', '--files-only', f'vp:{t["prefix"]}'], timeout=300)
        for o in json.loads(raw or '[]'):
            if o['Name'].startswith(startswith):
                try:
                    ts = int(time.mktime(time.strptime(o['ModTime'][:19], '%Y-%m-%dT%H:%M:%S')))
                except Exception:
                    ts = 0
                out.append({'name': o['Name'], 'size': o.get('Size', 0), 'time': ts})
    out.sort(key=lambda x: (x['name']), reverse=True)
    return out


def delete(tid, name):
    t = get_target(tid)
    if not t:
        raise StorageError('This backup destination no longer exists')
    if '/' in name or name.startswith('.'):
        raise StorageError('Invalid file name')
    if t['type'] == 's3':
        client, bucket = _s3()
        client.delete_object(Bucket=bucket, Key=t['prefix'] + name)
    elif t['type'] == 'ftp':
        f = _ftp(t)
        try:
            _ftp_cd(f, t['prefix'], create=False)
            f.delete(name)
        finally:
            try:
                f.quit()
            except Exception:
                pass
    else:
        _rclone(t, ['deletefile', f'vp:{t["prefix"]}{name}'], timeout=300)


def download(tid, name, dest):
    t = get_target(tid)
    if not t:
        raise StorageError('This backup destination no longer exists')
    if '/' in name or name.startswith('.'):
        raise StorageError('Invalid file name')
    if t['type'] == 's3':
        client, bucket = _s3()
        client.download_file(bucket, t['prefix'] + name, dest)
    elif t['type'] == 'ftp':
        f = _ftp(t)
        try:
            _ftp_cd(f, t['prefix'], create=False)
            with open(dest, 'wb') as fh:
                f.retrbinary(f'RETR {name}', fh.write, blocksize=1 << 20)
        finally:
            try:
                f.quit()
            except Exception:
                pass
    else:
        _rclone(t, ['copyto', f'vp:{t["prefix"]}{name}', dest])


def test(tid):
    """Write, list and delete a small file. Returns a message."""
    t = get_target(tid)
    if not t:
        raise StorageError('This backup destination no longer exists')
    name = f'.vortexpanel-test-{int(time.time())}.txt'
    tmp = os.path.join(tempfile.gettempdir(), name)
    with open(tmp, 'w') as f:
        f.write('VortexPanel storage test\n')
    try:
        upload(tid, tmp, name.lstrip('.'))
        files = [x['name'] for x in list_files(tid)]
        if name.lstrip('.') not in files:
            raise StorageError('The test file was uploaded but does not appear in the listing')
        delete(tid, name.lstrip('.'))
    finally:
        os.unlink(tmp)
    return f'{t["name"]}: upload, listing and delete work'


def prune(tid, startswith, keep, log=None):
    log = log or (lambda m: None)
    if keep is None or keep <= 0:
        return 0
    files = [f for f in list_files(tid, startswith)]
    files.sort(key=lambda x: x['name'], reverse=True)
    n = 0
    for f in files[keep:]:
        delete(tid, f['name'])
        n += 1
        log(f'Removed old copy {f["name"]}')
    return n
