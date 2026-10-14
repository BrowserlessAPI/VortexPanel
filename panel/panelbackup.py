"""Backup of the panel itself: accounts, settings, keys and certificates.

What is saved (paths that exist):
  credentials.json, config.json, secret.key, ssl/          panel login + HTTPS
  data/*.json (users, API keys, alerts, schedules, backup
  destinations, onboarding), data/rclone/                    panel state
  cloud_backup_config.json, ai_config.json, cdn_config.json  integrations
  /etc/nginx/vortex, /etc/cron.d/vortex*                      panel-made config
Not included: websites, databases (use website backups), monitoring history.

Archives go to /opt/vortexpanel/backups/panel/ (0600). A schedule in
data/panel_backup.json runs from the backups timer; copies can also be sent to
a backup destination (panel/storage.py).
"""
import glob
import json
import os
import re
import tarfile
import time

INSTALL_DIR = '/opt/vortexpanel'
OUT_DIR = os.path.join(INSTALL_DIR, 'backups', 'panel')
CONF = os.path.join(INSTALL_DIR, 'data', 'panel_backup.json')
NAME_RE = re.compile(r'^panel_\d{8}-\d{6}(_[a-z]+)?\.tar\.gz$')
DEFAULTS = {'enabled': False, 'hour': 2, 'keep': 14, 'target': '', 'keep_remote': 30, 'last_run': 0,
            'last_ok': None, 'last_message': ''}


def _items():
    rel = ['credentials.json', 'config.json', 'secret.key', 'ssl', 'cloud_backup_config.json',
           'ai_config.json', 'cdn_config.json', 'data/rclone']
    rel += [os.path.relpath(p, INSTALL_DIR) for p in glob.glob(os.path.join(INSTALL_DIR, 'data', '*.json'))]
    paths = [os.path.join(INSTALL_DIR, r) for r in rel]
    paths += glob.glob('/etc/nginx/vortex') + glob.glob('/etc/cron.d/vortex*')
    return [p for p in paths if os.path.exists(p)]


def load():
    try:
        d = json.load(open(CONF))
    except Exception:
        d = {}
    out = dict(DEFAULTS)
    out.update(d)
    return out


def save(d):
    os.makedirs(os.path.dirname(CONF), mode=0o700, exist_ok=True)
    tmp = CONF + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(d, f, indent=2)
    os.replace(tmp, CONF)


def create(note=''):
    os.makedirs(OUT_DIR, mode=0o700, exist_ok=True)
    os.chmod(OUT_DIR, 0o700)
    name = f'panel_{time.strftime("%Y%m%d-%H%M%S")}' + (f'_{note}' if note and note.isalpha() else '') + '.tar.gz'
    path = os.path.join(OUT_DIR, name)
    fd = os.open(path + '.part', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.close(fd)
    manifest = {'created': int(time.time()), 'items': _items()}
    try:
        manifest['version'] = open(os.path.join(INSTALL_DIR, 'version.txt')).read().strip()
    except Exception:
        manifest['version'] = ''
    with tarfile.open(path + '.part', 'w:gz') as tar:
        for p in manifest['items']:
            tar.add(p, arcname=p.lstrip('/'),
                    filter=lambda ti: None if ti.name.endswith(('.tmp', '.lock')) else ti)
        data = json.dumps(manifest, indent=2).encode()
        import io
        ti = tarfile.TarInfo('VORTEXPANEL_BACKUP.json')
        ti.size = len(data)
        ti.mtime = time.time()
        tar.addfile(ti, io.BytesIO(data))
    os.replace(path + '.part', path)
    return path


def list_local():
    if not os.path.isdir(OUT_DIR):
        return []
    out = []
    for n in sorted(os.listdir(OUT_DIR), reverse=True):
        if NAME_RE.match(n):
            st = os.stat(os.path.join(OUT_DIR, n))
            out.append({'name': n, 'size': st.st_size, 'time': int(st.st_mtime)})
    return out


def prune(keep):
    for b in list_local()[max(1, keep):]:
        try:
            os.unlink(os.path.join(OUT_DIR, b['name']))
        except OSError:
            pass


def restore(name, what=('accounts', 'settings')):
    """Restore panel files from an archive. A snapshot of the current state
    is taken first. Returns (restored paths, snapshot path)."""
    if not NAME_RE.match(name or ''):
        raise ValueError('Invalid backup name')
    path = os.path.join(OUT_DIR, name)
    if not os.path.exists(path):
        raise FileNotFoundError(name)
    snap = create(note='beforerestore')
    restored = []
    with tarfile.open(path, 'r:gz') as tar:
        members = []
        for m in tar.getmembers():
            n = m.name
            if n == 'VORTEXPANEL_BACKUP.json' or m.issym() or m.islnk() or n.startswith('/') or '..' in n.split('/'):
                continue
            target = '/' + n
            ok_prefix = target.startswith(INSTALL_DIR + '/') or target.startswith('/etc/nginx/vortex') \
                or target.startswith('/etc/cron.d/vortex')
            if not ok_prefix:
                continue
            is_account = any(target.startswith(os.path.join(INSTALL_DIR, x)) for x in
                             ('credentials.json', 'secret.key', 'data/users.json', 'data/api_keys.json'))
            if is_account and 'accounts' not in what:
                continue
            if not is_account and 'settings' not in what:
                continue
            members.append(m)
            if m.isfile():
                restored.append(target)
        tar.extractall('/', members=members)
    for p in restored:
        if p.startswith(INSTALL_DIR):
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
    return restored, snap


def run_due(now=None):
    """Daily scheduled panel backup (called by the backups timer)."""
    cfg = load()
    if not cfg.get('enabled'):
        return ''
    now = now or time.time()
    lt = time.localtime(now)
    if lt.tm_hour != int(cfg.get('hour', 2)) or now - (cfg.get('last_run') or 0) < 20 * 3600:
        return ''
    msg = ''
    try:
        path = create(note='scheduled')
        prune(int(cfg.get('keep', 14)))
        msg = os.path.basename(path)
        if cfg.get('target'):
            from panel import storage
            storage.upload(cfg['target'], path)
            storage.prune(cfg['target'], 'panel_', int(cfg.get('keep_remote', 30)))
            msg += ', uploaded'
        cfg.update(last_run=int(now), last_ok=True, last_message=msg)
    except Exception as e:
        cfg.update(last_run=int(now), last_ok=False, last_message=str(e)[:300])
        msg = f'failed: {e}'
    save(cfg)
    return f'panel backup {msg}'
