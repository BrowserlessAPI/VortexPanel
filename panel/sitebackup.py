"""Per-website backups: the site's files and its databases in one archive,
optional schedules, retention, and upload to the configured cloud storage.

Archive layout (site_<domain>_<YYYYmmdd_HHMMSS>.tar.gz in the backups folder):
    manifest.json            what is inside and where it came from
    databases/<name>.sql.gz  one dump per linked database
    files/...                the site's document root

Used by the Backups page (panel/routes/backups.py) and by the scheduled task
runner (panel/tasks.py), which runs due schedules every 5 minutes.
"""
import os, re, json, time, glob, shutil, tarfile, tempfile, subprocess, fcntl, calendar

BACKUP_DIR = '/opt/vortexpanel/backups'
SCHED_FILE = '/opt/vortexpanel/data/backup_schedules.json'
LOCK_DIR = '/opt/vortexpanel/data/locks'
LOG_FILE = '/var/log/vortexpanel/site-backups.log'

DOMAIN_RE = re.compile(r'^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$')
DB_RE = re.compile(r'^[A-Za-z0-9_$][A-Za-z0-9_$-]{0,63}$')
NAME_RE = re.compile(r'^site_(.+)_(\d{8}_\d{6})\.tar\.gz$')
FREQS = ('hourly', 'daily', 'weekly', 'monthly')


class BackupError(Exception):
    pass


# --- helpers -------------------------------------------------------------------
def _slug(domain):
    return domain.replace('*', 'wildcard')


def _unslug(s):
    return s.replace('wildcard', '*', 1) if s.startswith('wildcard.') else s


def archive_domain(name):
    m = NAME_RE.match(name or '')
    return _unslug(m.group(1)) if m else None


def _now():
    return int(time.time())


def _log_line(msg):
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, 'a') as f:
            f.write(time.strftime('%Y-%m-%d %H:%M:%S ') + msg + '\n')
    except OSError:
        pass


class _Lock:
    """Non-blocking per-site lock shared by the panel workers and the timer."""
    def __init__(self, key):
        os.makedirs(LOCK_DIR, exist_ok=True)
        self.path = os.path.join(LOCK_DIR, 'site-backup-' + re.sub(r'[^A-Za-z0-9._-]', '_', key) + '.lock')
        self.f = None

    def __enter__(self):
        self.f = open(self.path, 'w')
        try:
            fcntl.flock(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.f.close()
            raise BackupError('A backup or restore of this site is already running')
        return self

    def __exit__(self, *a):
        try:
            fcntl.flock(self.f, fcntl.LOCK_UN)
        finally:
            self.f.close()


def sites():
    """{domain: path} for every website on the server."""
    from panel.routes.backups import get_websites
    return {s['domain'].lower(): os.path.realpath(s['path']) for s in get_websites()}


def db_map():
    from panel.routes.backups import _db_map
    try:
        return _db_map()
    except Exception:
        return {}


# --- schedules ---------------------------------------------------------------------
def load_schedules():
    try:
        with open(SCHED_FILE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_schedules(d):
    os.makedirs(os.path.dirname(SCHED_FILE), exist_ok=True)
    tmp = SCHED_FILE + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(d, f, indent=2, sort_keys=True)
    os.replace(tmp, SCHED_FILE)


def _update_site_state(domain, **kw):
    d = load_schedules()
    e = d.setdefault(domain, {})
    e.update(kw)
    save_schedules(d)
    return e


DEFAULT_SCHEDULE = {'enabled': False, 'frequency': 'daily', 'time': '03:00', 'weekday': 0,
                    'monthday': 1, 'every_hours': 6, 'keep_local': 7, 'cloud': False,
                    'keep_cloud': 30, 'databases': None, 'excludes': []}


def get_schedule(domain):
    e = dict(DEFAULT_SCHEDULE)
    e.update(load_schedules().get(domain, {}))
    return e


def validate_schedule(d, dbs_on_server=None):
    """Clean a schedule posted by the UI. Returns (schedule, error)."""
    s = {}
    s['enabled'] = bool(d.get('enabled'))
    freq = d.get('frequency', 'daily')
    if freq not in FREQS:
        return None, 'Unknown frequency'
    s['frequency'] = freq
    t = str(d.get('time') or '03:00')
    if not re.fullmatch(r'([01]\d|2[0-3]):[0-5]\d', t):
        return None, 'Time must be HH:MM (24-hour)'
    s['time'] = t
    try:
        s['weekday'] = int(d.get('weekday', 0)) % 7
        s['monthday'] = min(28, max(1, int(d.get('monthday', 1))))
        s['every_hours'] = int(d.get('every_hours', 6))
        s['keep_local'] = max(0, min(365, int(d.get('keep_local', 7))))
        s['keep_cloud'] = max(0, min(3650, int(d.get('keep_cloud', 30))))
    except (TypeError, ValueError):
        return None, 'Numbers expected for day, hours and retention'
    if s['every_hours'] not in (1, 2, 3, 4, 6, 8, 12):
        return None, 'Hourly backups can run every 1, 2, 3, 4, 6, 8 or 12 hours'
    s['cloud'] = bool(d.get('cloud'))
    if s['enabled'] and s['keep_local'] == 0 and not s['cloud']:
        return None, 'Keep at least one local copy, or upload to cloud storage'
    dbs = d.get('databases')
    if dbs is None:
        s['databases'] = None  # detect automatically at backup time
    else:
        if not isinstance(dbs, list) or any(not DB_RE.match(str(x)) for x in dbs):
            return None, 'Invalid database name'
        s['databases'] = sorted(set(str(x) for x in dbs))
    ex = d.get('excludes') or []
    if isinstance(ex, str):
        ex = [x.strip() for x in ex.splitlines()]
    clean = []
    for x in ex:
        x = str(x).strip()
        if not x:
            continue
        if x.startswith('/') or '..' in x.split('/') or len(x) > 200 or '\n' in x:
            return None, f'Exclude patterns are paths inside the site, like wp-content/cache ({x})'
        clean.append(x)
    s['excludes'] = clean[:50]
    return s, None


def next_run(s, after=None):
    """Next time (epoch) a schedule is due, strictly after `after`."""
    after = int(after if after is not None else time.time())
    hh, mm = (int(x) for x in s.get('time', '03:00').split(':'))
    freq = s.get('frequency', 'daily')
    lt = time.localtime(after)
    if freq == 'hourly':
        step = int(s.get('every_hours', 6)) * 3600
        # slots aligned to local midnight + minute offset
        base = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, mm, 0, 0, 0, -1))
        t = base
        while t <= after:
            t += step
        return int(t)
    for add in range(0, 400):
        day = time.localtime(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + add, 12, 0, 0, 0, 0, -1)))
        if freq == 'weekly' and day.tm_wday != int(s.get('weekday', 0)):
            continue
        if freq == 'monthly' and day.tm_mday != int(s.get('monthday', 1)):
            continue
        t = time.mktime((day.tm_year, day.tm_mon, day.tm_mday, hh, mm, 0, 0, 0, -1))
        if t > after:
            return int(t)
    return after + 86400


# --- database detection --------------------------------------------------------
_WP_DB = re.compile(r"""define\(\s*['"]DB_NAME['"]\s*,\s*['"]([^'"]+)['"]""")
_ENV_DB = re.compile(r'^\s*DB_(?:DATABASE|NAME)\s*=\s*["\']?([A-Za-z0-9_$-]+)', re.M)


def detect_databases(domain, path, existing=None):
    """Databases a site uses: WordPress wp-config.php, a Laravel-style .env,
    and the database the panel creates with a new site (domain with _)."""
    existing = existing if existing is not None else db_map()
    found = []
    for rel, rx in (('wp-config.php', _WP_DB), ('.env', _ENV_DB)):
        fp = os.path.join(path, rel)
        try:
            if os.path.isfile(fp) and os.path.getsize(fp) < 2 * 1024 * 1024:
                with open(fp, errors='replace') as f:
                    for m in rx.finditer(f.read()):
                        found.append(m.group(1))
        except OSError:
            pass
    guess = re.sub(r'[^a-zA-Z0-9_]', '_', domain.replace('.', '_'))[:32]
    found.append(guess)
    out = []
    for n in found:
        if n in existing and n not in out:
            out.append(n)
    return out


def site_databases(domain, path, sched=None, existing=None):
    sched = sched or get_schedule(domain)
    existing = existing if existing is not None else db_map()
    if sched.get('databases') is not None:
        return [n for n in sched['databases'] if n in existing], existing
    return detect_databases(domain, path, existing), existing


# --- create ----------------------------------------------------------------------
def create_backup(domain, log=None, trigger='manual'):
    """Back up one site. Returns {'name', 'path', 'size', 'databases'}."""
    log = log or (lambda m: None)
    domain = (domain or '').lower()
    if not DOMAIN_RE.match(domain):
        raise BackupError('Invalid domain')
    all_sites = sites()
    path = all_sites.get(domain)
    if not path or not os.path.isdir(path):
        raise BackupError(f'Website {domain} was not found on this server')
    if path in ('/', '/www', '/www/wwwroot', '/var/www', '/root', '/home') or path.count('/') < 2:
        raise BackupError(f'Refusing to back up {path}')
    sched = get_schedule(domain)
    from panel.routes.backups import _dump_db
    with _Lock(domain):
        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
        while True:
            ts = time.strftime('%Y%m%d_%H%M%S')
            name = f'site_{_slug(domain)}_{ts}.tar.gz'
            dest = os.path.join(BACKUP_DIR, name)
            if not os.path.exists(dest):
                break
            time.sleep(1)
        stage = tempfile.mkdtemp(prefix='.site-', dir=BACKUP_DIR)
        try:
            dbs, existing = site_databases(domain, path, sched)
            os.makedirs(os.path.join(stage, 'databases'))
            dumped = []
            for n in dbs:
                engine = existing.get(n, 'mysql')
                log(f'Dumping database {n} ({"PostgreSQL" if engine == "postgresql" else "MySQL/MariaDB"})...')
                err = _dump_db(n, engine, os.path.join(stage, 'databases', n + '.sql.gz'))
                if err:
                    raise BackupError(f'Database {n} could not be dumped: {err[:400]}')
                dumped.append({'name': n, 'engine': engine})
            if not dbs:
                log('No database is linked to this site - backing up files only.')
            manifest = {
                'format': 'vortexpanel-site-backup', 'version': 1, 'domain': domain, 'path': path,
                'created': _now(), 'trigger': trigger, 'databases': dumped,
                'excludes': sched.get('excludes') or [],
                'panel_version': _panel_version(),
            }
            with open(os.path.join(stage, 'manifest.json'), 'w') as f:
                json.dump(manifest, f, indent=2)
            log(f'Archiving {path}...')
            cmd = ['tar', '-czf', dest, '-C', stage, 'manifest.json', 'databases',
                   '--transform', r's,^\.\(/\|$\),files\1,']
            for ex in manifest['excludes']:
                cmd.append('--exclude=./' + ex.strip('/'))
            # never archive the backups folder into itself if a site lives above it
            cmd += ['--exclude=./' + os.path.relpath(BACKUP_DIR, path)] if BACKUP_DIR.startswith(path + '/') else []
            cmd += ['-C', path, '.']
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=6 * 3600)
                rc, err = r.returncode, r.stderr.strip()
            except subprocess.TimeoutExpired:
                rc, err = 2, 'timed out after 6 hours'
            # tar exit 1 = some files changed while being read (live site): archive is complete
            if rc >= 2:
                try:
                    os.unlink(dest)
                except OSError:
                    pass
                raise BackupError(f'Archiving failed: {err[-400:] or rc}')
            os.chmod(dest, 0o600)
        finally:
            shutil.rmtree(stage, ignore_errors=True)
    size = os.path.getsize(dest)
    log(f'Backup complete: {name} ({_fmt(size)})')
    return {'name': name, 'path': dest, 'size': size, 'databases': [d['name'] for d in dumped]}


def _panel_version():
    for p in ('/opt/vortexpanel/VERSION', os.path.join(os.path.dirname(__file__), '..', 'VERSION')):
        try:
            with open(p) as f:
                return f.read().strip()
        except OSError:
            continue
    return ''


def _fmt(n):
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or u == 'TB':
            return f'{n:.0f} {u}' if u == 'B' else f'{n:.1f} {u}'
        n /= 1024.0


# --- list / prune ---------------------------------------------------------------
def list_backups(domain=None):
    out = []
    for p in glob.glob(os.path.join(BACKUP_DIR, 'site_*.tar.gz')):
        name = os.path.basename(p)
        dom = archive_domain(name)
        if not dom or (domain and dom != domain):
            continue
        try:
            st = os.stat(p)
        except OSError:
            continue
        out.append({'name': name, 'domain': dom, 'size': st.st_size, 'mtime': int(st.st_mtime)})
    out.sort(key=lambda e: e['name'], reverse=True)
    return out


def prune_local(domain, keep, log=None):
    log = log or (lambda m: None)
    if keep is None or keep < 0:
        return 0
    removed = 0
    for e in list_backups(domain)[keep:]:
        try:
            os.unlink(os.path.join(BACKUP_DIR, e['name']))
            removed += 1
            log(f'Removed old local backup {e["name"]}')
        except OSError:
            pass
    return removed


def read_manifest(name):
    path = os.path.join(BACKUP_DIR, os.path.basename(name))
    try:
        with tarfile.open(path, 'r:gz') as tf:
            m = tf.next()
            if m is None or m.name != 'manifest.json' or not m.isfile() or m.size > 1024 * 1024:
                return None
            return json.loads(tf.extractfile(m).read().decode('utf-8'))
    except Exception:
        return None


# --- cloud -----------------------------------------------------------------------
def cloud_config():
    try:
        from panel.routes.cloud_backup import load_config
        cfg = load_config()
        return cfg if cfg.get('bucket') else None
    except Exception:
        return None


def cloud_upload(path, name, log=None):
    log = log or (lambda m: None)
    cfg = cloud_config()
    if not cfg:
        raise BackupError('Cloud storage is not connected (Backups > Cloud Storage)')
    from panel.routes.cloud_backup import get_client
    client = get_client(cfg)
    prefix = cfg.get('prefix', 'vortexpanel-backups/')
    log(f'Uploading to {cfg.get("provider", "s3")} bucket {cfg["bucket"]}...')
    client.upload_file(path, cfg['bucket'], prefix + name)
    log('Uploaded to cloud storage')


def cloud_prune(domain, keep, log=None):
    log = log or (lambda m: None)
    cfg = cloud_config()
    if not cfg or keep is None or keep <= 0:
        return 0
    from panel.routes.cloud_backup import get_client
    client = get_client(cfg)
    prefix = cfg.get('prefix', 'vortexpanel-backups/') + f'site_{_slug(domain)}_'
    keys = []
    for page in client.get_paginator('list_objects_v2').paginate(Bucket=cfg['bucket'], Prefix=prefix):
        for o in page.get('Contents', []):
            if NAME_RE.match(o['Key'].rsplit('/', 1)[-1]) and archive_domain(o['Key'].rsplit('/', 1)[-1]) == domain:
                keys.append(o['Key'])
    keys.sort(reverse=True)
    removed = 0
    for k in keys[keep:]:
        client.delete_object(Bucket=cfg['bucket'], Key=k)
        removed += 1
        log(f'Removed old cloud backup {k.rsplit("/", 1)[-1]}')
    return removed


# --- restore ---------------------------------------------------------------------
def restore_backup(name, log=None, files=True, databases=True, target=None):
    """Restore a site backup: files go back to the site folder (or `target`),
    databases are imported into the databases they came from. The old files
    are kept until the new ones are in place, and put back if extracting fails."""
    log = log or (lambda m: None)
    name = os.path.basename(name or '')
    path = os.path.join(BACKUP_DIR, name)
    if not NAME_RE.match(name) or not os.path.isfile(path):
        raise BackupError('Site backup not found')
    man = read_manifest(name)
    if not man or man.get('format') != 'vortexpanel-site-backup':
        raise BackupError('This archive has no site backup manifest')
    domain = man.get('domain', '')
    if not DOMAIN_RE.match(domain):
        raise BackupError('The manifest names an invalid domain')
    from panel.routes.backups import _check_target, _restore_db, _member_ok
    dest = target or man.get('path') or ''
    real, err = _check_target(dest)
    if err:
        raise BackupError(err)
    if real.count('/') < 2:
        raise BackupError(f'Refusing to restore into {real}')
    # Check every member before extracting anything.
    try:
        with tarfile.open(path, 'r:gz') as tf:
            members = tf.getmembers()
    except (tarfile.TarError, OSError, EOFError) as e:
        raise BackupError(f'Archive is not readable: {e}')
    for m in members:
        if not _member_ok(m.name) or not (m.name in ('manifest.json', 'databases', 'files')
                                          or m.name.startswith(('databases/', 'files/'))):
            raise BackupError(f'Archive contains an unexpected path: {m.name}')
        if m.islnk() and not _member_ok(m.linkname):
            raise BackupError(f'Archive contains an unsafe hard link: {m.name}')
    with _Lock(domain):
        if files:
            parent = os.path.dirname(real.rstrip('/')) or '/'
            os.makedirs(parent, exist_ok=True)
            ts = time.strftime('%Y%m%d%H%M%S')
            tmp = os.path.join(parent, f'.{os.path.basename(real)}.vp-restore-{ts}')
            old = os.path.join(parent, f'.{os.path.basename(real)}.vp-old-{ts}')
            os.makedirs(tmp)
            log(f'Extracting files to {real}...')
            r = subprocess.run(['tar', '-xzf', path, '-C', tmp, '--strip-components=1', '--no-same-owner', 'files'],
                               capture_output=True, text=True, timeout=6 * 3600)
            if r.returncode != 0:
                shutil.rmtree(tmp, ignore_errors=True)
                raise BackupError(f'Extracting files failed: {r.stderr.strip()[-400:]}')
            had_old = os.path.isdir(real)
            if had_old:
                os.rename(real, old)
            try:
                os.rename(tmp, real)
            except OSError as e:
                if had_old:
                    os.rename(old, real)
                shutil.rmtree(tmp, ignore_errors=True)
                raise BackupError(f'Could not put the restored files in place: {e}')
            if had_old:
                shutil.rmtree(old, ignore_errors=True)
            try:
                from panel.routes.websites_core import ensure_web_ownership
                ensure_web_ownership(real)
            except Exception:
                pass
            log('Files restored')
        if databases and man.get('databases'):
            work = tempfile.mkdtemp(prefix='.restore-', dir=BACKUP_DIR)
            try:
                r = subprocess.run(['tar', '-xzf', path, '-C', work, 'databases'],
                                   capture_output=True, text=True, timeout=6 * 3600)
                if r.returncode != 0:
                    raise BackupError(f'Extracting the database dumps failed: {r.stderr.strip()[-400:]}')

                class _J:
                    def line(self, m):
                        log(m)
                for d in man['databases']:
                    n = d.get('name', '')
                    if not DB_RE.match(n):
                        raise BackupError(f'Invalid database name in manifest: {n}')
                    dump = os.path.join(work, 'databases', n + '.sql.gz')
                    if not os.path.isfile(dump):
                        raise BackupError(f'The archive has no dump for {n}')
                    err = _restore_db(_J(), dump, n)
                    if err:
                        raise BackupError(f'Database {n}: {err}')
                log('Databases restored: ' + ', '.join(d['name'] for d in man['databases']))
            finally:
                shutil.rmtree(work, ignore_errors=True)
    return {'domain': domain, 'path': real}


# --- scheduled runs --------------------------------------------------------------
def run_one(domain, trigger='schedule', log=None):
    """Back up a site and apply its upload and retention settings. Records the
    result on the site's schedule entry. Returns (ok, message)."""
    lines = []

    def _log(m):
        lines.append(m)
        _log_line(f'[{domain}] {m}')
        if log:
            log(m)
    sched = get_schedule(domain)
    started = _now()
    try:
        res = create_backup(domain, log=_log, trigger=trigger)
        cloud_msg = ''
        if sched.get('cloud'):
            try:
                cloud_upload(res['path'], res['name'], log=_log)
                cloud_prune(domain, sched.get('keep_cloud', 30), log=_log)
                cloud_msg = ', uploaded to cloud storage'
            except Exception as e:
                cloud_msg = f', but the cloud upload failed: {e}'
                _log(f'Cloud upload failed: {e}')
        if sched.get('cloud') and not cloud_msg.startswith(', but') and sched.get('keep_local', 7) == 0:
            os.unlink(res['path'])
            _log('Local copy removed (keep 0 local copies)')
        else:
            prune_local(domain, max(1, sched.get('keep_local', 7)) if sched.get('enabled') or trigger == 'schedule'
                        else None, log=_log)
        ok = not cloud_msg.startswith(', but')
        msg = f'{res["name"]} ({_fmt(res["size"])}){cloud_msg}'
        _update_site_state(domain, last_run=started, last_ok=ok, last_message=msg, last_file=res['name'],
                           last_trigger=trigger)
        return ok, msg
    except Exception as e:
        _log(f'Backup failed: {e}')
        _update_site_state(domain, last_run=started, last_ok=False, last_message=str(e)[:500],
                           last_trigger=trigger)
        return False, str(e)


def run_due(now=None):
    """Run every enabled schedule that is due. Called by the task timer."""
    now = int(now or time.time())
    data = load_schedules()
    existing = sites()
    ran = []
    for domain, raw in sorted(data.items()):
        s = dict(DEFAULT_SCHEDULE)
        s.update(raw)
        if not s.get('enabled'):
            continue
        if domain not in existing:
            continue
        nr = int(s.get('next_run') or 0)
        if not nr:
            _update_site_state(domain, next_run=next_run(s, now))
            continue
        if nr > now:
            continue
        ok, msg = run_one(domain, trigger='schedule')
        _update_site_state(domain, next_run=next_run(get_schedule(domain), int(time.time())))
        ran.append((domain, ok, msg))
    return ran
