from flask import Blueprint, jsonify, request, session, send_file
import subprocess, os, glob, time, threading, uuid, re, gzip, shutil, tarfile, zipfile, tempfile

backups_bp = Blueprint('backups', __name__)
def req(): return 'user' in session
BACKUP_DIR = '/opt/vortexpanel/backups'

_DOMAIN_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$')
# Never restore directly into (or replace) these.
_PROTECTED_TARGETS = {'/', '/bin', '/boot', '/dev', '/etc', '/home', '/lib', '/lib64', '/opt', '/proc',
                      '/root', '/run', '/sbin', '/srv', '/sys', '/tmp', '/usr', '/var', '/var/lib',
                      '/var/log', '/www', '/opt/vortexpanel'}

def sh(c, t=600):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return '', 'Timed out', 1
    except Exception as e:
        return '', str(e), 1

def get_webroot():
    """The panel's web root (/www/wwwroot) -- one implementation for the
    whole panel (websites_core -> os_utils.get_webroot())."""
    try:
        from panel.routes.websites_core import get_webroot as _gw
    except ImportError:
        from websites_core import get_webroot as _gw
    return _gw()

def _db_map():
    """{name: 'mysql'|'postgresql'} for every user database on the server, using
    the same connection logic as the Databases page (socket auth, mariadb
    binary, /root/.my.cnf, debian.cnf, runuser for PostgreSQL)."""
    from panel.routes.databases import detect_engines, mysql_dbs, pg_dbs
    res = {}
    ids = [e['id'] for e in detect_engines()]
    if 'mysql' in ids or 'mariadb' in ids:
        dbs, err = mysql_dbs()
        if not err:
            for d in dbs: res[d['name']] = 'mysql'
    if 'postgresql' in ids:
        dbs, err = pg_dbs()
        if not err:
            for d in dbs:
                if d['name'] != 'postgres': res.setdefault(d['name'], 'postgresql')
    return res

def mysql_available():
    from panel.routes.databases import mysql_cmd
    _, err = mysql_cmd('SELECT 1;', timeout=5)
    return err is None

def get_databases():
    return sorted(_db_map().keys())

def get_websites():
    """Every site with its REAL document root, from any web server
    (nginx / Apache / OpenLiteSpeed / Caddy) -- sites that live outside the
    web root (e.g. /var/www/html/x) are backed up from where they are."""
    sites = []
    try:
        from panel.routes.websites_core import list_sites
        for st in list_sites():
            p = (st.get('path') or '').rstrip('/')
            if p and os.path.isdir(p) and not any(s['domain'] == st['domain'] for s in sites):
                sites.append({'domain': st['domain'], 'path': p})
    except Exception:
        pass
    for conf_dir in ['/etc/nginx/vortex', '/etc/nginx/sites-available', '/etc/nginx/conf.d']:
        if not os.path.isdir(conf_dir): continue
        for f in os.listdir(conf_dir):
            fp = os.path.join(conf_dir, f)
            if not os.path.isfile(fp): continue
            try:
                with open(fp, errors='replace') as fh: c = fh.read()
                domains = re.findall(r'server_name\s+([^;]+);', c)
                if not domains: continue
                domain = domains[0].strip().split()[0]
                if domain in ('_', 'localhost', 'default'): continue
                path_m = re.search(r'root\s+([^;]+);', c)
                path = path_m.group(1).strip().strip('"\'') if path_m else get_webroot()+'/'+domain
                if os.path.isdir(path) and not any(s['domain']==domain for s in sites):
                    sites.append({'domain': domain, 'path': path})
            except Exception: pass
    return sites

# Job tracking for backup progress. Stored through job_state (a JSON file per
# job) because gunicorn runs 4 worker processes: an in-memory dict made the
# progress poll land on a worker that never saw the job ("Job not found"),
# which left the progress modal spinning forever.
class _Job(object):
    def __init__(self, job_id, **state):
        self.id = job_id
        self.state = dict({'done':False,'success':False,'name':'','size':0,'error':'','lines':[]}, **state)
        self.save()
    def save(self):
        from panel.routes.job_state import save_job
        try: save_job('backup_' + self.id, self.state)
        except Exception: pass
    def line(self, msg):
        self.state['lines'].append(msg); self.save()
    def fail(self, err):
        self.state.update({'done':True,'success':False,'error':err}); self.save()
    def ok(self, **kw):
        self.state.update(dict({'done':True,'success':True}, **kw)); self.save()

def _tar_create(dest, rel_paths, excludes=()):
    """tar exit code 1 means 'some files changed while being read' (live site,
    logs) - the archive is still complete. 2+ is fatal: remove the partial file
    instead of reporting a truncated archive as a successful backup."""
    cmd = ['tar', '-czf', dest]
    for e in excludes: cmd.append('--exclude=' + e)
    cmd += ['-C', '/'] + list(rel_paths)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=6 * 3600)
        rc, err = r.returncode, r.stderr.strip()
    except subprocess.TimeoutExpired:
        rc, err = 2, 'Timed out'
    if rc >= 2:
        try: os.unlink(dest)
        except OSError: pass
        return err or f'tar exited with {rc}'
    return None

def _gzip_file(src, dest):
    tmp = dest + '.part'
    with open(src, 'rb') as fi, gzip.open(tmp, 'wb', compresslevel=6) as fo:
        shutil.copyfileobj(fi, fo, 1024 * 1024)
    os.replace(tmp, dest)

def _dump_db(dbname, engine, dest_gz):
    """Dump to a temp file, then gzip in Python. The old `mysqldump | gzip > f`
    pipeline ran under /bin/sh without pipefail, so a failed dump (auth error,
    PostgreSQL database passed to mysqldump) still produced a tiny .sql.gz and
    was reported as a successful backup."""
    from panel.routes.databases import _mysql_run, _mysql_bin, _pg_prefix
    import shlex
    fd, tmp = tempfile.mkstemp(suffix='.sql', dir=BACKUP_DIR)
    os.close(fd); os.chmod(tmp, 0o644)
    try:
        if engine == 'mysql':
            what = shlex.quote(dbname) if dbname else '--all-databases'
            _, err = _mysql_run(_mysql_bin('dump'),
                                f'--single-transaction --routines --triggers {what} > {shlex.quote(tmp)}', 6 * 3600)
        else:
            if dbname:
                c = f'pg_dump --clean --if-exists {shlex.quote(dbname)} > {shlex.quote(tmp)}'
            else:
                c = f'pg_dumpall --clean --if-exists > {shlex.quote(tmp)}'
            _, err, rc = sh(_pg_prefix() + c, t=6 * 3600)
            err = (err or 'pg_dump failed') if rc != 0 else None
        if err: return err
        if os.path.getsize(tmp) == 0: return 'Dump produced no output'
        _gzip_file(tmp, dest_gz)
        os.chmod(dest_gz, 0o600)
        return None
    finally:
        try: os.unlink(tmp)
        except OSError: pass

@backups_bp.route('/api/backups')
def list_backups():
    if not req(): return jsonify({'ok':False}), 401
    os.makedirs(BACKUP_DIR, exist_ok=True)
    files = []
    for f in sorted(glob.glob(f'{BACKUP_DIR}/*.tar.gz') +
                    glob.glob(f'{BACKUP_DIR}/*.sql.gz') +
                    glob.glob(f'{BACKUP_DIR}/*.sql') +
                    glob.glob(f'{BACKUP_DIR}/*.zip'), key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0,
                   reverse=True):
        try: st = os.stat(f)
        except OSError: continue
        name  = os.path.basename(f)
        # Parse metadata from name: type_domain_timestamp.ext
        parts = name.split('_')
        btype = parts[0] if parts else 'unknown'
        files.append({
            'name':  name,
            'size':  st.st_size,
            'mtime': int(st.st_mtime),
            'path':  f,
            'type':  btype,
        })
    return jsonify({'ok':True, 'backups':files})

@backups_bp.route('/api/backups/info')
def backup_info():
    """Return what can be backed up"""
    if not req(): return jsonify({'ok':False}), 401
    dbs      = get_databases()
    websites = get_websites()
    return jsonify({
        'ok':      True,
        'databases': dbs,
        'websites':  websites,
        'mysql':     mysql_available(),
        'webroot':   get_webroot(),
    })

def _cloud_auto_upload(job, dest, name):
    try:
        from panel.routes.cloud_backup import load_config as _cb_load, get_client as _cb_client
        cfg = _cb_load()
        if cfg.get('bucket') and cfg.get('auto_upload'):
            job.line('Uploading to cloud storage...')
            client = _cb_client(cfg)
            prefix = cfg.get('prefix','vortexpanel-backups/')
            client.upload_file(dest, cfg['bucket'], prefix+name)
            job.line('Uploaded to cloud storage')
    except Exception as _e:
        job.line(f'Cloud upload failed: {_e}')

@backups_bp.route('/api/backups/create', methods=['POST'])
def create_backup():
    if not req(): return jsonify({'ok':False}), 401
    d      = request.get_json() or {}
    btype  = d.get('type') or 'website'  # website | database | full
    domain = (d.get('domain') or '').strip()   # specific domain or empty for all
    db     = (d.get('database') or '').strip() # specific DB or empty for all
    if btype not in ('website', 'database', 'full'):
        return jsonify({'ok':False,'error':f'Unknown backup type: {btype}'}), 400
    if domain and not _DOMAIN_RE.match(domain):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400
    if db and not re.match(r'^[A-Za-z0-9_$][A-Za-z0-9_$-]{0,63}$', db):
        return jsonify({'ok':False,'error':'Invalid database name'}), 400
    ts     = time.strftime('%Y%m%d_%H%M%S')
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    job = _Job(uuid.uuid4().hex[:12])

    def do_backup():
        try:
            if btype == 'website':
                # Validate: get path for domain
                if domain:
                    site = next((s for s in get_websites() if s['domain']==domain), None)
                    if not site:
                        # Fallback: check if directory exists
                        path = os.path.join(get_webroot(), domain)
                        if not os.path.isdir(path):
                            job.fail(f'Website path not found for {domain}')
                            return
                    else:
                        path = site['path']
                    name = f'website_{domain}_{ts}.tar.gz'
                else:
                    path = get_webroot()
                    name = f'website_all_{ts}.tar.gz'
                path = os.path.realpath(path)
                if path == '/' or not os.path.isdir(path):
                    job.fail(f'Refusing to archive {path}')
                    return
                include = [path.lstrip('/')]
                if not domain:
                    # sites whose root is outside the web root as well
                    for st in get_websites():
                        sp = os.path.realpath(st['path'])
                        if sp != '/' and sp.count('/') >= 2 and not any(
                                sp == '/' + i or sp.startswith('/' + i + '/') for i in include):
                            include.append(sp.lstrip('/'))
                dest = os.path.join(BACKUP_DIR, name)
                job.line(f'Archiving {", ".join("/" + i for i in include)}...')
                err = _tar_create(dest, include)
                if err:
                    job.fail(f'tar failed: {err}')
                    return
                dests = [(dest, name)]

            elif btype == 'database':
                dbmap = _db_map()
                if not dbmap:
                    job.fail('No databases found (or the database server could not be reached). Create a database first.')
                    return
                if db and db not in dbmap:
                    job.fail(f'Database "{db}" not found')
                    return
                dests = []
                if db:
                    jobs = [(db, dbmap[db], f'database_{db}_{ts}.sql.gz')]
                    job.line(f'Dumping database: {db}')
                else:
                    engines = sorted(set(dbmap.values()))
                    jobs = []
                    if 'mysql' in engines:
                        jobs.append(('', 'mysql', f'database_all_{ts}.sql.gz'))
                    if 'postgresql' in engines:
                        jobs.append(('', 'postgresql', f'database_pgall_{ts}.sql.gz'))
                    job.line(f'Dumping {len(dbmap)} databases: {", ".join(sorted(dbmap))}')
                for dbname, engine, name in jobs:
                    dest = os.path.join(BACKUP_DIR, name)
                    err = _dump_db(dbname, engine, dest)
                    if err:
                        job.fail(f'{"mysqldump" if engine == "mysql" else "pg_dump"} failed: {err[:500]}')
                        return
                    dests.append((dest, name))

            else:  # full
                name  = f'full_{ts}.tar.gz'
                dest  = os.path.join(BACKUP_DIR, name)
                webroot = get_webroot()
                job.line('Archiving websites, nginx configs, caddyfile...')
                include = [webroot.lstrip('/')]
                for st in get_websites():
                    sp = os.path.realpath(st['path'])
                    if sp != '/' and sp.count('/') >= 2 and not any(
                            sp == '/' + i or sp.startswith('/' + i + '/') for i in include):
                        include.append(sp.lstrip('/'))
                for extra in ['etc/nginx', 'etc/caddy']:
                    if os.path.isdir(f'/{extra}'): include.append(extra)
                # Never archive the backups directory into itself (the archive
                # being written lives there, and every older backup would be
                # duplicated into each new full backup).
                err = _tar_create(dest, include, excludes=[BACKUP_DIR.lstrip('/')])
                if err:
                    job.fail(f'Full backup failed: {err}')
                    return
                dests = [(dest, name)]

            total = 0
            for dest, name in dests:
                try: os.chmod(dest, 0o600)
                except OSError: pass
                size = os.path.getsize(dest) if os.path.exists(dest) else 0
                total += size
                job.line(f'Backup complete: {name} ({size//1024}KB)')
            job.state.update({'name': dests[0][1] if dests else '', 'size': total})
            for dest, name in dests:
                _cloud_auto_upload(job, dest, name)
            job.ok()
        except Exception as e:
            job.fail(str(e))

    threading.Thread(target=do_backup, daemon=True).start()
    return jsonify({'ok':True, 'job_id':job.id})

@backups_bp.route('/api/backups/job/<job_id>')
def job_status(job_id):
    if not req(): return jsonify({'ok':False}), 401
    from panel.routes.job_state import load_job
    job = load_job('backup_' + job_id)
    if not job: return jsonify({'ok':False,'error':'Job not found'}), 404
    return jsonify(dict(job, ok=True))

def _safe_backup_path(name):
    name = os.path.basename(name or '')
    if not name or name.startswith('.'):
        return None, None
    return name, os.path.join(BACKUP_DIR, name)

@backups_bp.route('/api/backups/download/<name>')
def download_backup(name):
    if not req(): return jsonify({'ok':False}), 401
    # Sanitize filename - no path traversal
    name, path = _safe_backup_path(name)
    if not name or not os.path.isfile(path):
        return jsonify({'ok':False,'error':'File not found'}), 404
    return send_file(path, as_attachment=True, download_name=name)

@backups_bp.route('/api/backups/<name>', methods=['DELETE'])
def delete_backup(name):
    if not req(): return jsonify({'ok':False}), 401
    name, path = _safe_backup_path(name)
    if not name: return jsonify({'ok':False,'error':'Invalid name'}), 400
    if os.path.isfile(path): os.unlink(path)
    return jsonify({'ok':True})

# --- Restore --------------------------------------------------------------------
def _allowed_restore_roots():
    roots = {get_webroot().lstrip('/'), 'www/wwwroot', 'var/www', 'etc/nginx', 'etc/caddy'}
    # the real roots of existing sites (a site outside the web root could be
    # backed up but never restored to its original place)
    try:
        for st in get_websites():
            sp = os.path.realpath(st['path'])
            if sp.count('/') >= 2 and sp.rstrip('/') not in _PROTECTED_TARGETS:
                roots.add(sp.strip('/'))
    except Exception:
        pass
    return sorted(r for r in roots if r)

def _member_ok(name):
    return not name.startswith('/') and '..' not in name.split('/')

def _check_target(target):
    """Restore target directory: absolute, not a system directory."""
    if not target.startswith('/'):
        return None, 'Restore path must be absolute'
    real = os.path.realpath(target)
    if real in _PROTECTED_TARGETS or real.rstrip('/') in _PROTECTED_TARGETS:
        return None, f'Refusing to restore into {real}'
    return real, None

def _restore_tar(job, path, target):
    try:
        with tarfile.open(path, 'r:*') as tf:
            names = [m.name for m in tf]
    except (tarfile.TarError, OSError, EOFError) as e:
        return f'Not a readable tar archive: {e}'
    if not names:
        return 'Archive is empty'
    bad = [n for n in names if not _member_ok(n)]
    if bad:
        return f'Archive contains unsafe paths (absolute or ..): {bad[0]}'
    norm = [n[2:] if n.startswith('./') else n for n in names]
    norm = [n.rstrip('/') for n in norm if n.strip('/').strip('.')]
    if not target:
        # Original location: every member must live under a web root / web
        # server config dir - an uploaded archive must not be able to drop
        # files into /etc, /root/.ssh, etc.
        roots = _allowed_restore_roots()
        outside = [n for n in norm if not any(n == r or n.startswith(r + '/') for r in roots)]
        if outside:
            return (f'Archive contains files outside the web root ({outside[0]}). '
                    'Enter a restore path to extract it into a specific directory.')
        job.line('Restoring to original paths...')
        cmd = ['tar', '-xzf', path, '-C', '/']
    else:
        real, err = _check_target(target)
        if err: return err
        # Strip the common leading directory so the site's files land directly
        # in the chosen path (website_<domain> archives store www/wwwroot/<domain>/...).
        try: common = os.path.commonpath(norm) if norm else ''
        except ValueError: common = ''
        strip = 0
        if common and any(n.startswith(common + '/') for n in norm):
            strip = len(common.split('/'))
        os.makedirs(real, exist_ok=True)
        job.line(f'Restoring to {real}...')
        cmd = ['tar', '-xzf', path, '-C', real]
        if strip: cmd.append(f'--strip-components={strip}')
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=6 * 3600)
    except subprocess.TimeoutExpired:
        return 'tar timed out'
    if r.returncode != 0:
        return f'Restore failed: {r.stderr.strip()[:500]}'
    return None

def _restore_zip(job, path, target):
    if not target:
        return 'ZIP archives need a restore path'
    real, err = _check_target(target)
    if err: return err
    try:
        with zipfile.ZipFile(path) as zf:
            for m in zf.infolist():
                dest = os.path.realpath(os.path.join(real, m.filename))
                if dest != real and not dest.startswith(real + os.sep):
                    return f'Archive contains unsafe path: {m.filename}'
            os.makedirs(real, exist_ok=True)
            job.line(f'Extracting to {real}...')
            zf.extractall(real)
    except (zipfile.BadZipFile, OSError) as e:
        return f'Not a readable ZIP archive: {e}'
    return None

def _restore_db(job, path, target):
    from panel.routes.databases import mysql_cmd, _mysql_run, _mysql_bin, _pg_prefix, pg_cmd
    import shlex
    fd, tmp = tempfile.mkstemp(suffix='.sql', dir=BACKUP_DIR)
    os.close(fd); os.chmod(tmp, 0o644)  # psql runs as postgres and must read it
    try:
        with open(path, 'rb') as fh:
            magic = fh.read(2)
        if magic == b'\x1f\x8b':
            with gzip.open(path, 'rb') as src, open(tmp, 'wb') as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
        else:
            shutil.copyfile(path, tmp)
        with open(tmp, 'rb') as fh:
            head = fh.read(8192).decode('utf-8', 'replace')
        dbmap = _db_map()
        if 'PostgreSQL database cluster dump' in head:
            engine, target = 'postgresql', 'postgres'
        elif 'PostgreSQL database dump' in head:
            engine = 'postgresql'
        elif 'MySQL dump' in head or 'MariaDB dump' in head:
            engine = 'mysql'
        else:
            engine = dbmap.get(target) or ('mysql' if mysql_available() else 'postgresql')
        job.line(f'Restoring database {target} ({"PostgreSQL" if engine == "postgresql" else "MySQL/MariaDB"})...')
        if engine == 'mysql':
            _, err = mysql_cmd(f'CREATE DATABASE IF NOT EXISTS `{target}`;', timeout=30)
            if err: return f'Could not create database: {err}'
            _, err = _mysql_run(_mysql_bin(), f'{shlex.quote(target)} < {shlex.quote(tmp)}', 6 * 3600)
            return f'Restore failed: {err[:500]}' if err else None
        if target != 'postgres' and target not in dbmap:
            out, _ = pg_cmd("SELECT 1 FROM pg_database WHERE datname='%s';" % target.replace("'", "''"))
            if not (out or '').strip():
                _, e2, rc = sh(f'{_pg_prefix()}createdb {shlex.quote(target)}', t=120)
                if rc != 0: return f'Could not create database: {e2}'
        _, err, rc = sh(f'{_pg_prefix()}psql -X -q -v ON_ERROR_STOP=1 -d {shlex.quote(target)} -f {shlex.quote(tmp)}', t=6 * 3600)
        return f'Restore failed: {(err or "psql failed")[:500]}' if rc != 0 else None
    except (OSError, EOFError) as e:
        return f'Could not read the backup file: {e}'
    finally:
        try: os.unlink(tmp)
        except OSError: pass

def _start_restore(name, btype, target):
    name, path = _safe_backup_path(name)
    if not name or not os.path.isfile(path):
        return None, ('Backup file not found', 404)
    target = (target or '').strip()
    is_db_file = name.endswith(('.sql.gz', '.sql'))
    if not btype:
        btype = 'database' if is_db_file or name.startswith(('database_', 'db_')) else 'website'
    if btype == 'database':
        if not target:
            return None, ('Database name required for restore', 400)
        if not re.fullmatch(r'[A-Za-z0-9_$][A-Za-z0-9_$-]{0,63}', target):
            return None, ('Invalid database name - only letters, numbers, underscore and hyphen are allowed', 400)
    elif btype == 'website':
        if is_db_file:
            return None, ('This is a database dump - restore it as a database', 400)
        if target:
            _, err = _check_target(target)
            if err: return None, (err, 400)
    else:
        return None, ('Cannot determine backup type. Specify type explicitly.', 400)

    job = _Job(uuid.uuid4().hex[:12])

    def do_restore():
        try:
            if btype == 'database':
                err = _restore_db(job, path, target)
            elif name.endswith('.zip'):
                err = _restore_zip(job, path, target)
            else:
                err = _restore_tar(job, path, target)
            if err:
                job.fail(err)
                return
            job.line('Database ' + target + ' restored' if btype == 'database'
                     else 'Restored to ' + (target or 'original paths'))
            job.ok()
        except Exception as e:
            job.fail(str(e))

    threading.Thread(target=do_restore, daemon=True).start()
    return job.id, None

@backups_bp.route('/api/backups/restore', methods=['POST'])
def restore_backup():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    job_id, err = _start_restore(d.get('name',''), d.get('type',''), d.get('target',''))
    if err: return jsonify({'ok':False,'error':err[0]}), err[1]
    return jsonify({'ok':True,'job_id':job_id})

@backups_bp.route('/api/backups/upload', methods=['POST'])
def upload_restore():
    """Upload a .tar.gz, .sql.gz, .sql or .zip file and restore it"""
    if not req(): return jsonify({'ok':False}), 401
    f      = request.files.get('file')
    btype  = request.form.get('type','website')
    target = request.form.get('target','')
    if not f: return jsonify({'ok':False,'error':'No file uploaded'}), 400

    name = re.sub(r'[^A-Za-z0-9._-]', '_', os.path.basename(f.filename or ''))
    if not name.endswith(('.tar.gz','.tgz','.sql.gz','.zip','.sql')):
        return jsonify({'ok':False,'error':'Only .tar.gz, .sql.gz, .zip, .sql files are supported'}), 400
    if name.endswith('.tgz'): name = name[:-4] + '.tar.gz'
    if btype == 'database' and not target:
        return jsonify({'ok':False,'error':'Enter the database name to restore into'}), 400

    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    upload_name = f'upload_{time.strftime("%Y%m%d_%H%M%S")}_{name}'
    upload_path = os.path.join(BACKUP_DIR, upload_name)
    f.save(upload_path)
    os.chmod(upload_path, 0o600)
    # Previously this returned 'File uploaded. Use restore endpoint ...' and
    # never restored anything while the UI showed "Upload started!".
    job_id, err = _start_restore(upload_name, btype, target)
    if err: return jsonify({'ok':False,'error':err[0],'name':upload_name}), err[1]
    return jsonify({'ok':True,'job_id':job_id,'name':upload_name})
