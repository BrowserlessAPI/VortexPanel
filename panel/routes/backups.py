from flask import Blueprint, jsonify, request, session, send_file
import subprocess, os, glob, time, threading, json, uuid

backups_bp = Blueprint('backups', __name__)
def req(): return 'user' in session
BACKUP_DIR = '/opt/vortexpanel/backups'

def sh(c, t=600):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return '', 'Timed out', 1
    except Exception as e:
        return '', str(e), 1

def get_webroot():
    for p in ['/www/wwwroot', '/var/www/html', '/var/www']:
        if os.path.isdir(p): return p
    return '/www/wwwroot'

def mysql_available():
    out, _, rc = sh('which mysql 2>/dev/null && mysql -u root -e "SELECT 1;" 2>/dev/null', t=5)
    return rc == 0

def get_databases():
    out, _, rc = sh('mysql -u root -e "SHOW DATABASES;" 2>/dev/null | grep -vE "^(Database|information_schema|performance_schema|mysql|sys)$"', t=10)
    if rc != 0: return []
    return [d.strip() for d in out.strip().split('\n') if d.strip()]

def get_websites():
    """Return list of {domain, path} from nginx configs"""
    sites = []
    import re
    for conf_dir in ['/etc/nginx/sites-available', '/etc/nginx/conf.d']:
        if not os.path.isdir(conf_dir): continue
        for f in os.listdir(conf_dir):
            fp = os.path.join(conf_dir, f)
            if not os.path.isfile(fp): continue
            try:
                with open(fp) as fh: content = fh.read()
                domains = re.findall(r'server_name\s+([^;]+);', content)
                if not domains: continue
                domain = domains[0].strip().split()[0]
                path_m = re.search(r'root\s+([^;]+);', content)
                path = path_m.group(1).strip() if path_m else f'{get_webroot()}/{domain}'
                if os.path.isdir(path):
                    sites.append({'domain': domain, 'path': path})
            except: pass
    return sites

# Job tracking for backup progress
_jobs = {}

@backups_bp.route('/api/backups')
def list_backups():
    if not req(): return jsonify({'ok':False}), 401
    os.makedirs(BACKUP_DIR, exist_ok=True)
    files = []
    for f in sorted(glob.glob(f'{BACKUP_DIR}/*.tar.gz') +
                    glob.glob(f'{BACKUP_DIR}/*.sql.gz') +
                    glob.glob(f'{BACKUP_DIR}/*.zip'), reverse=True):
        st    = os.stat(f)
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

@backups_bp.route('/api/backups/create', methods=['POST'])
def create_backup():
    if not req(): return jsonify({'ok':False}), 401
    d      = request.get_json() or {}
    btype  = d.get('type', 'website')  # website | database | full
    domain = d.get('domain', '')       # specific domain or empty for all
    db     = d.get('database', '')     # specific DB or empty for all
    ts     = time.strftime('%Y%m%d_%H%M%S')
    os.makedirs(BACKUP_DIR, exist_ok=True)
    job_id = str(uuid.uuid4())[:8]
    _jobs[job_id] = {'done':False,'success':False,'name':'','size':0,'error':'','lines':[]}

    def do_backup():
        try:
            if btype == 'website':
                # Validate: get path for domain
                if domain:
                    sites = get_websites()
                    site  = next((s for s in sites if s['domain']==domain), None)
                    if not site:
                        # Fallback: check if directory exists
                        path = os.path.join(get_webroot(), domain)
                        if not os.path.isdir(path):
                            _jobs[job_id].update({'done':True,'error':f'Website path not found for {domain}'})
                            return
                    else:
                        path = site['path']
                    name = f'website_{domain}_{ts}.tar.gz'
                else:
                    path = get_webroot()
                    name = f'website_all_{ts}.tar.gz'
                dest = os.path.join(BACKUP_DIR, name)
                _jobs[job_id]['lines'].append(f'Archiving {path}...')
                _, err, rc = sh(f'tar -czf {dest} -C / {path.lstrip("/")} 2>&1')
                if rc != 0 and not os.path.exists(dest):
                    _jobs[job_id].update({'done':True,'error':f'tar failed: {err}'})
                    return

            elif btype == 'database':
                dbs = get_databases()
                if not dbs:
                    _jobs[job_id].update({'done':True,'error':'No databases found. Create a database first.'})
                    return
                if db and db not in dbs:
                    _jobs[job_id].update({'done':True,'error':f'Database "{db}" not found'})
                    return
                target_dbs = [db] if db else dbs
                name = f'database_{db or "all"}_{ts}.sql.gz'
                dest = os.path.join(BACKUP_DIR, name)
                if db:
                    _jobs[job_id]['lines'].append(f'Dumping database: {db}')
                    _, err, rc = sh(f'mysqldump -u root --single-transaction --routines --triggers {db} | gzip > {dest}', t=300)
                else:
                    _jobs[job_id]['lines'].append(f'Dumping {len(dbs)} databases: {", ".join(dbs)}')
                    _, err, rc = sh(f'mysqldump -u root --single-transaction --routines --triggers --all-databases | gzip > {dest}', t=300)
                if rc != 0:
                    _jobs[job_id].update({'done':True,'error':f'mysqldump failed: {err}'})
                    return

            elif btype == 'full':
                name  = f'full_{ts}.tar.gz'
                dest  = os.path.join(BACKUP_DIR, name)
                webroot = get_webroot()
                _jobs[job_id]['lines'].append('Archiving websites, nginx configs, caddyfile...')
                include = [webroot.lstrip('/')]
                for extra in ['etc/nginx', 'etc/caddy', 'opt/vortexpanel/backups']:
                    if os.path.isdir(f'/{extra}'): include.append(extra)
                _, err, rc = sh(f'tar -czf {dest} -C / {" ".join(include)} 2>&1')
                if rc != 0 and not os.path.exists(dest):
                    _jobs[job_id].update({'done':True,'error':f'Full backup failed: {err}'})
                    return
            else:
                _jobs[job_id].update({'done':True,'error':f'Unknown backup type: {btype}'})
                return

            size = os.path.getsize(dest) if os.path.exists(dest) else 0
            _jobs[job_id].update({'done':True,'success':True,'name':name,'size':size})
            _jobs[job_id]['lines'].append(f'✓ Backup complete: {name} ({size//1024}KB)')

        except Exception as e:
            _jobs[job_id].update({'done':True,'error':str(e)})

    threading.Thread(target=do_backup, daemon=True).start()
    return jsonify({'ok':True, 'job_id':job_id})

@backups_bp.route('/api/backups/job/<job_id>')
def job_status(job_id):
    if not req(): return jsonify({'ok':False}), 401
    job = _jobs.get(job_id)
    if not job: return jsonify({'ok':False,'error':'Job not found'}), 404
    return jsonify({'ok':True, **job})

@backups_bp.route('/api/backups/download/<name>')
def download_backup(name):
    if not req(): return jsonify({'ok':False}), 401
    # Sanitize filename — no path traversal
    name = os.path.basename(name)
    path = os.path.join(BACKUP_DIR, name)
    if not os.path.exists(path):
        return jsonify({'ok':False,'error':'File not found'}), 404
    return send_file(path, as_attachment=True, download_name=name)

@backups_bp.route('/api/backups/<name>', methods=['DELETE'])
def delete_backup(name):
    if not req(): return jsonify({'ok':False}), 401
    name = os.path.basename(name)
    path = os.path.join(BACKUP_DIR, name)
    if os.path.exists(path): os.unlink(path)
    return jsonify({'ok':True})

@backups_bp.route('/api/backups/restore', methods=['POST'])
def restore_backup():
    if not req(): return jsonify({'ok':False}), 401
    d      = request.get_json() or {}
    name   = os.path.basename(d.get('name',''))
    btype  = d.get('type','')    # website | database
    target = d.get('target','')  # restore path for website, db name for database
    path   = os.path.join(BACKUP_DIR, name)

    if not name or not os.path.exists(path):
        return jsonify({'ok':False,'error':'Backup file not found'}), 404

    job_id = str(uuid.uuid4())[:8]
    _jobs[job_id] = {'done':False,'success':False,'error':'','lines':[]}

    def do_restore():
        try:
            if btype == 'website' or name.endswith('.tar.gz') and 'database' not in name and 'sql' not in name:
                restore_path = target or get_webroot()
                _jobs[job_id]['lines'].append(f'Restoring to {restore_path}...')
                os.makedirs(restore_path, exist_ok=True)
                _, err, rc = sh(f'tar -xzf {path} -C {restore_path} --strip-components=2 2>&1')
                if rc != 0:
                    # Try without strip
                    _, err2, rc2 = sh(f'tar -xzf {path} -C {restore_path} 2>&1')
                    if rc2 != 0:
                        _jobs[job_id].update({'done':True,'error':f'Restore failed: {err2}'})
                        return
                _jobs[job_id].update({'done':True,'success':True})
                _jobs[job_id]['lines'].append(f'✓ Restored to {restore_path}')

            elif btype == 'database' or name.endswith('.sql.gz') or 'database' in name:
                if not target:
                    _jobs[job_id].update({'done':True,'error':'Database name required for restore'})
                    return
                _jobs[job_id]['lines'].append(f'Restoring database {target}...')
                # Create DB if not exists
                sh(f'mysql -u root -e "CREATE DATABASE IF NOT EXISTS `{target}`;" 2>/dev/null')
                _, err, rc = sh(f'gunzip -c {path} | mysql -u root {target} 2>&1', t=300)
                if rc != 0:
                    _jobs[job_id].update({'done':True,'error':f'Restore failed: {err}'})
                    return
                _jobs[job_id].update({'done':True,'success':True})
                _jobs[job_id]['lines'].append(f'✓ Database {target} restored')
            else:
                _jobs[job_id].update({'done':True,'error':'Cannot determine backup type. Specify type explicitly.'})
        except Exception as e:
            _jobs[job_id].update({'done':True,'error':str(e)})

    threading.Thread(target=do_restore, daemon=True).start()
    return jsonify({'ok':True,'job_id':job_id})

@backups_bp.route('/api/backups/upload', methods=['POST'])
def upload_restore():
    """Upload a .tar.gz or .sql.gz file and restore it"""
    if not req(): return jsonify({'ok':False}), 401
    f      = request.files.get('file')
    btype  = request.form.get('type','website')
    target = request.form.get('target','')
    if not f: return jsonify({'ok':False,'error':'No file uploaded'}), 400

    name = os.path.basename(f.filename)
    if not name.endswith(('.tar.gz','.sql.gz','.zip','.sql')):
        return jsonify({'ok':False,'error':'Only .tar.gz, .sql.gz, .zip, .sql files are supported'}), 400

    upload_path = os.path.join(BACKUP_DIR, f'upload_{name}')
    f.save(upload_path)
    # Trigger restore
    return restore_backup.__wrapped__(request.json) if hasattr(restore_backup,'__wrapped__') else jsonify({'ok':True,'path':upload_path,'message':'File uploaded. Use restore endpoint with this path.'})
