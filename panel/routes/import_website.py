"""
Website Import — cPanel / aaPanel / HestiaCP
==============================================
Upload-based import wizard: user uploads a backup archive exported from the
old panel, VortexPanel extracts it, makes a best-effort detection of the
domain/PHP version/database, and shows an editable PREVIEW before doing
anything irreversible. The user confirms (correcting any fields the auto-
detection got wrong) and only then does the actual site+database creation
happen.

This "detect then confirm" design is deliberate: cPanel's cpmove format is
well-documented and stable, but aaPanel and HestiaCP backups are far less
rigidly standardized across versions — auto-detection is best-effort, not
guaranteed, so every detected field is editable rather than blindly trusted.

Only site files + database are imported (no email/cron/SSL in this version).
"""
from flask import Blueprint, jsonify, request, session
import os, re, subprocess, tempfile, threading, time, json, uuid, shutil

import_bp = Blueprint('import_website', __name__)

def req(): return 'user' in session

def sh(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return '', 'Timeout', 1
    except Exception as e:
        return '', str(e), 1

# Reuse the exact same site-creation logic as the normal "New Website" flow —
# imported sites get identical, correct nginx vhosts, no drift between the
# two code paths.
try:
    from panel.routes.websites_core import create_site_core, get_webroot, ensure_web_ownership
except ImportError:
    from websites_core import create_site_core, get_webroot, ensure_web_ownership

IMPORT_WORKSPACE = '/opt/vortexpanel/import_workspace'


# --- Job store (same JSONL-append pattern used across the panel: modules.py,
# go_projects.py, etc — kept self-contained here rather than cross-imported,
# matching the established convention of each route file owning its own copy) ---
def _job_dir():
    d = os.path.join(IMPORT_WORKSPACE, '_jobs')
    os.makedirs(d, exist_ok=True)
    return d

def _job_path(job_id):
    return os.path.join(_job_dir(), f'{job_id}.jsonl')

def _job_create(job_id):
    open(_job_path(job_id), 'w').close()

def _job_append(job_id, line):
    try:
        with open(_job_path(job_id), 'a') as f:
            f.write(json.dumps({'line': line}) + '\n')
    except Exception:
        pass

def _job_finish(job_id, success, **extra):
    try:
        with open(_job_path(job_id), 'a') as f:
            f.write(json.dumps({'done': True, 'success': success, **extra}) + '\n')
    except Exception:
        pass


# --- Upload -------------------------------------------------------------------
@import_bp.route('/api/import/upload', methods=['POST'])
def upload_backup():
    if not req(): return jsonify({'ok': False}), 401
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'ok': False, 'error': 'No file uploaded'})

    import_id = str(uuid.uuid4())[:12]
    workdir = os.path.join(IMPORT_WORKSPACE, import_id)
    os.makedirs(workdir, exist_ok=True)

    safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', f.filename)
    archive_path = os.path.join(workdir, safe_name)
    f.save(archive_path)

    size = os.path.getsize(archive_path)
    return jsonify({'ok': True, 'import_id': import_id, 'filename': safe_name, 'size_bytes': size})


# --- Detection ------------------------------------------------------------------
def _extract_archive(archive_path, dest_dir):
    """Extract a .tar.gz/.tar/.zip archive. Returns (ok, error_message)."""
    os.makedirs(dest_dir, exist_ok=True)
    lower = archive_path.lower()
    if lower.endswith('.zip'):
        _, err, rc = sh(f'unzip -q -o "{archive_path}" -d "{dest_dir}"', timeout=180)
    elif lower.endswith('.tar.gz') or lower.endswith('.tgz'):
        _, err, rc = sh(f'tar -xzf "{archive_path}" -C "{dest_dir}"', timeout=180)
    elif lower.endswith('.tar'):
        _, err, rc = sh(f'tar -xf "{archive_path}" -C "{dest_dir}"', timeout=180)
    else:
        return False, f'Unrecognized archive format: {os.path.basename(archive_path)} (expected .tar.gz, .tar, or .zip)'
    if rc != 0:
        return False, err or 'Extraction failed'
    return True, ''


def _find_first(root, *names):
    """Find the first path matching any of the given relative names, searching
    both at the top level and one level deep (since some backups wrap
    everything in an extra outer folder)."""
    for name in names:
        direct = os.path.join(root, name)
        if os.path.exists(direct):
            return direct
    # One level deep
    try:
        for entry in os.listdir(root):
            sub = os.path.join(root, entry)
            if os.path.isdir(sub):
                for name in names:
                    candidate = os.path.join(sub, name)
                    if os.path.exists(candidate):
                        return candidate
    except OSError:
        pass
    return None


DOMAIN_RE = re.compile(r'\b([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.IGNORECASE)


def _detect_cpanel(extract_dir):
    """cPanel cpmove/full-backup format — well-documented, stable for years.
    Structure: homedir/public_html, mysql/{db}.sql or mysql.sql, userdata/main."""
    info = {'panel_type': 'cpanel', 'domain': '', 'php_version': '', 'doc_root': '',
            'databases': [], 'notes': []}

    homedir = _find_first(extract_dir, 'homedir')
    if homedir:
        pub_html = os.path.join(homedir, 'public_html')
        if os.path.isdir(pub_html):
            info['doc_root'] = pub_html
            info['notes'].append(f'Found homedir/public_html: {pub_html}')
        else:
            info['doc_root'] = homedir
            info['notes'].append('No public_html found — using homedir root as doc root')
    else:
        info['notes'].append('⚠ No homedir/ found — cPanel structure not recognized')

    # Domain from userdata/main (YAML: "main_domain: example.com")
    userdata_main = _find_first(extract_dir, 'userdata/main', 'userdata')
    if userdata_main and os.path.isfile(userdata_main):
        try:
            content = open(userdata_main, errors='ignore').read()
            m = re.search(r'main_domain:\s*(\S+)', content)
            if m: info['domain'] = m.group(1).strip()
            m2 = re.search(r'documentroot:\s*(\S+)', content)
            if m2: info['notes'].append(f'userdata documentroot: {m2.group(1)}')
        except Exception:
            pass

    # Fallback: cp/{username} file often has a DNS= line with the primary domain
    if not info['domain']:
        cp_dir = _find_first(extract_dir, 'cp')
        if cp_dir and os.path.isdir(cp_dir):
            try:
                for fname in os.listdir(cp_dir):
                    content = open(os.path.join(cp_dir, fname), errors='ignore').read()
                    m = re.search(r'^DNS=(\S+)', content, re.MULTILINE)
                    if m:
                        info['domain'] = m.group(1).strip()
                        info['notes'].append(f'Domain from cp/{fname}')
                        break
            except Exception:
                pass

    if not info['domain']:
        info['notes'].append('⚠ Could not auto-detect domain — please enter it manually')

    # Databases: mysql/{name}.sql (one file per db) is the modern cpmove format
    mysql_dir = _find_first(extract_dir, 'mysql')
    if mysql_dir and os.path.isdir(mysql_dir):
        for fname in os.listdir(mysql_dir):
            if fname.endswith('.sql'):
                db_name = fname[:-4]
                info['databases'].append({'name': db_name, 'dump_path': os.path.join(mysql_dir, fname)})
    else:
        # Older format: single combined mysql.sql — can't cleanly split per-db,
        # surface it as one dump the user names manually.
        combined = _find_first(extract_dir, 'mysql.sql')
        if combined:
            info['databases'].append({'name': '', 'dump_path': combined,
                                       'note': 'Combined dump — please provide a database name'})

    if not info['databases']:
        info['notes'].append('No database dump found in this backup')

    return info


def _detect_aapanel(extract_dir):
    """aaPanel site/db backups are not rigidly standardized across versions —
    no reliable embedded metadata for domain name, unlike cPanel. Best-effort:
    look for a top-level folder that looks like a domain name (common when the
    zip wraps the site as wwwroot/domain.com/...). Database name is guessed
    from any .sql/.sql.gz filename found, but should be confirmed by the user."""
    info = {'panel_type': 'aapanel', 'domain': '', 'php_version': '', 'doc_root': '',
            'databases': [], 'notes': []}

    # Look for a wwwroot/{domain}/ nesting pattern first
    wwwroot = _find_first(extract_dir, 'wwwroot')
    search_root = wwwroot if wwwroot else extract_dir

    domain_dir = None
    try:
        for entry in os.listdir(search_root):
            full = os.path.join(search_root, entry)
            if os.path.isdir(full) and DOMAIN_RE.fullmatch(entry):
                domain_dir = full
                info['domain'] = entry
                info['notes'].append(f'Detected domain-like folder: {entry}')
                break
    except OSError:
        pass

    if domain_dir:
        info['doc_root'] = domain_dir
    else:
        # No domain-shaped folder — assume the archive root itself IS the site files
        info['doc_root'] = extract_dir
        info['notes'].append('⚠ No domain-named folder found — assuming archive root is the site files. Please verify the domain name manually.')

    # Database dumps: aaPanel typically exports these as separate .sql/.sql.gz
    # files, sometimes bundled in the same archive, sometimes not at all.
    for root, dirs, files in os.walk(extract_dir):
        for fname in files:
            if fname.endswith('.sql') or fname.endswith('.sql.gz'):
                # aaPanel naming convention: {dbname}_{timestamp}.sql[.gz]
                base = fname.replace('.sql.gz', '').replace('.sql', '')
                guessed_name = re.sub(r'_\d{8,}.*$', '', base)  # strip trailing date/time
                info['databases'].append({'name': guessed_name, 'dump_path': os.path.join(root, fname),
                                           'note': 'Name guessed from filename — please verify'})

    if not info['databases']:
        info['notes'].append('No .sql/.sql.gz database dump found in this archive — you can still import files-only, or upload the database separately afterward')

    return info


def _detect_hestia(extract_dir):
    """HestiaCP v-backup-user format: outer tar containing inner tars
    (web.tar, mysql.tar, dns.tar, mail.tar, cron.tar). Site files live under
    home/{user}/web/{domain}/public_html once web.tar is extracted."""
    info = {'panel_type': 'hestia', 'domain': '', 'php_version': '', 'doc_root': '',
            'databases': [], 'notes': []}

    # Extract inner web.tar if present
    web_tar = _find_first(extract_dir, 'web.tar')
    if web_tar:
        web_extract_dir = os.path.join(extract_dir, '_web_extracted')
        ok, err = _extract_archive(web_tar, web_extract_dir)
        if ok:
            info['notes'].append('Extracted inner web.tar')
            # Structure: home/{user}/web/{domain}/public_html
            for root, dirs, files in os.walk(web_extract_dir):
                if os.path.basename(root) == 'public_html':
                    info['doc_root'] = root
                    # Domain is typically the parent folder name
                    parent = os.path.basename(os.path.dirname(root))
                    if DOMAIN_RE.fullmatch(parent):
                        info['domain'] = parent
                        info['notes'].append(f'Detected domain from Hestia web/ structure: {parent}')
                    break
        else:
            info['notes'].append(f'⚠ Failed to extract web.tar: {err}')
    else:
        info['notes'].append('⚠ No web.tar found inside backup — Hestia structure not recognized')
        info['doc_root'] = extract_dir

    if not info['domain']:
        info['notes'].append('⚠ Could not auto-detect domain — please enter it manually')

    # Databases: mysql.tar containing per-db .sql files, OR a mysql/ folder directly
    mysql_tar = _find_first(extract_dir, 'mysql.tar')
    mysql_dir = None
    if mysql_tar:
        mysql_extract_dir = os.path.join(extract_dir, '_mysql_extracted')
        ok, err = _extract_archive(mysql_tar, mysql_extract_dir)
        if ok:
            mysql_dir = mysql_extract_dir
            info['notes'].append('Extracted inner mysql.tar')
        else:
            info['notes'].append(f'⚠ Failed to extract mysql.tar: {err}')
    else:
        mysql_dir = _find_first(extract_dir, 'mysql')

    if mysql_dir:
        for root, dirs, files in os.walk(mysql_dir):
            for fname in files:
                if fname.endswith('.sql'):
                    db_name = fname[:-4]
                    info['databases'].append({'name': db_name, 'dump_path': os.path.join(root, fname)})

    if not info['databases']:
        info['notes'].append('No database dump found in this backup')

    return info


DETECTORS = {
    'cpanel': _detect_cpanel,
    'aapanel': _detect_aapanel,
    'hestia': _detect_hestia,
}


@import_bp.route('/api/import/<import_id>/detect', methods=['POST'])
def detect_backup(import_id):
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    panel_type = d.get('panel_type', '')
    if panel_type not in DETECTORS:
        return jsonify({'ok': False, 'error': f'Unknown panel type: {panel_type}'})

    workdir = os.path.join(IMPORT_WORKSPACE, import_id)
    if not os.path.isdir(workdir):
        return jsonify({'ok': False, 'error': 'Import session not found — please re-upload'})

    # Find the uploaded archive (any file directly in workdir that isn't a dir)
    archive_files = [f for f in os.listdir(workdir) if os.path.isfile(os.path.join(workdir, f))]
    if not archive_files:
        return jsonify({'ok': False, 'error': 'No uploaded archive found in this session'})
    archive_path = os.path.join(workdir, archive_files[0])

    extract_dir = os.path.join(workdir, 'extracted')
    if not os.path.isdir(extract_dir):
        ok, err = _extract_archive(archive_path, extract_dir)
        if not ok:
            return jsonify({'ok': False, 'error': f'Extraction failed: {err}'})

    info = DETECTORS[panel_type](extract_dir)
    info['import_id'] = import_id
    return jsonify({'ok': True, **info})


# --- Execute --------------------------------------------------------------------
@import_bp.route('/api/import/<import_id>/execute', methods=['POST'])
def execute_import(import_id):
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}

    domain      = (d.get('domain') or '').strip().lower()
    doc_root    = (d.get('doc_root') or '').strip()
    php_version = (d.get('php_version') or '8.3').strip()
    databases   = d.get('databases') or []   # [{name, dump_path, target_db_name}]

    if not domain:
        return jsonify({'ok': False, 'error': 'Domain is required'})
    if not doc_root or not os.path.isdir(doc_root):
        return jsonify({'ok': False, 'error': 'Document root path is invalid or missing'})

    workdir = os.path.join(IMPORT_WORKSPACE, import_id)
    if not os.path.isdir(workdir):
        return jsonify({'ok': False, 'error': 'Import session not found'})

    job_id = str(uuid.uuid4())[:8]
    _job_create(job_id)

    def run_job():
        try:
            _job_append(job_id, f'[VortexPanel] Starting import for {domain}')

            # 1. Create the site (reusing the exact same core logic as "New Website")
            _job_append(job_id, '[VortexPanel] Creating website + nginx vhost...')
            site_path = f'{get_webroot()}/{domain}'
            ok, result = create_site_core(domain, site_path, php_version)
            if not ok:
                _job_append(job_id, f'[ERROR] Site creation failed: {result.get("error")}')
                _job_finish(job_id, False)
                return
            _job_append(job_id, f'[VortexPanel] ✓ Site created: {site_path}')

            # 2. Copy site files from the extracted doc root into the new webroot
            _job_append(job_id, f'[VortexPanel] Copying files from {doc_root} ...')
            copy_result = subprocess.run(
                f'cp -a "{doc_root}/." "{site_path}/"',
                shell=True, capture_output=True, text=True, timeout=300
            )
            if copy_result.returncode != 0:
                _job_append(job_id, f'[ERROR] File copy failed: {copy_result.stderr.strip()[:300]}')
                _job_finish(job_id, False)
                return
            file_count = subprocess.run(f'find "{site_path}" -type f | wc -l',
                                         shell=True, capture_output=True, text=True).stdout.strip()
            _job_append(job_id, f'[VortexPanel] ✓ Copied {file_count} files')

            ensure_web_ownership(site_path)
            _job_append(job_id, '[VortexPanel] ✓ File ownership set for web server user')

            # 3. Import databases
            imported_dbs = []
            for db in databases:
                target_name = re.sub(r'[^a-zA-Z0-9_]', '', db.get('target_db_name') or db.get('name') or '')
                dump_path = db.get('dump_path', '')
                if not target_name:
                    _job_append(job_id, '[WARN] Skipping a database with no name specified')
                    continue
                if not dump_path or not os.path.isfile(dump_path):
                    _job_append(job_id, f'[WARN] Skipping {target_name} — dump file not found')
                    continue

                _job_append(job_id, f'[VortexPanel] Creating database `{target_name}`...')
                sockets = ['/var/run/mysqld/mysqld.sock', '/run/mysqld/mysqld.sock']
                sock_flag = ''
                for sock in sockets:
                    if os.path.exists(sock):
                        sock_flag = f'--socket={sock}'
                        break

                create_out = subprocess.run(
                    f'mysql -u root {sock_flag} -e "CREATE DATABASE IF NOT EXISTS \\`{target_name}\\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"',
                    shell=True, capture_output=True, text=True, timeout=30
                )
                if create_out.returncode != 0:
                    _job_append(job_id, f'[ERROR] Failed to create database {target_name}: {create_out.stderr.strip()[:300]}')
                    continue

                # Generate a fresh random password for the import's DB user —
                # original passwords are never included in backup dumps, so we
                # can't (and shouldn't try to) recover them.
                import secrets, string
                new_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
                subprocess.run(
                    f"mysql -u root {sock_flag} -e \"CREATE USER IF NOT EXISTS '{target_name}'@'localhost' IDENTIFIED BY '{new_password}'; "
                    f"GRANT ALL PRIVILEGES ON \\`{target_name}\\`.* TO '{target_name}'@'localhost'; FLUSH PRIVILEGES;\"",
                    shell=True, capture_output=True, text=True, timeout=30
                )

                _job_append(job_id, f'[VortexPanel] Importing dump ({os.path.basename(dump_path)})...')
                if dump_path.endswith('.gz'):
                    import_cmd = f'zcat "{dump_path}" | mysql -u root {sock_flag} "{target_name}"'
                else:
                    import_cmd = f'mysql -u root {sock_flag} "{target_name}" < "{dump_path}"'
                imp = subprocess.run(import_cmd, shell=True, capture_output=True, text=True, timeout=300)
                if imp.returncode != 0:
                    _job_append(job_id, f'[ERROR] Import failed for {target_name}: {imp.stderr.strip()[:300]}')
                    continue

                _job_append(job_id, f'[VortexPanel] ✓ Database `{target_name}` imported — user `{target_name}` / password: {new_password}')
                imported_dbs.append({'name': target_name, 'user': target_name, 'password': new_password})

            _job_append(job_id, f'[VortexPanel] ✓ Import complete for {domain}')
            if imported_dbs:
                _job_append(job_id, '[VortexPanel] IMPORTANT: save these generated database credentials — they will not be shown again:')
                for db in imported_dbs:
                    _job_append(job_id, f'   • {db["name"]} — user: {db["user"]} — password: {db["password"]}')

            # Clean up the extraction workspace (keep the original uploaded archive
            # for a short while in case something needs re-checking, but the
            # extracted copy can be large and isn't needed after a successful import)
            shutil.rmtree(os.path.join(workdir, 'extracted'), ignore_errors=True)

            _job_finish(job_id, True, domain=domain, databases=imported_dbs)

        except Exception as e:
            _job_append(job_id, f'[ERROR] Unexpected error: {str(e)}')
            _job_finish(job_id, False)

    threading.Thread(target=run_job, daemon=True).start()
    return jsonify({'ok': True, 'job_id': job_id})


@import_bp.route('/api/import/job/<job_id>')
def import_job_stream(job_id):
    from flask import Response
    def generate():
        path = _job_path(job_id)
        for _ in range(50):
            if os.path.exists(path):
                break
            time.sleep(0.1)
        else:
            yield f'data: {json.dumps({"error": "Job not found"})}\n\n'
            return
        seen = 0
        for _ in range(600):  # up to 10 minutes of streaming
            try:
                with open(path) as f:
                    lines = f.readlines()
            except Exception:
                lines = []
            for line in lines[seen:]:
                yield f'data: {line.strip()}\n\n'
            seen = len(lines)
            if lines and json.loads(lines[-1]).get('done'):
                break
            time.sleep(1)
    return Response(generate(), mimetype='text/event-stream')


@import_bp.route('/api/import/<import_id>/cancel', methods=['POST'])
def cancel_import(import_id):
    if not req(): return jsonify({'ok': False}), 401
    workdir = os.path.join(IMPORT_WORKSPACE, import_id)
    shutil.rmtree(workdir, ignore_errors=True)
    return jsonify({'ok': True})
