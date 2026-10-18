"""Website > Clone: copy a site to a new domain - files, database and config.

POST /api/websites/<domain>/clone  {new_domain, database?, copy_db?}
  1. creates the new site with the same PHP version (create_site_core)
  2. copies the files (rsync, owner kept)
  3. MySQL/MariaDB: dumps the chosen database into a new one with its own
     user and a random password (WordPress: picked from wp-config.php)
  4. WordPress: points wp-config.php at the copy and replaces the old domain
     with the new one everywhere in the database (wp search-replace)
  5. copies the URL rewrite rules
Runs in the background (site_clone_<new domain>); the source site is only read.
"""
import os
import re
import secrets
import shlex
import shutil
import string
import subprocess
import threading
import time

from flask import jsonify, request, current_app

from panel.routes.websites_core import (websites_bp, req, is_valid_domain, create_site_core,
                                        _get_site_path, _find_site_config, _site_php, get_webroot)
from panel.routes.job_state import load_job, save_job

Q = shlex.quote


def _run(args, timeout=1800, env=None):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, f'timed out after {timeout}s'
    except FileNotFoundError as e:
        return 127, str(e)


def _wp_db_name(path):
    try:
        txt = open(os.path.join(path, 'wp-config.php'), errors='replace').read()
    except OSError:
        return ''
    m = re.search(r"define\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]", txt)
    return m.group(1) if m else ''


def _db_ident(name):
    return re.sub(r'[^A-Za-z0-9_]', '_', name)[:58]


@websites_bp.route('/api/websites/<domain>/clone/info')
def clone_info(domain):
    """What the Clone tab needs: the site's database (WordPress) and the
    MySQL databases to choose from."""
    if not req(): return jsonify({'ok': False}), 401
    if not is_valid_domain(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    path = _get_site_path(domain)
    dbs = []
    try:
        from panel.routes.databases import mysql_dbs
        dbs = [x['name'] for x in (mysql_dbs()[0] or [])]
    except Exception:
        pass
    return jsonify({'ok': True, 'path': path, 'wordpress': os.path.isfile(os.path.join(path, 'wp-config.php')),
                    'wp_database': _wp_db_name(path), 'databases': dbs,
                    'suggested_db': _db_ident(domain.split('.')[0] + '_copy')})


@websites_bp.route('/api/websites/<domain>/clone', methods=['POST'])
def clone_site(domain):
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    new = str(d.get('new_domain') or '').strip().lower()
    if not is_valid_domain(domain) or not is_valid_domain(new) or new.startswith('*'):
        return jsonify({'ok': False, 'error': 'Enter a valid new domain'}), 400
    if new == domain:
        return jsonify({'ok': False, 'error': 'The new domain must be different'}), 400
    if _find_site_config(new)[0]:
        return jsonify({'ok': False, 'error': f'{new} already exists'}), 400
    src_conf, ws = _find_site_config(domain)
    if not src_conf:
        return jsonify({'ok': False, 'error': 'Site not found'}), 404
    src = _get_site_path(domain).rstrip('/')
    if not os.path.isdir(src):
        return jsonify({'ok': False, 'error': f'{src} does not exist'}), 400
    dst = os.path.join(get_webroot(), new)
    if os.path.exists(dst) and os.listdir(dst):
        return jsonify({'ok': False, 'error': f'{dst} already exists and is not empty'}), 400
    src_db = str(d.get('database') or '').strip()
    copy_db = bool(d.get('copy_db', True)) and bool(src_db)
    if copy_db and not re.fullmatch(r'[A-Za-z0-9_$-]{1,64}', src_db):
        return jsonify({'ok': False, 'error': 'Invalid database name'}), 400
    new_db = _db_ident(str(d.get('new_database') or '') or (new.split('.')[0] + '_' + secrets.token_hex(2)))
    jid = f'site_clone_{new}'
    if load_job(jid, {}).get('running'):
        return jsonify({'ok': False, 'error': 'A clone to this domain is already running'}), 409
    php = _site_php(src_conf) or 'static'
    save_job(jid, {'running': True, 'step': 'Starting', 'output': ''})
    app = current_app._get_current_object()
    threading.Thread(target=_clone_job, args=(app, jid, domain, new, src, dst, php, copy_db, src_db, new_db, src_conf, ws),
                     daemon=True).start()
    return jsonify({'ok': True, 'job': jid})


@websites_bp.route('/api/websites/clone-job/<new>')
def clone_job(new):
    if not req(): return jsonify({'ok': False}), 401
    if not is_valid_domain(new):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    return jsonify({'ok': True, **load_job(f'site_clone_{new}', {})})


def _clone_job(app, jid, domain, new, src, dst, php, copy_db, src_db, new_db, src_conf, ws):
    log = []

    def note(m):
        log.append(m)
        save_job(jid, {'running': True, 'step': m.splitlines()[0][:120], 'output': '\n'.join(log)[-10000:]})

    def fail(m):
        log.append('FAILED: ' + m)
        save_job(jid, {'running': False, 'done': True, 'success': False, 'error': m, 'output': '\n'.join(log)[-10000:]})

    try:
        ok, res = create_site_core(new, path=dst, php=php)
        if not ok:
            return fail('creating the site failed: ' + res.get('error', ''))
        note(f'Created {new} (PHP {php}) at {dst}')
        if shutil.which('rsync'):
            rc, out = _run(['rsync', '-a', '--exclude', '.user.ini', src + '/', dst + '/'])
        else:
            rc, out = _run(['cp', '-a', src + '/.', dst + '/'])
        if rc != 0:
            return fail('copying files failed: ' + out[-500:])
        st = os.stat(src)
        _run(['chown', '-R', f'{st.st_uid}:{st.st_gid}', dst])
        note(f'Copied files from {src}')

        wp = os.path.isfile(os.path.join(dst, 'wp-config.php'))
        if copy_db:
            from panel.routes import databases as D
            pw = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20))
            _, err = D.mysql_cmd(f'CREATE DATABASE `{new_db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n'
                                 f"CREATE USER IF NOT EXISTS '{new_db}'@'localhost' IDENTIFIED BY '{pw}';\n"
                                 f"GRANT ALL PRIVILEGES ON `{new_db}`.* TO '{new_db}'@'localhost'; FLUSH PRIVILEGES;")
            if err:
                return fail('creating the database failed: ' + err)
            dump = D._mk_tmp('.sql')
            try:
                _, err = D._mysql_run(D._mysql_bin('dump'), f'--single-transaction --routines --triggers --events '
                                      f'{Q(src_db)} > {Q(dump)}', 1800)
                if err:
                    return fail('dumping the database failed: ' + err)
                _, err = D._mysql_run(D._mysql_bin(), f'{Q(new_db)} < {Q(dump)}', 1800)
                if err:
                    return fail('importing into the new database failed: ' + err)
            finally:
                D._unlink(dump)
            note(f'Copied database {src_db} to {new_db} (user {new_db})')
            if wp:
                from panel.routes import wp_toolkit as W
                for k, v in (('DB_NAME', new_db), ('DB_USER', new_db), ('DB_PASSWORD', pw)):
                    rc, out = _run(['bash', '-c', f'{W._wpx(dst)} config set {k} {Q(v)} --type=constant 2>&1'], 120)
                    if rc != 0:
                        return fail(f'updating wp-config.php ({k}) failed: ' + out[-300:])
                rc, out = _run(['bash', '-c', f'{W._wpx(dst)} search-replace {Q("//" + domain)} {Q("//" + new)} '
                                f'--all-tables --skip-columns=guid --precise 2>&1'], 1800)
                note('WordPress: wp-config.php updated; ' + (out.splitlines()[-1] if out else 'search-replace done'))
                if rc != 0:
                    return fail('replacing the domain in the database failed: ' + out[-400:])
                _run(['bash', '-c', f'{W._wpx(dst)} cache flush 2>&1'], 120)
            else:
                note(f'Update your app configuration to use database {new_db}, user {new_db}, password {pw}')
        # URL rewrite rules (nginx keeps them in the vhost between markers)
        if ws == 'nginx':
            m = re.search(r'#VP_REWRITE_START\n(.*?)\n\s*#VP_REWRITE_END', open(src_conf).read(), re.S)
            if m and m.group(1).strip():
                from panel.routes.websites_proxy import save_rewrite
                from panel.utils.authctx import elevate
                with app.test_request_context(json={'content': m.group(1)}), elevate():
                    r = save_rewrite(new)
                note('Copied URL rewrite rules')
        _run(['bash', '-c', 'nginx -t >/dev/null 2>&1 && (systemctl reload nginx || nginx -s reload)'], 60)
        save_job(jid, {'running': False, 'done': True, 'success': True, 'new_domain': new, 'output': '\n'.join(log)[-10000:]})
    except Exception as e:
        fail(f'{type(e).__name__}: {e}')
