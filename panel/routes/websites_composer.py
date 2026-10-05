import os, re, shlex
from flask import jsonify, request

try:
    from panel.routes.websites_core import websites_bp, req, sh, get_nginx_dirs, _get_site_path
except ImportError:
    from websites_core import websites_bp, req, sh, get_nginx_dirs, _get_site_path


@websites_bp.route('/api/websites/<domain>/composer', methods=['POST'])
def run_composer(domain):
    if not req(): return jsonify({'ok':False}), 401
    import threading, uuid, subprocess as _sp
    from panel.routes.job_state import save_job
    d = request.get_json() or {}
    action   = d.get('action','install')   # install|update|require|create-project
    packages = str(d.get('packages','') or '').strip()
    php_ver  = str(d.get('php_ver','') or '').strip()
    work_dir = str(d.get('work_dir','') or '').strip()

    # Find site path (any web server: nginx, Apache, OpenLiteSpeed, Caddy)
    site_path = work_dir or _get_site_path(domain)
    if not site_path.startswith('/') or '..' in site_path.split('/') or not os.path.isdir(site_path):
        return jsonify({'ok':False,'error':'Working directory does not exist'}), 400
    if php_ver and not re.fullmatch(r'\d+\.\d+', php_ver):
        return jsonify({'ok':False,'error':'Invalid PHP version'}), 400
    # every package / constraint becomes its own quoted argument (they were
    # pasted into a root shell command verbatim)
    try:
        pkg_args = ' '.join(shlex.quote(p) for p in shlex.split(packages))
    except ValueError:
        return jsonify({'ok':False,'error':'Could not parse the package list'}), 400
    if any(p.startswith('-') for p in shlex.split(packages)):
        return jsonify({'ok':False,'error':'Options are not allowed in the package list'}), 400

    # PHP binary of the requested version on any layout (Debian phpX.Y,
    # remi SCL /opt/remi/phpXY/root/usr/bin/php, RHEL module stream php);
    # without a version: `php` on PATH, else the newest installed PHP (a
    # remi-only RHEL box has no /usr/bin/php at all).
    import shutil as _shutil
    try:
        from panel.routes.php import php_layout, installed_php_layouts
    except ImportError:
        from php import php_layout, installed_php_layouts
    php_bin = ''
    if php_ver:
        lay = php_layout(php_ver)
        if not lay:
            return jsonify({'ok':False,'error':f'PHP {php_ver} is not installed'}), 400
        php_bin = lay['bin']
    elif _shutil.which('php'):
        php_bin = 'php'
    else:
        lays = installed_php_layouts()
        if not lays:
            return jsonify({'ok':False,'error':'PHP is not installed'}), 400
        php_bin = lays[0]['bin']
    php_bin = shlex.quote(php_bin)

    # Find composer
    composer_bin = _shutil.which('composer') or '/usr/local/bin/composer'
    if not os.path.exists(composer_bin):
        return jsonify({'ok':False,'error':'Composer not installed. Install it from App Store first.'})

    # Build command with HOME env set
    env_prefix = 'export HOME=/root COMPOSER_HOME=/root/.composer COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_NO_INTERACTION=1 && '
    base = f'{env_prefix}cd {shlex.quote(site_path)} && {php_bin} {shlex.quote(composer_bin)}'
    if action == 'create-project' and pkg_args:
        cmd = f'{base} create-project {pkg_args} . --prefer-dist 2>&1'
    elif action == 'require' and pkg_args:
        cmd = f'{base} require {pkg_args} 2>&1'
    elif action == 'remove' and pkg_args:
        cmd = f'{base} remove {pkg_args} 2>&1'
    elif action == 'update':
        cmd = f'{base} update 2>&1'
    elif action == 'dump-autoload':
        cmd = f'{base} dump-autoload 2>&1'
    else:
        cmd = f'{base} install 2>&1'

    job_id = uuid.uuid4().hex[:12]
    key = f'composer_{job_id}'
    # Job state lives in a file (job_state), not in this worker's memory:
    # gunicorn runs 4 workers, so 3 of 4 polls landed on a worker that had
    # never heard of the job, answered "Job not found", and the UI stopped
    # polling and reported failure while composer was still running.
    save_job(key, {'done':False,'output':'','error':''})

    def run():
        try:
            proc = _sp.Popen(cmd, shell=True, stdout=_sp.PIPE, stderr=_sp.STDOUT, stdin=_sp.DEVNULL, text=True)
            out = ''
            last = 0.0
            import time as _t
            for line in proc.stdout:
                out += line
                if _t.time() - last > 0.5:
                    save_job(key, {'done':False,'output':out[-20000:],'error':''})
                    last = _t.time()
            proc.wait()
            save_job(key, {'done':True,'output':out[-20000:],'error':'','exit':proc.returncode})
        except Exception as e:
            save_job(key, {'done':True,'output':'','error':str(e),'exit':1})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'ok':True,'job_id':job_id,'site_path':site_path})


@websites_bp.route('/api/websites/<domain>/composer/job/<job_id>')
def composer_job(domain, job_id):
    if not req(): return jsonify({'ok':False}), 401
    from panel.routes.job_state import load_job
    if not re.fullmatch(r'[0-9a-f]{8,32}', job_id or ''):
        return jsonify({'ok':False,'error':'Job not found'})
    job = load_job(f'composer_{job_id}', None) or None
    if not job: return jsonify({'ok':False,'error':'Job not found'})
    return jsonify({'ok':True,**job})
