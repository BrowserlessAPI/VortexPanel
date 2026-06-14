import os
from flask import jsonify, request

try:
    from panel.routes.websites_core import websites_bp, req, sh, get_nginx_dirs
except ImportError:
    from websites_core import websites_bp, req, sh, get_nginx_dirs


@websites_bp.route('/api/websites/<domain>/composer', methods=['POST'])
def run_composer(domain):
    if not req(): return jsonify({'ok':False}), 401
    import threading, uuid, subprocess as _sp, re as _re
    d = request.get_json() or {}
    action   = d.get('action','install')   # install|update|require|create-project
    packages = d.get('packages','').strip()
    php_ver  = d.get('php_ver','')
    work_dir = d.get('work_dir','')

    # Find site path
    avail, _ = get_nginx_dirs()
    conf_path = os.path.join(avail, f'{domain}.conf')
    site_path = work_dir
    if not site_path and os.path.exists(conf_path):
        with open(conf_path) as f: content = f.read()
        m = _re.search(r'root\s+([^;]+);', content)
        if m: site_path = m.group(1).strip()
    if not site_path: site_path = f'/www/wwwroot/{domain}'

    # Find PHP binary
    php_bin = 'php'
    if php_ver:
        for p in [f'/usr/bin/php{php_ver}', f'/usr/local/bin/php{php_ver}']:
            if os.path.exists(p): php_bin = p; break

    # Find composer
    composer_bin = sh('which composer 2>/dev/null') or '/usr/local/bin/composer'
    if not os.path.exists(composer_bin):
        return jsonify({'ok':False,'error':'Composer not installed. Install it from App Store first.'})

    # Build command with HOME env set
    env_prefix = 'export HOME=/root COMPOSER_HOME=/root/.composer COMPOSER_ALLOW_SUPERUSER=1 && '
    if action == 'create-project' and packages:
        cmd = f'{env_prefix}cd "{site_path}" && {php_bin} {composer_bin} create-project {packages} . --prefer-dist 2>&1'
    elif action == 'require' and packages:
        cmd = f'{env_prefix}cd "{site_path}" && {php_bin} {composer_bin} require {packages} 2>&1'
    elif action == 'remove' and packages:
        cmd = f'{env_prefix}cd "{site_path}" && {php_bin} {composer_bin} remove {packages} 2>&1'
    elif action == 'update':
        cmd = f'{env_prefix}cd "{site_path}" && {php_bin} {composer_bin} update 2>&1'
    elif action == 'dump-autoload':
        cmd = f'{env_prefix}cd "{site_path}" && {php_bin} {composer_bin} dump-autoload 2>&1'
    else:
        cmd = f'{env_prefix}cd "{site_path}" && {php_bin} {composer_bin} install 2>&1'

    job_id = str(uuid.uuid4())[:8]
    _composer_jobs = getattr(run_composer, '_jobs', {})
    _composer_jobs[job_id] = {'done':False,'output':'','error':''}
    run_composer._jobs = _composer_jobs

    def run():
        try:
            proc = _sp.Popen(cmd, shell=True, stdout=_sp.PIPE, stderr=_sp.STDOUT, text=True)
            out = ''
            for line in proc.stdout:
                out += line
                run_composer._jobs[job_id]['output'] = out
            proc.wait()
            run_composer._jobs[job_id].update({'done':True,'exit':proc.returncode})
        except Exception as e:
            run_composer._jobs[job_id].update({'done':True,'error':str(e)})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'ok':True,'job_id':job_id,'site_path':site_path})


@websites_bp.route('/api/websites/<domain>/composer/job/<job_id>')
def composer_job(domain, job_id):
    if not req(): return jsonify({'ok':False}), 401
    jobs = getattr(run_composer, '_jobs', {})
    job = jobs.get(job_id)
    if not job: return jsonify({'ok':False,'error':'Job not found'})
    return jsonify({'ok':True,**job})

