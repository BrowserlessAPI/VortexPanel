from flask import Blueprint, jsonify, request, session, Response
import subprocess, os, json, threading, time, uuid

docker_bp = Blueprint('docker', __name__)
def req(): return 'user' in session
_jobs = {}

def sh(cmd, t=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return '', 'Timeout', 1
    except Exception as e:
        return '', str(e), 1

def docker_ok():
    """Check Docker daemon is running"""
    _, _, rc = sh('docker info 2>/dev/null', t=5)
    return rc == 0

# --- STATUS ---------------------------------------------------------------------
@docker_bp.route('/api/docker/status')
def status():
    if not req(): return jsonify({'ok': False}), 401
    installed = bool(sh('which docker 2>/dev/null')[0])
    running   = docker_ok() if installed else False
    version   = ''
    if installed:
        version, _, _ = sh('docker --version 2>/dev/null')
    return jsonify({'ok': True, 'installed': installed, 'running': running, 'version': version})

# --- CONTAINERS -----------------------------------------------------------------
@docker_bp.route('/api/docker/containers')
def list_containers():
    if not req(): return jsonify({'ok': False}), 401
    if not docker_ok(): return jsonify({'ok': False, 'error': 'Docker not running'}), 400
    out, _, rc = sh('docker ps -a --format "{{json .}}" 2>/dev/null')
    containers = []
    for line in out.strip().split('\n'):
        if not line.strip(): continue
        try:
            c = json.loads(line)
            containers.append({
                'id':      c.get('ID','')[:12],
                'name':    c.get('Names','').lstrip('/'),
                'image':   c.get('Image',''),
                'status':  c.get('Status',''),
                'state':   c.get('State',''),
                'ports':   c.get('Ports',''),
                'created': c.get('CreatedAt',''),
            })
        except: pass
    return jsonify({'ok': True, 'containers': containers})

@docker_bp.route('/api/docker/containers/<cid>/action', methods=['POST'])
def container_action(cid):
    if not req(): return jsonify({'ok': False}), 401
    action = (request.get_json() or {}).get('action', '')
    if action not in ('start','stop','restart','remove','pause','unpause'):
        return jsonify({'ok': False, 'error': 'Invalid action'}), 400
    cmd = f'docker rm -f {cid}' if action == 'remove' else f'docker {action} {cid}'
    _, err, rc = sh(cmd)
    return jsonify({'ok': rc == 0, 'error': err if rc != 0 else ''})

@docker_bp.route('/api/docker/containers/<cid>/logs')
def container_logs(cid):
    if not req(): return jsonify({'ok': False}), 401
    lines = request.args.get('lines', 100)
    out, _, _ = sh(f'docker logs --tail {lines} {cid} 2>&1')
    return jsonify({'ok': True, 'logs': out})

@docker_bp.route('/api/docker/containers/<cid>/stats')
def container_stats(cid):
    if not req(): return jsonify({'ok': False}), 401
    out, _, rc = sh(f'docker stats {cid} --no-stream --format "{{json .}}" 2>/dev/null')
    if rc != 0: return jsonify({'ok': False, 'error': 'Stats unavailable'}), 400
    try:
        s = json.loads(out)
        return jsonify({'ok': True, 'cpu': s.get('CPUPerc',''), 'mem': s.get('MemUsage',''),
                        'net': s.get('NetIO',''), 'block': s.get('BlockIO','')})
    except:
        return jsonify({'ok': False, 'error': 'Parse failed'}), 400

# --- IMAGES ---------------------------------------------------------------------
@docker_bp.route('/api/docker/images')
def list_images():
    if not req(): return jsonify({'ok': False}), 401
    if not docker_ok(): return jsonify({'ok': False, 'error': 'Docker not running'}), 400
    out, _, _ = sh('docker images --format "{{json .}}" 2>/dev/null')
    images = []
    for line in out.strip().split('\n'):
        if not line.strip(): continue
        try:
            img = json.loads(line)
            images.append({
                'id':         img.get('ID','')[:12],
                'repository': img.get('Repository',''),
                'tag':        img.get('Tag',''),
                'size':       img.get('Size',''),
                'created':    img.get('CreatedSince',''),
            })
        except: pass
    return jsonify({'ok': True, 'images': images})

@docker_bp.route('/api/docker/images/<image_id>', methods=['DELETE'])
def remove_image(image_id):
    if not req(): return jsonify({'ok': False}), 401
    _, err, rc = sh(f'docker rmi {image_id} 2>&1')
    return jsonify({'ok': rc == 0, 'error': err})

# --- PULL & RUN (with job streaming) -------------------------------------------
@docker_bp.route('/api/docker/pull', methods=['POST'])
def pull_image():
    if not req(): return jsonify({'ok': False}), 401
    if not docker_ok(): return jsonify({'ok': False, 'error': 'Docker not running — install Docker via Modules first'}), 400
    d     = request.get_json() or {}
    image = d.get('image', '').strip()
    if not image: return jsonify({'ok': False, 'error': 'Image name required'}), 400

    job_id = str(uuid.uuid4())[:8]
    _jobs[job_id] = {'done': False, 'success': False, 'lines': [], 'error': ''}

    def run():
        proc = subprocess.Popen(f'docker pull {image} 2>&1',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout:
            _jobs[job_id]['lines'].append(line.rstrip())
        proc.wait()
        ok = proc.returncode == 0
        _jobs[job_id].update({'done': True, 'success': ok,
            'error': '' if ok else f'Pull failed (exit {proc.returncode})'})
        _jobs[job_id]['lines'].append(f'{"✓ Pull complete: " + image if ok else "✗ Pull failed"}')

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'ok': True, 'job_id': job_id})

@docker_bp.route('/api/docker/run', methods=['POST'])
def run_container():
    if not req(): return jsonify({'ok': False}), 401
    if not docker_ok(): return jsonify({'ok': False, 'error': 'Docker not running'}), 400
    d = request.get_json() or {}

    image   = d.get('image', '').strip()
    name    = d.get('name', '').strip()
    ports   = d.get('ports', [])    # [{'host':'8080','container':'80'}]
    envs    = d.get('envs', [])     # [{'key':'MYSQL_ROOT_PASSWORD','value':'secret'}]
    volumes = d.get('volumes', [])  # [{'host':'/data','container':'/var/lib/mysql'}]
    restart = d.get('restart', 'unless-stopped')
    network = d.get('network', '')
    cmd_extra = d.get('cmd', '')

    if not image: return jsonify({'ok': False, 'error': 'Image required'}), 400

    # Build docker run command
    parts = ['docker run -d']
    if name:    parts.append(f'--name {name}')
    if restart: parts.append(f'--restart={restart}')
    for p in ports:
        if p.get('host') and p.get('container'):
            parts.append(f'-p {p["host"]}:{p["container"]}')
    for e in envs:
        if e.get('key') and e.get('value') is not None:
            val = e['value'].replace("'", "'\"'\"'")
            parts.append(f"-e '{e['key']}={val}'")
    for v in volumes:
        if v.get('host') and v.get('container'):
            os.makedirs(v['host'], exist_ok=True)
            parts.append(f'-v {v["host"]}:{v["container"]}')
    if network: parts.append(f'--network={network}')
    parts.append(image)
    if cmd_extra: parts.append(cmd_extra)

    full_cmd = ' '.join(parts)
    job_id   = str(uuid.uuid4())[:8]
    _jobs[job_id] = {'done': False, 'success': False, 'lines': [full_cmd], 'error': '', 'container_id': ''}

    def run():
        _jobs[job_id]['lines'].append(f'Pulling {image} if not cached...')
        # Pull first
        pull_proc = subprocess.Popen(f'docker pull {image} 2>&1',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in pull_proc.stdout:
            _jobs[job_id]['lines'].append(line.rstrip())
        pull_proc.wait()

        _jobs[job_id]['lines'].append(f'Starting container...')
        out, err, rc = sh(full_cmd, t=60)
        if rc == 0:
            cid = out.strip()[:12]
            _jobs[job_id].update({'done': True, 'success': True, 'container_id': cid})
            _jobs[job_id]['lines'].append(f'✓ Container started: {cid}')
        else:
            _jobs[job_id].update({'done': True, 'success': False, 'error': err or out})
            _jobs[job_id]['lines'].append(f'✗ Failed: {err or out}')

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'ok': True, 'job_id': job_id})

@docker_bp.route('/api/docker/job/<job_id>')
def job_status(job_id):
    if not req(): return jsonify({'ok': False}), 401
    job = _jobs.get(job_id)
    if not job: return jsonify({'ok': False, 'error': 'Job not found'}), 404
    return jsonify({'ok': True, **job})

# --- VOLUMES & NETWORKS ---------------------------------------------------------
@docker_bp.route('/api/docker/volumes')
def list_volumes():
    if not req(): return jsonify({'ok': False}), 401
    if not docker_ok(): return jsonify({'ok': True, 'volumes': []}), 200
    out, _, _ = sh('docker volume ls --format "{{json .}}" 2>/dev/null')
    vols = []
    for line in out.strip().split('\n'):
        if not line.strip(): continue
        try:
            v = json.loads(line)
            vols.append({'name': v.get('Name',''), 'driver': v.get('Driver',''), 'mountpoint': v.get('Mountpoint','')})
        except: pass
    return jsonify({'ok': True, 'volumes': vols})

@docker_bp.route('/api/docker/networks')
def list_networks():
    if not req(): return jsonify({'ok': False}), 401
    if not docker_ok(): return jsonify({'ok': True, 'networks': []}), 200
    out, _, _ = sh('docker network ls --format "{{json .}}" 2>/dev/null')
    nets = []
    for line in out.strip().split('\n'):
        if not line.strip(): continue
        try:
            n = json.loads(line)
            nets.append({'id': n.get('ID','')[:12], 'name': n.get('Name',''), 'driver': n.get('Driver','')})
        except: pass
    return jsonify({'ok': True, 'networks': nets})

@docker_bp.route('/api/docker/system/prune', methods=['POST'])
def system_prune():
    if not req(): return jsonify({'ok': False}), 401
    out, err, rc = sh('docker system prune -f 2>&1', t=120)
    return jsonify({'ok': rc == 0, 'output': out or err})

@docker_bp.route('/api/docker/system/df')
def system_df():
    if not req(): return jsonify({'ok': False}), 401
    if not docker_ok(): return jsonify({'ok': False, 'error': 'Docker not running'}), 400
    out, _, rc = sh('docker system df --format "{{json .}}" 2>/dev/null')
    return jsonify({'ok': rc == 0, 'output': out})
