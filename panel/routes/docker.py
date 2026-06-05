from flask import Blueprint, jsonify, request, session
import subprocess, json

docker_bp = Blueprint('docker', __name__)
def req(): return 'user' in session
def sh(c,t=30):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL,timeout=t).strip()
    except: return ''

@docker_bp.route('/api/docker/info')
def info():
    if not req(): return jsonify({'ok':False}),401
    raw = sh('docker info --format json 2>/dev/null')
    try:
        d = json.loads(raw)
        return jsonify({'ok':True,'containers':d.get('Containers',0),'running':d.get('ContainersRunning',0),'images':d.get('Images',0),'version':d.get('ServerVersion','')})
    except:
        return jsonify({'ok':False,'error':'Docker not running or not installed'})

@docker_bp.route('/api/docker/containers')
def containers():
    if not req(): return jsonify({'ok':False}),401
    raw = sh('docker ps -a --format "{{json .}}" 2>/dev/null')
    result = []
    for line in raw.split('\n'):
        try:
            c = json.loads(line)
            result.append({'id':c.get('ID',''),'name':c.get('Names',''),'image':c.get('Image',''),'status':c.get('Status',''),'ports':c.get('Ports',''),'state':c.get('State','')})
        except: pass
    return jsonify({'ok':True,'containers':result})

@docker_bp.route('/api/docker/containers/<name>/<action>', methods=['POST'])
def control(name, action):
    if not req(): return jsonify({'ok':False}),401
    if action not in ('start','stop','restart','remove'): return jsonify({'ok':False,'error':'Invalid'}),400
    cmd = f'docker {"rm -f" if action=="remove" else action} {name}'
    ok = subprocess.run(cmd,shell=True).returncode == 0
    return jsonify({'ok':ok})

@docker_bp.route('/api/docker/images')
def images():
    if not req(): return jsonify({'ok':False}),401
    raw = sh('docker images --format "{{json .}}" 2>/dev/null')
    result = []
    for line in raw.split('\n'):
        try:
            img = json.loads(line)
            result.append({'repo':img.get('Repository',''),'tag':img.get('Tag',''),'id':img.get('ID',''),'size':img.get('Size',''),'created':img.get('CreatedSince','')})
        except: pass
    return jsonify({'ok':True,'images':result})

@docker_bp.route('/api/docker/images/<image>', methods=['DELETE'])
def remove_image(image):
    if not req(): return jsonify({'ok':False}),401
    ok = subprocess.run(f'docker rmi {image}',shell=True).returncode == 0
    return jsonify({'ok':ok})

@docker_bp.route('/api/docker/logs/<name>')
def container_logs(name):
    if not req(): return jsonify({'ok':False}),401
    logs = sh(f'docker logs --tail=100 {name} 2>&1')
    return jsonify({'ok':True,'logs':logs})

@docker_bp.route('/api/docker/compose', methods=['POST'])
def compose_up():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    path = d.get('path','').strip()
    action = d.get('action','up')
    if not path: return jsonify({'ok':False,'error':'Path required'}),400
    out = sh(f'cd {path} && docker compose {action} -d 2>&1', t=120)
    return jsonify({'ok':True,'output':out})
