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

# --- DOMAIN / REVERSE PROXY (reuses the pattern from go_projects.py / nodejs_projects.py) ----
DOCKER_DOMAINS_FILE = '/opt/vortexpanel/docker_domains.json'

def _os_family():
    if os.path.exists('/etc/debian_version'): return 'debian'
    if os.path.exists('/etc/redhat-release'): return 'rhel'
    _, _, rc = sh('which apt-get 2>/dev/null')
    return 'debian' if rc == 0 else 'rhel'

def _detect_active_webserver():
    checks = [
        ('nginx',         'systemctl is-active nginx 2>/dev/null'),
        ('apache2',       'systemctl is-active apache2 2>/dev/null || systemctl is-active httpd 2>/dev/null'),
        ('openlitespeed', 'systemctl is-active lsws 2>/dev/null'),
        ('caddy',         'systemctl is-active caddy 2>/dev/null'),
    ]
    for name, cmd in checks:
        out, _, _ = sh(cmd)
        if 'active' in out: return name
    return None

def _apache_conf_dir():
    return '/etc/apache2/sites-available' if _os_family() == 'debian' else '/etc/httpd/conf.d'

def _apache_log_dir():
    return '/var/log/apache2' if _os_family() == 'debian' else '/var/log/httpd'

def _apache_enable_modules():
    if _os_family() == 'debian':
        sh('a2enmod proxy proxy_http headers 2>/dev/null')
    else:
        sh('dnf install -y mod_proxy 2>/dev/null || yum install -y mod_proxy 2>/dev/null || true')

def _apache_enable_site(name):
    if _os_family() == 'debian': sh(f'a2ensite {name} 2>/dev/null')

def _apache_disable_site(name):
    if _os_family() == 'debian': sh(f'a2dissite {name} 2>/dev/null')

def _apache_test_config():
    if _os_family() == 'debian': return sh('apache2ctl configtest 2>&1')
    return sh('apachectl configtest 2>&1 || httpd -t 2>&1')

def _apache_reload():
    if _os_family() == 'debian':
        sh('systemctl reload apache2 2>/dev/null || apache2ctl graceful 2>/dev/null')
    else:
        sh('systemctl reload httpd 2>/dev/null || apachectl graceful 2>/dev/null')

def _load_docker_domains():
    if os.path.exists(DOCKER_DOMAINS_FILE):
        try: return json.load(open(DOCKER_DOMAINS_FILE))
        except Exception: pass
    return {}

def _save_docker_domains(d):
    os.makedirs(os.path.dirname(DOCKER_DOMAINS_FILE), exist_ok=True)
    json.dump(d, open(DOCKER_DOMAINS_FILE, 'w'), indent=2)

def _remove_docker_proxy(cname):
    """Remove proxy config for a container across ALL webservers (safe no-op if absent)."""
    tag = f'vortex-docker-{cname}'
    sh(f'rm -f /etc/nginx/conf.d/{tag}.conf 2>/dev/null')
    sh(f'a2dissite {tag} 2>/dev/null; rm -f /etc/apache2/sites-available/{tag}.conf '
       f'/etc/apache2/sites-enabled/{tag}.conf /etc/httpd/conf.d/{tag}.conf 2>/dev/null')
    sh(f'rm -rf /usr/local/lsws/conf/vhosts/{tag}/ 2>/dev/null')
    sh(f'rm -f /etc/caddy/sites/{tag}.caddy 2>/dev/null')
    ws = _detect_active_webserver()
    if ws == 'nginx':        sh('nginx -t 2>/dev/null && (systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null)')
    elif ws == 'apache2':    _apache_reload()
    elif ws == 'openlitespeed': sh('systemctl restart lsws 2>/dev/null')
    elif ws == 'caddy':      sh('systemctl reload caddy 2>/dev/null')

def _write_docker_proxy(cname, domain, port):
    """Write reverse-proxy vhost mapping domain -> 127.0.0.1:port for a Docker container."""
    domain = (domain or '').strip()
    if not domain or not port:
        return False, 'Domain and host port required'

    ws = _detect_active_webserver()
    if not ws:
        return False, 'No active webserver. Install nginx, Apache, OLS, or Caddy from App Store first.'

    tag     = f'vortex-docker-{cname}'
    primary = domain.splitlines()[0].strip().split(':')[0]
    all_d   = ' '.join(d.strip().split(':')[0] for d in domain.splitlines() if d.strip())

    _remove_docker_proxy(cname)  # clean old config first

    if ws == 'nginx':
        conf = f"""server {{
    listen 80;
    server_name {all_d};
    access_log /var/log/nginx/{tag}-access.log;
    error_log  /var/log/nginx/{tag}-error.log;

    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }}
}}
"""
        conf_path = f'/etc/nginx/conf.d/{tag}.conf'
        open(conf_path, 'w').write(conf)
        _, err, rc = sh('nginx -t 2>&1')
        if rc != 0:
            try: os.remove(conf_path)
            except Exception: pass
            return False, f'nginx config test failed: {err}'
        sh('systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null')

    elif ws == 'apache2':
        _apache_enable_modules()
        log_dir  = _apache_log_dir()
        conf_dir = _apache_conf_dir()
        conf = f"""<VirtualHost *:80>
    ServerName {primary}
    ServerAlias {all_d}
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:{port}/
    ProxyPassReverse / http://127.0.0.1:{port}/
    RequestHeader set X-Forwarded-Proto "http"
    ErrorLog {log_dir}/{tag}-error.log
    CustomLog {log_dir}/{tag}-access.log combined
</VirtualHost>
"""
        os.makedirs(conf_dir, exist_ok=True)
        conf_path = os.path.join(conf_dir, f'{tag}.conf')
        open(conf_path, 'w').write(conf)
        _apache_enable_site(tag)
        _, err, rc = _apache_test_config()
        if rc != 0:
            _apache_disable_site(tag)
            try: os.remove(conf_path)
            except Exception: pass
            return False, f'Apache config test failed: {err}'
        _apache_reload()

    elif ws == 'openlitespeed':
        vhost_dir = f'/usr/local/lsws/conf/vhosts/{tag}'
        os.makedirs(vhost_dir, exist_ok=True)
        conf = f"""docRoot                   /var/www/html
virtualHostConfig {{
  extprocessor {tag} {{
    type                    proxy
    address                 127.0.0.1:{port}
    maxConns                100
    pcKeepAliveTimeout      60
    initTimeout             60
    retryTimeout            0
    respBuffer              0
  }}
  context / {{
    type                    proxy
    handler                 {tag}
    addDefaultCharset       off
  }}
}}
"""
        open(f'{vhost_dir}/vhconf.conf', 'w').write(conf)
        sh('/usr/local/lsws/bin/lswsctrl restart 2>/dev/null || systemctl restart lsws 2>/dev/null')

    elif ws == 'caddy':
        os.makedirs('/etc/caddy/sites', exist_ok=True)
        conf = f"""{all_d} {{
    reverse_proxy 127.0.0.1:{port}
    log {{
        output file /var/log/caddy/{tag}.log
    }}
}}
"""
        open(f'/etc/caddy/sites/{tag}.caddy', 'w').write(conf)
        caddyfile = '/etc/caddy/Caddyfile'
        if os.path.exists(caddyfile) and 'import sites/*' not in open(caddyfile).read():
            open(caddyfile, 'a').write('\nimport sites/*\n')
        _, err, rc = sh('caddy validate --config /etc/caddy/Caddyfile 2>&1')
        if rc != 0:
            sh(f'rm -f /etc/caddy/sites/{tag}.caddy')
            return False, f'Caddy config validate failed: {err}'
        sh('systemctl reload caddy 2>/dev/null')

    return True, ws

@docker_bp.route('/api/docker/webserver')
def docker_webserver():
    if not req(): return jsonify({'ok': False}), 401
    ws = _detect_active_webserver()
    return jsonify({'ok': True, 'webserver': ws,
                     'message': f'Domains will proxy via {ws}' if ws else 'No active webserver — install one from App Store first'})

@docker_bp.route('/api/docker/containers/<cname>/domain', methods=['GET', 'POST', 'DELETE'])
def container_domain(cname):
    if not req(): return jsonify({'ok': False}), 401
    domains = _load_docker_domains()

    if request.method == 'GET':
        return jsonify({'ok': True, 'domain': domains.get(cname, {})})

    if request.method == 'DELETE':
        _remove_docker_proxy(cname)
        domains.pop(cname, None)
        _save_docker_domains(domains)
        return jsonify({'ok': True})

    # POST — set/update domain
    d = request.get_json() or {}
    domain = (d.get('domain') or '').strip()
    port   = str(d.get('port') or '').strip()
    if not domain or not port:
        return jsonify({'ok': False, 'error': 'Domain and host port are required'})
    if not port.isdigit():
        return jsonify({'ok': False, 'error': 'Port must be numeric — this is the HOST port you mapped when running the container (e.g. 8080 in -p 8080:80)'})

    ok, result = _write_docker_proxy(cname, domain, port)
    if not ok:
        return jsonify({'ok': False, 'error': result})

    domains[cname] = {'domain': domain, 'port': port, 'webserver': result}
    _save_docker_domains(domains)
    return jsonify({'ok': True, 'webserver': result})

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
    domains = _load_docker_domains()
    containers = []
    for line in out.strip().split('\n'):
        if not line.strip(): continue
        try:
            c = json.loads(line)
            name = c.get('Names','').lstrip('/')
            containers.append({
                'id':      c.get('ID','')[:12],
                'name':    name,
                'image':   c.get('Image',''),
                'status':  c.get('Status',''),
                'state':   c.get('State',''),
                'ports':   c.get('Ports',''),
                'created': c.get('CreatedAt',''),
                'domain':  domains.get(name, {}).get('domain', ''),
            })
        except: pass
    return jsonify({'ok': True, 'containers': containers})

@docker_bp.route('/api/docker/containers/<cid>/action', methods=['POST'])
def container_action(cid):
    if not req(): return jsonify({'ok': False}), 401
    action = (request.get_json() or {}).get('action', '')
    if action not in ('start','stop','restart','remove','pause','unpause'):
        return jsonify({'ok': False, 'error': 'Invalid action'}), 400
    # Resolve the container NAME before removal — the domain/proxy map is
    # keyed by name, not id, so cleaning up after `docker rm` needs the name
    # captured while the container still exists.
    cname = ''
    if action == 'remove':
        cname, _, _ = sh(f'docker inspect -f "{{{{.Name}}}}" {cid}')
        cname = (cname or '').lstrip('/').strip()
    cmd = f'docker rm -f {cid}' if action == 'remove' else f'docker {action} {cid}'
    _, err, rc = sh(cmd)
    if action == 'remove' and rc == 0:
        # Clean up any domain/proxy config tied to this container (by name or id)
        domains = _load_docker_domains()
        for key in (cname, cid):
            if key and key in domains:
                _remove_docker_proxy(key)
                domains.pop(key, None)
                _save_docker_domains(domains)
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
