from flask import Blueprint, jsonify, request, session, Response
import subprocess, os, json, threading, time, uuid, re, shlex, shutil
try:
    from panel.routes import os_utils as _ou
except ImportError:
    try:
        import os_utils as _ou
    except ImportError:
        _ou = None
try:
    from panel.routes.job_state import save_job, load_job
except ImportError:
    from job_state import save_job, load_job

docker_bp = Blueprint('docker', __name__)
def req(): return 'user' in session
_jobs = {}

# Container names/ids, image references, network names: everything that is
# interpolated into a shell command is checked against these first.
_NAME_RE  = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$')
_IMAGE_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,254}$')
_ENVK_RE  = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]*$')
_HOST_RE  = re.compile(r'^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*(:\d{1,5})?$')

def _valid_domains(domain):
    """Each non-empty line must be a plain hostname (optionally :port); anything
    else would be injected verbatim into nginx/Apache/Caddy config."""
    lines = [l.strip() for l in (domain or '').splitlines() if l.strip()]
    return bool(lines) and all(_HOST_RE.match(l) for l in lines)

def _job_save(job_id, force=False):
    """Persist job state so the poll (served by any gunicorn worker) sees it."""
    job = _jobs.get(job_id)
    if job is None: return
    now = time.monotonic()
    if not force and now - job.get('_saved', 0) < 0.5:
        return
    job['_saved'] = now
    try: save_job(f'docker_{job_id}', {k: v for k, v in job.items() if not k.startswith('_')})
    except Exception: pass

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
    _, _, rc = sh('docker info >/dev/null 2>&1', t=10)
    return rc == 0

# --- DOMAIN / REVERSE PROXY (reuses the pattern from go_projects.py / nodejs_projects.py) ----
DOCKER_DOMAINS_FILE = '/opt/vortexpanel/docker_domains.json'

def _os_family():
    if os.path.exists('/etc/debian_version'): return 'debian'
    if os.path.exists('/etc/redhat-release'): return 'rhel'
    return 'debian' if shutil.which('apt-get') else 'rhel'

def _selinux_proxy():
    """nginx/httpd may not connect to the container's published port under
    SELinux (every proxied request 502) unless httpd_can_network_connect is on."""
    try:
        if _ou: _ou.selinux_web_booleans(proxy=True, db=False)
    except Exception:
        pass

def _detect_active_webserver():
    checks = [
        ('nginx',         'systemctl is-active nginx 2>/dev/null'),
        ('apache2',       'systemctl is-active apache2 2>/dev/null || systemctl is-active httpd 2>/dev/null'),
        ('openlitespeed', 'systemctl is-active lsws 2>/dev/null'),
        ('caddy',         'systemctl is-active caddy 2>/dev/null'),
    ]
    for name, cmd in checks:
        out, _, _ = sh(cmd)
        if 'active' in out.split(): return name
    return None

def _apache_conf_dir():
    return '/etc/apache2/sites-available' if _os_family() == 'debian' else '/etc/httpd/conf.d'

def _apache_log_dir():
    return '/var/log/apache2' if _os_family() == 'debian' else '/var/log/httpd'

def _apache_enable_modules():
    # RHEL httpd loads mod_proxy / proxy_http / headers from the base package
    # (conf.modules.d); there is no separate mod_proxy package to install.
    if _os_family() == 'debian':
        sh('a2enmod proxy proxy_http headers 2>/dev/null')

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
    with open(DOCKER_DOMAINS_FILE, 'w') as f:
        json.dump(d, f, indent=2)

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
    if not _NAME_RE.match(cname or ''):
        return False, 'Invalid container name'
    if not _valid_domains(domain):
        return False, 'Invalid domain (one hostname per line, e.g. app.example.com)'
    if not str(port).isdigit() or not (1 <= int(port) <= 65535):
        return False, 'Invalid port'

    ws = _detect_active_webserver()
    if not ws:
        return False, 'No active webserver. Install nginx, Apache, OLS, or Caddy from App Store first.'

    tag     = f'vortex-docker-{cname}'
    primary = domain.splitlines()[0].strip().split(':')[0]
    all_d   = ' '.join(d.strip().split(':')[0] for d in domain.splitlines() if d.strip())

    _remove_docker_proxy(cname)  # clean old config first

    if ws == 'nginx':
        v6 = '\n    listen [::]:80;' if os.path.exists('/proc/net/if_inet6') else ''
        conf = f"""server {{
    listen 80;{v6}
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
        os.makedirs('/etc/nginx/conf.d', exist_ok=True)
        with open(conf_path, 'w') as f: f.write(conf)
        out, err, rc = sh('nginx -t 2>&1')
        err = err or out
        if rc != 0:
            try: os.remove(conf_path)
            except Exception: pass
            return False, f'nginx config test failed: {err}'
        sh('systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null')
        _selinux_proxy()

    elif ws == 'apache2':
        _apache_enable_modules()
        _selinux_proxy()
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
    if not _NAME_RE.match(cname or ''):
        return jsonify({'ok': False, 'error': 'Invalid container name'}), 400
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
    installed = bool(shutil.which('docker'))
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
            # Podman (podman-docker shim on RHEL) emits Names/Ports as lists
            # and 'Id' instead of 'ID' -- normalise instead of dropping them.
            names = c.get('Names', '')
            if isinstance(names, list): names = names[0] if names else ''
            name = str(names).split(',')[0].lstrip('/')
            ports = c.get('Ports', '')
            if isinstance(ports, list):
                ports = ', '.join(
                    f"{p.get('host_ip') or '0.0.0.0'}:{p.get('host_port')}->{p.get('container_port')}/{p.get('protocol', 'tcp')}"
                    if isinstance(p, dict) else str(p) for p in ports)
            state = c.get('State', '')
            containers.append({
                'id':      str(c.get('ID') or c.get('Id') or '')[:12],
                'name':    name,
                'image':   c.get('Image',''),
                'status':  c.get('Status',''),
                'state':   state.lower() if isinstance(state, str) else str(state),
                'ports':   ports,
                'created': c.get('CreatedAt',''),
                'domain':  domains.get(name, {}).get('domain', ''),
            })
        except Exception: pass
    return jsonify({'ok': True, 'containers': containers})

@docker_bp.route('/api/docker/containers/<cid>/action', methods=['POST'])
def container_action(cid):
    if not req(): return jsonify({'ok': False}), 401
    action = (request.get_json() or {}).get('action', '')
    if action not in ('start','stop','restart','remove','pause','unpause'):
        return jsonify({'ok': False, 'error': 'Invalid action'}), 400
    if not _NAME_RE.match(cid or ''):
        return jsonify({'ok': False, 'error': 'Invalid container id'}), 400
    # Resolve the container NAME before removal — the domain/proxy map is
    # keyed by name, not id, so cleaning up after `docker rm` needs the name
    # captured while the container still exists.
    cname = ''
    if action == 'remove':
        cname, _, _ = sh(f'docker inspect -f "{{{{.Name}}}}" {cid}')
        cname = (cname or '').lstrip('/').strip()
    cmd = f'docker rm -f {cid}' if action == 'remove' else f'docker {action} {cid}'
    _, err, rc = sh(cmd, t=90)
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
    if not _NAME_RE.match(cid or ''):
        return jsonify({'ok': False, 'error': 'Invalid container id'}), 400
    try: lines = max(1, min(int(request.args.get('lines', 100)), 10000))
    except (TypeError, ValueError): lines = 100
    out, _, _ = sh(f'docker logs --tail {lines} {cid} 2>&1')
    return jsonify({'ok': True, 'logs': out})

@docker_bp.route('/api/docker/containers/<cid>/stats')
def container_stats(cid):
    if not req(): return jsonify({'ok': False}), 401
    if not _NAME_RE.match(cid or ''):
        return jsonify({'ok': False, 'error': 'Invalid container id'}), 400
    out, _, rc = sh(f'docker stats {cid} --no-stream --format "{{{{json .}}}}" 2>/dev/null')
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
    if not _IMAGE_RE.match(image_id or ''):
        return jsonify({'ok': False, 'error': 'Invalid image id'}), 400
    out, err, rc = sh(f'docker rmi {image_id} 2>&1', t=120)
    return jsonify({'ok': rc == 0, 'error': '' if rc == 0 else (err or out)})

# --- PULL & RUN (with job streaming) -------------------------------------------
@docker_bp.route('/api/docker/pull', methods=['POST'])
def pull_image():
    if not req(): return jsonify({'ok': False}), 401
    if not docker_ok(): return jsonify({'ok': False, 'error': 'Docker not running — install Docker via Modules first'}), 400
    d     = request.get_json() or {}
    image = str(d.get('image', '')).strip()
    if not image: return jsonify({'ok': False, 'error': 'Image name required'}), 400
    if not _IMAGE_RE.match(image): return jsonify({'ok': False, 'error': 'Invalid image name'}), 400

    job_id = str(uuid.uuid4())[:8]
    _jobs[job_id] = {'done': False, 'success': False, 'lines': [], 'error': ''}
    _job_save(job_id, force=True)

    def run():
        try:
            proc = subprocess.Popen(['docker', 'pull', image],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in proc.stdout:
                _jobs[job_id]['lines'].append(line.rstrip())
                _job_save(job_id)
            proc.wait()
            ok = proc.returncode == 0
            _jobs[job_id].update({'done': True, 'success': ok,
                'error': '' if ok else f'Pull failed (exit {proc.returncode})'})
            _jobs[job_id]['lines'].append(f'Pull complete: {image}' if ok else 'Pull failed')
        except Exception as e:
            _jobs[job_id].update({'done': True, 'success': False, 'error': str(e)})
        _job_save(job_id, force=True)

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'ok': True, 'job_id': job_id})

@docker_bp.route('/api/docker/run', methods=['POST'])
def run_container():
    if not req(): return jsonify({'ok': False}), 401
    if not docker_ok(): return jsonify({'ok': False, 'error': 'Docker not running'}), 400
    d = request.get_json() or {}

    image   = str(d.get('image', '')).strip()
    name    = str(d.get('name', '') or '').strip()
    ports   = d.get('ports', [])    # [{'host':'8080','container':'80'}]
    envs    = d.get('envs', [])     # [{'key':'MYSQL_ROOT_PASSWORD','value':'secret'}]
    volumes = d.get('volumes', [])  # [{'host':'/data','container':'/var/lib/mysql'}]
    restart = d.get('restart', 'unless-stopped')
    network = d.get('network', '')
    cmd_extra = d.get('cmd', '')

    if not image: return jsonify({'ok': False, 'error': 'Image required'}), 400
    if not _IMAGE_RE.match(image): return jsonify({'ok': False, 'error': 'Invalid image name'}), 400
    if name and not _NAME_RE.match(name):
        return jsonify({'ok': False, 'error': 'Invalid container name (letters, digits, _ . - only)'}), 400
    if restart and restart not in ('no', 'always', 'unless-stopped', 'on-failure'):
        return jsonify({'ok': False, 'error': 'Invalid restart policy'}), 400
    if network and not _NAME_RE.match(network):
        return jsonify({'ok': False, 'error': 'Invalid network name'}), 400

    # Build docker run command -- every user-supplied value is shell-quoted.
    q = shlex.quote
    parts = ['docker run -d']
    if name:    parts.append(f'--name {q(name)}')
    if restart: parts.append(f'--restart={restart}')
    for p in ports or []:
        if p.get('host') and p.get('container'):
            parts.append(f'-p {q(str(p["host"]).strip() + ":" + str(p["container"]).strip())}')
    for e in envs or []:
        if e.get('key') and e.get('value') is not None:
            key = str(e['key']).strip()
            if not _ENVK_RE.match(key):
                return jsonify({'ok': False, 'error': f'Invalid environment variable name: {key}'}), 400
            parts.append(f"-e {q(key + '=' + str(e['value']))}")
    for v in volumes or []:
        if v.get('host') and v.get('container'):
            host = str(v['host']).strip()
            # Only bind-mount paths are directories to create; a bare name is
            # a named Docker volume (creating ./name in the panel cwd is wrong).
            if host.startswith('/'):
                try: os.makedirs(host, exist_ok=True)
                except OSError as ex:
                    return jsonify({'ok': False, 'error': f'Cannot create {host}: {ex}'}), 400
            parts.append(f'-v {q(host + ":" + str(v["container"]).strip())}')
    if network: parts.append(f'--network={q(network)}')
    parts.append(q(image))
    if cmd_extra:
        try: parts.extend(q(a) for a in shlex.split(str(cmd_extra)))
        except ValueError as ex:
            return jsonify({'ok': False, 'error': f'Invalid command: {ex}'}), 400

    full_cmd = ' '.join(parts)
    job_id   = str(uuid.uuid4())[:8]
    _jobs[job_id] = {'done': False, 'success': False, 'lines': [full_cmd], 'error': '', 'container_id': ''}
    _job_save(job_id, force=True)

    def run():
        try:
            _jobs[job_id]['lines'].append(f'Pulling {image} if not cached...')
            # Pull first
            pull_proc = subprocess.Popen(['docker', 'pull', image],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in pull_proc.stdout:
                _jobs[job_id]['lines'].append(line.rstrip())
                _job_save(job_id)
            pull_proc.wait()

            _jobs[job_id]['lines'].append('Starting container...')
            _job_save(job_id, force=True)
            out, err, rc = sh(full_cmd, t=120)
            if rc == 0:
                cid = out.strip()[:12]
                _jobs[job_id].update({'done': True, 'success': True, 'container_id': cid})
                _jobs[job_id]['lines'].append(f'Container started: {cid}')
            else:
                _jobs[job_id].update({'done': True, 'success': False, 'error': err or out})
                _jobs[job_id]['lines'].append(f'Failed: {err or out}')
        except Exception as e:
            _jobs[job_id].update({'done': True, 'success': False, 'error': str(e)})
            _jobs[job_id]['lines'].append(f'Failed: {e}')
        _job_save(job_id, force=True)

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'ok': True, 'job_id': job_id})

@docker_bp.route('/api/docker/job/<job_id>')
def job_status(job_id):
    if not req(): return jsonify({'ok': False}), 401
    # Read the shared on-disk state first: the poll may land on a different
    # gunicorn worker than the one running the job thread.
    job = load_job(f'docker_{job_id}') or None
    if not job:
        mem = _jobs.get(job_id)
        job = {k: v for k, v in mem.items() if not k.startswith('_')} if mem else None
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
    if not docker_ok(): return jsonify({'ok': False, 'error': 'Docker not running'}), 400
    out, err, rc = sh('docker system prune -f 2>&1', t=300)
    return jsonify({'ok': rc == 0, 'output': out or err, 'error': '' if rc == 0 else (out or err)})

@docker_bp.route('/api/docker/system/df')
def system_df():
    if not req(): return jsonify({'ok': False}), 401
    if not docker_ok(): return jsonify({'ok': False, 'error': 'Docker not running'}), 400
    out, _, rc = sh('docker system df --format "{{json .}}" 2>/dev/null')
    return jsonify({'ok': rc == 0, 'output': out})
