"""
Node.js Project Manager for VortexPanel
Supports: Default projects (systemd) + PM2 projects
Webserver proxy: nginx / Apache2 / httpd / OpenLiteSpeed / Caddy
OS family: Debian/Ubuntu + RHEL/AlmaLinux/Rocky/CentOS/Oracle/Fedora
"""
from flask import Blueprint, jsonify, request, session
import subprocess, os, json, re, shutil
try:
    from panel.routes.os_utils import get_webserver_user as _get_web_user
except Exception:
    try:
        from os_utils import get_webserver_user as _get_web_user
    except Exception:
        def _get_web_user():
            return 'www-data' if os.path.exists('/etc/debian_version') else 'nginx'
def _default_svc_user():
    """A service user that actually exists on this distro (www-data on
    Debian/Ubuntu, nginx on RHEL) -- the old hardcoded 'www' default does
    not exist on any supported distro, so systemd failed the unit with
    'Failed to determine user credentials' and the app never started."""
    try:
        u=_get_web_user()
        return u or 'www-data'
    except Exception:
        return 'www-data'


nodejs_bp = Blueprint('nodejs', __name__)
PROJECTS_FILE = '/opt/vortexpanel/nodejs_projects.json'
NVM_DIR       = os.path.expanduser('~/.nvm')
NVM_SH        = os.path.join(NVM_DIR, 'nvm.sh')


def req(): return 'user' in session

def sh(cmd, timeout=60, nvm=False):
    if nvm and os.path.exists(NVM_SH):
        cmd = f'. {NVM_SH} 2>/dev/null; {cmd}'
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, executable='/bin/bash')
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return '', str(e), 1

def os_family():
    """Return 'debian' or 'rhel' based on current OS."""
    if os.path.exists('/etc/debian_version'):
        return 'debian'
    if os.path.exists('/etc/redhat-release') or os.path.exists('/etc/fedora-release'):
        return 'rhel'
    # Fallback: check for apt
    _, _, rc = sh('which apt-get 2>/dev/null')
    return 'debian' if rc == 0 else 'rhel'

# Apache helpers — differ between Debian and RHEL
def apache_conf_dir():
    if os_family() == 'debian':
        return '/etc/apache2/sites-available'
    return '/etc/httpd/conf.d'

def apache_log_dir():
    if os_family() == 'debian':
        return '/var/log/apache2'
    return '/var/log/httpd'

def apache_enable_modules():
    """Enable proxy modules — command differs by OS family."""
    if os_family() == 'debian':
        sh('a2enmod proxy proxy_http proxy_wstunnel headers rewrite 2>/dev/null')
    else:
        # RHEL-family httpd ships proxy/rewrite/headers modules INSIDE the base httpd
        # package — there's no separate 'mod_proxy' package. They load by default via
        # LoadModule lines in /etc/httpd/conf.modules.d/. Just ensure httpd is present.
        sh('dnf install -y httpd 2>/dev/null || yum install -y httpd 2>/dev/null || true')

def apache_enable_site(name):
    """Enable a vhost config — Debian needs a2ensite, RHEL just needs the file present."""
    if os_family() == 'debian':
        sh(f'a2ensite {name} 2>/dev/null')

def apache_disable_site(name):
    """Disable a vhost config — Debian needs a2dissite, RHEL just removes the file."""
    if os_family() == 'debian':
        sh(f'a2dissite {name} 2>/dev/null')

def apache_test_config():
    """Test Apache config syntax."""
    if os_family() == 'debian':
        return sh('apache2ctl configtest 2>&1')
    return sh('apachectl configtest 2>&1 || httpd -t 2>&1')

def apache_reload():
    """Reload Apache — service name differs by OS family."""
    if os_family() == 'debian':
        sh('systemctl reload apache2 2>/dev/null || apache2ctl graceful 2>/dev/null')
    else:
        sh('systemctl reload httpd 2>/dev/null || apachectl graceful 2>/dev/null')

def load_projects():
    if os.path.exists(PROJECTS_FILE):
        try: return json.load(open(PROJECTS_FILE))
        except: pass
    return []

def save_projects(projects):
    os.makedirs(os.path.dirname(PROJECTS_FILE), exist_ok=True)
    with open(PROJECTS_FILE, 'w') as f: json.dump(projects, f, indent=2)

def svc_name(pid): return f'vortex-node-{pid}'

# --- Webserver detection + proxy config ------------------------------------

def detect_active_webserver():
    checks = [
        ('nginx',         'systemctl is-active nginx 2>/dev/null'),
        ('apache2',       'systemctl is-active apache2 2>/dev/null || systemctl is-active httpd 2>/dev/null'),
        ('openlitespeed', 'systemctl is-active lsws 2>/dev/null'),
        ('caddy',         'systemctl is-active caddy 2>/dev/null'),
    ]
    for name, cmd in checks:
        out, _, _ = sh(cmd)
        if 'active' in out:
            return name
    return None

def write_proxy_conf(p):
    domain = p.get('domain','').strip()
    port   = p.get('port','')
    pid    = p['id']
    if not domain or not port:
        return False, 'Domain and port are required for proxy setup'

    ws = detect_active_webserver()
    if not ws:
        return False, 'No active webserver found. Install nginx, Apache, OLS, or Caddy first.'

    primary = domain.splitlines()[0].strip().split(':')[0]
    all_d   = ' '.join(d.strip().split(':')[0] for d in domain.splitlines() if d.strip())

    # Remove old configs from any previous webserver before writing new one
    remove_proxy_conf(pid)

    if ws == 'nginx':
        conf = f"""server {{
    listen 80;
    server_name {all_d};
    access_log /var/log/nginx/vortex-node-{pid}-access.log;
    error_log  /var/log/nginx/vortex-node-{pid}-error.log;

    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }}
}}
"""
        conf_path = f'/etc/nginx/conf.d/vortex-node-{pid}.conf'
        open(conf_path, 'w').write(conf)
        _, err, rc = sh('nginx -t 2>&1')
        if rc != 0:
            os.remove(conf_path)
            return False, f'nginx config test failed: {err}'
        sh('systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null')

    elif ws == 'apache2':
        apache_enable_modules()
        log_dir = apache_log_dir()
        conf = f"""<VirtualHost *:80>
    ServerName {primary}
    ServerAlias {all_d}
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:{port}/
    ProxyPassReverse / http://127.0.0.1:{port}/
    RequestHeader set X-Forwarded-Proto "http"
    RequestHeader set X-Real-IP "%{{REMOTE_ADDR}}s"
    ErrorLog {log_dir}/vortex-node-{pid}-error.log
    CustomLog {log_dir}/vortex-node-{pid}-access.log combined
</VirtualHost>
"""
        conf_dir  = apache_conf_dir()
        conf_name = f'vortex-node-{pid}'
        conf_path = os.path.join(conf_dir, f'{conf_name}.conf')
        os.makedirs(conf_dir, exist_ok=True)
        open(conf_path, 'w').write(conf)
        apache_enable_site(conf_name)
        _, err, rc = apache_test_config()
        if rc != 0:
            apache_disable_site(conf_name)
            try: os.remove(conf_path)
            except: pass
            return False, f'Apache config test failed: {err}'
        apache_reload()

    elif ws == 'openlitespeed':
        vhost_dir = f'/usr/local/lsws/conf/vhosts/vortex-node-{pid}'
        os.makedirs(vhost_dir, exist_ok=True)
        conf = f"""docRoot                   /var/www/html
virtualHostConfig  {{
  extprocessor vortex-node-{pid} {{
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
    handler                 vortex-node-{pid}
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
        output file /var/log/caddy/vortex-node-{pid}.log
    }}
}}
"""
        conf_path = f'/etc/caddy/sites/vortex-node-{pid}.caddy'
        open(conf_path, 'w').write(conf)
        caddyfile = '/etc/caddy/Caddyfile'
        if os.path.exists(caddyfile):
            content = open(caddyfile).read()
            if 'import sites/*' not in content:
                open(caddyfile, 'a').write('\nimport sites/*\n')
        _, err, rc = sh('caddy validate --config /etc/caddy/Caddyfile 2>&1')
        if rc != 0:
            try: os.remove(conf_path)
            except: pass
            return False, f'Caddy config validate failed: {err}'
        sh('systemctl reload caddy 2>/dev/null')

    return True, ws

def remove_proxy_conf(pid):
    """Remove proxy config from ALL webservers — cleans both Debian and RHEL paths."""
    # nginx (same path on all distros)
    sh(f'rm -f /etc/nginx/conf.d/vortex-node-{pid}.conf 2>/dev/null')

    # Apache — clean BOTH Debian and RHEL paths
    sh(f'a2dissite vortex-node-{pid} 2>/dev/null || true')
    sh(f'rm -f /etc/apache2/sites-available/vortex-node-{pid}.conf 2>/dev/null')
    sh(f'rm -f /etc/apache2/sites-enabled/vortex-node-{pid}.conf 2>/dev/null')
    sh(f'rm -f /etc/httpd/conf.d/vortex-node-{pid}.conf 2>/dev/null')

    # OLS (same path on all distros)
    sh(f'rm -rf /usr/local/lsws/conf/vhosts/vortex-node-{pid}/ 2>/dev/null')

    # Caddy (same path on all distros)
    sh(f'rm -f /etc/caddy/sites/vortex-node-{pid}.caddy 2>/dev/null')

    # Reload active webserver after cleanup
    ws = detect_active_webserver()
    if ws == 'nginx':
        sh('nginx -t 2>/dev/null && (systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null)')
    elif ws == 'apache2':
        apache_reload()
    elif ws == 'openlitespeed':
        sh('/usr/local/lsws/bin/lswsctrl restart 2>/dev/null || systemctl restart lsws 2>/dev/null')
    elif ws == 'caddy':
        sh('systemctl reload caddy 2>/dev/null')

# --- Node Version Manager (nvm) -------------------------------------------

@nodejs_bp.route('/api/nodejs/versions')
def nvm_list():
    if not req(): return jsonify({'ok':False}), 401
    installed_out, _, _ = sh('nvm ls --no-colors 2>/dev/null', nvm=True)
    current_out,   _, _ = sh('nvm current 2>/dev/null', nvm=True)
    current = current_out.strip()

    installed = []
    for line in installed_out.splitlines():
        line = line.strip().lstrip('*').strip()
        m = re.match(r'v?(\d+\.\d+\.\d+)', line)
        if m:
            ver = 'v' + m.group(1)
            installed.append({'version': ver,
                               'active': ver == current or ('v'+m.group(1)) == current})

    sys_node, _, _ = sh('node --version 2>/dev/null')
    if sys_node and not any(v['version'] == sys_node for v in installed):
        installed.insert(0, {'version': sys_node, 'active': True, 'system': True})

    return jsonify({'ok': True, 'installed': installed, 'current': current})

@nodejs_bp.route('/api/nodejs/versions/available')
def nvm_available():
    if not req(): return jsonify({'ok':False}), 401
    # Source: nodejs.org release schedule — verified June 2026
    versions = [
        {'version':'v26.x', 'lts':'Current (not LTS yet)',  'value':'26', 'status':'current',     'recommended':False},
        {'version':'v24.x', 'lts':'Active LTS — Krypton',   'value':'24', 'status':'active-lts',  'recommended':True},
        {'version':'v22.x', 'lts':'Maintenance LTS — Jod',  'value':'22', 'status':'maintenance', 'recommended':False},
    ]
    # EOL versions are intentionally excluded — v20 EOL Apr 2026, v18 EOL Apr 2025

    installed_out, _, _ = sh('nvm ls --no-colors 2>/dev/null', nvm=True)
    installed_vers = set(re.findall(r'v(\d+)\.\d+\.\d+', installed_out))

    # Also check system Node.js (installed via App Store/nodesource — NOT via nvm)
    sys_node, _, _ = sh('node --version 2>/dev/null')
    if sys_node:
        m = re.match(r'v(\d+)', sys_node)
        if m:
            installed_vers.add(m.group(1))

    for v in versions:
        v['installed'] = v['value'] in installed_vers
    return jsonify({'ok': True, 'versions': versions})

@nodejs_bp.route('/api/nodejs/versions/install', methods=['POST'])
def nvm_install():
    if not req(): return jsonify({'ok':False}), 401
    ver = (request.get_json() or {}).get('version','').strip()
    if not re.match(r'^\d+$', ver) and not re.match(r'^v?\d+(\.\d+)*$', ver):
        return jsonify({'ok':False,'error':'Invalid version'})
    out, err, rc = sh(f'nvm install {ver} 2>&1', timeout=300, nvm=True)
    if rc != 0:
        return jsonify({'ok':False,'error': err or out})
    return jsonify({'ok':True,'output':out})

@nodejs_bp.route('/api/nodejs/versions/use', methods=['POST'])
def nvm_use():
    if not req(): return jsonify({'ok':False}), 401
    ver = (request.get_json() or {}).get('version','').strip()
    out, err, rc = sh(f'nvm alias default {ver} 2>&1 && nvm use {ver} 2>&1', nvm=True)
    return jsonify({'ok': rc == 0, 'error': err or ''})

@nodejs_bp.route('/api/nodejs/versions/uninstall', methods=['POST'])
def nvm_uninstall():
    if not req(): return jsonify({'ok':False}), 401
    ver = (request.get_json() or {}).get('version','').strip()
    out, err, rc = sh(f'nvm uninstall {ver} 2>&1', nvm=True)
    return jsonify({'ok': rc == 0, 'error': err or ''})

# --- PM2 utilities ----------------------------------------------------------

def pm2_cmd(cmd, timeout=30):
    return sh(f'pm2 {cmd} --no-color 2>&1', timeout=timeout, nvm=True)

def pm2_list_raw():
    out, _, _ = pm2_cmd('jlist')
    try: return json.loads(out)
    except: return []

def pm2_status(name):
    procs = pm2_list_raw()
    for p in procs:
        if p.get('name') == name:
            return {
                'status':   p.get('pm2_env',{}).get('status','stopped'),
                'pid':      p.get('pid', ''),
                'cpu':      p.get('monit',{}).get('cpu', 0),
                'memory':   round(p.get('monit',{}).get('memory', 0) / 1024 / 1024, 1),
                'restarts': p.get('pm2_env',{}).get('restart_time', 0),
                'uptime':   p.get('pm2_env',{}).get('pm_uptime', ''),
            }
    return {'status':'stopped','pid':'','cpu':0,'memory':0,'restarts':0}

@nodejs_bp.route('/api/nodejs/pm2/list')
def pm2_list():
    if not req(): return jsonify({'ok':False}), 401
    procs = pm2_list_raw()
    result = []
    for p in procs:
        env = p.get('pm2_env', {})
        result.append({
            'id':        p.get('pm_id'),
            'name':      p.get('name'),
            'status':    env.get('status'),
            'pid':       p.get('pid'),
            'cpu':       p.get('monit',{}).get('cpu', 0),
            'memory_mb': round(p.get('monit',{}).get('memory',0)/1024/1024, 1),
            'restarts':  env.get('restart_time', 0),
            'path':      env.get('pm_cwd',''),
            'node_ver':  env.get('node_version',''),
        })
    return jsonify({'ok': True, 'processes': result})

@nodejs_bp.route('/api/nodejs/pm2/monitor')
def pm2_monitor():
    if not req(): return jsonify({'ok':False}), 401
    procs = pm2_list_raw()
    total_cpu = sum(p.get('monit',{}).get('cpu',0) for p in procs)
    total_mem = sum(p.get('monit',{}).get('memory',0) for p in procs)
    return jsonify({
        'ok': True,
        'total_processes': len(procs),
        'total_cpu': total_cpu,
        'total_memory_mb': round(total_mem / 1024 / 1024, 1),
        'processes': procs,
    })

# --- Package managers -------------------------------------------------------

def run_pkg_install(path, manager='npm'):
    manager = manager if manager in ('npm','yarn','pnpm') else 'npm'
    if manager in ('yarn','pnpm'):
        sh(f'npm install -g {manager} 2>/dev/null', nvm=True)
    out, err, rc = sh(f'cd {path} && {manager} install 2>&1', timeout=120, nvm=True)
    return rc == 0, out + err

def get_pkg_scripts(path):
    pkg = os.path.join(path, 'package.json')
    if not os.path.exists(pkg): return []
    try:
        data = json.load(open(pkg))
        return [{'name': k, 'cmd': v} for k, v in data.get('scripts', {}).items()]
    except: return []

# --- Systemd service (same format on ALL 9 distros) -------------------------

def write_systemd_node(p):
    node_bin, _, _ = sh('which node 2>/dev/null', nvm=True)
    node_bin = node_bin or '/usr/bin/node'
    cmd = p.get('run_cmd') or f'{node_bin} {p["startup_file"]}'
    env_str = '\n'.join(f'Environment="{k}={v}"'
                        for k, v in (p.get('env') or {}).items())
    port_env = f'Environment="PORT={p["port"]}"' if p.get('port') else ''
    unit = f"""[Unit]
Description=VortexPanel Node.js: {p['name']}
After=network.target

[Service]
Type=simple
User={p.get('user') or _default_svc_user()}
WorkingDirectory={p['path']}
ExecStart={cmd}
Restart=always
RestartSec=5
{env_str}
{port_env}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    svc = f'/etc/systemd/system/{svc_name(p["id"])}.service'
    open(svc, 'w').write(unit)
    sh('systemctl daemon-reload')

# --- Project CRUD -----------------------------------------------------------

@nodejs_bp.route('/api/nodejs/projects')
def list_projects():
    if not req(): return jsonify({'ok':False}), 401
    projects = load_projects()
    for p in projects:
        if p.get('pm2'):
            st = pm2_status(p['id'])
        else:
            out, _, _ = sh(f'systemctl is-active {svc_name(p["id"])} 2>/dev/null')
            pid_out, _, _ = sh(f'systemctl show {svc_name(p["id"])} --property=MainPID 2>/dev/null')
            pid = pid_out.split('=')[-1].strip() if '=' in pid_out else ''
            st = {'status': out.strip() or 'inactive', 'pid': pid, 'cpu': 0, 'memory': 0}
        p.update(st)
        p['scripts'] = get_pkg_scripts(p['path'])
    return jsonify({'ok':True,'projects':projects})

@nodejs_bp.route('/api/nodejs/projects', methods=['POST'])
def create_project():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    name         = d.get('name','').strip()
    path         = d.get('path','').strip()
    pm2_mode     = d.get('pm2', False)
    port         = d.get('port','')
    user         = d.get('user') or _default_svc_user()
    node_ver     = d.get('node_version','')
    domain       = d.get('domain','').strip()
    startup_file = d.get('startup_file','').strip()
    run_cmd      = d.get('run_cmd','').strip()
    run_opt      = d.get('run_opt','').strip()
    pkg_mgr      = d.get('package_manager','npm')
    clusters     = int(d.get('clusters', 1))
    mem_limit    = int(d.get('memory_limit', 1024))
    auto_restart = d.get('auto_restart', True)
    env_raw      = d.get('env_vars','').strip()
    remark       = d.get('remark','').strip()
    no_pkg_install = d.get('no_pkg_install', False)

    if not name or not path:
        return jsonify({'ok':False,'error':'Name and path are required'})
    if not os.path.isdir(path):
        return jsonify({'ok':False,'error':f'Directory not found: {path}'})

    pid = re.sub(r'[^a-zA-Z0-9_-]','',name.lower().replace(' ','-'))
    projects = load_projects()
    if any(p['id']==pid for p in projects):
        return jsonify({'ok':False,'error':f'Project "{pid}" already exists'})

    env = {}
    for line in env_raw.splitlines():
        if '=' in line:
            k, _, v = line.partition('=')
            env[k.strip()] = v.strip()

    if not no_pkg_install:
        ok, out = run_pkg_install(path, pkg_mgr)
        if not ok:
            return jsonify({'ok':False,'error':f'Package install failed: {out[:300]}'})

    p = {
        'id': pid, 'name': name, 'path': path, 'port': port,
        'pm2': pm2_mode, 'user': user, 'node_version': node_ver,
        'domain': domain, 'startup_file': startup_file,
        'run_cmd': run_cmd, 'run_opt': run_opt,
        'package_manager': pkg_mgr, 'clusters': clusters,
        'memory_limit': mem_limit, 'auto_restart': auto_restart,
        'env': env, 'remark': remark,
    }

    if pm2_mode:
        entry        = startup_file or 'app.js'
        cluster_flag = f'-i {clusters}' if clusters > 1 else ''
        mem_flag     = f'--max-memory-restart {mem_limit}M'
        restart_flag = '--restart-delay=5000' if auto_restart else '--no-autorestart'
        out, err, rc = pm2_cmd(
            f'start {os.path.join(path, entry)} --name {pid} '
            f'{cluster_flag} {mem_flag} {restart_flag} --watch false',
            timeout=60
        )
        if rc != 0:
            return jsonify({'ok':False,'error':f'PM2 start failed: {err or out}'})
        pm2_cmd('save')
    else:
        write_systemd_node(p)
        sh(f'systemctl enable {svc_name(pid)} 2>/dev/null')
        sh(f'systemctl start {svc_name(pid)} 2>/dev/null')

    proxy_ws = None
    if domain:
        ok, result = write_proxy_conf(p)
        if ok:
            proxy_ws = result
        else:
            p['proxy_warning'] = result

    projects.append(p)
    save_projects(projects)
    return jsonify({'ok':True,'id':pid,'proxy_webserver':proxy_ws})

@nodejs_bp.route('/api/nodejs/projects/<pid>/control', methods=['POST'])
def control_project(pid):
    if not req(): return jsonify({'ok':False}), 401
    action   = (request.get_json() or {}).get('action','')
    projects = load_projects()
    p = next((x for x in projects if x['id']==pid), None)
    if not p:  return jsonify({'ok':False,'error':'Project not found'})
    if action not in ('start','stop','restart'):
        return jsonify({'ok':False,'error':'Invalid action'})
    if p.get('pm2'):
        pm2_cmd(f'{action} {pid}')
        status = pm2_status(pid)['status']
    else:
        sh(f'systemctl {action} {svc_name(pid)}')
        out, _, _ = sh(f'systemctl is-active {svc_name(pid)} 2>/dev/null')
        status = out.strip()
    return jsonify({'ok':True,'status':status})

@nodejs_bp.route('/api/nodejs/projects/<pid>', methods=['DELETE'])
def delete_project(pid):
    if not req(): return jsonify({'ok':False}), 401
    projects = load_projects()
    p = next((x for x in projects if x['id']==pid), None)
    if not p: return jsonify({'ok':False,'error':'Not found'})
    if p.get('pm2'):
        pm2_cmd(f'stop {pid}'); pm2_cmd(f'delete {pid}'); pm2_cmd('save')
    else:
        sh(f'systemctl stop {svc_name(pid)} 2>/dev/null')
        sh(f'systemctl disable {svc_name(pid)} 2>/dev/null')
        sh(f'rm -f /etc/systemd/system/{svc_name(pid)}.service')
        sh('systemctl daemon-reload')
    remove_proxy_conf(pid)
    save_projects([x for x in projects if x['id'] != pid])
    return jsonify({'ok':True})

@nodejs_bp.route('/api/nodejs/projects/<pid>/logs')
def project_logs(pid):
    if not req(): return jsonify({'ok':False}), 401
    projects = load_projects()
    p = next((x for x in projects if x['id']==pid), None)
    if not p: return jsonify({'ok':False,'error':'Not found'})
    if p.get('pm2'):
        out, _, _ = pm2_cmd(f'logs {pid} --lines 100 --nostream 2>&1')
    else:
        out, _, _ = sh(f'journalctl -u {svc_name(pid)} -n 100 --no-pager 2>/dev/null')
    return jsonify({'ok':True,'logs':out or 'No logs yet'})

@nodejs_bp.route('/api/nodejs/projects/<pid>/update', methods=['POST'])
def update_project(pid):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    projects = load_projects()
    idx = next((i for i,x in enumerate(projects) if x['id']==pid), None)
    if idx is None: return jsonify({'ok':False,'error':'Not found'})
    p = projects[idx]
    for field in ('port','domain','remark','clusters','memory_limit','auto_restart','run_cmd','startup_file','env'):
        if field in d: p[field] = d[field]
    if not p.get('pm2'):
        write_systemd_node(p)
        sh(f'systemctl restart {svc_name(pid)} 2>/dev/null')
    if p.get('domain'):
        write_proxy_conf(p)
    projects[idx] = p
    save_projects(projects)
    return jsonify({'ok':True})

@nodejs_bp.route('/api/nodejs/projects/<pid>/git-pull', methods=['POST'])
def git_pull(pid):
    if not req(): return jsonify({'ok':False}), 401
    projects = load_projects()
    p = next((x for x in projects if x['id']==pid), None)
    if not p: return jsonify({'ok':False,'error':'Not found'})
    out, err, rc = sh(f'cd {p["path"]} && git pull 2>&1', timeout=60)
    return jsonify({'ok': rc==0, 'output': out or err})

@nodejs_bp.route('/api/nodejs/pkg-scripts')
def pkg_scripts_by_path():
    if not req(): return jsonify({'ok':False}), 401
    path = request.args.get('path','').strip()
    if not path or not os.path.isdir(path):
        return jsonify({'ok':True,'scripts':[]})
    return jsonify({'ok':True,'scripts':get_pkg_scripts(path)})

@nodejs_bp.route('/api/nodejs/projects/<pid>/pkg-scripts')
def pkg_scripts(pid):
    if not req(): return jsonify({'ok':False}), 401
    projects = load_projects()
    p = next((x for x in projects if x['id']==pid), None)
    if not p: return jsonify({'ok':False,'error':'Not found'})
    return jsonify({'ok':True,'scripts':get_pkg_scripts(p['path'])})

@nodejs_bp.route('/api/nodejs/pm2/save', methods=['POST'])
def pm2_save():
    if not req(): return jsonify({'ok':False}), 401
    pm2_cmd('save'); pm2_cmd('startup')
    return jsonify({'ok':True})

@nodejs_bp.route('/api/nodejs/webserver')
def active_webserver():
    if not req(): return jsonify({'ok':False}), 401
    ws = detect_active_webserver()
    family = os_family()
    return jsonify({
        'ok': True,
        'webserver': ws,
        'os_family': family,
        'message': f'Domain proxy will be configured for {ws} ({family})' if ws
                   else 'No active webserver found. Install nginx, Apache, OLS, or Caddy first.'
    })
