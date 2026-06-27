from flask import Blueprint, jsonify, request, session
import subprocess, os, json, re, tempfile

go_bp = Blueprint('go', __name__)
def req(): return 'user' in session

PROJECTS_FILE = '/opt/vortexpanel/go_projects.json'
GO_INSTALL_DIR = '/usr/local'
GO_DATA_DIR    = '/opt/vortexpanel/go'

def sh(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return '', str(e), 1

def load_projects():
    if os.path.exists(PROJECTS_FILE):
        try: return json.load(open(PROJECTS_FILE))
        except: pass
    return []

def save_projects(projects):
    os.makedirs(os.path.dirname(PROJECTS_FILE), exist_ok=True)
    with open(PROJECTS_FILE, 'w') as f: json.dump(projects, f, indent=2)

def get_goproxy():
    out, _, _ = sh('go env GOPROXY 2>/dev/null')
    return out or 'https://proxy.golang.org,direct'

def get_installed_go():
    """Return list of installed Go versions."""
    installed = []
    for d in os.listdir(GO_INSTALL_DIR):
        if d.startswith('go') and os.path.isdir(os.path.join(GO_INSTALL_DIR, d, 'bin')):
            ver = d
            active = os.path.islink(os.path.join(GO_INSTALL_DIR, 'go')) and \
                     os.readlink(os.path.join(GO_INSTALL_DIR, 'go')) == os.path.join(GO_INSTALL_DIR, d)
            installed.append({'version': ver, 'path': os.path.join(GO_INSTALL_DIR, d), 'active': active})
    return installed

def svc_name(project_id): return f'vortex-go-{project_id}'

def write_systemd(p):
    env_str = '\n'.join(f'Environment="{k}={v}"' for k, v in (p.get('env') or {}).items())
    unit = f"""[Unit]
Description=VortexPanel Go: {p['name']}
After=network.target

[Service]
Type=simple
User={p.get('user','www')}
WorkingDirectory={os.path.dirname(p['path'])}
ExecStart={p.get('cmd') or p['path']}
Restart=always
RestartSec=5
{env_str}

[Install]
WantedBy=multi-user.target
"""
    svc = f'/etc/systemd/system/{svc_name(p["id"])}.service'
    with open(svc, 'w') as f: f.write(unit)
    sh('systemctl daemon-reload')

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

def write_proxy(p, prefix='vortex-go'):
    domain = p.get('domain','').strip()
    port   = p.get('port','')
    pid    = p['id']
    if not domain or not port: return False, 'Domain and port required'
    ws = detect_active_webserver()
    if not ws: return False, 'No active webserver found'

    primary = domain.splitlines()[0].strip().split(':')[0]
    all_d   = ' '.join(d.strip().split(':')[0] for d in domain.splitlines() if d.strip())

    if ws == 'nginx':
        conf = f"""server {{
    listen 80;
    server_name {all_d};
    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
}}
"""
        open(f'/etc/nginx/conf.d/{prefix}-{pid}.conf','w').write(conf)
        sh('nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null')
    elif ws in ('apache2','httpd'):
        sh('a2enmod proxy proxy_http headers 2>/dev/null')
        conf = f"""<VirtualHost *:80>
    ServerName {primary}
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:{port}/
    ProxyPassReverse / http://127.0.0.1:{port}/
    RequestHeader set X-Forwarded-Proto "http"
</VirtualHost>
"""
        open(f'/etc/apache2/sites-available/{prefix}-{pid}.conf','w').write(conf)
        sh(f'a2ensite {prefix}-{pid} 2>/dev/null')
        sh('systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null')
    elif ws == 'openlitespeed':
        vdir = f'/usr/local/lsws/conf/vhosts/{prefix}-{pid}'
        os.makedirs(vdir, exist_ok=True)
        open(f'{vdir}/vhconf.conf','w').write(f"""extprocessor {prefix}-{pid} {{
  type proxy
  address 127.0.0.1:{port}
  maxConns 100
}}
context / {{
  type proxy
  handler {prefix}-{pid}
}}
""")
        sh('systemctl restart lsws 2>/dev/null')
    elif ws == 'caddy':
        os.makedirs('/etc/caddy/sites', exist_ok=True)
        open(f'/etc/caddy/sites/{prefix}-{pid}.caddy','w').write(f'{all_d} {{\n    reverse_proxy 127.0.0.1:{port}\n}}\n')
        cf = '/etc/caddy/Caddyfile'
        if os.path.exists(cf) and 'import sites/*' not in open(cf).read():
            open(cf,'a').write('\nimport sites/*\n')
        sh('systemctl reload caddy 2>/dev/null')
    return True, ws

def remove_proxy(pid, prefix='vortex-go'):
    sh(f'rm -f /etc/nginx/conf.d/{prefix}-{pid}.conf 2>/dev/null')
    sh(f'a2dissite {prefix}-{pid} 2>/dev/null; rm -f /etc/apache2/sites-available/{prefix}-{pid}.conf 2>/dev/null')
    sh(f'rm -rf /usr/local/lsws/conf/vhosts/{prefix}-{pid}/ 2>/dev/null')
    sh(f'rm -f /etc/caddy/sites/{prefix}-{pid}.caddy 2>/dev/null')
    ws = detect_active_webserver()
    if ws == 'nginx':     sh('nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null')
    elif ws == 'apache2': sh('systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null')
    elif ws == 'openlitespeed': sh('systemctl restart lsws 2>/dev/null')
    elif ws == 'caddy':   sh('systemctl reload caddy 2>/dev/null')

# --- SDK endpoints -------------------------------------------------------

@go_bp.route('/api/go/sdk')
def sdk_list():
    if not req(): return jsonify({'ok':False}), 401
    installed = get_installed_go()
    active_go = sh('go version 2>/dev/null')[0]
    return jsonify({'ok':True, 'installed': installed,
                    'active': active_go, 'goproxy': get_goproxy()})

@go_bp.route('/api/go/sdk/versions')
def sdk_versions():
    if not req(): return jsonify({'ok':False}), 401
    # Fetch available versions from golang.org
    out, _, rc = sh('curl -fsSL --max-time 10 https://go.dev/dl/?mode=json 2>/dev/null | python3 -c "import sys,json; data=json.load(sys.stdin); [print(r[\'version\']) for r in data[:20] if r.get(\'stable\')]"', 15)
    versions = []
    if rc == 0 and out:
        versions = [v.strip() for v in out.splitlines() if v.strip()]
    if not versions:
        # Fallback list if API unreachable
        versions = ['go1.23.4','go1.22.10','go1.21.13','go1.20.14']
    installed_vers = {i['version'] for i in get_installed_go()}
    return jsonify({'ok':True, 'versions': [
        {'version': v, 'installed': v in installed_vers} for v in versions
    ]})

@go_bp.route('/api/go/sdk/install', methods=['POST'])
def sdk_install():
    if not req(): return jsonify({'ok':False}), 401
    ver = (request.get_json() or {}).get('version','').strip()
    if not re.match(r'^go[\d.]+$', ver):
        return jsonify({'ok':False,'error':'Invalid version format'})
    arch_map = {'x86_64':'amd64','aarch64':'arm64','armv7l':'armv6l'}
    arch_raw, _, _ = sh('uname -m')
    arch = arch_map.get(arch_raw, 'amd64')
    url = f'https://golang.org/dl/{ver}.linux-{arch}.tar.gz'
    dest = os.path.join(GO_INSTALL_DIR, ver)
    if os.path.exists(dest):
        return jsonify({'ok':False,'error':f'{ver} already installed'})
    tmp = tempfile.mktemp(suffix='.tar.gz')
    _, err, rc = sh(f'curl -fsSL --max-time 120 {url} -o {tmp}', 130)
    if rc != 0: return jsonify({'ok':False,'error':f'Download failed: {err}'})
    sh(f'tar -C {GO_INSTALL_DIR} -xzf {tmp} && mv {GO_INSTALL_DIR}/go {dest}')
    sh(f'rm -f {tmp}')
    # If no active go, set this as active
    if not os.path.exists(os.path.join(GO_INSTALL_DIR,'go')):
        sh(f'ln -sfn {dest} {GO_INSTALL_DIR}/go')
        sh(f'ln -sfn {dest}/bin/go /usr/local/bin/go')
    return jsonify({'ok':True,'version':ver})

@go_bp.route('/api/go/sdk/activate', methods=['POST'])
def sdk_activate():
    if not req(): return jsonify({'ok':False}), 401
    ver = (request.get_json() or {}).get('version','').strip()
    dest = os.path.join(GO_INSTALL_DIR, ver)
    if not os.path.exists(dest):
        return jsonify({'ok':False,'error':'Version not installed'})
    sh(f'ln -sfn {dest} {GO_INSTALL_DIR}/go')
    sh(f'ln -sfn {dest}/bin/go /usr/local/bin/go')
    sh(f'ln -sfn {dest}/bin/gofmt /usr/local/bin/gofmt')
    return jsonify({'ok':True})

@go_bp.route('/api/go/sdk/remove', methods=['POST'])
def sdk_remove():
    if not req(): return jsonify({'ok':False}), 401
    ver = (request.get_json() or {}).get('version','').strip()
    dest = os.path.join(GO_INSTALL_DIR, ver)
    if not os.path.exists(dest):
        return jsonify({'ok':False,'error':'Version not found'})
    sh(f'rm -rf {dest}')
    # If this was active, unlink
    link = os.path.join(GO_INSTALL_DIR, 'go')
    if os.path.islink(link) and os.readlink(link) == dest:
        os.unlink(link)
    return jsonify({'ok':True})

@go_bp.route('/api/go/sdk/goproxy', methods=['POST'])
def set_goproxy():
    if not req(): return jsonify({'ok':False}), 401
    proxy = (request.get_json() or {}).get('proxy','').strip()
    if not proxy: return jsonify({'ok':False,'error':'Proxy URL required'})
    # Set for all future go commands via /etc/profile.d
    os.makedirs('/etc/profile.d', exist_ok=True)
    with open('/etc/profile.d/goproxy.sh','w') as f:
        f.write(f'export GOPROXY="{proxy}"\n')
    sh(f'go env -w GOPROXY="{proxy}" 2>/dev/null || true')
    return jsonify({'ok':True,'proxy':proxy})

# --- Project endpoints ---------------------------------------------------

@go_bp.route('/api/go/projects')
def list_projects():
    if not req(): return jsonify({'ok':False}), 401
    projects = load_projects()
    for p in projects:
        out, _, _ = sh(f'systemctl is-active {svc_name(p["id"])} 2>/dev/null')
        p['status'] = out.strip() or 'inactive'
    return jsonify({'ok':True,'projects':projects})

@go_bp.route('/api/go/projects', methods=['POST'])
def create_project():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    name   = d.get('name','').strip()
    path   = d.get('path','').strip()
    port   = int(d.get('port', 8080))
    cmd    = d.get('cmd','').strip()
    user   = d.get('user','www')
    domain = d.get('domain','').strip()
    env    = d.get('env', {})
    startup= d.get('startup', True)

    if not name or not path:
        return jsonify({'ok':False,'error':'Name and executable path required'})

    pid = re.sub(r'[^a-zA-Z0-9_-]','',name.lower().replace(' ','-'))
    projects = load_projects()
    if any(p['id']==pid for p in projects):
        return jsonify({'ok':False,'error':f'Project "{pid}" already exists'})

    p = {'id':pid,'name':name,'path':path,'port':port,
         'cmd':cmd or path,'user':user,'domain':domain,'env':env,'startup':startup}
    write_systemd(p)
    if startup: sh(f'systemctl enable {svc_name(pid)}')
    sh(f'systemctl start {svc_name(pid)}')
    if domain: write_proxy(p, 'vortex-go')
    projects.append(p)
    save_projects(projects)
    return jsonify({'ok':True,'id':pid})

@go_bp.route('/api/go/projects/<pid>', methods=['DELETE'])
def remove_project(pid):
    if not req(): return jsonify({'ok':False}), 401
    svc = svc_name(pid)
    sh(f'systemctl stop {svc} 2>/dev/null; systemctl disable {svc} 2>/dev/null')
    sh(f'rm -f /etc/systemd/system/{svc}.service')
    sh(f'rm -f /etc/nginx/conf.d/vortex-go-{pid}.conf')
    remove_proxy(pid, 'vortex-go')
    sh('systemctl daemon-reload')
    projects = [p for p in load_projects() if p['id'] != pid]
    save_projects(projects)
    return jsonify({'ok':True})

@go_bp.route('/api/go/projects/<pid>/control', methods=['POST'])
def control_project(pid):
    if not req(): return jsonify({'ok':False}), 401
    action = (request.get_json() or {}).get('action','')
    if action not in ('start','stop','restart'):
        return jsonify({'ok':False,'error':'Invalid action'})
    sh(f'systemctl {action} {svc_name(pid)}')
    out, _, _ = sh(f'systemctl is-active {svc_name(pid)}')
    return jsonify({'ok':True,'status':out.strip()})

@go_bp.route('/api/go/projects/<pid>/logs')
def project_logs(pid):
    if not req(): return jsonify({'ok':False}), 401
    out, _, _ = sh(f'journalctl -u {svc_name(pid)} -n 100 --no-pager 2>/dev/null')
    return jsonify({'ok':True,'logs':out or 'No logs yet'})
