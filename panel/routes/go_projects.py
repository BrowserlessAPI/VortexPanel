"""
Go Project Manager for VortexPanel
- Binary-only deployment (compiled Go binaries, same as aaPanel)
- SDK management: install/activate/remove Go versions
- GOPROXY management
- Systemd process management
- Universal webserver reverse proxy (nginx/Apache/OLS/Caddy)
- Firewall integration (Release Port auto-opens UFW/firewalld)
- All 9 supported distros

Go version support (June 2026):
  - 1.26.4 — Latest stable (RECOMMENDED)
  - 1.25.11 — Previous stable (still supported)
  - 1.24.x  — EOL (Go 1.26 + 1.25 = 2 newer releases)
"""
from flask import Blueprint, jsonify, request, session
import subprocess, os, json, re, tempfile

go_bp = Blueprint('go', __name__)
PROJECTS_FILE = '/opt/vortexpanel/go_projects.json'
GO_INSTALL_DIR = '/usr/local'
GO_PROFILE     = '/etc/profile.d/go.sh'

# ─── Helpers ─────────────────────────────────────────────────────────────────

def req(): return 'user' in session

def sh(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, executable='/bin/bash')
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return '', str(e), 1

def os_family():
    if os.path.exists('/etc/debian_version'): return 'debian'
    if os.path.exists('/etc/redhat-release'): return 'rhel'
    _, _, rc = sh('which apt-get 2>/dev/null')
    return 'debian' if rc == 0 else 'rhel'

def load_projects():
    if os.path.exists(PROJECTS_FILE):
        try: return json.load(open(PROJECTS_FILE))
        except: pass
    return []

def save_projects(projects):
    os.makedirs(os.path.dirname(PROJECTS_FILE), exist_ok=True)
    with open(PROJECTS_FILE, 'w') as f: json.dump(projects, f, indent=2)

def svc_name(pid): return f'vortex-go-{pid}'

# ─── Firewall integration ─────────────────────────────────────────────────────

def open_port(port):
    """Open a port in the active firewall (UFW or firewalld)."""
    if not port: return
    # UFW (Debian/Ubuntu)
    ufw_out, _, _ = sh('ufw status 2>/dev/null')
    if 'Status: active' in ufw_out:
        sh(f'ufw allow {port}/tcp 2>/dev/null')
        return
    # firewalld (RHEL family)
    fw_out, _, _ = sh('firewall-cmd --state 2>/dev/null')
    if 'running' in fw_out:
        sh(f'firewall-cmd --permanent --add-port={port}/tcp 2>/dev/null')
        sh('firewall-cmd --reload 2>/dev/null')

def close_port(port):
    """Close a port in the active firewall."""
    if not port: return
    ufw_out, _, _ = sh('ufw status 2>/dev/null')
    if 'Status: active' in ufw_out:
        sh(f'ufw delete allow {port}/tcp 2>/dev/null')
        return
    fw_out, _, _ = sh('firewall-cmd --state 2>/dev/null')
    if 'running' in fw_out:
        sh(f'firewall-cmd --permanent --remove-port={port}/tcp 2>/dev/null')
        sh('firewall-cmd --reload 2>/dev/null')

# ─── Webserver proxy ──────────────────────────────────────────────────────────

def detect_active_webserver():
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

def apache_log_dir():
    return '/var/log/apache2' if os_family() == 'debian' else '/var/log/httpd'

def apache_conf_dir():
    return '/etc/apache2/sites-available' if os_family() == 'debian' else '/etc/httpd/conf.d'

def apache_enable_modules():
    if os_family() == 'debian':
        sh('a2enmod proxy proxy_http headers 2>/dev/null')
    else:
        sh('dnf install -y mod_proxy 2>/dev/null || yum install -y mod_proxy 2>/dev/null || true')

def apache_enable_site(name):
    if os_family() == 'debian': sh(f'a2ensite {name} 2>/dev/null')

def apache_disable_site(name):
    if os_family() == 'debian': sh(f'a2dissite {name} 2>/dev/null')

def apache_test_config():
    if os_family() == 'debian': return sh('apache2ctl configtest 2>&1')
    return sh('apachectl configtest 2>&1 || httpd -t 2>&1')

def apache_reload():
    if os_family() == 'debian':
        sh('systemctl reload apache2 2>/dev/null || apache2ctl graceful 2>/dev/null')
    else:
        sh('systemctl reload httpd 2>/dev/null || apachectl graceful 2>/dev/null')

def write_proxy(p):
    """Write reverse proxy config for active webserver."""
    domain = p.get('domain','').strip()
    port   = p.get('port','')
    pid    = p['id']
    if not domain or not port: return False, 'Domain and port required'

    ws = detect_active_webserver()
    if not ws: return False, 'No active webserver. Install nginx, Apache, OLS, or Caddy first.'

    primary = domain.splitlines()[0].strip().split(':')[0]
    all_d   = ' '.join(d.strip().split(':')[0] for d in domain.splitlines() if d.strip())

    remove_proxy(pid)  # clean old configs first

    if ws == 'nginx':
        conf = f"""server {{
    listen 80;
    server_name {all_d};
    access_log /var/log/nginx/vortex-go-{pid}-access.log;
    error_log  /var/log/nginx/vortex-go-{pid}-error.log;

    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""
        conf_path = f'/etc/nginx/conf.d/vortex-go-{pid}.conf'
        open(conf_path, 'w').write(conf)
        _, err, rc = sh('nginx -t 2>&1')
        if rc != 0:
            try: os.remove(conf_path)
            except: pass
            return False, f'nginx config test failed: {err}'
        sh('systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null')

    elif ws == 'apache2':
        apache_enable_modules()
        log_dir  = apache_log_dir()
        conf_dir = apache_conf_dir()
        conf_name = f'vortex-go-{pid}'
        conf = f"""<VirtualHost *:80>
    ServerName {primary}
    ServerAlias {all_d}
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:{port}/
    ProxyPassReverse / http://127.0.0.1:{port}/
    RequestHeader set X-Forwarded-Proto "http"
    RequestHeader set X-Real-IP "%{{REMOTE_ADDR}}s"
    ErrorLog {log_dir}/vortex-go-{pid}-error.log
    CustomLog {log_dir}/vortex-go-{pid}-access.log combined
</VirtualHost>
"""
        os.makedirs(conf_dir, exist_ok=True)
        conf_path = os.path.join(conf_dir, f'{conf_name}.conf')
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
        vhost_dir = f'/usr/local/lsws/conf/vhosts/vortex-go-{pid}'
        os.makedirs(vhost_dir, exist_ok=True)
        conf = f"""docRoot                   /var/www/html
virtualHostConfig {{
  extprocessor vortex-go-{pid} {{
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
    handler                 vortex-go-{pid}
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
        output file /var/log/caddy/vortex-go-{pid}.log
    }}
}}
"""
        open(f'/etc/caddy/sites/vortex-go-{pid}.caddy', 'w').write(conf)
        caddyfile = '/etc/caddy/Caddyfile'
        if os.path.exists(caddyfile) and 'import sites/*' not in open(caddyfile).read():
            open(caddyfile,'a').write('\nimport sites/*\n')
        _, err, rc = sh('caddy validate --config /etc/caddy/Caddyfile 2>&1')
        if rc != 0:
            sh(f'rm -f /etc/caddy/sites/vortex-go-{pid}.caddy')
            return False, f'Caddy config validate failed: {err}'
        sh('systemctl reload caddy 2>/dev/null')

    return True, ws

def remove_proxy(pid):
    """Remove all proxy configs — cleans ALL webservers, both Debian and RHEL paths."""
    sh(f'rm -f /etc/nginx/conf.d/vortex-go-{pid}.conf 2>/dev/null')
    sh(f'a2dissite vortex-go-{pid} 2>/dev/null; rm -f /etc/apache2/sites-available/vortex-go-{pid}.conf /etc/apache2/sites-enabled/vortex-go-{pid}.conf /etc/httpd/conf.d/vortex-go-{pid}.conf 2>/dev/null')
    sh(f'rm -rf /usr/local/lsws/conf/vhosts/vortex-go-{pid}/ 2>/dev/null')
    sh(f'rm -f /etc/caddy/sites/vortex-go-{pid}.caddy 2>/dev/null')
    ws = detect_active_webserver()
    if ws == 'nginx':        sh('nginx -t 2>/dev/null && (systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null)')
    elif ws == 'apache2':    apache_reload()
    elif ws == 'openlitespeed': sh('systemctl restart lsws 2>/dev/null')
    elif ws == 'caddy':      sh('systemctl reload caddy 2>/dev/null')

# ─── Go SDK ───────────────────────────────────────────────────────────────────

def go_active_version():
    """Return currently active Go version string e.g. '1.26.4'"""
    out, _, _ = sh('go version 2>/dev/null')
    m = re.search(r'go(\d+\.\d+\.\d+)', out)
    return m.group(1) if m else None

def go_install_dir(version):
    return os.path.join(GO_INSTALL_DIR, f'go{version}')

@go_bp.route('/api/go/sdk')
def sdk_list():
    if not req(): return jsonify({'ok':False}), 401
    installed = []
    active_ver = go_active_version()
    for entry in os.listdir(GO_INSTALL_DIR):
        if re.match(r'^go\d+\.\d+', entry):
            full_path = os.path.join(GO_INSTALL_DIR, entry)
            if os.path.isdir(full_path):
                ver = entry[2:]  # strip 'go' prefix
                installed.append({
                    'version': ver,
                    'path':    full_path,
                    'active':  ver == active_ver,
                })
    installed.sort(key=lambda x: [int(n) for n in x['version'].split('.') if n.isdigit()], reverse=True)
    goproxy, _, _ = sh('go env GOPROXY 2>/dev/null')
    return jsonify({
        'ok': True,
        'installed': installed,
        'active_version': active_ver,
        'goproxy': goproxy or 'https://proxy.golang.org,direct',
    })

@go_bp.route('/api/go/sdk/versions')
def sdk_versions():
    """Return curated Go version list with support status — verified June 2026."""
    if not req(): return jsonify({'ok':False}), 401
    # Go supports latest 2 major versions only
    versions = [
        {'version':'1.26.4', 'label':'1.26.4 (Latest stable)', 'value':'1.26.4', 'status':'latest',    'recommended':True},
        {'version':'1.25.11','label':'1.25.11 (Previous stable)','value':'1.25.11','status':'stable',   'recommended':False},
        {'version':'1.27rc1','label':'1.27rc1 (Release candidate)','value':'1.27rc1','status':'rc',     'recommended':False},
    ]
    # Check which are installed
    active_ver = go_active_version()
    for v in versions:
        v['installed'] = os.path.isdir(go_install_dir(v['value']))
        v['active']    = v['value'] == active_ver
    return jsonify({'ok':True,'versions':versions})

@go_bp.route('/api/go/sdk/install', methods=['POST'])
def sdk_install():
    if not req(): return jsonify({'ok':False}), 401
    ver = (request.get_json() or {}).get('version','').strip()
    if not re.match(r'^\d+\.\d+', ver):
        return jsonify({'ok':False,'error':'Invalid Go version format'})

    arch_map  = {'x86_64':'amd64','aarch64':'arm64','armv7l':'armv6l'}
    arch_raw, _, _ = sh('uname -m')
    arch = arch_map.get(arch_raw, 'amd64')
    url  = f'https://dl.google.com/go/go{ver}.linux-{arch}.tar.gz'
    dest = go_install_dir(ver)

    if os.path.exists(dest):
        return jsonify({'ok':False,'error':f'Go {ver} already installed at {dest}'})

    # Download to temp file
    tmp = tempfile.mktemp(suffix='.tar.gz')
    _, err, rc = sh(f'curl -fsSL --max-time 120 "{url}" -o "{tmp}"', timeout=130)
    if rc != 0 or not os.path.exists(tmp):
        return jsonify({'ok':False,'error':f'Download failed: {err}'})

    # Extract
    _, err, rc = sh(f'tar -C {GO_INSTALL_DIR} -xzf "{tmp}" && mv {GO_INSTALL_DIR}/go "{dest}"', timeout=60)
    sh(f'rm -f "{tmp}"')
    if rc != 0:
        return jsonify({'ok':False,'error':f'Extract failed: {err}'})

    # If no Go active, set this as default
    if not go_active_version():
        _activate_version(ver)

    return jsonify({'ok':True,'version':ver,'path':dest})

@go_bp.route('/api/go/sdk/activate', methods=['POST'])
def sdk_activate():
    if not req(): return jsonify({'ok':False}), 401
    ver = (request.get_json() or {}).get('version','').strip()
    if not os.path.isdir(go_install_dir(ver)):
        return jsonify({'ok':False,'error':f'Go {ver} not installed'})
    _activate_version(ver)
    return jsonify({'ok':True,'version':ver})

def _activate_version(ver):
    """Symlink go binary and update PATH profile."""
    dest = go_install_dir(ver)
    # Symlink /usr/local/go → /usr/local/go{ver}
    active_link = os.path.join(GO_INSTALL_DIR, 'go')
    sh(f'rm -f "{active_link}" && ln -sfn "{dest}" "{active_link}"')
    # Symlink binaries for direct access
    sh(f'ln -sfn "{dest}/bin/go" /usr/local/bin/go 2>/dev/null')
    sh(f'ln -sfn "{dest}/bin/gofmt" /usr/local/bin/gofmt 2>/dev/null')
    # Write profile.d for PATH persistence
    with open(GO_PROFILE, 'w') as f:
        f.write(f'export GOROOT="{dest}"\n')
        f.write('export PATH="$GOROOT/bin:$PATH"\n')
        f.write('export GOPATH="$HOME/go"\n')
        f.write('export PATH="$GOPATH/bin:$PATH"\n')

@go_bp.route('/api/go/sdk/remove', methods=['POST'])
def sdk_remove():
    if not req(): return jsonify({'ok':False}), 401
    ver = (request.get_json() or {}).get('version','').strip()
    dest = go_install_dir(ver)
    if not os.path.isdir(dest):
        return jsonify({'ok':False,'error':f'Go {ver} not found'})
    if ver == go_active_version():
        return jsonify({'ok':False,'error':'Cannot remove the active Go version. Activate another version first.'})
    sh(f'rm -rf "{dest}"')
    return jsonify({'ok':True})

@go_bp.route('/api/go/sdk/goproxy', methods=['POST'])
def set_goproxy():
    if not req(): return jsonify({'ok':False}), 401
    proxy = (request.get_json() or {}).get('proxy','').strip()
    if not proxy: return jsonify({'ok':False,'error':'Proxy value required'})
    sh(f'go env -w GOPROXY="{proxy}" 2>/dev/null')
    # Also persist in profile
    if os.path.exists(GO_PROFILE):
        content = open(GO_PROFILE).read()
        if 'GOPROXY' in content:
            sh(f'sed -i "s|export GOPROXY=.*|export GOPROXY=\\"{proxy}\\"|" {GO_PROFILE}')
        else:
            open(GO_PROFILE,'a').write(f'\nexport GOPROXY="{proxy}"\n')
    return jsonify({'ok':True,'proxy':proxy})

# ─── Project CRUD ─────────────────────────────────────────────────────────────

@go_bp.route('/api/go/projects')
def list_projects():
    if not req(): return jsonify({'ok':False}), 401
    projects = load_projects()
    for p in projects:
        out, _, _   = sh(f'systemctl is-active {svc_name(p["id"])} 2>/dev/null')
        pid_out,_,_ = sh(f'systemctl show {svc_name(p["id"])} --property=MainPID 2>/dev/null')
        pid = pid_out.split('=')[-1].strip() if '=' in pid_out else ''
        p['status'] = out.strip() or 'inactive'
        p['pid']    = pid if pid != '0' else ''
    return jsonify({'ok':True,'projects':projects})

@go_bp.route('/api/go/projects', methods=['POST'])
def create_project():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    name      = d.get('name','').strip()
    exec_file = d.get('exec_file','').strip()
    port      = str(d.get('port','')).strip()
    exec_cmd  = d.get('exec_cmd','').strip()
    user      = d.get('user','www')
    domain    = d.get('domain','').strip()
    env_raw   = d.get('env_vars','').strip()
    remark    = d.get('remark','').strip()
    release_port = d.get('release_port', False)

    if not name:        return jsonify({'ok':False,'error':'Project name required'})
    if not exec_file:   return jsonify({'ok':False,'error':'Executable file path required'})
    if not os.path.isfile(exec_file):
        return jsonify({'ok':False,'error':f'Executable file not found: {exec_file}'})
    if not os.access(exec_file, os.X_OK):
        # Auto-fix permissions
        sh(f'chmod +x "{exec_file}"')

    pid = re.sub(r'[^a-zA-Z0-9_-]','',name.lower().replace(' ','-'))
    projects = load_projects()
    if any(p['id']==pid for p in projects):
        return jsonify({'ok':False,'error':f'Project "{pid}" already exists'})

    # Parse env vars (KEY=value per line)
    env = {}
    for line in env_raw.splitlines():
        if '=' in line:
            k, _, v = line.partition('=')
            env[k.strip()] = v.strip()

    # Build effective execution command
    cmd = exec_cmd or exec_file
    run_dir = os.path.dirname(exec_file)

    # Write systemd unit
    env_str  = '\n'.join(f'Environment="{k}={v}"' for k,v in env.items())
    port_env = f'Environment="PORT={port}"' if port else ''
    unit = f"""[Unit]
Description=VortexPanel Go: {name}
After=network.target

[Service]
Type=simple
User={user}
WorkingDirectory={run_dir}
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
    svc = f'/etc/systemd/system/{svc_name(pid)}.service'
    open(svc, 'w').write(unit)
    sh('systemctl daemon-reload')
    sh(f'systemctl enable {svc_name(pid)} 2>/dev/null')
    sh(f'systemctl start {svc_name(pid)} 2>/dev/null')

    # Firewall
    if release_port and port:
        open_port(port)

    p = {
        'id': pid, 'name': name, 'exec_file': exec_file,
        'exec_cmd': exec_cmd, 'port': port, 'user': user,
        'domain': domain, 'env': env, 'remark': remark,
        'release_port': release_port,
    }

    # Webserver proxy
    proxy_ws = None
    if domain and port:
        ok, result = write_proxy(p)
        proxy_ws = result if ok else None
        if not ok: p['proxy_warning'] = result

    projects.append(p)
    save_projects(projects)

    out, _, _ = sh(f'systemctl is-active {svc_name(pid)} 2>/dev/null')
    return jsonify({'ok':True,'id':pid,'status':out.strip(),'proxy_webserver':proxy_ws})

@go_bp.route('/api/go/projects/<pid>/control', methods=['POST'])
def control_project(pid):
    if not req(): return jsonify({'ok':False}), 401
    action = (request.get_json() or {}).get('action','')
    if action not in ('start','stop','restart'):
        return jsonify({'ok':False,'error':'Invalid action'})
    sh(f'systemctl {action} {svc_name(pid)}')
    out, _, _ = sh(f'systemctl is-active {svc_name(pid)} 2>/dev/null')
    return jsonify({'ok':True,'status':out.strip()})

@go_bp.route('/api/go/projects/<pid>', methods=['DELETE'])
def delete_project(pid):
    if not req(): return jsonify({'ok':False}), 401
    projects = load_projects()
    p = next((x for x in projects if x['id']==pid), None)
    if not p: return jsonify({'ok':False,'error':'Project not found'})

    sh(f'systemctl stop {svc_name(pid)} 2>/dev/null')
    sh(f'systemctl disable {svc_name(pid)} 2>/dev/null')
    sh(f'rm -f /etc/systemd/system/{svc_name(pid)}.service')
    sh('systemctl daemon-reload')

    if p.get('release_port') and p.get('port'):
        close_port(p['port'])

    remove_proxy(pid)
    save_projects([x for x in projects if x['id'] != pid])
    return jsonify({'ok':True})

@go_bp.route('/api/go/projects/<pid>/logs')
def project_logs(pid):
    if not req(): return jsonify({'ok':False}), 401
    lines = request.args.get('lines','100')
    out, _, _ = sh(f'journalctl -u {svc_name(pid)} -n {lines} --no-pager 2>/dev/null')
    return jsonify({'ok':True,'logs':out or 'No logs yet'})

@go_bp.route('/api/go/projects/<pid>/update', methods=['POST'])
def update_project(pid):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    projects = load_projects()
    idx = next((i for i,x in enumerate(projects) if x['id']==pid), None)
    if idx is None: return jsonify({'ok':False,'error':'Project not found'})
    p = projects[idx]

    for field in ('port','domain','remark','exec_cmd','user','env','release_port'):
        if field in d: p[field] = d[field]

    # Rewrite systemd unit with new settings
    env_str  = '\n'.join(f'Environment="{k}={v}"' for k,v in (p.get('env') or {}).items())
    port_env = f'Environment="PORT={p["port"]}"' if p.get('port') else ''
    cmd      = p.get('exec_cmd') or p['exec_file']
    run_dir  = os.path.dirname(p['exec_file'])
    unit = f"""[Unit]
Description=VortexPanel Go: {p['name']}
After=network.target

[Service]
Type=simple
User={p.get('user','www')}
WorkingDirectory={run_dir}
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
    open(f'/etc/systemd/system/{svc_name(pid)}.service','w').write(unit)
    sh('systemctl daemon-reload')
    sh(f'systemctl restart {svc_name(pid)} 2>/dev/null')

    if p.get('domain') and p.get('port'):
        write_proxy(p)

    projects[idx] = p
    save_projects(projects)
    return jsonify({'ok':True})

@go_bp.route('/api/go/webserver')
def active_webserver():
    if not req(): return jsonify({'ok':False}), 401
    ws = detect_active_webserver()
    return jsonify({
        'ok': True,
        'webserver': ws,
        'message': f'Proxy will use {ws}' if ws else 'No active webserver found'
    })
