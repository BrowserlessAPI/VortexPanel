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
import subprocess, os, json, re, tempfile, shutil
try:
    from panel.routes import os_utils as _ou
except Exception:
    try:
        import os_utils as _ou
    except Exception:
        _ou = None
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


import pwd


def _resolve_user(u):
    """Return an existing account name for the unit's User=. The UI still
    defaults to 'www' (an aaPanel convention that exists on no supported
    distro); map that to the distro web user instead of writing a unit
    systemd cannot start. Returns (user, error)."""
    u = (u or '').strip()
    if not u or u == 'www':
        u2 = _default_svc_user()
        try:
            pwd.getpwnam(u2)
            return u2, None
        except KeyError:
            return None, f'Service user {u2} does not exist on this server'
    if not re.fullmatch(r'[a-z_][a-z0-9_.-]*\$?', u):
        return None, 'Invalid user name'
    try:
        pwd.getpwnam(u)
    except KeyError:
        return None, f'User "{u}" does not exist on this server'
    return u, None


_DOMAIN_RE = re.compile(r'^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*(:\d{1,5})?$')


def _valid_domains(domain):
    lines = [l.strip() for l in (domain or '').splitlines() if l.strip()]
    return all(_DOMAIN_RE.match(l) for l in lines)


def _valid_port(port):
    port = str(port or '').strip()
    return port == '' or (port.isdigit() and 1 <= int(port) <= 65535)


def _unit_val(v):
    """A value safe to put on one unit-file line: no newlines (which would
    inject extra directives such as ExecStartPre=+...), '%' escaped so
    systemd does not treat it as a specifier."""
    return str(v).replace('\r', ' ').replace('\n', ' ').replace('%', '%%')


def _validate_project_fields(p):
    """Shared validation for create/update. Returns an error string or None."""
    if not _valid_port(p.get('port')):
        return 'Port must be a number between 1 and 65535'
    if p.get('domain') and not _valid_domains(p['domain']):
        return 'Invalid domain (one hostname per line, e.g. app.example.com)'
    if p.get('mem_limit') and not re.fullmatch(r'\d+(\.\d+)?[KMGT]?|infinity|\d{1,3}%', str(p['mem_limit']).strip()):
        return 'Memory limit must look like 512M, 1G or 50%'
    if p.get('cpu_quota') and not re.fullmatch(r'\d{1,5}', str(p['cpu_quota']).strip()):
        return 'CPU quota must be a whole percentage, e.g. 50'
    env = p.get('env') or {}
    if not isinstance(env, dict):
        return 'Invalid environment variables'
    for k in env:
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', str(k)):
            return f'Invalid environment variable name: {k}'
    return None


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
    return 'debian' if shutil.which('apt-get') else 'rhel'

def _selinux_proxy():
    """nginx/httpd may not connect to the app's local port under SELinux
    (every proxied request 502) unless httpd_can_network_connect is on."""
    try:
        if _ou: _ou.selinux_web_booleans(proxy=True, db=False)
    except Exception:
        pass

def _v6_listen():
    """`listen [::]:80;` only where the kernel has IPv6."""
    return '\n    listen [::]:80;' if os.path.exists('/proc/net/if_inet6') else ''

def _cgroup_v2():
    return os.path.exists('/sys/fs/cgroup/cgroup.controllers')

def load_projects():
    if os.path.exists(PROJECTS_FILE):
        try: return json.load(open(PROJECTS_FILE))
        except: pass
    return []

def save_projects(projects):
    os.makedirs(os.path.dirname(PROJECTS_FILE), exist_ok=True)
    with open(PROJECTS_FILE, 'w') as f: json.dump(projects, f, indent=2)

def svc_name(pid): return f'vortex-go-{pid}'

def _find_project(pid):
    """Only ids of known projects ever reach a shell command."""
    return next((x for x in load_projects() if x.get('id') == pid), None)

def _port_owner(port, pid=None):
    """Name of another Go/Node.js project already configured on this port."""
    port = str(port or '').strip()
    if not port: return None
    for x in load_projects():
        if x.get('id') != pid and str(x.get('port') or '') == port:
            return f'Go project "{x.get("name")}"'
    try:
        for x in json.load(open('/opt/vortexpanel/nodejs_projects.json')):
            if str(x.get('port') or '') == port:
                return f'Node.js project "{x.get("name")}"'
    except Exception:
        pass
    return None

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

def _ensure_nginx_ws_map():
    """nginx requires the $connection_upgrade map in http{} context, not per-site.
    Written once to a shared conf.d file; safe to call on every proxy write."""
    map_path = '/etc/nginx/conf.d/00-vortex-websocket-map.conf'
    if os.path.exists(map_path):
        return
    conf = """# Shared by all VortexPanel-managed reverse proxies (Go/Node.js projects, Docker domains)
# Required for WebSocket upgrade support — proxy_set_header Connection $connection_upgrade;
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
"""
    try:
        open(map_path, 'w').write(conf)
    except Exception:
        pass  # non-fatal — nginx -t will catch it if genuinely broken

def detect_active_webserver():
    checks = [
        ('nginx',         'systemctl is-active nginx 2>/dev/null'),
        ('apache2',       'systemctl is-active apache2 2>/dev/null || systemctl is-active httpd 2>/dev/null'),
        ('openlitespeed', 'systemctl is-active lsws 2>/dev/null'),
        ('caddy',         'systemctl is-active caddy 2>/dev/null'),
    ]
    for name, cmd in checks:
        out, _, _ = sh(cmd)
        # 'systemctl is-active' prints "inactive" for stopped and for
        # non-existent units -- a substring test matched nginx on every box.
        if 'active' in out.split(): return name
    return None

def apache_log_dir():
    return '/var/log/apache2' if os_family() == 'debian' else '/var/log/httpd'

def apache_conf_dir():
    return '/etc/apache2/sites-available' if os_family() == 'debian' else '/etc/httpd/conf.d'

def apache_enable_modules():
    if os_family() == 'debian':
        sh('a2enmod proxy proxy_http proxy_wstunnel headers rewrite 2>/dev/null')
    else:
        # RHEL-family httpd ships proxy/proxy_wstunnel/rewrite/headers modules INSIDE the base
        # httpd package — there is no separate 'mod_proxy' package to install. They're loaded
        # via LoadModule lines in /etc/httpd/conf.modules.d/, uncommented by default on a
        # standard install. We just ensure httpd itself is present; nothing to "enable" here.
        sh('dnf install -y httpd 2>/dev/null || yum install -y httpd 2>/dev/null || true')

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
    domain = (p.get('domain') or '').strip()
    port   = str(p.get('port') or '').strip()
    pid    = p['id']
    if not domain or not port: return False, 'Domain and port required'
    if not _valid_domains(domain) or not _valid_port(port):
        return False, 'Invalid domain or port'

    ws = detect_active_webserver()
    if not ws: return False, 'No active webserver. Install nginx, Apache, OLS, or Caddy first.'

    primary = domain.splitlines()[0].strip().split(':')[0]
    all_d   = ' '.join(d.strip().split(':')[0] for d in domain.splitlines() if d.strip())

    remove_proxy(pid)  # clean old configs first

    if ws == 'nginx':
        conf = f"""server {{
    listen 80;{_v6_listen()}
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
        # WebSocket support (gorilla/websocket, gin-contrib/websocket, gRPC-Web, etc.)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}
}}
"""
        conf_path = f'/etc/nginx/conf.d/vortex-go-{pid}.conf'
        os.makedirs('/etc/nginx/conf.d', exist_ok=True)
        with open(conf_path, 'w') as f: f.write(conf)
        _ensure_nginx_ws_map()
        out, err, rc = sh('nginx -t 2>&1')
        err = err or out
        if rc != 0:
            try: os.remove(conf_path)
            except: pass
            return False, f'nginx config test failed: {err}'
        sh('systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null')
        _selinux_proxy()

    elif ws == 'apache2':
        apache_enable_modules()
        _selinux_proxy()
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
    # WebSocket support (gorilla/websocket, gin-contrib/websocket, gRPC-Web, etc.)
    RewriteEngine On
    RewriteCond %{{HTTP:Upgrade}} websocket [NC]
    RewriteCond %{{HTTP:Connection}} upgrade [NC]
    RewriteRule ^/?(.*) "ws://127.0.0.1:{port}/$1" [P,L]
    ProxyTimeout 3600
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

_GO_VER_RE = re.compile(r'^\d+\.\d+(\.\d+)?((rc|beta)\d+)?$')

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
    ver = str((request.get_json() or {}).get('version','')).strip()
    if not _GO_VER_RE.match(ver):
        return jsonify({'ok':False,'error':'Invalid Go version format'})

    arch_map  = {'x86_64':'amd64','aarch64':'arm64','armv7l':'armv6l'}
    arch_raw, _, _ = sh('uname -m')
    arch = arch_map.get(arch_raw, 'amd64')
    url  = f'https://dl.google.com/go/go{ver}.linux-{arch}.tar.gz'
    dest = go_install_dir(ver)

    if os.path.exists(dest):
        return jsonify({'ok':False,'error':f'Go {ver} already installed at {dest}'})

    # Download to temp file
    fd, tmp = tempfile.mkstemp(suffix='.tar.gz')
    os.close(fd)
    _, err, rc = sh(f'curl -fsSL --max-time 300 "{url}" -o "{tmp}"', timeout=310)
    if rc != 0 or not os.path.getsize(tmp):
        sh(f'rm -f "{tmp}"')
        return jsonify({'ok':False,'error':f'Download failed: {err}'})

    # Extract into a private staging dir: the tarball's top-level dir is
    # "go/", and extracting straight into /usr/local would write THROUGH the
    # /usr/local/go symlink into the currently active version (corrupting
    # it) and then mv that symlink instead of the new tree.
    stage = tempfile.mkdtemp(prefix='.vp-go-', dir=GO_INSTALL_DIR)
    _, err, rc = sh(f'tar -C "{stage}" -xzf "{tmp}" && mv "{stage}/go" "{dest}"', timeout=180)
    sh(f'rm -rf "{stage}" "{tmp}"')
    if rc != 0:
        return jsonify({'ok':False,'error':f'Extract failed: {err}'})

    # If no Go active, set this as default
    if not go_active_version():
        _activate_version(ver)

    return jsonify({'ok':True,'version':ver,'path':dest})

@go_bp.route('/api/go/sdk/activate', methods=['POST'])
def sdk_activate():
    if not req(): return jsonify({'ok':False}), 401
    ver = str((request.get_json() or {}).get('version','')).strip()
    if not _GO_VER_RE.match(ver) or not os.path.isdir(go_install_dir(ver)):
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
    ver = str((request.get_json() or {}).get('version','')).strip()
    if not _GO_VER_RE.match(ver):
        return jsonify({'ok':False,'error':'Invalid Go version format'})
    dest = go_install_dir(ver)
    if not os.path.isdir(dest) or os.path.islink(dest):
        return jsonify({'ok':False,'error':f'Go {ver} not found'})
    if ver == go_active_version():
        return jsonify({'ok':False,'error':'Cannot remove the active Go version. Activate another version first.'})
    sh(f'rm -rf "{dest}"')
    return jsonify({'ok':True})

@go_bp.route('/api/go/sdk/goproxy', methods=['POST'])
def set_goproxy():
    if not req(): return jsonify({'ok':False}), 401
    proxy = str((request.get_json() or {}).get('proxy','')).strip()
    if not proxy: return jsonify({'ok':False,'error':'Proxy value required'})
    if not re.fullmatch(r'[A-Za-z0-9:/._,|@%+=~-]+', proxy):
        return jsonify({'ok':False,'error':'Invalid GOPROXY value'})
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
        # Cheap resource snapshot — reads systemd's own cgroup accounting, no extra process spawned
        mem_out, _, _ = sh(f'systemctl show {svc_name(p["id"])} --property=MemoryCurrent 2>/dev/null')
        try:
            mem_bytes = int(mem_out.split('=')[-1].strip())
            p['memory_mb'] = round(mem_bytes / 1024 / 1024, 1) if mem_bytes > 0 else None
        except (ValueError, IndexError):
            p['memory_mb'] = None
    return jsonify({'ok':True,'projects':projects})

@go_bp.route('/api/go/projects/<pid>/health')
def project_health(pid):
    """On-demand health check — verifies the port is actually accepting connections,
    not just that the process exists (systemd Restart=always only catches process death,
    not a hung/deadlocked app still holding the port open)."""
    if not req(): return jsonify({'ok': False}), 401
    projects = load_projects()
    p = next((x for x in projects if x['id'] == pid), None)
    if not p: return jsonify({'ok': False, 'error': 'Project not found'})
    port = p.get('port', '')
    if not port:
        return jsonify({'ok': True, 'checked': False, 'message': 'No port configured for this project'})

    import socket, time as _time
    start = _time.time()
    try:
        with socket.create_connection(('127.0.0.1', int(port)), timeout=3):
            latency_ms = round((_time.time() - start) * 1000, 1)
            return jsonify({'ok': True, 'checked': True, 'responsive': True, 'latency_ms': latency_ms})
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return jsonify({'ok': True, 'checked': True, 'responsive': False, 'error': str(e)})

def _build_unit_file(p):
    """Single source of truth for the systemd unit — used by both create and update
    so the two paths can never drift out of sync (they had 100% duplicated code before)."""
    name     = _unit_val(p['name'])
    user     = p.get('user') or _default_svc_user()
    # A bare executable path with spaces must be quoted for ExecStart=.
    cmd      = _unit_val(p.get('exec_cmd') or (f'"{p["exec_file"]}"' if ' ' in p['exec_file'] else p['exec_file']))
    run_dir  = _unit_val(os.path.dirname(p['exec_file']))
    port     = p.get('port', '')
    env      = p.get('env') or {}
    mem_limit = str(p.get('mem_limit') or '').strip()
    if mem_limit.isdigit():
        # a bare number is bytes to systemd ("256" = 256 bytes); users mean MB
        mem_limit += 'M'
    cpu_quota = str(p.get('cpu_quota') or '').strip()

    def _q(v):
        return _unit_val(v).replace('\\', '\\\\').replace('"', '\\"')
    env_str  = '\n'.join(f'Environment="{k}={_q(v)}"' for k, v in env.items())
    port_env = f'Environment="PORT={port}"' if port else ''
    # MemoryMax= is cgroup v2 only; systemd ignores it on cgroup v1 hosts
    # (CentOS 7-era kernels, some VPS/containers) -- MemoryLimit= there
    mem_line = (f'MemoryMax={mem_limit}' if _cgroup_v2() else f'MemoryLimit={mem_limit}') if mem_limit else ''
    cpu_line = f'CPUQuota={cpu_quota}%' if cpu_quota else ''

    return f"""[Unit]
Description=VortexPanel Go: {name}
After=network.target
# Start-rate limits live in [Unit]; in [Service] systemd ignores
# StartLimitIntervalSec with an "Unknown key" warning.
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User={user}
WorkingDirectory={run_dir}
ExecStart={cmd}
Restart=always
RestartSec=5
{env_str}
{port_env}
{mem_line}
{cpu_line}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

@go_bp.route('/api/go/projects', methods=['POST'])
def create_project():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    name      = d.get('name','').strip()
    exec_file = d.get('exec_file','').strip()
    port      = str(d.get('port','')).strip()
    exec_cmd  = d.get('exec_cmd','').strip()
    user, uerr = _resolve_user(d.get('user'))
    domain    = d.get('domain','').strip()
    env_raw   = d.get('env_vars','').strip()
    remark    = d.get('remark','').strip()
    release_port = d.get('release_port', False)
    mem_limit = str(d.get('mem_limit','')).strip()   # e.g. "512M", "1G" — systemd MemoryMax format
    cpu_quota = str(d.get('cpu_quota','')).strip()   # percent, e.g. "50" = half a core

    if not name:        return jsonify({'ok':False,'error':'Project name required'})
    if not exec_file:   return jsonify({'ok':False,'error':'Executable file path required'})
    if uerr:            return jsonify({'ok':False,'error':uerr})
    if not exec_file.startswith('/') or '\n' in exec_file or '"' in exec_file:
        return jsonify({'ok':False,'error':'Executable file must be an absolute path'})
    if not os.path.isfile(exec_file):
        return jsonify({'ok':False,'error':f'Executable file not found: {exec_file}'})

    pid = re.sub(r'[^a-zA-Z0-9_-]','',name.lower().replace(' ','-'))
    if not pid:
        return jsonify({'ok':False,'error':'Project name must contain letters or digits'})
    projects = load_projects()
    if any(p['id']==pid for p in projects):
        return jsonify({'ok':False,'error':f'Project "{pid}" already exists'})

    # Parse env vars (KEY=value per line)
    env = {}
    for line in env_raw.splitlines():
        if '=' in line:
            k, _, v = line.partition('=')
            if k.strip(): env[k.strip()] = v.strip()

    verr = _validate_project_fields({'port': port, 'domain': domain, 'mem_limit': mem_limit,
                                     'cpu_quota': cpu_quota, 'env': env})
    if verr: return jsonify({'ok':False,'error':verr})
    clash = _port_owner(port, pid)
    if clash: return jsonify({'ok':False,'error':f'Port {port} is already used by {clash}'})

    if not os.access(exec_file, os.X_OK):
        # Auto-fix permissions
        sh(f'chmod +x "{exec_file}"')

    p = {
        'id': pid, 'name': name, 'exec_file': exec_file,
        'exec_cmd': exec_cmd, 'port': port, 'user': user,
        'domain': domain, 'env': env, 'remark': remark,
        'release_port': release_port,
        'mem_limit': mem_limit, 'cpu_quota': cpu_quota,
    }

    # Write systemd unit
    svc = f'/etc/systemd/system/{svc_name(pid)}.service'
    with open(svc, 'w') as f: f.write(_build_unit_file(p))
    sh('systemctl daemon-reload')
    sh(f'systemctl enable {svc_name(pid)} 2>/dev/null')
    sh(f'systemctl start {svc_name(pid)} 2>/dev/null')

    # Firewall
    if release_port and port:
        open_port(port)

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

GO_BACKUPS_DIR = '/opt/vortexpanel/go_backups'

def _snapshot_binary(pid, exec_file):
    """Save a copy of the current binary before (re)starting, so a bad deploy can be
    rolled back. Skips if the file hasn't changed since the last snapshot (by hash)
    to avoid piling up identical copies on repeated restarts."""
    if not exec_file or not os.path.isfile(exec_file):
        return
    import hashlib, shutil, time as _time
    backup_dir = os.path.join(GO_BACKUPS_DIR, pid)
    os.makedirs(backup_dir, exist_ok=True)

    with open(exec_file, 'rb') as f:
        current_hash = hashlib.sha256(f.read()).hexdigest()[:12]

    existing = sorted(os.listdir(backup_dir)) if os.path.isdir(backup_dir) else []
    if existing and current_hash in existing[-1]:
        return  # unchanged since last snapshot

    ts = _time.strftime('%Y%m%d-%H%M%S')
    snap_name = f'{ts}_{current_hash}.bin'
    try:
        shutil.copy2(exec_file, os.path.join(backup_dir, snap_name))
    except Exception:
        return  # non-fatal — snapshot failure shouldn't block starting the app

    # Keep only the last 5 snapshots
    all_snaps = sorted(os.listdir(backup_dir))
    for old in all_snaps[:-5]:
        try: os.remove(os.path.join(backup_dir, old))
        except Exception: pass

@go_bp.route('/api/go/projects/<pid>/control', methods=['POST'])
def control_project(pid):
    if not req(): return jsonify({'ok':False}), 401
    action = (request.get_json() or {}).get('action','')
    if action not in ('start','stop','restart'):
        return jsonify({'ok':False,'error':'Invalid action'})
    p = _find_project(pid)
    if not p: return jsonify({'ok':False,'error':'Project not found'})
    if action in ('start', 'restart'):
        _snapshot_binary(pid, p.get('exec_file', ''))
    _, err, rc = sh(f'systemctl {action} {svc_name(pid)}')
    out, _, _ = sh(f'systemctl is-active {svc_name(pid)} 2>/dev/null')
    status = out.strip()
    if rc != 0 or (action != 'stop' and status != 'active'):
        logs, _, _ = sh(f'journalctl -u {svc_name(pid)} -n 5 --no-pager 2>/dev/null')
        return jsonify({'ok':False,'status':status,'error':(err or f'Service is {status or "not running"}') + ('\n' + logs if logs else '')})
    return jsonify({'ok':True,'status':status})

@go_bp.route('/api/go/projects/<pid>/versions')
def list_versions(pid):
    if not req(): return jsonify({'ok': False}), 401
    if not _find_project(pid): return jsonify({'ok': False, 'error': 'Project not found'})
    backup_dir = os.path.join(GO_BACKUPS_DIR, pid)
    if not os.path.isdir(backup_dir):
        return jsonify({'ok': True, 'versions': []})
    versions = []
    for fname in sorted(os.listdir(backup_dir), reverse=True):
        fpath = os.path.join(backup_dir, fname)
        try:
            size = os.path.getsize(fpath)
            ts_str, hash_str = fname.replace('.bin', '').split('_', 1)
        except (ValueError, OSError):
            continue
        versions.append({'file': fname, 'timestamp': ts_str, 'hash': hash_str, 'size_bytes': size})
    return jsonify({'ok': True, 'versions': versions})

@go_bp.route('/api/go/projects/<pid>/rollback', methods=['POST'])
def rollback_version(pid):
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    snapshot_file = d.get('file', '').strip()
    if not snapshot_file or '/' in snapshot_file or '..' in snapshot_file:
        return jsonify({'ok': False, 'error': 'Invalid snapshot filename'})

    projects = load_projects()
    p = next((x for x in projects if x['id'] == pid), None)
    if not p: return jsonify({'ok': False, 'error': 'Project not found'})

    snap_path = os.path.join(GO_BACKUPS_DIR, pid, snapshot_file)
    if not os.path.isfile(snap_path):
        return jsonify({'ok': False, 'error': 'Snapshot not found'})

    import shutil
    exec_file = p['exec_file']
    sh(f'systemctl stop {svc_name(pid)} 2>/dev/null')
    shutil.copy2(snap_path, exec_file)
    sh(f'chmod +x "{exec_file}"')
    sh(f'systemctl start {svc_name(pid)} 2>/dev/null')
    out, _, _ = sh(f'systemctl is-active {svc_name(pid)} 2>/dev/null')
    return jsonify({'ok': True, 'status': out.strip(), 'restored_from': snapshot_file})

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
    if not _find_project(pid): return jsonify({'ok':False,'error':'Project not found'})
    try: lines = max(1, min(int(request.args.get('lines', 100)), 10000))
    except (TypeError, ValueError): lines = 100
    out, _, _ = sh(f'journalctl -u {svc_name(pid)} -n {lines} --no-pager 2>/dev/null')
    return jsonify({'ok':True,'logs':out or 'No logs yet'})

@go_bp.route('/api/go/projects/<pid>/update', methods=['POST'])
def update_project(pid):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    projects = load_projects()
    idx = next((i for i,x in enumerate(projects) if x['id']==pid), None)
    if idx is None: return jsonify({'ok':False,'error':'Project not found'})
    p = dict(projects[idx])
    old = projects[idx]

    for field in ('port','domain','remark','exec_cmd','user','env','release_port','mem_limit','cpu_quota'):
        if field in d: p[field] = d[field]
    p['port'] = str(p.get('port') or '').strip()
    p['domain'] = (p.get('domain') or '').strip()
    if 'user' in d:
        user, uerr = _resolve_user(d.get('user'))
        if uerr: return jsonify({'ok':False,'error':uerr})
        p['user'] = user
    verr = _validate_project_fields(p)
    if verr: return jsonify({'ok':False,'error':verr})
    clash = _port_owner(p['port'], pid)
    if clash: return jsonify({'ok':False,'error':f'Port {p["port"]} is already used by {clash}'})

    # Rewrite systemd unit with new settings (shared builder — stays in sync with create_project)
    with open(f'/etc/systemd/system/{svc_name(pid)}.service','w') as f: f.write(_build_unit_file(p))
    sh('systemctl daemon-reload')
    sh(f'systemctl restart {svc_name(pid)} 2>/dev/null')

    # Firewall: follow port / release_port changes instead of leaving the
    # old port open forever.
    old_open = old.get('port') if old.get('release_port') else None
    new_open = p.get('port') if p.get('release_port') else None
    if old_open and old_open != new_open: close_port(old_open)
    if new_open and new_open != old_open: open_port(new_open)

    warning = None
    if p.get('domain') and p.get('port'):
        ok, result = write_proxy(p)
        if not ok: warning = result
    elif old.get('domain'):
        remove_proxy(pid)   # domain cleared -> drop the stale vhost
    p.pop('proxy_warning', None)
    if warning: p['proxy_warning'] = warning

    projects[idx] = p
    save_projects(projects)
    return jsonify({'ok':True, 'proxy_warning': warning})

@go_bp.route('/api/go/webserver')
def active_webserver():
    if not req(): return jsonify({'ok':False}), 401
    ws = detect_active_webserver()
    return jsonify({
        'ok': True,
        'webserver': ws,
        'message': f'Proxy will use {ws}' if ws else 'No active webserver found'
    })

# --- SSL / Let's Encrypt ------------------------------------------------------
def _ssl_status(domain):
    """Check if a domain already has a Let's Encrypt cert on disk."""
    live_dir = f'/etc/letsencrypt/live/{domain}'
    cert = f'{live_dir}/fullchain.pem'
    if not os.path.exists(cert):
        return {'enabled': False}
    out, _, rc = sh(f'openssl x509 -in {cert} -noout -enddate 2>/dev/null')
    days_left = None
    if rc == 0 and out.startswith('notAfter='):
        try:
            from datetime import datetime
            end_dt = datetime.strptime(out[9:].strip(), '%b %d %H:%M:%S %Y %Z')
            days_left = (end_dt - datetime.utcnow()).days
        except Exception:
            pass
    return {'enabled': True, 'days_left': days_left, 'cert_path': cert}

def _pkg_install_certbot(ws):
    """RHEL-family (RHEL/CentOS/AlmaLinux/Rocky/Oracle Linux) don't ship certbot in base
    repos — it requires EPEL. Fedora has it natively. Debian/Ubuntu have it natively too."""
    plugin = {'nginx': 'python3-certbot-nginx', 'apache2': 'python3-certbot-apache'}.get(ws, '')
    if os_family() == 'debian':
        return f'DEBIAN_FRONTEND=noninteractive apt-get install -y certbot {plugin} 2>/dev/null'
    # RHEL family: EPEL first (epel-release exists only on Alma/Rocky/CentOS/
    # CloudLinux; RHEL/Oracle need their own route -- os_utils.ensure_epel_cmd).
    # Fedora ships certbot itself.
    epel = _ou.ensure_epel_cmd() + '; ' if (_ou and not os.path.exists('/etc/fedora-release')) else ''
    return (
        f'{epel}'
        f'dnf install -y certbot {plugin} 2>/dev/null || yum install -y certbot {plugin} 2>/dev/null'
    )

def _wire_ols_ssl(pid, domain):
    """After certonly issues a standalone cert, add an HTTPS listener to the OLS vhost."""
    cert_dir = f'/etc/letsencrypt/live/{domain}'
    vhost_dir = f'/usr/local/lsws/conf/vhosts/vortex-go-{pid}'
    conf_path = f'{vhost_dir}/vhconf.conf'
    if not os.path.exists(conf_path):
        return False
    with open(conf_path) as f:
        content = f.read()
    if 'vhssl' in content:
        return True  # already wired
    ssl_block = f"""
vhssl  {{
  keyFile                 {cert_dir}/privkey.pem
  certFile                {cert_dir}/fullchain.pem
  certChain               1
  sslProtocol             30
}}
"""
    with open(conf_path, 'a') as f:
        f.write(ssl_block)
    sh('/usr/local/lsws/bin/lswsctrl restart 2>/dev/null || systemctl restart lsws 2>/dev/null')
    return True

@go_bp.route('/api/go/projects/<pid>/ssl', methods=['GET', 'POST'])
def project_ssl(pid):
    if not req(): return jsonify({'ok': False}), 401
    projects = load_projects()
    p = next((x for x in projects if x['id'] == pid), None)
    if not p: return jsonify({'ok': False, 'error': 'Project not found'})
    domain_lines = [d.strip() for d in (p.get('domain') or '').splitlines() if d.strip()]
    if not domain_lines:
        return jsonify({'ok': False, 'error': 'Assign a domain to this project first'})
    primary = domain_lines[0].split(':')[0]

    if request.method == 'GET':
        return jsonify({'ok': True, 'domain': primary, **_ssl_status(primary)})

    # POST — issue certificate
    d = request.get_json() or {}
    email = (d.get('email') or f'admin@{primary}').strip()
    if not re.fullmatch(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', email):
        return jsonify({'ok': False, 'error': 'Invalid email address'})
    if not _valid_domains(p.get('domain')):
        return jsonify({'ok': False, 'error': 'Invalid domain on this project'})
    ws = detect_active_webserver()

    if ws == 'caddy':
        return jsonify({'ok': True, 'method': 'automatic',
                         'message': "Caddy issues and renews SSL automatically for any domain in its config — no action needed. HTTPS is already active once DNS points here."})

    if ws not in ('nginx', 'apache2', 'openlitespeed'):
        return jsonify({'ok': False, 'error': 'No active webserver detected'})

    plugin_ok = ws == 'openlitespeed' or \
        ('nginx' if ws == 'nginx' else 'apache') in sh('certbot plugins 2>/dev/null', timeout=60)[0]
    if not shutil.which('certbot') or not plugin_ok:
        sh(_pkg_install_certbot(ws), timeout=600)
    # EPEL ships certbot-renew.timer disabled: certificates expired after 90 days
    try:
        if _ou: _ou.certbot_enable_renewal()
    except Exception:
        pass

    # Certificates are per hostname: drop any :port suffix.
    domain_args = ' '.join(f'-d {dm.split(":")[0]}' for dm in domain_lines)

    # sh() returns (stdout, stderr, rc); it used to be called with an unknown
    # t= keyword (TypeError -> HTTP 500 on every issue attempt).
    if ws == 'nginx':
        out = sh(f'certbot --nginx {domain_args} --non-interactive --agree-tos -m {email} 2>&1', timeout=180)[0]
    elif ws == 'apache2':
        out = sh(f'certbot --apache {domain_args} --non-interactive --agree-tos -m {email} 2>&1', timeout=180)[0]
    else:  # openlitespeed — no certbot plugin; issue standalone cert then wire into vhost manually
        webroot = '/usr/local/lsws/Example/html'
        out = sh(f'certbot certonly --webroot -w {webroot} {domain_args} --non-interactive --agree-tos -m {email} 2>&1', timeout=180)[0]
        if 'Congratulations' in out or 'Successfully' in out or 'Certificate not yet due' in out:
            _wire_ols_ssl(pid, primary)

    ok = 'Congratulations' in out or 'Successfully' in out or 'Certificate not yet due' in out
    resp = {'ok': ok, 'output': out[-800:], 'webserver': ws}
    if not ok: resp['error'] = (out[-400:] or 'certbot failed')
    return jsonify(resp)

