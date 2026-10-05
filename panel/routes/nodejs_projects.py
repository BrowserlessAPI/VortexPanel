"""
Node.js Project Manager for VortexPanel
Supports: Default projects (systemd) + PM2 projects
Webserver proxy: nginx / Apache2 / httpd / OpenLiteSpeed / Caddy
OS family: Debian/Ubuntu + RHEL/AlmaLinux/Rocky/CentOS/Oracle/Fedora
"""
from flask import Blueprint, jsonify, request, session
import subprocess, os, json, re, shutil, shlex, pwd, glob
try:
    from panel.routes.os_utils import get_webserver_user as _get_web_user
except Exception:
    try:
        from os_utils import get_webserver_user as _get_web_user
    except Exception:
        def _get_web_user():
            return 'www-data' if os.path.exists('/etc/debian_version') else 'nginx'
try:
    from panel.routes import os_utils as _ou
except Exception:
    try:
        import os_utils as _ou
    except Exception:
        _ou = None


def _selinux_proxy():
    """nginx/httpd may not connect to the app's local port under SELinux
    (every proxied request 502) unless httpd_can_network_connect is on."""
    try:
        if _ou: _ou.selinux_web_booleans(proxy=True, db=False)
    except Exception:
        pass


def _v6_listen():
    """`listen [::]:80;` only when the kernel has IPv6 (nginx refuses to
    start with an IPv6 listener on an IPv6-disabled host)."""
    return '\n    listen [::]:80;' if os.path.exists('/proc/net/if_inet6') else ''
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


def _resolve_user(u):
    """Existing account for User= (the UI defaults to 'www', which exists on
    no supported distro -> 'Failed to determine user credentials')."""
    u = (u or '').strip()
    if not u or u == 'www':
        u = _default_svc_user()
    if not re.fullmatch(r'[a-z_][a-z0-9_.-]*\$?', u):
        return None, 'Invalid user name'
    try:
        pwd.getpwnam(u)
    except KeyError:
        return None, f'User "{u}" does not exist on this server'
    return u, None


_DOMAIN_RE = re.compile(r'^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*(:\d{1,5})?$')
_VER_RE    = re.compile(r'^(v?\d+(\.\d+){0,2}|lts/[a-z*-]+|node|system)$')


def _valid_domains(domain):
    lines = [l.strip() for l in (domain or '').splitlines() if l.strip()]
    return all(_DOMAIN_RE.match(l) for l in lines)


def _valid_port(port):
    port = str(port or '').strip()
    return port == '' or (port.isdigit() and 1 <= int(port) <= 65535)


def _unit_val(v):
    """One unit-file line: no newline injection, '%' not a specifier."""
    return str(v).replace('\r', ' ').replace('\n', ' ').replace('%', '%%')


def _int(v, default, lo, hi):
    try: return max(lo, min(int(v), hi))
    except (TypeError, ValueError): return default


def _validate_fields(p):
    if not _valid_port(p.get('port')):
        return 'Port must be a number between 1 and 65535'
    if p.get('domain') and not _valid_domains(p['domain']):
        return 'Invalid domain (one hostname per line, e.g. app.example.com)'
    env = p.get('env') or {}
    if not isinstance(env, dict):
        return 'Invalid environment variables'
    for k in env:
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', str(k)):
            return f'Invalid environment variable name: {k}'
    sf = p.get('startup_file') or ''
    if '\n' in sf or '..' in sf.split('/'):
        return 'Invalid startup file'
    return None


def _port_owner(port, pid=None):
    port = str(port or '').strip()
    if not port: return None
    for x in load_projects():
        if x.get('id') != pid and str(x.get('port') or '') == port:
            return f'Node.js project "{x.get("name")}"'
    try:
        for x in json.load(open('/opt/vortexpanel/go_projects.json')):
            if str(x.get('port') or '') == port:
                return f'Go project "{x.get("name")}"'
    except Exception:
        pass
    return None


nodejs_bp = Blueprint('nodejs', __name__)
PROJECTS_FILE = '/opt/vortexpanel/nodejs_projects.json'
# nvm lives outside /root: /root is 0700 (0550 on RHEL), so a node binary
# under /root/.nvm could never be executed by a unit running as
# www-data/nginx (status=203/EXEC). An existing /root/.nvm is left untouched
# and keeps working for root/PM2 until the first version is installed here;
# units for other users get their legacy node version copied over
# (_node_for_user), never moved.
NVM_DIR        = '/opt/vortexpanel/nvm'
NVM_SH         = os.path.join(NVM_DIR, 'nvm.sh')
LEGACY_NVM_DIR = '/root/.nvm'
NVM_INSTALL_URL = 'https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh'


def req(): return 'user' in session


def _nvm_versions(d):
    return sorted(os.path.basename(p) for p in glob.glob(os.path.join(d, 'versions', 'node', 'v*')) if os.path.isdir(p))


def _nvm_run_dir():
    """nvm installation commands run against: the panel's own dir once it
    holds a node version (or when there is no legacy one), else /root/.nvm."""
    new_ok = os.path.exists(NVM_SH)
    legacy_ok = os.path.exists(os.path.join(LEGACY_NVM_DIR, 'nvm.sh'))
    if new_ok and (_nvm_versions(NVM_DIR) or not legacy_ok):
        return NVM_DIR
    if legacy_ok:
        return LEGACY_NVM_DIR
    return None


def _nvm_prefix(d):
    q = shlex.quote(d)
    return f'export NVM_DIR={q}; . {q}/nvm.sh >/dev/null 2>&1; '


def sh(cmd, timeout=60, nvm=False, nvm_dir=None):
    if nvm:
        d = nvm_dir or _nvm_run_dir()
        if d and os.path.exists(os.path.join(d, 'nvm.sh')):
            cmd = _nvm_prefix(d) + cmd
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, executable='/bin/bash')
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return '', str(e), 1


def _nvm_fix_perms():
    """NVM_DIR world-readable/executable, and /opt/vortexpanel traversable
    (o+x only: no listing; the secrets in it are 0600 files)."""
    try:
        os.chmod(NVM_DIR, 0o755)
        st = os.stat('/opt/vortexpanel').st_mode
        if not st & 0o001:
            os.chmod('/opt/vortexpanel', (st & 0o7777) | 0o001)
    except OSError:
        pass


def _ensure_nvm():
    """nvm in NVM_DIR. Bootstrapped from /root/.nvm's own scripts when that
    exists (no download), else with the official installer. Returns (ok, error)."""
    if os.path.exists(NVM_SH):
        _nvm_fix_perms()
        return True, ''
    os.makedirs(NVM_DIR, exist_ok=True)
    legacy_sh = os.path.join(LEGACY_NVM_DIR, 'nvm.sh')
    if os.path.exists(legacy_sh):
        try:
            for f in ('nvm.sh', 'nvm-exec', 'bash_completion'):
                src = os.path.join(LEGACY_NVM_DIR, f)
                if os.path.exists(src):
                    shutil.copy2(src, os.path.join(NVM_DIR, f))
        except OSError as e:
            return False, f'Could not copy nvm from {LEGACY_NVM_DIR}: {e}'
    else:
        out, err, rc = sh(f'curl -fsSL --max-time 120 {NVM_INSTALL_URL} | '
                          f'NVM_DIR={shlex.quote(NVM_DIR)} PROFILE=/dev/null bash 2>&1', timeout=300)
        if rc != 0 or not os.path.exists(NVM_SH):
            return False, 'Installing nvm failed: ' + (out or err)[-400:]
    _nvm_fix_perms()
    return True, ''


def _node_for_user(node_bin, user):
    """A node binary `user` can execute. A version under /root/.nvm is
    copied (not moved) to NVM_DIR for non-root users."""
    if not node_bin or user == 'root':
        return node_bin
    pat = r'^' + re.escape(LEGACY_NVM_DIR) + r'/versions/node/(v[0-9][0-9.]*)/(bin/[^/]+)$'
    m = re.match(pat, node_bin) or re.match(pat, os.path.realpath(node_bin))
    if not m:
        return node_bin
    src = os.path.join(LEGACY_NVM_DIR, 'versions', 'node', m.group(1))
    dest = os.path.join(NVM_DIR, 'versions', 'node', m.group(1))
    if not os.path.exists(os.path.join(dest, 'bin', 'node')):
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copytree(src, dest, symlinks=True)
        except (OSError, shutil.Error):
            return node_bin
    _nvm_fix_perms()
    return os.path.join(dest, m.group(2))


def os_family():
    """Return 'debian' or 'rhel' based on current OS."""
    if os.path.exists('/etc/debian_version'):
        return 'debian'
    if os.path.exists('/etc/redhat-release') or os.path.exists('/etc/fedora-release'):
        return 'rhel'
    return 'debian' if shutil.which('apt-get') else 'rhel'

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
        # "inactive" (stopped or unknown unit) contains "active": compare words.
        if 'active' in out.split():
            return name
    return None

def write_proxy_conf(p):
    domain = (p.get('domain') or '').strip()
    port   = str(p.get('port') or '').strip()
    pid    = p['id']
    if not domain or not port:
        return False, 'Domain and port are required for proxy setup'
    if not _valid_domains(domain) or not _valid_port(port):
        return False, 'Invalid domain or port'

    ws = detect_active_webserver()
    if not ws:
        return False, 'No active webserver found. Install nginx, Apache, OLS, or Caddy first.'

    primary = domain.splitlines()[0].strip().split(':')[0]
    all_d   = ' '.join(d.strip().split(':')[0] for d in domain.splitlines() if d.strip())

    # Remove old configs from any previous webserver before writing new one
    remove_proxy_conf(pid)

    if ws == 'nginx':
        conf = f"""server {{
    listen 80;{_v6_listen()}
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
        os.makedirs('/etc/nginx/conf.d', exist_ok=True)
        with open(conf_path, 'w') as f: f.write(conf)
        out, err, rc = sh('nginx -t 2>&1')
        if rc != 0:
            try: os.remove(conf_path)
            except OSError: pass
            return False, f'nginx config test failed: {err or out}'
        sh('systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null')
        _selinux_proxy()

    elif ws == 'apache2':
        apache_enable_modules()
        _selinux_proxy()
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
        line = line.strip().lstrip('-*>').strip()   # current version is shown as "->  v22.11.0"
        m = re.match(r'v?(\d+\.\d+\.\d+)', line)
        if m:
            ver = 'v' + m.group(1)
            if any(i['version'] == ver for i in installed): continue
            installed.append({'version': ver,
                               'active': ver == current or ('v'+m.group(1)) == current})

    # versions still only in the old /root/.nvm (usable by root / PM2;
    # copied to the panel's nvm when a unit for another user needs them)
    if _nvm_run_dir() != LEGACY_NVM_DIR:
        for ver in _nvm_versions(LEGACY_NVM_DIR):
            if not any(i['version'] == ver for i in installed):
                installed.append({'version': ver, 'active': False, 'legacy': True})

    sys_node, _, _ = sh('node --version 2>/dev/null')
    if sys_node and not any(v['version'] == sys_node for v in installed):
        installed.insert(0, {'version': sys_node, 'active': not current or current in ('none', 'system'), 'system': True})

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
    ver = str((request.get_json() or {}).get('version','')).strip()
    if not re.fullmatch(r'v?\d+(\.\d+){0,2}', ver):
        return jsonify({'ok':False,'error':'Invalid version'})
    ok, nerr = _ensure_nvm()
    if not ok:
        return jsonify({'ok':False,'error':nerr})
    # always into the panel's nvm (readable by the service users)
    out, err, rc = sh(f'nvm install {ver} 2>&1', timeout=600, nvm=True, nvm_dir=NVM_DIR)
    if rc != 0:
        return jsonify({'ok':False,'error': err or out})
    _nvm_fix_perms()
    return jsonify({'ok':True,'output':out})

@nodejs_bp.route('/api/nodejs/versions/use', methods=['POST'])
def nvm_use():
    if not req(): return jsonify({'ok':False}), 401
    ver = str((request.get_json() or {}).get('version','')).strip()
    if not _VER_RE.match(ver):
        return jsonify({'ok':False,'error':'Invalid version'})
    qv = shlex.quote(ver)
    out, err, rc = sh(f'nvm alias default {qv} 2>&1 && nvm use {qv} 2>&1', nvm=True)
    return jsonify({'ok': rc == 0, 'error': '' if rc == 0 else (err or out)})

@nodejs_bp.route('/api/nodejs/versions/uninstall', methods=['POST'])
def nvm_uninstall():
    if not req(): return jsonify({'ok':False}), 401
    ver = str((request.get_json() or {}).get('version','')).strip()
    if not re.fullmatch(r'v?\d+(\.\d+){0,2}', ver):
        return jsonify({'ok':False,'error':'Invalid version'})
    out, err, rc = sh(f'nvm uninstall {ver} 2>&1', nvm=True)
    return jsonify({'ok': rc == 0, 'error': '' if rc == 0 else (err or out)})

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

def _ensure_pm2():
    out, _, rc = sh('command -v pm2 2>/dev/null', nvm=True)
    if rc == 0 and out:
        return True
    sh('npm install -g pm2 2>&1', timeout=300, nvm=True)
    out, _, rc = sh('command -v pm2 2>/dev/null', nvm=True)
    return rc == 0 and bool(out)

def run_pkg_install(path, manager='npm'):
    manager = manager if manager in ('npm','yarn','pnpm') else 'npm'
    if manager in ('yarn','pnpm'):
        sh(f'npm install -g {manager} 2>/dev/null', nvm=True)
    out, err, rc = sh(f'cd {shlex.quote(path)} && {manager} install 2>&1', timeout=600, nvm=True)
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
    user = p.get('user') or _default_svc_user()
    node_bin = ''
    want = str(p.get('node_version') or '').strip()
    if want and _VER_RE.match(want) and want != 'system':
        node_bin, _, rc = sh(f'nvm which {shlex.quote(want)} 2>/dev/null', nvm=True)
        node_bin = node_bin.strip().splitlines()[-1] if rc == 0 and node_bin.strip() else ''
    if not node_bin or not os.path.exists(node_bin):
        node_bin, _, _ = sh('command -v node 2>/dev/null', nvm=True)
    node_bin = node_bin or shutil.which('node') or '/usr/bin/node'
    node_bin = _node_for_user(node_bin, user)
    node_dir = os.path.dirname(node_bin)
    startup = p.get('startup_file') or 'app.js'
    run_cmd = (p.get('run_cmd') or '').strip()
    if run_cmd:
        # "npm start" / "yarn start": ExecStart needs an absolute binary on
        # older systemd, and nvm's bin dir is never on systemd's PATH.
        first, _, rest = run_cmd.partition(' ')
        if not first.startswith('/'):
            cand = os.path.join(node_dir, first)
            if os.path.exists(cand):
                first = cand
            else:
                found, _, _ = sh(f'command -v {shlex.quote(first)} 2>/dev/null', nvm=True)
                first = _node_for_user(found, user) if found else first
        cmd = f'{first} {rest}'.strip()
    else:
        cmd = f'{node_bin} "{startup}"' if ' ' in startup else f'{node_bin} {startup}'
    def _q(v):
        return _unit_val(v).replace('\\', '\\\\').replace('"', '\\"')
    env_str = '\n'.join(f'Environment="{k}={_q(v)}"'
                        for k, v in (p.get('env') or {}).items())
    port_env = f'Environment="PORT={p["port"]}"' if p.get('port') else ''
    # npm scripts call "node" by name: put the chosen node's dir first on PATH.
    path_env = f'Environment="PATH={node_dir}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'
    unit = f"""[Unit]
Description=VortexPanel Node.js: {_unit_val(p['name'])}
After=network.target

[Service]
Type=simple
User={user}
WorkingDirectory={_unit_val(p['path'])}
ExecStart={_unit_val(cmd)}
Restart=always
RestartSec=5
{path_env}
{env_str}
{port_env}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    svc = f'/etc/systemd/system/{svc_name(p["id"])}.service'
    with open(svc, 'w') as f: f.write(unit)
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
    pm2_mode     = bool(d.get('pm2', False))
    port         = str(d.get('port','') or '').strip()
    user, uerr   = _resolve_user(d.get('user'))
    node_ver     = d.get('node_version','')
    domain       = d.get('domain','').strip()
    startup_file = d.get('startup_file','').strip()
    run_cmd      = d.get('run_cmd','').strip()
    run_opt      = d.get('run_opt','').strip()
    pkg_mgr      = d.get('package_manager','npm')
    clusters     = _int(d.get('clusters', 1), 1, 1, 256)
    mem_limit    = _int(d.get('memory_limit', 1024), 1024, 16, 1048576)
    auto_restart = d.get('auto_restart', True)
    env_raw      = d.get('env_vars','').strip()
    remark       = d.get('remark','').strip()
    no_pkg_install = d.get('no_pkg_install', False)

    if not name or not path:
        return jsonify({'ok':False,'error':'Name and path are required'})
    if uerr:
        return jsonify({'ok':False,'error':uerr})
    if not path.startswith('/') or '\n' in path:
        return jsonify({'ok':False,'error':'Path must be absolute'})
    if not os.path.isdir(path):
        return jsonify({'ok':False,'error':f'Directory not found: {path}'})

    pid = re.sub(r'[^a-zA-Z0-9_-]','',name.lower().replace(' ','-'))
    if not pid:
        return jsonify({'ok':False,'error':'Project name must contain letters or digits'})
    projects = load_projects()
    if any(p['id']==pid for p in projects):
        return jsonify({'ok':False,'error':f'Project "{pid}" already exists'})

    env = {}
    for line in env_raw.splitlines():
        if '=' in line:
            k, _, v = line.partition('=')
            if k.strip(): env[k.strip()] = v.strip()

    verr = _validate_fields({'port': port, 'domain': domain, 'env': env, 'startup_file': startup_file})
    if verr:
        return jsonify({'ok':False,'error':verr})
    clash = _port_owner(port, pid)
    if clash:
        return jsonify({'ok':False,'error':f'Port {port} is already used by {clash}'})

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

    if pm2_mode and not _ensure_pm2():
        return jsonify({'ok':False,'error':'PM2 is not installed and could not be installed with npm (install Node.js first)'})

    if pm2_mode:
        entry        = startup_file or 'app.js'
        cluster_flag = f'-i {clusters}' if clusters > 1 else ''
        mem_flag     = f'--max-memory-restart {mem_limit}M'
        restart_flag = '--restart-delay=5000' if auto_restart else '--no-autorestart'
        env_prefix = ' '.join(f'{k}={shlex.quote(str(v))}' for k, v in env.items())
        if port: env_prefix = f'PORT={port} {env_prefix}'
        out, err, rc = sh(
            f'cd {shlex.quote(path)} && {env_prefix} pm2 start {shlex.quote(os.path.join(path, entry))} --name {pid} '
            f'{cluster_flag} {mem_flag} {restart_flag} --no-color 2>&1',
            timeout=60, nvm=True
        )
        if rc != 0:
            return jsonify({'ok':False,'error':f'PM2 start failed: {err or out}'})
        pm2_cmd('save')
    else:
        write_systemd_node(p)
        sh(f'systemctl enable {svc_name(pid)} 2>/dev/null')
        sh(f'systemctl start {svc_name(pid)} 2>/dev/null')
    p['user'] = user

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
        out, err, rc = pm2_cmd(f'{action} {pid}')
        status = pm2_status(pid)['status']
        want = 'stopped' if action == 'stop' else 'online'
    else:
        out, err, rc = sh(f'systemctl {action} {svc_name(pid)} 2>&1')
        st, _, _ = sh(f'systemctl is-active {svc_name(pid)} 2>/dev/null')
        status = st.strip()
        want = 'inactive' if action == 'stop' else 'active'
    if rc != 0 or status != want:
        return jsonify({'ok':False,'status':status,'error':(out or err or f'Process is {status}')[-500:]})
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
    old = projects[idx]
    p = dict(old)
    for field in ('port','domain','remark','clusters','memory_limit','auto_restart','run_cmd','startup_file','env'):
        if field in d: p[field] = d[field]
    p['port'] = str(p.get('port') or '').strip()
    p['domain'] = (p.get('domain') or '').strip()
    verr = _validate_fields(p)
    if verr: return jsonify({'ok':False,'error':verr})
    clash = _port_owner(p['port'], pid)
    if clash: return jsonify({'ok':False,'error':f'Port {p["port"]} is already used by {clash}'})
    if not p.get('pm2'):
        write_systemd_node(p)
        sh(f'systemctl restart {svc_name(pid)} 2>/dev/null')
    warning = None
    if p.get('domain'):
        ok, result = write_proxy_conf(p)
        if not ok: warning = result
    elif old.get('domain'):
        remove_proxy_conf(pid)
    projects[idx] = p
    save_projects(projects)
    return jsonify({'ok':True, 'proxy_warning': warning})

@nodejs_bp.route('/api/nodejs/projects/<pid>/git-pull', methods=['POST'])
def git_pull(pid):
    if not req(): return jsonify({'ok':False}), 401
    projects = load_projects()
    p = next((x for x in projects if x['id']==pid), None)
    if not p: return jsonify({'ok':False,'error':'Not found'})
    out, err, rc = sh(f'cd {shlex.quote(p["path"])} && git pull 2>&1', timeout=120)
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
