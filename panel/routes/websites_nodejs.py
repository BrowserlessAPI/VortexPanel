import os, re, json, shlex, shutil
from flask import jsonify, request

try:
    from panel.routes.websites_core import (websites_bp, req, sh, get_nginx_dirs, reload_nginx,
        nginx_edit_site, nginx_insert_in_servers, selinux_allow_proxy, valid_site_path, _get_site_path)
except ImportError:
    from websites_core import (websites_bp, req, sh, get_nginx_dirs, reload_nginx,
        nginx_edit_site, nginx_insert_in_servers, selinux_allow_proxy, valid_site_path, _get_site_path)

NODE_BEGIN = '#VP_NODEJS_BEGIN:'
NODE_END = '#VP_NODEJS_END'
NODE_ORIG = '#VP_NODEJS_ORIG '


def _node_enable(content, port):
    """Comment out the site's `location /` and PHP location (kept verbatim,
    prefixed with NODE_ORIG, so disabling restores them exactly) and add a
    proxy location in every server block. The old code deleted them for good,
    and Disable only removed the marker comment: the site stayed proxied to a
    stopped app (502) and its PHP handling was lost."""
    content = _node_disable(content)
    def comment(m):
        return '\n'.join(NODE_ORIG + l for l in m.group(0).split('\n'))
    content = re.sub(r'location\s+/\s*\{[^{}]*\}', comment, content)
    content = re.sub(r'location\s+~\s+\\\.php\$\s*\{[^{}]*\}', comment, content)
    block = (f'    {NODE_BEGIN}{port}\n'
             f'    location / {{\n'
             f'        proxy_pass http://127.0.0.1:{port};\n'
             f'        proxy_http_version 1.1;\n'
             f'        proxy_set_header Upgrade $http_upgrade;\n'
             f"        proxy_set_header Connection 'upgrade';\n"
             f'        proxy_set_header Host $host;\n'
             f'        proxy_set_header X-Real-IP $remote_addr;\n'
             f'        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n'
             f'        proxy_set_header X-Forwarded-Proto $scheme;\n'
             f'        proxy_cache_bypass $http_upgrade;\n'
             f'    }}\n'
             f'    {NODE_END}\n')
    return nginx_insert_in_servers(content, block, at='end')


def _node_disable(content):
    content = re.sub(r'\n[ \t]*' + re.escape(NODE_BEGIN) + r'\d+.*?' + re.escape(NODE_END) + r'[^\n]*', '', content, flags=re.S)
    content = content.replace(NODE_ORIG, '')
    # legacy format (no markers): the proxy location followed by #VP_NODEJS:<port>
    if re.search(r'#VP_NODEJS:\d+', content):
        content = re.sub(r'location\s+/\s*\{[^{}]*proxy_pass\s+http://127\.0\.0\.1:\d+;[^{}]*\}\s*#VP_NODEJS:\d+',
                         'location / {\n        try_files $uri $uri/ /index.php?$args;\n    }', content)
        content = re.sub(r'[ \t]*#VP_NODEJS:\d+[^\n]*\n?', '', content)
    return content

# Project metadata + environment variables are stored OUTSIDE the webroot —
# this is strictly more secure than even a hidden .env file inside the site
# directory, since it can never be accidentally served by a misconfigured
# webserver and isn't touched by git pulls/redeploys of the project itself.
NODE_ENV_DIR = '/opt/vortexpanel/node_env'

def _meta_path(domain):
    return os.path.join(NODE_ENV_DIR, f'{domain}.json')

def _ecosystem_path(domain):
    return os.path.join(NODE_ENV_DIR, domain, 'ecosystem.config.js')

def _load_meta(domain):
    p = _meta_path(domain)
    if os.path.exists(p):
        try: return json.load(open(p))
        except Exception: pass
    return {'app_path':'', 'startup':'index.js', 'runtime':'node', 'port':'3000', 'env':{}}

def _save_meta(domain, meta):
    os.makedirs(NODE_ENV_DIR, exist_ok=True)
    with open(_meta_path(domain), 'w') as f:
        json.dump(meta, f, indent=2)
    try: os.chmod(_meta_path(domain), 0o600)
    except Exception: pass

def _interpreter_for(runtime):
    return {'python': 'python3', 'go': 'none', 'node': 'node'}.get(runtime, 'node')

def _write_ecosystem(domain, meta):
    """
    Generate a PM2 ecosystem.config.js that injects env vars directly into
    the process at runtime — the app never needs to read a .env file from
    disk at all. File lives outside the webroot (NODE_ENV_DIR), so the
    secrets it contains are never reachable over HTTP regardless of
    webserver misconfiguration.
    """
    eco_dir = os.path.join(NODE_ENV_DIR, domain)
    os.makedirs(eco_dir, exist_ok=True)

    pm2_name   = domain.replace('.', '_')
    runtime    = meta.get('runtime', 'node')
    interpreter = _interpreter_for(runtime)
    script     = './vp_app' if runtime == 'go' else meta.get('startup', 'index.js')

    # Auto-inject PORT from the panel's configured port so the app's actual
    # listening port can never silently drift from what nginx proxies to —
    # this is the #1 cause of "works on first deploy, 502s after a restart"
    # bugs in hand-rolled Node.js hosting setups. User-set PORT in their own
    # variables still wins if they explicitly added one.
    env = {'PORT': str(meta.get('port', '3000'))}
    env.update(meta.get('env', {}))
    env_block  = json.dumps(env, indent=6)

    interpreter_line = '' if interpreter == 'none' else f"      interpreter: '{interpreter}',\n"

    content = f"""// Auto-generated by VortexPanel — do not edit manually.
// Environment variables are managed from the panel's "Environment
// Variables" tab and injected here, never read from a .env file.
module.exports = {{
  apps: [{{
      name: {json.dumps(pm2_name)},
      script: {json.dumps(script)},
      cwd: {json.dumps(meta.get("app_path",""))},
{interpreter_line}      env: {env_block},
      autorestart: true,
      max_restarts: 10,
  }}]
}};
"""
    path = _ecosystem_path(domain)
    with open(path, 'w') as f:
        f.write(content)
    try: os.chmod(path, 0o600)
    except Exception: pass
    return path


@websites_bp.route('/api/websites/<domain>/nodejs', methods=['POST'])
def setup_nodejs(domain):
    if not req(): return jsonify({'ok':False}), 401
    d        = request.get_json() or {}
    port     = str(d.get('port', '3000')).strip()
    app_path = str(d.get('app_path') or _get_site_path(domain)).strip().rstrip('/')
    startup  = str(d.get('startup') or 'index.js').strip()
    enable   = d.get('enable', True)
    runtime  = d.get('runtime', 'node')

    fp = os.path.join('/etc/nginx/vortex', f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site not found'}), 404

    pm2_name = domain.replace('.', '_')

    if enable:
        # every value below ends up in a shell command, the nginx vhost or the
        # generated ecosystem.config.js
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            return jsonify({'ok':False,'error':'Port must be a number between 1 and 65535'}), 400
        perr = valid_site_path(app_path)
        if perr or not os.path.isdir(app_path):
            return jsonify({'ok':False,'error':perr or f'App directory {app_path} does not exist'}), 400
        if runtime not in ('node', 'python', 'go'):
            return jsonify({'ok':False,'error':'Unknown runtime'}), 400
        if not re.fullmatch(r'[A-Za-z0-9_./-]{1,200}', startup) or '..' in startup.split('/'):
            return jsonify({'ok':False,'error':'Invalid startup file'}), 400
        if runtime == 'go' and not shutil.which('go'):
            return jsonify({'ok':False,'error':'Go is not installed on this server. Install it via Terminal (e.g. apt-get install golang-go) or App Store, then try again.'}), 400
        if not shutil.which('pm2'):
            sh('npm install -g pm2 2>/dev/null', t=180)
            if not shutil.which('pm2'):
                return jsonify({'ok':False,'error':'PM2 is not installed and could not be installed with npm (install Node.js first)'}), 400

        ok, err, code = nginx_edit_site(domain, lambda c: _node_enable(c, port))
        if not ok:
            return jsonify({'ok':False,'error':err}), code
        selinux_allow_proxy()

        # Install dependencies / build, as before
        qp = shlex.quote(app_path)
        if runtime == 'python':
            if os.path.exists(os.path.join(app_path,'requirements.txt')):
                sh(f'cd {qp} && (pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt 2>/dev/null)', t=300)
        elif runtime == 'go':
            sh(f'cd {qp} && go build -o vp_app . 2>&1', t=300)
        else:
            if os.path.exists(os.path.join(app_path,'package.json')) and not os.path.isdir(os.path.join(app_path,'node_modules')):
                sh(f'cd {qp} && npm install 2>/dev/null', t=300)

        # Persist project metadata (preserve any existing env vars on re-enable)
        meta = _load_meta(domain)
        meta.update({'app_path':app_path, 'startup':startup, 'runtime':runtime, 'port':port})
        meta.setdefault('env', {})
        _save_meta(domain, meta)

        # Start via ecosystem.config.js — this is what actually injects env vars
        eco_path = _write_ecosystem(domain, meta)
        sh(f'pm2 delete {pm2_name} 2>/dev/null')  # clear any old non-ecosystem process
        sh(f'pm2 start {shlex.quote(eco_path)} 2>/dev/null', t=60)
        sh('pm2 save 2>/dev/null')
        return jsonify({'ok':True,'port':port})

    ok, err, code = nginx_edit_site(domain, _node_disable)
    if not ok:
        return jsonify({'ok':False,'error':err}), code
    sh(f'pm2 stop {pm2_name} 2>/dev/null')
    sh('pm2 save 2>/dev/null')
    return jsonify({'ok':True,'port':port})


@websites_bp.route('/api/websites/<domain>/nodejs')
def get_nodejs(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':True,'enabled':False})
    with open(fp) as f: content = f.read()
    m = re.search(r'#VP_NODEJS(?:_BEGIN)?:(\d+)', content)
    meta = _load_meta(domain)
    return jsonify({
        'ok': True, 'enabled': bool(m), 'port': m.group(1) if m else '',
        'runtime': meta.get('runtime','node'), 'app_path': meta.get('app_path',''),
        'startup': meta.get('startup','index.js'),
        'env_count': len(meta.get('env', {})),
    })


# ===============================================================================
# ENVIRONMENT VARIABLES
# ===============================================================================

@websites_bp.route('/api/websites/<domain>/env')
def get_env_vars(domain):
    if not req(): return jsonify({'ok':False}), 401
    meta = _load_meta(domain)
    return jsonify({'ok': True, 'env': meta.get('env', {})})


@websites_bp.route('/api/websites/<domain>/env', methods=['PUT'])
def save_env_vars(domain):
    """
    Replace the full environment variable set, regenerate the PM2
    ecosystem file, and restart the app so the new values take effect
    immediately. Variables persist independently of the project's own
    files — a fresh git pull or redeploy of the app code never touches them.
    """
    if not req(): return jsonify({'ok':False}), 401
    d   = request.get_json() or {}
    env = d.get('env', {})

    if not isinstance(env, dict):
        return jsonify({'ok':False,'error':'env must be a key-value object'}), 400

    # Validate keys: standard env var naming rules
    for key in env.keys():
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', key):
            return jsonify({'ok':False,'error':f'Invalid variable name: "{key}" — use letters, numbers, underscore, must not start with a number'}), 400

    meta = _load_meta(domain)
    if not meta.get('app_path'):
        return jsonify({'ok':False,'error':'No app configured for this site yet — enable App Runner first'}), 400

    meta['env'] = {str(k): str(v) for k, v in env.items()}
    _save_meta(domain, meta)

    # Regenerate ecosystem file and restart so the app picks up new values
    eco_path = _write_ecosystem(domain, meta)
    pm2_name = domain.replace('.', '_')
    sh(f'pm2 delete {pm2_name} 2>/dev/null')
    sh(f'pm2 start {shlex.quote(eco_path)} 2>/dev/null', t=60)
    sh('pm2 save 2>/dev/null')

    return jsonify({'ok': True, 'count': len(meta['env']), 'restarted': True})


@websites_bp.route('/api/websites/<domain>/env/<key>', methods=['DELETE'])
def delete_env_var(domain, key):
    if not req(): return jsonify({'ok':False}), 401
    meta = _load_meta(domain)
    if key in meta.get('env', {}):
        del meta['env'][key]
        _save_meta(domain, meta)
        eco_path = _write_ecosystem(domain, meta)
        pm2_name = domain.replace('.', '_')
        sh(f'pm2 delete {pm2_name} 2>/dev/null; pm2 start {shlex.quote(eco_path)} 2>/dev/null', t=60)
        sh('pm2 save 2>/dev/null')
    return jsonify({'ok': True})


