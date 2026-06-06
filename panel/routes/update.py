from flask import Blueprint, jsonify, request, session, Response
import subprocess, os, json, threading, time, urllib.request, urllib.error

update_bp = Blueprint('update', __name__)
def req(): return 'user' in session

GITHUB_REPO   = 'BrowserlessAPI/Vortexpanel'
CURRENT_VERSION = 'v3.0.0'
VERSION_FILE  = '/opt/vortexpanel/version.txt'
INSTALL_DIR   = '/opt/vortexpanel'
REPO_DIR      = '/root/Vortexpanel'

_update_job = {'running': False, 'lines': [], 'done': False, 'success': False, 'error': ''}

def get_current_version():
    if os.path.exists(VERSION_FILE):
        v = open(VERSION_FILE).read().strip()
        if v: return v
    # Also check git tag
    try:
        import subprocess
        result = subprocess.run('cd /root/Vortexpanel && git describe --tags --abbrev=0 2>/dev/null || git log --oneline -1 2>/dev/null | cut -c1-7', 
                               shell=True, capture_output=True, text=True, timeout=5)
        tag = result.stdout.strip()
        if tag: return tag
    except: pass
    return CURRENT_VERSION

def save_current_version(version):
    os.makedirs(os.path.dirname(VERSION_FILE), exist_ok=True)
    with open(VERSION_FILE, 'w') as f:
        f.write(version)

def sh(cmd, t=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return '', 'Timeout', 1
    except Exception as e:
        return '', str(e), 1

def compare_versions(current, latest):
    """Returns True if latest > current"""
    try:
        def parse(v):
            return [int(x) for x in v.lstrip('v').split('.')]
        return parse(latest) > parse(current)
    except:
        return current != latest

@update_bp.route('/api/update/check')
def check_update():
    if not req(): return jsonify({'ok': False}), 401
    current = get_current_version()

    # Always return a valid response — never fail completely
    base = {
        'ok': True, 'current': current, 'latest': current,
        'name': 'VortexPanel', 'body': '', 'published': '',
        'url': 'https://github.com/'+GITHUB_REPO+'/releases',
        'has_update': False,
    }

    try:
        url  = f'https://api.github.com/repos/{GITHUB_REPO}/releases/latest'
        req2 = urllib.request.Request(url)
        req2.add_header('Accept', 'application/vnd.github+json')
        req2.add_header('User-Agent', 'VortexPanel/3.0')
        req2.add_header('X-GitHub-Api-Version', '2022-11-28')

        try:
            with urllib.request.urlopen(req2, timeout=10) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # No releases published yet — totally normal for new repos
                return jsonify({**base, 'note': 'No releases on GitHub yet. Panel is up to date.'})
            raise

        latest_tag = data.get('tag_name', '').strip()
        if not latest_tag:
            return jsonify({**base, 'note': 'No release tags found.'})

        has_update = compare_versions(current, latest_tag)
        return jsonify({
            'ok':         True,
            'current':    current,
            'latest':     latest_tag,
            'name':       data.get('name', latest_tag),
            'body':       data.get('body', ''),
            'published':  data.get('published_at', ''),
            'url':        data.get('html_url', base['url']),
            'has_update': has_update,
        })

    except urllib.error.URLError as e:
        reason = str(getattr(e, 'reason', e))
        return jsonify({**base, 'error': f'Cannot reach GitHub: {reason}'})
    except Exception as e:
        return jsonify({**base, 'error': str(e)})

@update_bp.route('/api/update/start', methods=['POST'])
def start_update():
    if not req(): return jsonify({'ok': False}), 401
    global _update_job
    if _update_job['running']:
        return jsonify({'ok': False, 'error': 'Update already in progress'}), 400

    d      = request.get_json() or {}
    target = d.get('version', '')  # tag name like v3.1.0

    _update_job = {'running': True, 'lines': [], 'done': False, 'success': False, 'error': ''}

    def run_update():
        global _update_job

        def log(msg):
            _update_job['lines'].append(msg)

        try:
            log('🔍 Checking system prerequisites...')

            # 1. Ensure git is installed
            _, _, rc = sh('which git 2>/dev/null', t=5)
            if rc != 0:
                log('📦 Installing git...')
                sh('apt-get install -y git 2>&1')

            # 2. Clone or pull repo
            if os.path.isdir(os.path.join(REPO_DIR, '.git')):
                log(f'📥 Fetching latest code from GitHub...')
                out, err, rc = sh(f'cd {REPO_DIR} && git fetch --all && git reset --hard origin/main 2>&1')
                log(out or err)
            else:
                log(f'📥 Cloning repository...')
                sh(f'rm -rf {REPO_DIR}')
                out, err, rc = sh(f'git clone https://github.com/{GITHUB_REPO}.git {REPO_DIR} 2>&1')
                log(out or err)
                if rc != 0:
                    raise Exception(f'Git clone failed: {err}')

            if target:
                log(f'🏷 Checking out version {target}...')
                sh(f'cd {REPO_DIR} && git checkout {target} 2>&1')

            # 3. Copy new files
            log('📋 Copying updated files to installation directory...')
            os.makedirs(INSTALL_DIR, exist_ok=True)
            for folder in ['panel', 'web']:
                src = os.path.join(REPO_DIR, folder)
                if os.path.isdir(src):
                    out, err, rc = sh(f'cp -r {src} {INSTALL_DIR}/')
                    if rc != 0:
                        log(f'⚠ Warning copying {folder}: {err}')
                    else:
                        log(f'✓ Updated {folder}/')

            # Copy app.py and other root files
            for f in ['app.py', 'requirements.txt', 'install.sh']:
                src = os.path.join(REPO_DIR, f)
                if os.path.exists(src):
                    sh(f'cp {src} {INSTALL_DIR}/')
                    log(f'✓ Updated {f}')

            # 4. Install any new Python dependencies
            req_file = os.path.join(INSTALL_DIR, 'requirements.txt')
            if os.path.exists(req_file):
                log('📦 Installing Python dependencies...')
                out, err, _ = sh(f'pip3 install -r {req_file} --quiet 2>&1', t=120)
                if out: log(out[-500:])

            # 5. Save new version
            if target:
                save_current_version(target)
                log(f'✓ Version updated to {target}')

            # 6. Restart service
            log('🔄 Restarting VortexPanel service...')
            _, _, rc = sh('systemctl restart vortexpanel 2>&1')
            if rc == 0:
                log('✓ VortexPanel service restarted successfully')
            else:
                # Try alternative restart methods
                sh('pkill -f "python.*app.py" 2>/dev/null || true')
                log('✓ Process restarted')

            log('')
            log('✅ VortexPanel updated successfully!')
            log(f'   New version: {target or "latest"}')
            log('   Reload this page to see the latest version.')
            _update_job.update({'running': False, 'done': True, 'success': True})

        except Exception as e:
            log(f'✗ Update failed: {str(e)}')
            _update_job.update({'running': False, 'done': True, 'success': False, 'error': str(e)})

    threading.Thread(target=run_update, daemon=True).start()
    return jsonify({'ok': True})

@update_bp.route('/api/update/status')
def update_status():
    if not req(): return jsonify({'ok': False}), 401
    return jsonify({'ok': True, **_update_job})

@update_bp.route('/api/update/version')
def current_version():
    if not req(): return jsonify({'ok': False}), 401
    return jsonify({'ok': True, 'version': get_current_version()})
