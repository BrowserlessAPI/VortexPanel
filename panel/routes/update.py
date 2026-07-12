from flask import Blueprint, jsonify, request, session, Response
import subprocess, os, json, threading, time, urllib.request, urllib.error
try:
    from panel.routes.os_utils import get_os, pkg_install, pkg_update, pkg_remove
except ImportError:
    try:
        from os_utils import get_os, pkg_install, pkg_update, pkg_remove
    except ImportError:
        def get_os(): return {'family':'debian','pkg':'apt','id':'ubuntu','codename':'noble'}
        def pkg_install(p, f=''): return f'DEBIAN_FRONTEND=noninteractive apt-get install -y {f} {p}'
        def pkg_update(): return 'apt-get update -qq'
        def pkg_remove(p): return f'apt-get remove -y --purge {p} && apt-get autoremove -y'


update_bp = Blueprint('update', __name__)
def req(): return 'user' in session

GITHUB_REPO   = 'BrowserlessAPI/VortexPanel'
CURRENT_VERSION = 'v3.4.0'
VERSION_FILE  = '/opt/vortexpanel/version.txt'
INSTALL_DIR   = '/opt/vortexpanel'
REPO_DIR      = '/root/Vortexpanel'

_update_job = {'running': False, 'lines': [], 'done': False, 'success': False, 'error': ''}

def get_current_version():
    # 1. Check explicit version file written on update
    if os.path.exists(VERSION_FILE):
        v = open(VERSION_FILE).read().strip()
        if v and v.startswith('v'): return v
    # 2. Check VERSION file in install dir
    vf = os.path.join(INSTALL_DIR, 'VERSION')
    if os.path.exists(vf):
        v = open(vf).read().strip()
        if v: return 'v' + v.lstrip('v')
    # 3. Default to hardcoded constant — always valid semver
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

    # Base response used ONLY when we can positively confirm the version (or
    # explicitly could not check) — 'has_update' must never default to a lie.
    # 'checked' distinguishes "confirmed up to date" from "check failed", so
    # the frontend (and a human reading logs) can tell the difference instead
    # of both cases silently collapsing into "nothing shown".
    base = {
        'ok': True, 'current': current, 'latest': current,
        'name': 'VortexPanel', 'body': '', 'published': '',
        'url': 'https://github.com/'+GITHUB_REPO+'/releases',
        'has_update': False, 'checked': False,
    }

    try:
        # Compare against git TAGS, not GitHub "Releases" — a Release is a
        # separate object someone has to manually create in the GitHub UI
        # after pushing a tag; requiring that extra manual step is exactly
        # how updates silently stopped reaching users before (a tag was
        # pushed, or should have been, but no Release existed, so the old
        # /releases/latest check 404'd and was — wrongly — treated as
        # "no releases yet, you're up to date").
        url  = f'https://api.github.com/repos/{GITHUB_REPO}/tags'
        req2 = urllib.request.Request(url)
        req2.add_header('Accept', 'application/vnd.github+json')
        req2.add_header('User-Agent', 'VortexPanel/3.0')
        req2.add_header('X-GitHub-Api-Version', '2022-11-28')

        with urllib.request.urlopen(req2, timeout=10) as resp:
            tags = json.loads(resp.read().decode())

        if not tags:
            # Genuinely zero tags exist — this really is "up to date"
            # (nothing to compare against), safe to report as checked.
            return jsonify({**base, 'checked': True, 'note': 'No release tags found on GitHub.'})

        tag_names = [t.get('name', '') for t in tags if t.get('name', '').lstrip('v').replace('.', '').isdigit()]
        if not tag_names:
            return jsonify({**base, 'checked': True, 'note': 'No valid version tags found.'})

        def semver_key(v):
            try: return [int(x) for x in v.lstrip('v').split('.')]
            except Exception: return [0]
        latest_tag = max(tag_names, key=semver_key)

        # Try to enrich with release notes if a matching Release object also
        # exists — purely cosmetic, never required for has_update to work.
        name, body, published, html_url = latest_tag, '', '', base['url']
        try:
            rel_url = f'https://api.github.com/repos/{GITHUB_REPO}/releases/tags/{latest_tag}'
            rel_req = urllib.request.Request(rel_url)
            rel_req.add_header('Accept', 'application/vnd.github+json')
            rel_req.add_header('User-Agent', 'VortexPanel/3.0')
            with urllib.request.urlopen(rel_req, timeout=8) as resp:
                rel_data = json.loads(resp.read().decode())
                name       = rel_data.get('name') or latest_tag
                body       = rel_data.get('body') or ''
                published  = rel_data.get('published_at') or ''
                html_url   = rel_data.get('html_url') or html_url
        except Exception:
            pass  # no Release object for this tag — fine, we still have the tag itself

        has_update = compare_versions(current, latest_tag)
        return jsonify({
            'ok': True, 'checked': True,
            'current': current, 'latest': latest_tag,
            'name': name, 'body': body, 'published': published, 'url': html_url,
            'has_update': has_update,
        })

    except urllib.error.HTTPError as e:
        # Explicit failure — including rate-limiting (403) — must NOT be
        # reported as "up to date". checked:False + error tells the truth.
        return jsonify({**base, 'error': f'GitHub API returned {e.code}: {e.reason}'})
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
