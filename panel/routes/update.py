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
VERSION_FILE  = '/opt/vortexpanel/version.txt'
INSTALL_DIR   = '/opt/vortexpanel'
REPO_DIR      = '/root/Vortexpanel'
CURRENT_VERSION = 'v3.4.1'  # last-resort only, used solely if nothing below is readable


def get_current_version():
    # 1. Check explicit version file written after a successful in-panel update
    if os.path.exists(VERSION_FILE):
        v = open(VERSION_FILE).read().strip()
        if v and v.startswith('v'): return v
    # 2. Fall back to the repo's own VERSION file (/root/Vortexpanel/VERSION) --
    #    this is the file git pull actually keeps current, unlike
    #    /opt/vortexpanel/VERSION which nothing in the update process ever
    #    writes (only panel/, web/, app.py get copied to INSTALL_DIR), so that
    #    old check #2 here was silently dead code checking a file that could
    #    never exist. Reading the repo source directly means this self-updates
    #    on every git pull without needing a second hand-maintained constant.
    vf = os.path.join(REPO_DIR, 'VERSION')
    if os.path.exists(vf):
        v = open(vf).read().strip()
        if v: return 'v' + v.lstrip('v')
    # 3. Absolute last resort — hardcoded constant, only reached if the repo
    #    checkout itself is somehow missing its VERSION file entirely.
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

    def semver_key(v):
        try: return [int(x) for x in v.lstrip('v').split('.')]
        except Exception: return [0]

    # --- PRIMARY signal: raw VERSION file straight off the main branch ---------
    # Served via raw.githubusercontent.com (GitHub's Fastly-backed CDN), which
    # is a COMPLETELY SEPARATE infrastructure from api.github.com — it is not
    # subject to the unauthenticated API's 60-requests/hour-per-IP limit, and
    # it needs neither a pushed git tag NOR a manually-created GitHub Release
    # to reflect what's actually on main. This is what makes the check robust:
    # even if a release was never tagged, or the API is rate-limited, this
    # still tells the truth about whether main has moved ahead of `current`.
    raw_latest = None
    try:
        raw_url = f'https://raw.githubusercontent.com/{GITHUB_REPO}/main/VERSION'
        raw_req = urllib.request.Request(raw_url)
        raw_req.add_header('User-Agent', 'VortexPanel/3.0')
        with urllib.request.urlopen(raw_req, timeout=8) as resp:
            raw_latest = 'v' + resp.read().decode().strip().lstrip('v')
    except Exception:
        pass  # fall through to the tags-API path below

    # --- SECONDARY: git tags + optional Release metadata (cosmetic only) -------
    # Only used to (a) confirm/replace the raw check if it failed, and (b) try
    # to attach a human-readable changelog for the modal. Never load-bearing
    # for has_update on its own — if this whole block fails, we still trust
    # whatever raw_latest already told us.
    tag_latest, name, body, published, html_url = None, None, '', '', base['url']
    try:
        url  = f'https://api.github.com/repos/{GITHUB_REPO}/tags'
        req2 = urllib.request.Request(url)
        req2.add_header('Accept', 'application/vnd.github+json')
        req2.add_header('User-Agent', 'VortexPanel/3.0')
        req2.add_header('X-GitHub-Api-Version', '2022-11-28')
        with urllib.request.urlopen(req2, timeout=10) as resp:
            tags = json.loads(resp.read().decode())
        tag_names = [t.get('name', '') for t in tags if t.get('name', '').lstrip('v').replace('.', '').isdigit()]
        if tag_names:
            tag_latest = max(tag_names, key=semver_key)
            try:
                rel_url = f'https://api.github.com/repos/{GITHUB_REPO}/releases/tags/{tag_latest}'
                rel_req = urllib.request.Request(rel_url)
                rel_req.add_header('Accept', 'application/vnd.github+json')
                rel_req.add_header('User-Agent', 'VortexPanel/3.0')
                with urllib.request.urlopen(rel_req, timeout=8) as resp:
                    rel_data = json.loads(resp.read().decode())
                    name      = rel_data.get('name') or tag_latest
                    body      = rel_data.get('body') or ''
                    published = rel_data.get('published_at') or ''
                    html_url  = rel_data.get('html_url') or html_url
            except Exception:
                pass  # no Release object for this tag — fine
    except Exception:
        pass  # tags API unreachable/rate-limited — fine, raw_latest may still be valid

    # --- Reconcile: prefer whichever source actually succeeded, take the
    # numerically-higher version if both did (main can be ahead of the last tag) ---
    candidates = [v for v in (raw_latest, tag_latest) if v]
    if not candidates:
        return jsonify({**base, 'error': 'Could not reach GitHub (raw file and API both failed)'})

    latest = max(candidates, key=semver_key)
    has_update = compare_versions(current, latest)
    return jsonify({
        'ok': True, 'checked': True,
        'current': current, 'latest': latest,
        'name': name or latest, 'body': body, 'published': published,
        'url': html_url,
        'has_update': has_update,
    })



@update_bp.route('/api/update/start', methods=['POST'])
def start_update():
    from panel.routes.job_state import save_job, load_job
    if not req(): return jsonify({'ok': False}), 401
    existing = load_job('panel_update', {'running': False})
    if existing.get('running'):
        return jsonify({'ok': False, 'error': 'Update already in progress'}), 400

    d      = request.get_json() or {}
    target = (d.get('version', '') or '').strip()  # tag name like v3.1.0
    # `target` is interpolated into `git checkout {target}` (shell=True) below.
    # Constrain it to the shape of a real version tag so it can never carry
    # shell metacharacters (`;`, `|`, `$(...)`, backticks, spaces, …). Anything
    # else is rejected outright rather than escaped.
    import re as _re
    if target and not _re.fullmatch(r'v?\d+(\.\d+){0,3}', target):
        return jsonify({'ok': False, 'error': 'Invalid version tag'}), 400

    save_job('panel_update', {'running': True, 'lines': [], 'done': False, 'success': False, 'error': ''})

    def run_update():
        lines = []

        def log(msg):
            lines.append(msg)
            state = load_job('panel_update', {'running': True, 'lines': [], 'done': False, 'success': False, 'error': ''})
            state['lines'] = lines
            save_job('panel_update', state)

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
                _, cerr, crc = sh(f'cd {REPO_DIR} && git checkout {target} 2>&1')
                if crc != 0:
                    # Not fatal — the reset above already put us on latest main,
                    # this just means no formal tag exists yet for this version
                    # (e.g. detected via the raw VERSION file ahead of tagging).
                    log(f'ℹ No tag "{target}" on GitHub yet — already on latest main branch, continuing')
                else:
                    # Re-attach main to this exact commit rather than leaving
                    # HEAD detached. A tag checkout on its own detaches HEAD --
                    # confirmed as the real cause of a live incident where a
                    # user's own SSH git push afterward failed with "you are
                    # not currently on a branch", silently leaving their next
                    # commit unreachable from any branch. This keeps the
                    # benefit of pinning to a specific tagged version while
                    # never leaving the server's checkout in a state that
                    # breaks the normal git workflow for anyone using SSH
                    # alongside the in-panel updater.
                    sh(f'cd {REPO_DIR} && git checkout -B main {target} 2>&1')
                    log(f'✓ Checked out {target}')

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

            # 6. Restart service -- mark the job as successfully done BEFORE
            # triggering this, not after. systemctl restart can terminate
            # this very worker process shortly after being issued, and code
            # placed after it is racy to depend on -- confirmed as the same
            # root cause behind a live bug report on a related job (the
            # Security Updates apply button), except here it's guaranteed
            # to happen on every single successful update, not just
            # occasionally depending on gunicorn's worker routing.
            log('')
            log('✅ VortexPanel updated successfully!')
            log(f'   New version: {target or "latest"}')
            log('   Reload this page to see the latest version.')
            log('🔄 Restarting VortexPanel service...')
            save_job('panel_update', {'running': False, 'lines': lines, 'done': True, 'success': True, 'error': ''})

            _, _, rc = sh('systemctl restart vortexpanel 2>&1')
            # Anything below this line is best-effort only -- this process
            # may already be mid-termination by the time it runs.
            if rc == 0:
                log('✓ VortexPanel service restarted successfully')
            else:
                sh('pkill -f "python.*app.py" 2>/dev/null || true')
                log('✓ Process restarted')

        except Exception as e:
            log(f'✗ Update failed: {str(e)}')
            save_job('panel_update', {'running': False, 'lines': lines, 'done': True, 'success': False, 'error': str(e)})

    threading.Thread(target=run_update, daemon=True).start()
    return jsonify({'ok': True})

@update_bp.route('/api/update/status')
def update_status():
    from panel.routes.job_state import load_job
    if not req(): return jsonify({'ok': False}), 401
    state = load_job('panel_update', {'running': False, 'lines': [], 'done': False, 'success': False, 'error': ''})
    return jsonify({'ok': True, **state})

@update_bp.route('/api/update/version')
def current_version():
    if not req(): return jsonify({'ok': False}), 401
    return jsonify({'ok': True, 'version': get_current_version()})
