from flask import Blueprint, jsonify, request
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
def req():
    from panel.routes.auth import check_ip_and_session
    return check_ip_and_session()

GITHUB_REPO   = 'BrowserlessAPI/VortexPanel'
VERSION_FILE  = '/opt/vortexpanel/version.txt'
INSTALL_DIR   = '/opt/vortexpanel'
REPO_DIR      = '/root/Vortexpanel'
CURRENT_VERSION = 'v3.4.1'  # last-resort only, used solely if nothing below is readable


def get_current_version():
    # 1. Check explicit version file written after a successful in-panel update
    if os.path.exists(VERSION_FILE):
        try:
            v = open(VERSION_FILE).read().strip()
            if v and v.startswith('v'): return v
        except Exception:
            pass
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
    with open(VERSION_FILE + '.tmp', 'w') as f:
        f.write(version)
    os.replace(VERSION_FILE + '.tmp', VERSION_FILE)

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



_UPDATE_STALE_AFTER = 20 * 60
BACKUP_ROOT = os.path.join(INSTALL_DIR, 'update_backups')   # same place deploy.sh/rollback.sh use
_CODE_ITEMS = ['panel', 'web', 'app.py', 'requirements.txt', 'install.sh', 'VERSION']

# Runs detached (systemd-run / setsid) so it survives the restart it performs.
# Restarts the panel, waits for it to answer and, if it does not, restores the
# pre-update code snapshot and restarts again, recording the outcome in the
# job file the update modal polls.
_UPDATE_RESTART_HELPER = r"""
import json, os, shutil, ssl, subprocess, sys, time, urllib.request, urllib.error
job_path, backup_dir, install_dir, scheme, port = sys.argv[1:6]
items = sys.argv[6:]
def probe():
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    try:
        return op.open(f'{scheme}://127.0.0.1:{port}/', timeout=3).status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0
def healthy(tries):
    for _ in range(tries):
        time.sleep(1)
        if probe() in (200, 301, 302, 401, 403):
            return True
    return False
def update_job(extra_lines, **kw):
    try:
        st = json.load(open(job_path))
    except Exception:
        st = {'lines': []}
    st['lines'] = (st.get('lines') or []) + extra_lines
    st.update(kw)
    tmp = job_path + '.tmp'
    json.dump(st, open(tmp, 'w')); os.replace(tmp, job_path)
time.sleep(2)
subprocess.run('systemctl restart vortexpanel', shell=True)
if healthy(30):
    update_job(['Panel restarted and is answering on the new version.'])
    sys.exit(0)
log = subprocess.run('journalctl -u vortexpanel -n 20 --no-pager 2>/dev/null', shell=True,
                     capture_output=True, text=True).stdout[-1500:]
for it in items:
    src = os.path.join(backup_dir, it)
    dst = os.path.join(install_dir, it)
    if not os.path.exists(src):
        continue
    if os.path.isdir(dst) and not os.path.islink(dst):
        shutil.rmtree(dst, ignore_errors=True)
    elif os.path.exists(dst):
        os.remove(dst)
    if os.path.isdir(src):
        shutil.copytree(src, dst, symlinks=True)
    else:
        shutil.copy2(src, dst)
vb = os.path.join(backup_dir, 'version.txt')
if os.path.exists(vb):
    shutil.copy2(vb, os.path.join(install_dir, 'version.txt'))
subprocess.run('systemctl restart vortexpanel', shell=True)
back = healthy(30)
update_job(['', 'The panel did not start on the new version - the previous version was restored'
            + (' and is running again.' if back else ' but is NOT answering yet, check: journalctl -u vortexpanel'),
            log], success=False, done=True, running=False,
           error='New version failed to start; rolled back to ' + backup_dir)
"""


def _panel_scheme_port():
    """(scheme, port) the panel currently serves on, read from the unit."""
    try:
        import re as _re
        unit = open('/etc/systemd/system/vortexpanel.service').read()
        m = _re.search(r'(?:--bind|-b)\s+\S+:(\d+)', unit)
        return ('https' if '--certfile' in unit else 'http'), (m.group(1) if m else '8888')
    except Exception:
        return 'http', '8888'


def _venv_pip():
    for p in (os.path.join(INSTALL_DIR, 'venv/bin/pip'), os.path.join(INSTALL_DIR, 'venv/bin/pip3')):
        if os.path.exists(p):
            return p
    import sys as _sys
    return f'{_sys.executable} -m pip'


def _venv_python():
    p = os.path.join(INSTALL_DIR, 'venv/bin/python')
    if os.path.exists(p):
        return p
    import sys as _sys
    return _sys.executable


@update_bp.route('/api/update/start', methods=['POST'])
def start_update():
    from panel.routes.job_state import save_job, load_job
    if not req(): return jsonify({'ok': False}), 401
    existing = load_job('panel_update', {'running': False})
    if existing.get('running') and time.time() - (existing.get('heartbeat') or 0) < _UPDATE_STALE_AFTER:
        return jsonify({'ok': False, 'error': 'Update already in progress'}), 400

    d      = request.get_json(silent=True) or {}
    target = str(d.get('version', '') or '').strip()  # tag name like v3.1.0
    # `target` is interpolated into `git checkout {target}` (shell=True) below.
    # Constrain it to the shape of a real version tag so it can never carry
    # shell metacharacters (`;`, `|`, `$(...)`, backticks, spaces, …). Anything
    # else is rejected outright rather than escaped.
    import re as _re
    if target and not _re.fullmatch(r'v?\d+(\.\d+){0,3}', target):
        return jsonify({'ok': False, 'error': 'Invalid version tag'}), 400

    save_job('panel_update', {'running': True, 'lines': [], 'done': False, 'success': False, 'error': '',
                              'heartbeat': time.time()})

    def run_update():
        lines = []

        def log(msg):
            lines.append(msg)
            save_job('panel_update', {'running': True, 'lines': lines, 'done': False, 'success': False,
                                      'error': '', 'heartbeat': time.time()})

        try:
            log('Checking system prerequisites...')

            # 1. Ensure git is installed (apt-get only used to be tried, so
            #    RHEL-family servers without git could never update).
            _, _, rc = sh('command -v git 2>/dev/null', t=5)
            if rc != 0:
                log('Installing git...')
                out, err, rc = sh(pkg_install('git') + ' 2>&1', t=600)
                if sh('command -v git 2>/dev/null', t=5)[2] != 0:
                    raise Exception('git is not installed and could not be installed: ' + (out or err)[-300:])

            # 2. Clone or fetch the repo
            if os.path.isdir(os.path.join(REPO_DIR, '.git')):
                # /root/Vortexpanel is also the admin's own working copy
                # (deploy.sh, SSH git push). A blind `reset --hard` destroyed
                # uncommitted edits and local commits there.
                dirty, _, _ = sh(f'cd {REPO_DIR} && git status --porcelain --untracked-files=no 2>/dev/null', t=30)
                if dirty:
                    raise Exception(f'{REPO_DIR} has uncommitted changes - commit/stash them over SSH '
                                    f'(or run: git -C {REPO_DIR} stash) and update again')
                log('Fetching latest code from GitHub...')
                out, err, rc = sh(f'cd {REPO_DIR} && git fetch --tags --force origin 2>&1', t=300)
                if rc != 0:
                    raise Exception('git fetch failed: ' + (out or err)[-400:])
                ahead, _, _ = sh(f'cd {REPO_DIR} && git rev-list --count origin/main..HEAD 2>/dev/null', t=30)
                if ahead.strip().isdigit() and int(ahead) > 0:
                    raise Exception(f'{REPO_DIR} has {ahead.strip()} local commit(s) not on origin/main - '
                                    f'push them first; refusing to discard them')
                out, err, rc = sh(f'cd {REPO_DIR} && git checkout -B main origin/main 2>&1 && git reset --hard origin/main 2>&1', t=120)
                if rc != 0:
                    raise Exception('git reset failed: ' + (out or err)[-400:])
                log(out[-300:] or 'Updated to origin/main')
            else:
                log('Cloning repository...')
                sh(f'rm -rf {REPO_DIR}')
                out, err, rc = sh(f'git clone https://github.com/{GITHUB_REPO}.git {REPO_DIR} 2>&1', t=600)
                log(out[-300:] or err[-300:])
                if rc != 0:
                    raise Exception(f'Git clone failed: {(out or err)[-300:]}')

            if target:
                log(f'Checking out version {target}...')
                _, cerr, crc = sh(f'cd {REPO_DIR} && git rev-parse -q --verify "refs/tags/{target}" >/dev/null 2>&1')
                if crc != 0:
                    # No formal tag (version detected via the raw VERSION file
                    # ahead of tagging): stay on the latest main just fetched.
                    log(f'No tag "{target}" on GitHub yet - using the latest main branch')
                else:
                    # Re-attach main to the tag instead of leaving HEAD
                    # detached (breaks a later `git push` over SSH).
                    _, cerr, crc = sh(f'cd {REPO_DIR} && git checkout -B main {target} 2>&1')
                    if crc != 0:
                        raise Exception(f'git checkout {target} failed: {cerr[-300:]}')
                    log(f'OK: checked out {target}')

            if not os.path.exists(os.path.join(REPO_DIR, 'app.py')) or not os.path.isdir(os.path.join(REPO_DIR, 'panel')):
                raise Exception(f'{REPO_DIR} does not look like a VortexPanel checkout (app.py/panel missing)')

            # 3. Python dependencies FIRST, into the panel's venv. This used
            #    the system pip3, which is missing or refuses to install
            #    (PEP 668) on Debian 12+/Ubuntu 23.04+, so a release that added
            #    a dependency restarted into an ImportError with the panel down.
            req_file = os.path.join(REPO_DIR, 'requirements.txt')
            if os.path.exists(req_file):
                log('Installing Python dependencies...')
                out, err, rc = sh(f'{_venv_pip()} install -r {req_file} --quiet --disable-pip-version-check 2>&1', t=900)
                if rc != 0:
                    raise Exception('pip install failed (nothing was changed): ' + (out or err)[-500:])

            # 4. Snapshot the running version (same layout as deploy.sh so
            #    /root/rollback.sh can restore it too).
            stamp = time.strftime('%Y%m%d-%H%M%S')
            backup_dir = os.path.join(BACKUP_ROOT, stamp + '-panel-update')
            os.makedirs(backup_dir, exist_ok=True)
            for it in _CODE_ITEMS + ['version.txt']:
                src = os.path.join(INSTALL_DIR, it)
                if os.path.exists(src):
                    out, err, rc = sh(f'cp -a {src} {backup_dir}/ 2>&1')
                    if rc != 0:
                        raise Exception(f'Could not back up {it}: {(out or err)[-200:]}')
            with open(os.path.join(INSTALL_DIR, '.last_backup'), 'w') as f:
                f.write(backup_dir + '\n')
            sh(f'ls -1dt {BACKUP_ROOT}/*/ 2>/dev/null | tail -n +6 | xargs -r rm -rf')
            log(f'Backed up current version to {backup_dir}')

            # 5. Copy new files. Directories are replaced (not merged), so
            #    modules deleted upstream do not linger. Runtime files
            #    (credentials.json, config.json, data/, secret.key, ...) live
            #    outside these items and are never touched.
            log('Copying updated files to installation directory...')
            for it in _CODE_ITEMS:
                src = os.path.join(REPO_DIR, it)
                if not os.path.exists(src):
                    continue
                dst = os.path.join(INSTALL_DIR, it)
                if os.path.isdir(src):
                    out, err, rc = sh(f'rm -rf {dst}.new && cp -r {src} {dst}.new && rm -rf {dst} && mv {dst}.new {dst} 2>&1')
                else:
                    out, err, rc = sh(f'cp {src} {dst}.new && mv -f {dst}.new {dst} 2>&1')
                if rc != 0:
                    raise Exception(f'Copying {it} failed: {(out or err)[-300:]}')
                log(f'OK: updated {it}')
            sh(f'find {INSTALL_DIR}/panel {INSTALL_DIR}/web -name __pycache__ -prune -exec rm -rf {{}} + 2>/dev/null')

            # 6. Record the deployed version. Always set it: a version.txt left
            #    by an earlier targeted update otherwise pinned the displayed
            #    version (and "update available") forever after an untargeted one.
            new_ver = target
            vf = os.path.join(REPO_DIR, 'VERSION')
            if not new_ver and os.path.exists(vf):
                new_ver = 'v' + open(vf).read().strip().lstrip('v')
            if new_ver:
                save_current_version(new_ver)
                log(f'OK: version set to {new_ver}')

            # 7. Import test before restarting: a syntax/import error in the
            #    new code is caught here and rolled back with no downtime.
            out, err, rc = sh(f'cd {INSTALL_DIR} && {_venv_python()} -c "import app" 2>&1', t=120)
            if rc != 0:
                for it in _CODE_ITEMS + ['version.txt']:
                    src = os.path.join(backup_dir, it)
                    if os.path.exists(src):
                        sh(f'rm -rf {INSTALL_DIR}/{it} && cp -a {src} {INSTALL_DIR}/')
                raise Exception('The new version failed to load, previous version restored: ' + (out or err)[-600:])

            # 8. Restart through a detached helper that verifies the panel
            #    comes back and restores the snapshot if it does not. Mark the
            #    job done BEFORE restarting: the restart kills this worker.
            log('')
            log('VortexPanel updated successfully.')
            log(f'   New version: {new_ver or "latest"}')
            log('   Restarting VortexPanel service - reload this page in a few seconds.')
            log('   If the new version does not start, the previous one is restored automatically.')
            save_job('panel_update', {'running': False, 'lines': lines, 'done': True, 'success': True, 'error': '',
                                      'heartbeat': time.time()})

            from panel.routes.job_state import _job_path
            import shlex
            helper = os.path.join(INSTALL_DIR, 'data', 'panel_update_restart.py')
            os.makedirs(os.path.dirname(helper), exist_ok=True)
            with open(helper, 'w') as f:
                f.write(_UPDATE_RESTART_HELPER)
            scheme, port = _panel_scheme_port()
            args = ' '.join(shlex.quote(a) for a in [_venv_python(), helper, _job_path('panel_update'),
                                                     backup_dir, INSTALL_DIR, scheme, port] + _CODE_ITEMS)
            if sh('command -v systemd-run 2>/dev/null', t=5)[2] == 0:
                sh(f'systemd-run --no-block --collect --unit=vortexpanel-update-{int(time.time())} {args} 2>&1', t=30)
            else:
                sh(f'setsid {args} >/dev/null 2>&1 < /dev/null &', t=30)

        except Exception as e:
            lines.append(f'FAILED: update failed: {str(e)}')
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
