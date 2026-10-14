"""Panel self-update: signed release tags only.

Used by the web updater (Settings > Update) and by `vortexpanel update`.

1. Fetch the tags from GitHub into a bare mirror (/opt/vortexpanel/src.git)
   or, on a developer install, into the existing /root/Vortexpanel clone
   (only remote refs and tags change, never the working tree).
2. Pick the requested tag or the highest vX.Y.Z tag. There is no fallback
   to the main branch: only released code is installed.
3. Verify the tag signature with `git verify-tag` against the signing keys
   shipped in the *installed* version (panel/trust/allowed_signers). An
   unsigned or badly signed tag is refused unless the administrator turned
   on "Allow unsigned updates".
4. Export the tag with `git archive` into a staging directory.
5. Snapshot the running code and the venv package list (pip freeze).
6. Install the new requirements; on failure reinstall the snapshot list.
7. Swap the code, run an import test, restart through a detached helper
   that probes /api/health and rolls everything back if the panel does not
   come up.
"""
import json
import os
import re
import shlex
import shutil
import subprocess
import time

GITHUB_REPO = 'BrowserlessAPI/VortexPanel'
GIT_URL = os.environ.get('VP_UPDATE_GIT_URL') or f'https://github.com/{GITHUB_REPO}.git'
INSTALL_DIR = '/opt/vortexpanel'
DEV_REPO = '/root/Vortexpanel'
MIRROR = os.path.join(INSTALL_DIR, 'src.git')
STAGING = os.path.join(INSTALL_DIR, 'data', 'update_staging')
BACKUP_ROOT = os.path.join(INSTALL_DIR, 'update_backups')
VERSION_FILE = os.path.join(INSTALL_DIR, 'version.txt')
CONFIG_FILE = os.path.join(INSTALL_DIR, 'config.json')
CODE_ITEMS = ['panel', 'web', 'app.py', 'requirements.txt', 'install.sh', 'VERSION']
TAG_RE = re.compile(r'^v\d+\.\d+\.\d+$')


def sh(cmd, t=120, env=None):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t, env=env)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return '', 'Timeout', 1
    except Exception as e:
        return '', str(e), 1


def semver(v):
    try:
        return tuple(int(x) for x in v.lstrip('v').split('.'))
    except Exception:
        return (0,)


def venv_python():
    p = os.path.join(INSTALL_DIR, 'venv/bin/python')
    return p if os.path.exists(p) else 'python3'


def allowed_signers():
    return os.path.join(INSTALL_DIR, 'panel', 'trust', 'allowed_signers')


def allow_unsigned():
    try:
        return bool(json.load(open(CONFIG_FILE)).get('allow_unsigned_updates'))
    except Exception:
        return False


def repo_dir():
    """The git directory updates are fetched into."""
    if os.path.isdir(os.path.join(DEV_REPO, '.git')):
        return DEV_REPO
    return MIRROR


def current_version():
    try:
        v = open(VERSION_FILE).read().strip()
        if TAG_RE.match(v):
            return v
    except Exception:
        pass
    try:
        return 'v' + open(os.path.join(INSTALL_DIR, 'VERSION')).read().strip().lstrip('v')
    except Exception:
        return 'v0.0.0'


def save_version(v):
    with open(VERSION_FILE + '.tmp', 'w') as f:
        f.write(v)
    os.replace(VERSION_FILE + '.tmp', VERSION_FILE)


def remote_tags(timeout=20):
    """Release tags on GitHub, newest first. git ls-remote is not rate
    limited like the REST API; the API is the fallback when git is missing."""
    tags = set()
    out, _, rc = sh(f'git ls-remote --tags --refs {GIT_URL} 2>/dev/null', t=timeout)
    if rc == 0:
        for line in out.splitlines():
            name = line.rsplit('refs/tags/', 1)[-1].strip()
            if TAG_RE.match(name):
                tags.add(name)
    if not tags:
        try:
            import urllib.request
            req = urllib.request.Request(f'https://api.github.com/repos/{GITHUB_REPO}/tags?per_page=100',
                                         headers={'User-Agent': 'VortexPanel',
                                                  'Accept': 'application/vnd.github+json'})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                for t in json.loads(r.read().decode()):
                    if TAG_RE.match(t.get('name', '')):
                        tags.add(t['name'])
        except Exception:
            pass
    return sorted(tags, key=semver, reverse=True)


def release_notes(tag):
    try:
        import urllib.request
        req = urllib.request.Request(f'https://api.github.com/repos/{GITHUB_REPO}/releases/tags/{tag}',
                                     headers={'User-Agent': 'VortexPanel',
                                              'Accept': 'application/vnd.github+json'})
        with urllib.request.urlopen(req, timeout=8) as r:
            d = json.loads(r.read().decode())
            return {'name': d.get('name') or tag, 'body': d.get('body') or '',
                    'published': d.get('published_at') or '', 'url': d.get('html_url') or ''}
    except Exception:
        return {'name': tag, 'body': '', 'published': '',
                'url': f'https://github.com/{GITHUB_REPO}/releases/tag/{tag}'}


def check():
    cur = current_version()
    tags = remote_tags()
    if not tags:
        return {'ok': True, 'checked': False, 'current': cur, 'latest': cur, 'has_update': False,
                'error': 'Could not reach GitHub to list releases'}
    latest = tags[0]
    info = release_notes(latest) if semver(latest) > semver(cur) else {}
    return {'ok': True, 'checked': True, 'current': cur, 'latest': latest,
            'has_update': semver(latest) > semver(cur), 'versions': tags[:10],
            'allow_unsigned': allow_unsigned(),
            'name': info.get('name', latest), 'body': info.get('body', ''),
            'published': info.get('published', ''),
            'url': info.get('url') or f'https://github.com/{GITHUB_REPO}/releases'}


def _ensure_git(log):
    if sh('command -v git', t=5)[2] == 0:
        return
    log('Installing git...')
    try:
        from panel.routes.os_utils import pkg_install
        cmd = pkg_install('git')
    except Exception:
        cmd = 'DEBIAN_FRONTEND=noninteractive apt-get install -y git'
    sh(cmd + ' 2>&1', t=600)
    if sh('command -v git', t=5)[2] != 0:
        raise RuntimeError('git is not installed and could not be installed')


def fetch(log):
    _ensure_git(log)
    rd = repo_dir()
    if rd == MIRROR and not os.path.isdir(MIRROR):
        log('Downloading the release history from GitHub...')
        out, err, rc = sh(f'git clone --bare --filter=blob:none {GIT_URL} {MIRROR} 2>&1', t=600)
        if rc != 0:
            out, err, rc = sh(f'rm -rf {MIRROR}; git clone --bare {GIT_URL} {MIRROR} 2>&1', t=900)
        if rc != 0:
            raise RuntimeError('git clone failed: ' + (out or err)[-400:])
        os.chmod(MIRROR, 0o700)
    log('Fetching release tags from GitHub...')
    out, err, rc = sh(f'git -C {shlex.quote(rd)} fetch --tags --force --prune origin 2>&1', t=300)
    if rc != 0:
        raise RuntimeError('git fetch failed: ' + (out or err)[-400:])
    return rd


def verify_tag(rd, tag):
    """(ok, message). Accepts SSH-signed tags whose key is listed in the
    installed panel/trust/allowed_signers (and GPG-signed tags whose key is
    in root's keyring)."""
    signers = allowed_signers()
    if sh('command -v ssh-keygen', t=5)[2] != 0:
        return False, 'ssh-keygen (openssh-client) is needed to check signatures'
    typ, _, _ = sh(f'git -C {shlex.quote(rd)} cat-file -t refs/tags/{tag}', t=30)
    if typ != 'tag':
        return False, f'{tag} is not a signed (annotated) tag'
    out, err, rc = sh(f'git -C {shlex.quote(rd)} -c gpg.ssh.allowedSignersFile={shlex.quote(signers)} '
                      f'verify-tag {tag} 2>&1', t=60)
    msg = (out or err).strip()
    if rc == 0:
        line = next((l for l in msg.splitlines() if 'Good' in l), msg.splitlines()[0] if msg else 'Good signature')
        return True, line
    return False, msg[-300:] or 'no valid signature'


def _copy_items(src_root, dst_root, items):
    for it in items:
        src = os.path.join(src_root, it)
        if not os.path.exists(src):
            continue
        dst = os.path.join(dst_root, it)
        if os.path.isdir(src):
            tmp = dst + '.new'
            shutil.rmtree(tmp, ignore_errors=True)
            shutil.copytree(src, tmp, symlinks=True)
            if os.path.isdir(dst) and not os.path.islink(dst):
                shutil.rmtree(dst)
            elif os.path.lexists(dst):
                os.remove(dst)
            os.rename(tmp, dst)
        else:
            shutil.copy2(src, dst + '.new')
            os.replace(dst + '.new', dst)


def prune_snapshots(keep=5, protect=()):
    """Keep the newest `keep` update/deploy snapshots and 2 before-rollback ones."""
    b = list_backups()
    normal = [x for x in b if 'before-rollback' not in x['name']]
    rb = [x for x in b if 'before-rollback' in x['name']]
    for x in normal[keep:] + rb[2:]:
        if x['path'] not in protect:
            shutil.rmtree(x['path'], ignore_errors=True)


def snapshot(label, prune=True):
    """Copy the running code + version + pip freeze into update_backups/."""
    stamp = time.strftime('%Y%m%d-%H%M%S')
    bdir = os.path.join(BACKUP_ROOT, f'{stamp}-{label}')
    os.makedirs(bdir, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    for it in CODE_ITEMS + ['version.txt']:
        src = os.path.join(INSTALL_DIR, it)
        if os.path.exists(src):
            if os.path.isdir(src):
                shutil.copytree(src, os.path.join(bdir, it), symlinks=True,
                                ignore=shutil.ignore_patterns('__pycache__'))
            else:
                shutil.copy2(src, bdir)
    out, _, rc = sh(f'{venv_python()} -m pip freeze --disable-pip-version-check 2>/dev/null', t=120)
    if rc == 0 and out:
        with open(os.path.join(bdir, 'requirements.freeze'), 'w') as f:
            f.write(out + '\n')
    if not os.path.exists(os.path.join(bdir, 'version.txt')):
        with open(os.path.join(bdir, 'version.txt'), 'w') as f:
            f.write(current_version())
    with open(os.path.join(INSTALL_DIR, '.last_backup'), 'w') as f:
        f.write(bdir + '\n')
    if prune:
        prune_snapshots(protect=(bdir,))
    return bdir


def _drop_snapshot(bdir):
    """A snapshot that was just restored equals the running version: remove
    it so `rollback` goes back to the version before the last real update."""
    shutil.rmtree(bdir, ignore_errors=True)
    try:
        b = list_backups()
        with open(os.path.join(INSTALL_DIR, '.last_backup'), 'w') as f:
            f.write((b[0]['path'] if b else '') + '\n')
    except Exception:
        pass


def pip_install(req_file, t=900):
    return sh(f'{venv_python()} -m pip install -r {shlex.quote(req_file)} --quiet '
              f'--disable-pip-version-check 2>&1', t=t)


def restore(bdir, log=print):
    """Put a snapshot back: code, version.txt and the package list."""
    if not os.path.isdir(os.path.join(bdir, 'panel')) or not os.path.exists(os.path.join(bdir, 'app.py')):
        raise RuntimeError(f'The snapshot {bdir} is incomplete - nothing was restored')
    _copy_items(bdir, INSTALL_DIR, CODE_ITEMS)
    vb = os.path.join(bdir, 'version.txt')
    if os.path.exists(vb):
        shutil.copy2(vb, VERSION_FILE)
    elif os.path.exists(os.path.join(bdir, 'VERSION')):
        save_version('v' + open(os.path.join(bdir, 'VERSION')).read().strip().lstrip('v'))
    fr = os.path.join(bdir, 'requirements.freeze')
    if os.path.exists(fr):
        out, err, rc = pip_install(fr)
        if rc != 0:
            log('Warning: could not reinstall the previous Python packages: ' + (out or err)[-300:])
    sh(f'find {INSTALL_DIR}/panel {INSTALL_DIR}/web -name __pycache__ -prune -exec rm -rf {{}} + 2>/dev/null')


def import_test():
    env = dict(os.environ, VP_NO_INIT='1')
    return sh(f'cd {INSTALL_DIR} && {venv_python()} -c "import app" 2>&1', t=120, env=env)


def panel_scheme_port():
    try:
        unit = open('/etc/systemd/system/vortexpanel.service').read()
        m = re.search(r'(?:--bind|-b)\s+\S+:(\d+)', unit)
        return ('https' if '--certfile' in unit else 'http'), (m.group(1) if m else '8888')
    except Exception:
        return 'http', '8888'


RESTART_HELPER = r'''
import json, os, shutil, ssl, subprocess, sys, time, urllib.request, urllib.error
job_path, backup_dir, install_dir, scheme, port = sys.argv[1:6]
ITEMS = ['panel', 'web', 'app.py', 'requirements.txt', 'install.sh', 'VERSION']
def restore():
    # Self-contained on purpose: it must work even if the new code is broken.
    for it in ITEMS:
        src, dst = os.path.join(backup_dir, it), os.path.join(install_dir, it)
        if not os.path.exists(src):
            continue
        if os.path.isdir(dst) and not os.path.islink(dst):
            shutil.rmtree(dst, ignore_errors=True)
        elif os.path.lexists(dst):
            os.remove(dst)
        if os.path.isdir(src):
            shutil.copytree(src, dst, symlinks=True)
        else:
            shutil.copy2(src, dst)
    vb = os.path.join(backup_dir, 'version.txt')
    if os.path.exists(vb):
        shutil.copy2(vb, os.path.join(install_dir, 'version.txt'))
    fr = os.path.join(backup_dir, 'requirements.freeze')
    py = os.path.join(install_dir, 'venv/bin/python')
    if os.path.exists(fr) and os.path.exists(py):
        subprocess.run([py, '-m', 'pip', 'install', '-r', fr, '--quiet', '--disable-pip-version-check'],
                       capture_output=True, timeout=900)
def probe():
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    for host in ('127.0.0.1', '[::1]'):
        try:
            return op.open(f'{scheme}://{host}:{port}/api/health', timeout=3).status
        except urllib.error.HTTPError as e:
            if e.code != 404:
                return e.code
        except Exception:
            pass
    return 0
def healthy(tries):
    for _ in range(tries):
        time.sleep(1)
        if probe() == 200:
            return True
    return False
def update_job(extra_lines, **kw):
    if not job_path or job_path == '-':
        print('\n'.join(extra_lines)); return
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
if healthy(40):
    update_job(['Panel restarted and is answering on the new version.'])
    sys.exit(0)
log = subprocess.run('journalctl -u vortexpanel -n 20 --no-pager 2>/dev/null', shell=True,
                     capture_output=True, text=True).stdout[-1500:]
restore()
shutil.rmtree(backup_dir, ignore_errors=True)   # equals the running version now
subprocess.run('systemctl restart vortexpanel', shell=True)
back = healthy(40)
update_job(['', 'The panel did not start on the new version - the previous version was restored'
            + (' and is running again.' if back else ' but is NOT answering yet, check: journalctl -u vortexpanel'),
            log], success=False, done=True, running=False,
           error='New version failed to start; the previous version was restored')
sys.exit(1)
'''


def schedule_restart(job_path, bdir, wait=False):
    helper = os.path.join(INSTALL_DIR, 'data', 'panel_update_restart.py')
    os.makedirs(os.path.dirname(helper), exist_ok=True)
    with open(helper, 'w') as f:
        f.write(RESTART_HELPER)
    scheme, port = panel_scheme_port()
    args = [venv_python(), helper, job_path or '-', bdir, INSTALL_DIR, scheme, port]
    cmd = ' '.join(shlex.quote(a) for a in args)
    if wait:
        return subprocess.call(f'cd {shlex.quote(bdir)} && {cmd}', shell=True)
    if sh('command -v systemd-run', t=5)[2] == 0:
        sh(f'systemd-run --no-block --collect --working-directory={shlex.quote(bdir)} '
           f'--unit=vortexpanel-update-{int(time.time())} {cmd} 2>&1', t=30)
    else:
        sh(f'cd {shlex.quote(bdir)} && setsid {cmd} >/dev/null 2>&1 < /dev/null &', t=30)
    return 0


def run_update(target='', log=print, job_path=None, wait_restart=False, force_unsigned=False):
    """Install a release. Returns the version installed. Raises on failure
    (nothing is changed unless the error says otherwise)."""
    if target and not TAG_RE.match(target if target.startswith('v') else 'v' + target):
        raise ValueError('Invalid version tag')
    if target and not target.startswith('v'):
        target = 'v' + target
    if repo_dir() == DEV_REPO:
        log(f'Using the developer clone {DEV_REPO} (its working tree is not modified).')
    rd = fetch(log)
    out, _, _ = sh(f"git -C {shlex.quote(rd)} tag -l 'v*'", t=30)
    tags = sorted([t for t in out.split() if TAG_RE.match(t)], key=semver, reverse=True)
    if not tags:
        raise RuntimeError('No release tags were found on GitHub')
    tag = target or tags[0]
    if tag not in tags:
        raise RuntimeError(f'Release {tag} does not exist on GitHub')
    cur = current_version()
    log(f'Installed: {cur}   Selected release: {tag}')

    ok, msg = verify_tag(rd, tag)
    if ok:
        log(f'Signature check: {msg}')
    elif force_unsigned or allow_unsigned():
        log(f'WARNING: the signature of {tag} could not be verified ({msg}).')
        log('Continuing because unsigned updates are allowed in Settings.')
    else:
        raise RuntimeError(f'The signature of {tag} could not be verified: {msg}. '
                           'Nothing was changed. If you trust this release, turn on '
                           '"Allow unsigned updates" in Settings > Update (or run '
                           '"vortexpanel update --allow-unsigned").')

    stage = os.path.join(STAGING, tag)
    shutil.rmtree(stage, ignore_errors=True)
    os.makedirs(stage, mode=0o700)
    out, err, rc = sh(f'git -C {shlex.quote(rd)} archive --format=tar {tag} | tar -x -C {shlex.quote(stage)}', t=300)
    if rc != 0 or not os.path.exists(os.path.join(stage, 'app.py')):
        raise RuntimeError('Could not unpack the release: ' + (out or err)[-300:])

    log('Saving the current version and its Python packages...')
    bdir = snapshot('panel-update')
    log(f'Snapshot: {bdir}')

    req = os.path.join(stage, 'requirements.txt')
    if os.path.exists(req):
        log('Installing Python dependencies...')
        out, err, rc = pip_install(req)
        if rc != 0:
            restore(bdir, log)
            _drop_snapshot(bdir)
            raise RuntimeError('pip install failed, the previous packages were restored: ' + (out or err)[-500:])

    log('Copying the new release into place...')
    _copy_items(stage, INSTALL_DIR, CODE_ITEMS)
    sh(f'find {INSTALL_DIR}/panel {INSTALL_DIR}/web -name __pycache__ -prune -exec rm -rf {{}} + 2>/dev/null')
    save_version(tag)
    shutil.rmtree(stage, ignore_errors=True)

    out, err, rc = import_test()
    if rc != 0:
        restore(bdir, log)
        _drop_snapshot(bdir)
        raise RuntimeError('The new version failed to load, the previous version was restored: '
                           + (out or err)[-600:])
    log(f'Release {tag} installed. Restarting the panel...')
    rc = schedule_restart(job_path, bdir, wait=wait_restart)
    if wait_restart and rc != 0:
        raise RuntimeError('The new version did not start; the previous version was restored.')
    return tag


def list_backups():
    if not os.path.isdir(BACKUP_ROOT):
        return []
    out = []
    for n in sorted(os.listdir(BACKUP_ROOT), reverse=True):
        p = os.path.join(BACKUP_ROOT, n)
        if os.path.isdir(p):
            v = ''
            try:
                v = open(os.path.join(p, 'version.txt')).read().strip()
            except Exception:
                try:
                    v = 'v' + open(os.path.join(p, 'VERSION')).read().strip()
                except Exception:
                    pass
            out.append({'path': p, 'name': n, 'version': v})
    return out


def rollback(log=print):
    """Restore the newest snapshot and restart (with health check)."""
    now = current_version()
    b = [x for x in list_backups() if 'before-rollback' not in x['name'] and x['version'] and x['version'] != now]
    if not b:
        raise RuntimeError(f'No snapshot of a version other than {now} in {BACKUP_ROOT}')
    pick = b[0]
    log(f'Restoring {pick["name"]} ({pick["version"]})...')
    cur = snapshot('before-rollback', prune=False)
    restore(pick['path'], log)
    prune_snapshots(protect=(cur, pick['path']))
    rc = schedule_restart(None, cur, wait=True)
    if rc != 0:
        raise RuntimeError('The restored version did not start; the state before the rollback was put back.')
    return pick['version']
