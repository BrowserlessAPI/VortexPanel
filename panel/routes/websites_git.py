"""Website > Git Deploy: deploy a site from a Git repository.

- Repository over HTTPS (public, or private with a token in the URL) or SSH
  with a per-site deploy key the panel generates (add the public key to the
  repository as a read-only deploy key).
- The repository data lives outside the website, in
  /opt/vortexpanel/data/git_deploy/<domain>/repo.git, so no .git folder is ever
  published on the web.
- Deploy = fetch the branch and check it out over the site's files: files in
  the repository are updated, files that are not in the repository (uploads,
  .env, cache) are left alone.
- Optional command after each deploy (composer install, npm run build...),
  run as the site's owner in the site folder.
- Webhook: GitHub, GitLab, Gitea and Bitbucket can call
  POST /api/hooks/git/<domain>/<token> after each push (GitHub's
  X-Hub-Signature-256 is checked when a secret is set).
"""
import hashlib
import hmac
import json
import os
import pwd
import re
import secrets
import shutil
import subprocess
import threading
import time

from flask import jsonify, request

from panel.routes.websites_core import websites_bp, req, is_valid_domain, _get_site_path, _find_site_config
from panel.routes.job_state import load_job, save_job

BASE = '/opt/vortexpanel/data/git_deploy'
_URL_RE = re.compile(r'^(https://([A-Za-z0-9._~%!$&\'()*+,;=-]+@)?[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9._~/-]+?(\.git)?/?'
                     r'|(ssh://)?[A-Za-z0-9._-]+@[A-Za-z0-9.-]+(:\d+)?[:/][A-Za-z0-9._~/-]+?(\.git)?)$')
_BRANCH_RE = re.compile(r'^[A-Za-z0-9._/-]{1,100}$')


def _dir(domain):
    return os.path.join(BASE, domain)


def _cfg_path(domain):
    return os.path.join(_dir(domain), 'config.json')


def load_cfg(domain):
    try:
        return json.load(open(_cfg_path(domain)))
    except Exception:
        return {}


def save_cfg(domain, cfg):
    os.makedirs(_dir(domain), mode=0o700, exist_ok=True)
    tmp = _cfg_path(domain) + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(cfg, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, _cfg_path(domain))


def _mask(url):
    return re.sub(r'(https://)[^@/]+@', r'\1***@', url or '')


def _run(args, timeout=600, env=None, cwd=None):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, f'timed out after {timeout}s'
    except FileNotFoundError as e:
        return 127, str(e)


def _git_env(domain):
    d = _dir(domain)
    key = os.path.join(d, 'id_ed25519')
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_DIR=os.path.join(d, 'repo.git'), HOME=d)
    ssh = f'ssh -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile={d}/known_hosts -o BatchMode=yes'
    if os.path.exists(key):
        ssh += f' -i {key}'
    env['GIT_SSH_COMMAND'] = ssh
    return env


_GIT_SAFE = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never', '-c', 'advice.detachedHead=false']


def _public(domain, cfg):
    d = _dir(domain)
    pub = ''
    try:
        pub = open(os.path.join(d, 'id_ed25519.pub')).read().strip()
    except OSError:
        pass
    host = request.host_url.rstrip('/')
    return {
        'configured': bool(cfg.get('url')), 'url': _mask(cfg.get('url', '')), 'branch': cfg.get('branch', 'main'),
        'post_cmd': cfg.get('post_cmd', ''), 'auto_deploy': bool(cfg.get('auto_deploy')),
        'has_secret': bool(cfg.get('secret')), 'public_key': pub,
        'webhook_url': f'{host}/api/hooks/git/{domain}/{cfg["token"]}' if cfg.get('token') else '',
        'last': cfg.get('last') or {}, 'job': load_job(f'git_deploy_{domain}', {}),
    }


def _site_ok(domain):
    return is_valid_domain(domain) and _find_site_config(domain)[0]


@websites_bp.route('/api/websites/<domain>/git')
def git_get(domain):
    if not req(): return jsonify({'ok': False}), 401
    if not _site_ok(domain):
        return jsonify({'ok': False, 'error': 'Site not found'}), 404
    return jsonify({'ok': True, **_public(domain, load_cfg(domain))})


@websites_bp.route('/api/websites/<domain>/git', methods=['PUT'])
def git_save(domain):
    if not req(): return jsonify({'ok': False}), 401
    if not _site_ok(domain):
        return jsonify({'ok': False, 'error': 'Site not found'}), 404
    d = request.get_json() or {}
    cfg = load_cfg(domain)
    url = str(d.get('url') or '').strip()
    if url.startswith('https://***@'):           # unchanged masked value from the form
        url = cfg.get('url', '')
    if not _URL_RE.match(url):
        return jsonify({'ok': False, 'error': 'Repository URL must be https://host/owner/repo.git or git@host:owner/repo.git'}), 400
    branch = str(d.get('branch') or 'main').strip()
    if not _BRANCH_RE.match(branch) or '..' in branch or branch.startswith('-'):
        return jsonify({'ok': False, 'error': 'Invalid branch name'}), 400
    post = str(d.get('post_cmd') or '').strip()
    if len(post) > 500 or '\n' in post:
        return jsonify({'ok': False, 'error': 'The command after deploy must be one line'}), 400
    if cfg.get('url') and cfg['url'] != url and os.path.isdir(os.path.join(_dir(domain), 'repo.git')):
        shutil.rmtree(os.path.join(_dir(domain), 'repo.git'), ignore_errors=True)   # new repository
    cfg.update(url=url, branch=branch, post_cmd=post, auto_deploy=bool(d.get('auto_deploy')))
    secret = d.get('secret')
    if secret is not None:
        cfg['secret'] = str(secret)[:200]
    cfg.setdefault('token', secrets.token_urlsafe(24))
    save_cfg(domain, cfg)
    return jsonify({'ok': True, **_public(domain, cfg)})


@websites_bp.route('/api/websites/<domain>/git', methods=['DELETE'])
def git_remove(domain):
    """Stop deploying from Git. The website's files are not touched."""
    if not req(): return jsonify({'ok': False}), 401
    if not is_valid_domain(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    shutil.rmtree(_dir(domain), ignore_errors=True)
    return jsonify({'ok': True})


@websites_bp.route('/api/websites/<domain>/git/key', methods=['POST'])
def git_key(domain):
    if not req(): return jsonify({'ok': False}), 401
    if not _site_ok(domain):
        return jsonify({'ok': False, 'error': 'Site not found'}), 404
    d = _dir(domain)
    os.makedirs(d, mode=0o700, exist_ok=True)
    for f in ('id_ed25519', 'id_ed25519.pub'):
        try:
            os.remove(os.path.join(d, f))
        except OSError:
            pass
    rc, out = _run(['ssh-keygen', '-t', 'ed25519', '-N', '', '-C', f'vortexpanel-deploy@{domain}',
                    '-f', os.path.join(d, 'id_ed25519')], timeout=30)
    if rc != 0:
        return jsonify({'ok': False, 'error': 'ssh-keygen failed: ' + out[-200:]}), 500
    cfg = load_cfg(domain)
    cfg.setdefault('token', secrets.token_urlsafe(24))
    save_cfg(domain, cfg)
    return jsonify({'ok': True, **_public(domain, cfg)})


@websites_bp.route('/api/websites/<domain>/git/token', methods=['POST'])
def git_new_token(domain):
    """New webhook address (the old one stops working)."""
    if not req(): return jsonify({'ok': False}), 401
    if not _site_ok(domain):
        return jsonify({'ok': False, 'error': 'Site not found'}), 404
    cfg = load_cfg(domain)
    cfg['token'] = secrets.token_urlsafe(24)
    save_cfg(domain, cfg)
    return jsonify({'ok': True, **_public(domain, cfg)})


@websites_bp.route('/api/websites/<domain>/git/deploy', methods=['POST'])
def git_deploy_now(domain):
    if not req(): return jsonify({'ok': False}), 401
    if not _site_ok(domain):
        return jsonify({'ok': False, 'error': 'Site not found'}), 404
    ok, err = start_deploy(domain, 'manual')
    return (jsonify({'ok': True}) if ok else (jsonify({'ok': False, 'error': err}), 409 if 'running' in err else 400))


def start_deploy(domain, trigger):
    cfg = load_cfg(domain)
    if not cfg.get('url'):
        return False, 'Set the repository first'
    jid = f'git_deploy_{domain}'
    if load_job(jid, {}).get('running'):
        return False, 'A deploy is already running'
    save_job(jid, {'running': True, 'step': 'Starting', 'trigger': trigger, 'started': time.time()})
    threading.Thread(target=_deploy, args=(domain, trigger), daemon=True).start()
    return True, ''


def _deploy(domain, trigger):
    jid = f'git_deploy_{domain}'
    cfg = load_cfg(domain)
    log = []

    def note(m):
        log.append(m)
        save_job(jid, {'running': True, 'trigger': trigger, 'step': m.splitlines()[0][:120], 'output': '\n'.join(log)[-12000:]})

    def finish(ok, err=''):
        if err:
            log.append('FAILED: ' + err)
        out = '\n'.join(log)[-12000:]
        save_job(jid, {'running': False, 'done': True, 'success': ok, 'error': err, 'trigger': trigger, 'output': out})
        c = load_cfg(domain)
        c['last'] = {'time': time.time(), 'success': ok, 'trigger': trigger, 'commit': commit[0], 'error': err}
        save_cfg(domain, c)
        try:
            from panel.alerts import notify_event
            if not ok:
                notify_event('deploy', f'Git deploy of {domain} failed', err, {'domain': domain})
        except Exception:
            pass

    commit = ['']
    try:
        path = _get_site_path(domain).rstrip('/')
        if not os.path.isdir(path):
            return finish(False, f'{path} does not exist')
        env = _git_env(domain)
        gitdir = env['GIT_DIR']
        branch = cfg.get('branch') or 'main'
        if not os.path.isdir(gitdir):
            rc, out = _run(_GIT_SAFE + ['init', '-q', '--bare', gitdir], env=env)
            if rc != 0:
                return finish(False, 'git init failed: ' + out)
            _run(_GIT_SAFE + ['config', 'core.bare', 'false'], env=env)
            _run(_GIT_SAFE + ['config', 'core.worktree', path], env=env)
            _run(_GIT_SAFE + ['remote', 'add', 'origin', cfg['url']], env=env)
        else:
            _run(_GIT_SAFE + ['remote', 'set-url', 'origin', cfg['url']], env=env)
        note(f'Fetching {branch} from {_mask(cfg["url"])}')
        rc, out = _run(_GIT_SAFE + ['fetch', '--depth', '50', 'origin', branch], env=env, timeout=900)
        if rc != 0:
            hint = ''
            if 'Permission denied' in out or 'publickey' in out:
                hint = ' (add the deploy key below to the repository)'
            elif 'could not read Username' in out or 'Authentication failed' in out:
                hint = ' (private repository: use the SSH address with the deploy key, or put a token in the URL)'
            return finish(False, 'git fetch failed' + hint + ': ' + out[-400:])
        rc, out = _run(_GIT_SAFE + ['--work-tree', path, 'checkout', '-f', '-B', branch, 'FETCH_HEAD'], env=env, timeout=600)
        if rc != 0:
            return finish(False, 'checkout failed: ' + out[-400:])
        _, commit[0] = _run(_GIT_SAFE + ['log', '-1', '--format=%h %s'], env=env)
        note('Checked out ' + commit[0])
        st = os.stat(path)
        _run(['chown', '-R', f'{st.st_uid}:{st.st_gid}', path], timeout=600)
        if cfg.get('post_cmd'):
            user = pwd.getpwuid(st.st_uid).pw_name
            if user == 'root':
                user = 'www-data' if _user_exists('www-data') else 'nobody'
            rc, out = _run([shutil.which('runuser') or '/usr/sbin/runuser', '-u', user, '--', 'bash', '-c', cfg['post_cmd']],
                           cwd=path, timeout=1200,
                           env={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': path, 'LANG': 'C.UTF-8'})
            note(f'$ {cfg["post_cmd"]}  (as {user})\n' + out[-6000:])
            if rc != 0:
                return finish(False, f'the command after deploy exited with {rc}')
        finish(True)
    except Exception as e:
        finish(False, f'{type(e).__name__}: {e}')


def _user_exists(u):
    try:
        pwd.getpwnam(u)
        return True
    except KeyError:
        return False


@websites_bp.route('/api/hooks/git/<domain>/<token>', methods=['POST'])
def git_webhook(domain, token):
    """Called by the Git host after a push. No sign-in: the long random token
    in the address (and the optional GitHub secret) is the authentication."""
    if not is_valid_domain(domain):
        return jsonify({'ok': False}), 404
    cfg = load_cfg(domain)
    if not cfg.get('token') or not hmac.compare_digest(str(token), str(cfg['token'])):
        return jsonify({'ok': False}), 404
    if cfg.get('secret'):
        sig = request.headers.get('X-Hub-Signature-256', '')
        gl = request.headers.get('X-Gitlab-Token', '')
        good = False
        if sig.startswith('sha256='):
            mac = hmac.new(cfg['secret'].encode(), request.get_data(), hashlib.sha256).hexdigest()
            good = hmac.compare_digest(sig[7:], mac)
        elif gl:
            good = hmac.compare_digest(gl, cfg['secret'])
        if not good:
            return jsonify({'ok': False, 'error': 'Bad signature'}), 403
    if not cfg.get('auto_deploy'):
        return jsonify({'ok': True, 'deployed': False, 'reason': 'Auto deploy is off'})
    body = request.get_json(silent=True) or {}
    ref = str(body.get('ref') or '')
    if ref.startswith('refs/heads/') and ref[len('refs/heads/'):] != (cfg.get('branch') or 'main'):
        return jsonify({'ok': True, 'deployed': False, 'reason': f'Push to {ref} ignored'})
    ok, err = start_deploy(domain, 'webhook')
    return jsonify({'ok': ok, 'deployed': ok, 'error': err}), (202 if ok else 409)
