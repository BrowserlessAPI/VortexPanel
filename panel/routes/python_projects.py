"""Python Projects: run Django, Flask, FastAPI and other Python apps.

Each project gets
  - its own virtualenv (<project>/.venv) built with the Python version chosen
  - dependencies from requirements.txt or pyproject.toml, installed in the
    background with the output kept for the UI
  - a systemd service vortex-py-<id> (restart on crash, memory/CPU limits,
    environment variables, runs as a normal user - never root)
  - optionally a domain: a reverse proxy in the active web server (shared
    with Go projects, panel/routes/go_projects.write_proxy)
  - optionally a Git repository: clone on create, "Pull and restart" later

Start modes:
  gunicorn  WSGI apps (Django, Flask):   gunicorn -w N -b 127.0.0.1:PORT module:app
  uvicorn   ASGI apps (FastAPI, Starlette, Django ASGI):  uvicorn module:app --port PORT
  command   any command line, run inside the venv (python bot.py, celery ..., etc.)
"""
import glob
import json
import os
import pwd
import re
import shlex
import shutil
import subprocess
import threading
import time

from flask import Blueprint, jsonify, request

from panel.utils.authctx import authed as _vp_authed
from panel.routes import go_projects as _go
from panel.routes.job_state import load_job, save_job

python_bp = Blueprint('python_projects', __name__)

PROJECTS_FILE = '/opt/vortexpanel/data/python_projects.json'
_ID_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{0,40}$')
_APP_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_.()]*$')   # module.path:app / :create_app()
_GIT_RE = re.compile(r'^(https://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9._~/-]+?(\.git)?|git@[A-Za-z0-9.-]+:[A-Za-z0-9._/-]+?(\.git)?)$')
_BRANCH_RE = re.compile(r'^[A-Za-z0-9._/-]{1,100}$')
_PYVER_RE = re.compile(r'^3\.\d{1,2}$')
Q = shlex.quote


def req():
    return _vp_authed()


def sh(args, timeout=120, cwd=None, user=None, env=None):
    """Run argv (never a shell string); as `user` when given."""
    if user and user != 'root':
        args = [shutil.which('runuser') or '/usr/sbin/runuser', '-u', user, '--'] + args
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, f'timed out after {timeout}s'
    except FileNotFoundError as e:
        return 127, str(e)


def load_projects():
    try:
        return json.load(open(PROJECTS_FILE))
    except Exception:
        return []


def save_projects(projects):
    os.makedirs(os.path.dirname(PROJECTS_FILE), exist_ok=True)
    tmp = PROJECTS_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(projects, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, PROJECTS_FILE)


def svc_name(pid):
    return f'vortex-py-{pid}'


def _find(pid):
    return next((p for p in load_projects() if p['id'] == pid), None)


# --- Python runtimes ------------------------------------------------------------

def runtimes():
    """Installed Python 3 interpreters: [{'version': '3.12', 'path': '/usr/bin/python3.12', 'full': '3.12.3', 'venv': True}]."""
    seen, out = set(), []
    cands = glob.glob('/usr/bin/python3.[0-9]*') + glob.glob('/usr/local/bin/python3.[0-9]*') + \
        glob.glob('/opt/python/*/bin/python3.[0-9]*')
    for path in sorted(cands):
        m = re.search(r'python(3\.\d+)$', path)
        if not m or not os.access(path, os.X_OK) or os.path.islink(path) and not os.path.exists(path):
            continue
        ver = m.group(1)
        real = os.path.realpath(path)
        if real in seen or ver in [o['version'] for o in out]:
            continue
        seen.add(real)
        rc, full = sh([path, '-c', 'import sys;print("%d.%d.%d"%sys.version_info[:3])'], timeout=10)
        if rc != 0:
            continue
        rc2, _ = sh([path, '-c', 'import venv, ensurepip'], timeout=10)
        out.append({'version': ver, 'path': path, 'full': full.strip(), 'venv': rc2 == 0})
    out.sort(key=lambda r: tuple(int(x) for x in r['version'].split('.')), reverse=True)
    return out


def _runtime(ver):
    return next((r for r in runtimes() if r['version'] == ver), None)


def _os_family():
    try:
        txt = open('/etc/os-release').read().lower()
    except OSError:
        return 'debian'
    return 'rhel' if re.search(r'rhel|fedora|centos|almalinux|rocky', txt) else 'debian'


@python_bp.route('/api/python/runtimes')
def list_runtimes():
    if not req(): return jsonify({'ok': False}), 401
    st = load_job('py_runtime_install', {})
    return jsonify({'ok': True, 'runtimes': runtimes(), 'installable': ['3.14', '3.13', '3.12', '3.11', '3.10'],
                    'install_job': st})


@python_bp.route('/api/python/runtimes/install', methods=['POST'])
def install_runtime():
    """Ubuntu: deadsnakes PPA (python3.X + venv); Debian: the distro version
    only; RHEL family: dnf python3.X. Runs in the background."""
    if not req(): return jsonify({'ok': False}), 401
    ver = str((request.get_json() or {}).get('version') or '').strip()
    if not _PYVER_RE.match(ver):
        return jsonify({'ok': False, 'error': 'Version must look like 3.13'}), 400
    if load_job('py_runtime_install', {}).get('running'):
        return jsonify({'ok': False, 'error': 'An install is already running'}), 409

    def run():
        save_job('py_runtime_install', {'running': True, 'version': ver, 'output': '', 'started': time.time()})
        log = []

        def step(args, t=900):
            rc, out = sh(args, timeout=t, env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'))
            log.append('$ ' + ' '.join(args) + '\n' + out[-3000:])
            save_job('py_runtime_install', {'running': True, 'version': ver, 'output': '\n'.join(log)[-8000:]})
            return rc
        ok = False
        if _os_family() == 'rhel':
            ok = step(['dnf', 'install', '-y', f'python{ver}', f'python{ver}-pip']) == 0
        else:
            distro = open('/etc/os-release').read().lower() if os.path.exists('/etc/os-release') else ''
            pkgs = [f'python{ver}', f'python{ver}-venv', f'python{ver}-dev']
            if step(['apt-get', 'install', '-y'] + pkgs) == 0:
                ok = True
            elif 'ubuntu' in distro:
                if not shutil.which('add-apt-repository'):
                    step(['apt-get', 'install', '-y', 'software-properties-common'])
                if step(['add-apt-repository', '-y', 'ppa:deadsnakes/ppa']) == 0:
                    step(['apt-get', 'update'])
                    ok = step(['apt-get', 'install', '-y'] + pkgs) == 0
                else:
                    log.append('The deadsnakes PPA could not be added (launchpad.net unreachable?).')
            else:
                log.append(f'Python {ver} is not packaged for this distribution. Installed versions can be used.')
        ok = ok and bool(_runtime(ver))
        save_job('py_runtime_install', {'running': False, 'done': True, 'success': ok, 'version': ver,
                                        'output': '\n'.join(log)[-8000:]})
    threading.Thread(target=run, daemon=True).start()
    return jsonify({'ok': True, 'started': True})


# --- projects ---------------------------------------------------------------------

def _resolve_user(u):
    u = (u or '').strip()
    if not u or u == 'www':
        u = _go._default_svc_user()
    if u == 'root':
        return None, 'Python projects never run as root; pick a normal user or the web server user'
    if not re.fullmatch(r'[a-z_][a-z0-9_.-]*', u):
        return None, 'Invalid user name'
    try:
        pwd.getpwnam(u)
    except KeyError:
        return None, f'User "{u}" does not exist on this server'
    return u, None


def _venv_bin(p, name):
    return os.path.join(p['path'], '.venv', 'bin', name)


def _exec_start(p):
    """The ExecStart line for a project (shell-free argv, quoted for systemd)."""
    mode = p.get('mode') or 'gunicorn'
    port = str(p.get('port') or '')
    if mode == 'gunicorn':
        args = [_venv_bin(p, 'gunicorn'), '--workers', str(p.get('workers') or 2), '--bind', f'127.0.0.1:{port}',
                '--access-logfile', '-', '--error-logfile', '-', p['app']]
    elif mode == 'uvicorn':
        args = [_venv_bin(p, 'uvicorn'), p['app'], '--host', '127.0.0.1', '--port', port,
                '--workers', str(p.get('workers') or 1), '--proxy-headers']
    else:
        args = shlex.split(p.get('command') or '')
        if args and not args[0].startswith('/'):
            cand = _venv_bin(p, args[0])
            if os.path.exists(cand):
                args[0] = cand
    return ' '.join(_go._unit_val(Q(a)) for a in args)


def _unit_text(p):
    env = dict(p.get('env') or {})
    if p.get('port'):
        env.setdefault('PORT', str(p['port']))
    env.setdefault('PYTHONUNBUFFERED', '1')
    env['PATH'] = os.path.join(p['path'], '.venv', 'bin') + ':/usr/local/bin:/usr/bin:/bin'
    env['VIRTUAL_ENV'] = os.path.join(p['path'], '.venv')

    def q(v):
        return _go._unit_val(v).replace('\\', '\\\\').replace('"', '\\"')
    env_lines = '\n'.join(f'Environment="{k}={q(v)}"' for k, v in env.items())
    mem = str(p.get('mem_limit') or '').strip()
    if mem.isdigit():
        mem += 'M'
    mem_line = (f'MemoryMax={mem}' if _go._cgroup_v2() else f'MemoryLimit={mem}') if mem else ''
    cpu_line = f'CPUQuota={p["cpu_quota"]}%' if p.get('cpu_quota') else ''
    return f"""[Unit]
Description=VortexPanel Python: {_go._unit_val(p['name'])}
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
WorkingDirectory={_go._unit_val(p.get('workdir') or p['path'])}
ExecStart={_exec_start(p)}
Restart=always
RestartSec=5
{env_lines}
{mem_line}
{cpu_line}
NoNewPrivileges=true
StandardOutput=journal
StandardError=journal
User={_go._unit_val(p['user'])}

[Install]
WantedBy=multi-user.target
"""


def _validate(d, creating):
    """Clean the request body into a project dict. Returns (project, error)."""
    p = {}
    name = str(d.get('name') or '').strip()
    if not name or len(name) > 60 or re.search(r'[\x00-\x1f]', name):
        return None, 'Project name required (up to 60 characters)'
    p['name'] = name
    path = os.path.realpath(str(d.get('path') or '').strip() or '/')
    if not path.startswith('/') or path.count('/') < 2 or path in ('/etc', '/usr', '/bin', '/sbin', '/boot', '/root', '/opt/vortexpanel') \
            or path.startswith(('/opt/vortexpanel/', '/etc/', '/usr/', '/proc', '/sys', '/dev', '/boot')):
        return None, 'Choose a project folder such as /www/wwwroot/myapp'
    p['path'] = path
    workdir = str(d.get('workdir') or '').strip()
    if workdir:
        wd = os.path.realpath(os.path.join(path, workdir) if not workdir.startswith('/') else workdir)
        if not (wd == path or wd.startswith(path + '/')):
            return None, 'Working folder must be inside the project folder'
        p['workdir'] = wd
    ver = str(d.get('python') or '').strip()
    rt = _runtime(ver)
    if not rt:
        return None, f'Python {ver or "?"} is not installed (install it from the Python versions tab)'
    if not rt['venv']:
        return None, f'Python {ver} has no venv module; install python{ver}-venv'
    p['python'] = ver
    mode = str(d.get('mode') or 'gunicorn')
    if mode not in ('gunicorn', 'uvicorn', 'command'):
        return None, 'Start mode must be gunicorn, uvicorn or command'
    p['mode'] = mode
    if mode in ('gunicorn', 'uvicorn'):
        app = str(d.get('app') or '').strip()
        if not _APP_RE.match(app):
            return None, 'Application must look like module:app (for Django: mysite.wsgi:application)'
        p['app'] = app
    else:
        cmd = str(d.get('command') or '').strip()
        if not cmd or '\n' in cmd or len(cmd) > 500:
            return None, 'Start command required (one line)'
        try:
            shlex.split(cmd)
        except ValueError:
            return None, 'Start command has unbalanced quotes'
        p['command'] = cmd
    port = str(d.get('port') or '').strip()
    if mode != 'command' and not port:
        return None, 'Port required'
    if port and not (port.isdigit() and 1024 <= int(port) <= 65535):
        return None, 'Port must be between 1024 and 65535'
    p['port'] = port
    try:
        p['workers'] = max(1, min(64, int(d.get('workers') or (2 if mode == 'gunicorn' else 1))))
    except (TypeError, ValueError):
        return None, 'Workers must be a number'
    user, err = _resolve_user(d.get('user'))
    if err:
        return None, err
    p['user'] = user
    domain = str(d.get('domain') or '').strip()
    if domain and not _go._valid_domains(domain):
        return None, 'Invalid domain (one hostname per line)'
    p['domain'] = domain
    env = {}
    for line in str(d.get('env_vars') or '').splitlines():
        if '=' in line:
            k, _, v = line.partition('=')
            k = k.strip()
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', k):
                return None, f'Invalid environment variable name: {k}'
            env[k] = v.strip()
    p['env'] = env
    mem = str(d.get('mem_limit') or '').strip()
    if mem and not re.fullmatch(r'\d+(\.\d+)?[KMGT]?|\d{1,3}%', mem):
        return None, 'Memory limit must look like 512M or 1G'
    p['mem_limit'] = mem
    cpu = str(d.get('cpu_quota') or '').strip()
    if cpu and not re.fullmatch(r'\d{1,4}', cpu):
        return None, 'CPU limit must be a whole percentage, e.g. 50'
    p['cpu_quota'] = cpu
    git = str(d.get('git_url') or '').strip()
    if git and not _GIT_RE.match(git):
        return None, 'Git URL must be https://host/owner/repo(.git) or git@host:owner/repo.git'
    p['git_url'] = git
    branch = str(d.get('git_branch') or '').strip()
    if branch and (not _BRANCH_RE.match(branch) or '..' in branch or branch.startswith('-')):
        return None, 'Invalid branch name'
    p['git_branch'] = branch
    p['remark'] = str(d.get('remark') or '')[:200]
    return p, None


def _port_clash(port, pid):
    if not port:
        return None
    for p in load_projects():
        if p['id'] != pid and str(p.get('port')) == str(port):
            return f'Python project {p["name"]}'
    return _go._port_owner(port, None)


def _write_unit(p):
    with open(f'/etc/systemd/system/{svc_name(p["id"])}.service', 'w') as f:
        f.write(_unit_text(p))
    sh(['systemctl', 'daemon-reload'])


def _deploy_job(p, fresh_clone):
    """Background: clone (optional), venv, dependencies, unit, start."""
    jid = f'py_deploy_{p["id"]}'
    log = []

    def note(msg):
        log.append(msg)
        save_job(jid, {'running': True, 'step': msg.splitlines()[0][:120], 'output': '\n'.join(log)[-12000:]})

    def fail(msg):
        log.append('FAILED: ' + msg)
        save_job(jid, {'running': False, 'done': True, 'success': False, 'error': msg, 'output': '\n'.join(log)[-12000:]})

    try:
        rt = _runtime(p['python'])
        if fresh_clone and p.get('git_url'):
            if os.path.isdir(p['path']) and os.listdir(p['path']):
                return fail(f'{p["path"]} is not empty; clone needs an empty folder')
            os.makedirs(os.path.dirname(p['path']), exist_ok=True)
            args = ['git', 'clone', '--depth', '50']
            if p.get('git_branch'):
                args += ['--branch', p['git_branch']]
            rc, out = sh(args + ['--', p['git_url'], p['path']], timeout=600,
                         env=dict(os.environ, GIT_TERMINAL_PROMPT='0'))
            note('$ git clone ' + p['git_url'] + '\n' + out[-2000:])
            if rc != 0:
                return fail('git clone failed')
        os.makedirs(p['path'], exist_ok=True)
        uid, gid = pwd.getpwnam(p['user']).pw_uid, pwd.getpwnam(p['user']).pw_gid
        sh(['chown', '-R', f'{uid}:{gid}', p['path']])
        venv = os.path.join(p['path'], '.venv')
        if not os.path.exists(os.path.join(venv, 'bin', 'python')):
            rc, out = sh([rt['path'], '-m', 'venv', venv], timeout=300, user=p['user'])
            note(f'$ python{p["python"]} -m venv .venv\n' + out[-2000:])
            if rc != 0:
                return fail('creating the virtualenv failed')
        pip = [os.path.join(venv, 'bin', 'python'), '-m', 'pip', '--disable-pip-version-check', 'install', '-q']
        env = dict(os.environ, HOME=p['path'], PIP_CACHE_DIR=os.path.join(p['path'], '.venv', '.pip-cache'))
        rc, out = sh(pip + ['--upgrade', 'pip', 'wheel'], timeout=600, user=p['user'], env=env)
        note('$ pip install --upgrade pip wheel\n' + out[-1500:])
        req_txt = os.path.join(p.get('workdir') or p['path'], 'requirements.txt')
        if os.path.isfile(req_txt):
            rc, out = sh(pip + ['-r', req_txt], timeout=1800, user=p['user'], env=env)
            note('$ pip install -r requirements.txt\n' + out[-4000:])
            if rc != 0:
                return fail('installing requirements.txt failed (see output)')
        elif os.path.isfile(os.path.join(p.get('workdir') or p['path'], 'pyproject.toml')):
            rc, out = sh(pip + [p.get('workdir') or p['path']], timeout=1800, user=p['user'], env=env)
            note('$ pip install . (pyproject.toml)\n' + out[-4000:])
            if rc != 0:
                return fail('installing the project (pyproject.toml) failed')
        server = {'gunicorn': 'gunicorn', 'uvicorn': 'uvicorn[standard]'}.get(p['mode'])
        if server and not os.path.exists(_venv_bin(p, server.split('[')[0])):
            rc, out = sh(pip + [server], timeout=900, user=p['user'], env=env)
            note(f'$ pip install {server}\n' + out[-1500:])
            if rc != 0:
                return fail(f'installing {server} failed')
        _write_unit(p)
        sh(['systemctl', 'enable', svc_name(p['id'])])
        sh(['systemctl', 'restart', svc_name(p['id'])])
        time.sleep(3)
        rc, state = sh(['systemctl', 'is-active', svc_name(p['id'])])
        note(f'service {svc_name(p["id"])}: {state}')
        if p.get('domain') and p.get('port'):
            ok, res = _go.write_proxy(p, prefix='vortex-py')
            note(('reverse proxy written for ' + res) if ok else ('reverse proxy NOT written: ' + res))
        if state != 'active':
            _, logs = sh(['journalctl', '-u', svc_name(p['id']), '-n', '30', '--no-pager'])
            note(logs)
            return fail('the service did not stay running (see the log above)')
        save_job(jid, {'running': False, 'done': True, 'success': True, 'output': '\n'.join(log)[-12000:]})
    except Exception as e:
        fail(f'{type(e).__name__}: {e}')


def _status(pid):
    rc, out = sh(['systemctl', 'is-active', svc_name(pid)])
    return out.strip() or 'unknown'


@python_bp.route('/api/python/projects')
def list_projects():
    if not req(): return jsonify({'ok': False}), 401
    out = []
    for p in load_projects():
        q = dict(p)
        q['status'] = _status(p['id'])
        q['job'] = load_job(f'py_deploy_{p["id"]}', {})
        q.pop('env', None)
        q['env_vars'] = '\n'.join(f'{k}={v}' for k, v in (p.get('env') or {}).items())
        out.append(q)
    return jsonify({'ok': True, 'projects': out, 'web_user': _go._default_svc_user()})


@python_bp.route('/api/python/projects', methods=['POST'])
def create_project():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    p, err = _validate(d, creating=True)
    if err:
        return jsonify({'ok': False, 'error': err}), 400
    pid = re.sub(r'[^a-z0-9_-]', '', p['name'].lower().replace(' ', '-'))[:40] or 'app'
    projects = load_projects()
    if any(x['id'] == pid for x in projects):
        return jsonify({'ok': False, 'error': f'A project "{pid}" already exists'}), 400
    p['id'] = pid
    clash = _port_clash(p['port'], pid)
    if clash:
        return jsonify({'ok': False, 'error': f'Port {p["port"]} is already used by {clash}'}), 400
    if not p.get('git_url') and not os.path.isdir(p['path']):
        return jsonify({'ok': False, 'error': f'{p["path"]} does not exist; upload your code there first or give a Git URL'}), 400
    p['created'] = time.time()
    projects.append(p)
    save_projects(projects)
    save_job(f'py_deploy_{pid}', {'running': True, 'step': 'Starting'})
    threading.Thread(target=_deploy_job, args=(p, True), daemon=True).start()
    return jsonify({'ok': True, 'id': pid, 'job': f'py_deploy_{pid}'})


@python_bp.route('/api/python/projects/<pid>', methods=['PUT'])
def update_project(pid):
    if not req(): return jsonify({'ok': False}), 401
    old = _find(pid)
    if not old:
        return jsonify({'ok': False, 'error': 'Project not found'}), 404
    d = request.get_json() or {}
    d.setdefault('path', old['path'])
    p, err = _validate(d, creating=False)
    if err:
        return jsonify({'ok': False, 'error': err}), 400
    p['path'] = old['path']                 # the folder never moves
    p['id'] = pid
    p['created'] = old.get('created')
    clash = _port_clash(p['port'], pid)
    if clash:
        return jsonify({'ok': False, 'error': f'Port {p["port"]} is already used by {clash}'}), 400
    projects = [p if x['id'] == pid else x for x in load_projects()]
    save_projects(projects)
    if old.get('domain') and not p.get('domain'):
        _go.remove_proxy(pid, prefix='vortex-py')
    save_job(f'py_deploy_{pid}', {'running': True, 'step': 'Starting'})
    threading.Thread(target=_deploy_job, args=(p, False), daemon=True).start()
    return jsonify({'ok': True, 'job': f'py_deploy_{pid}'})


@python_bp.route('/api/python/projects/<pid>/job')
def project_job(pid):
    if not req(): return jsonify({'ok': False}), 401
    return jsonify({'ok': True, **load_job(f'py_deploy_{pid}', {})})


@python_bp.route('/api/python/projects/<pid>/control', methods=['POST'])
def control(pid):
    if not req(): return jsonify({'ok': False}), 401
    p = _find(pid)
    if not p:
        return jsonify({'ok': False, 'error': 'Project not found'}), 404
    action = (request.get_json() or {}).get('action')
    if action not in ('start', 'stop', 'restart'):
        return jsonify({'ok': False, 'error': 'Unknown action'}), 400
    rc, out = sh(['systemctl', action, svc_name(pid)], timeout=60)
    time.sleep(1.5)
    return jsonify({'ok': rc == 0, 'status': _status(pid), 'error': '' if rc == 0 else out[-300:]})


@python_bp.route('/api/python/projects/<pid>/logs')
def logs(pid):
    if not req(): return jsonify({'ok': False}), 401
    if not _find(pid):
        return jsonify({'ok': False, 'error': 'Project not found'}), 404
    try:
        n = max(20, min(2000, int(request.args.get('lines', 200))))
    except ValueError:
        n = 200
    rc, out = sh(['journalctl', '-u', svc_name(pid), '-n', str(n), '--no-pager', '-o', 'short-iso'])
    return jsonify({'ok': True, 'logs': out})


@python_bp.route('/api/python/projects/<pid>/git-pull', methods=['POST'])
def git_pull(pid):
    """Pull the latest commit (as the project's user), reinstall the
    dependencies and restart - in the background."""
    if not req(): return jsonify({'ok': False}), 401
    p = _find(pid)
    if not p:
        return jsonify({'ok': False, 'error': 'Project not found'}), 404
    if not os.path.isdir(os.path.join(p['path'], '.git')):
        return jsonify({'ok': False, 'error': 'This project folder is not a Git repository'}), 400

    def run():
        rc, out = sh(['git', '-C', p['path'], 'pull', '--ff-only'], timeout=300, user=p['user'],
                     env=dict(os.environ, GIT_TERMINAL_PROMPT='0', HOME=p['path']))
        if rc != 0:
            save_job(f'py_deploy_{pid}', {'running': False, 'done': True, 'success': False,
                                          'error': 'git pull failed', 'output': out[-4000:]})
            return
        _deploy_job(p, False)
    save_job(f'py_deploy_{pid}', {'running': True, 'step': 'git pull'})
    threading.Thread(target=run, daemon=True).start()
    return jsonify({'ok': True, 'job': f'py_deploy_{pid}'})


@python_bp.route('/api/python/projects/<pid>', methods=['DELETE'])
def delete_project(pid):
    """Removes the service and the reverse proxy. The project folder is kept
    unless delete_files is true."""
    if not req(): return jsonify({'ok': False}), 401
    p = _find(pid)
    if not p:
        return jsonify({'ok': False, 'error': 'Project not found'}), 404
    sh(['systemctl', 'disable', '--now', svc_name(pid)], timeout=60)
    try:
        os.remove(f'/etc/systemd/system/{svc_name(pid)}.service')
    except OSError:
        pass
    sh(['systemctl', 'daemon-reload'])
    _go.remove_proxy(pid, prefix='vortex-py')
    if (request.get_json(silent=True) or {}).get('delete_files'):
        real = os.path.realpath(p['path'])
        if real.count('/') >= 3 and not real.startswith(('/etc', '/usr', '/opt/vortexpanel', '/root')):
            shutil.rmtree(real, ignore_errors=True)
    save_projects([x for x in load_projects() if x['id'] != pid])
    return jsonify({'ok': True})
