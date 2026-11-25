"""All Projects and Scan & import.

  GET  /api/projects/all             every website and app project on this server in one list:
                                     PHP / static / WordPress websites, Node.js, Go and Python
                                     projects, Docker containers
  GET  /api/projects/scan/<kind>     running apps the panel does not manage yet
                                     (kind: pm2 | go | python), see panel/project_scan.py
  POST /api/projects/import/<kind>   take one over as a panel project
"""
import json
import os
import re
import shlex
import subprocess
import time

from flask import Blueprint, jsonify, request

from panel import project_scan as S
from panel.utils.authctx import authed as _vp_authed

projects_bp = Blueprint('projects_all', __name__)
_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._-]{0,59}$')


def req():
    return _vp_authed()


def _admin():
    try:
        from panel.utils.authctx import is_admin
        return is_admin()
    except Exception:  # noqa: BLE001
        return False


def _unit_states(units):
    """{unit: ActiveState} in one systemctl call."""
    if not units:
        return {}
    try:
        r = subprocess.run(['systemctl', 'show', '--property=Id,ActiveState', '--'] + units,
                           capture_output=True, text=True, timeout=20)
    except Exception:  # noqa: BLE001
        return {}
    res = {}
    for block in r.stdout.strip().split('\n\n'):
        props = dict(l.split('=', 1) for l in block.splitlines() if '=' in l)
        if props.get('Id'):
            res[props['Id']] = props.get('ActiveState', '')
    return res


def _unique_id(base, taken):
    base = re.sub(r'[^a-z0-9_-]', '', base.lower().replace(' ', '-'))[:40] or 'app'
    pid, n = base, 2
    while pid in taken:
        pid = f'{base[:36]}-{n}'
        n += 1
    return pid


# ------------------------------------------------------------------ All Projects

@projects_bp.route('/api/projects/all')
def all_projects():
    if not req(): return jsonify({'ok': False}), 401
    rows, errors = [], []
    # websites (PHP, static, WordPress, reverse proxy)
    try:
        from panel.routes.websites_core import list_sites, site_names
        names = site_names()
        for s in list_sites():
            path = s.get('path') or ''
            kind = 'wordpress' if path and os.path.isfile(os.path.join(path, 'wp-config.php')) else \
                   ('php' if s.get('php') and s.get('php') not in ('static', 'none', '') else 'static')
            rows.append({'type': kind, 'name': names.get(s.get('domain')) or s.get('domain'), 'domain': s.get('domain'), 'path': path,
                         'status': 'active' if s.get('enabled', True) else 'stopped',
                         'detail': (f'PHP {s["php"]}' if kind != 'static' and s.get('php') else 'Static') +
                                   (' · ' + s.get('webserver', '') if s.get('webserver') else ''),
                         'ssl': bool(s.get('ssl')), 'page': 'wp' if kind == 'wordpress' else 'websites'})
    except Exception as e:  # noqa: BLE001
        errors.append(f'websites: {e}')
    # Node.js, Go, Python projects (one systemctl call for all their units)
    groups = []
    try:
        from panel.routes import nodejs_projects as N
        groups.append(('node', N.load_projects(), N.svc_name, 'node-projects'))
    except Exception as e:  # noqa: BLE001
        errors.append(f'node: {e}')
    try:
        from panel.routes import go_projects as G
        groups.append(('go', G.load_projects(), G.svc_name, 'go-projects'))
    except Exception as e:  # noqa: BLE001
        errors.append(f'go: {e}')
    try:
        from panel.routes import python_projects as P
        groups.append(('python', P.load_projects(), P.svc_name, 'python-projects'))
    except Exception as e:  # noqa: BLE001
        errors.append(f'python: {e}')
    units = [svc(p['id']) + '.service' for kind, lst, svc, _pg in groups for p in lst if not p.get('pm2')]
    states = _unit_states(units)
    pm2 = {}
    if any(p.get('pm2') for kind, lst, _s, _pg in groups for p in lst):
        try:
            from panel.routes import nodejs_projects as N
            pm2 = {a.get('name'): (a.get('pm2_env') or {}).get('status', '') for a in N.pm2_list_raw()}
        except Exception:  # noqa: BLE001
            pm2 = {}
    for kind, lst, svc, page in groups:
        for p in lst:
            if p.get('pm2'):
                st = pm2.get(p.get('pm2_name') or p['id'], 'stopped')
                status = 'active' if st == 'online' else ('stopped' if st in ('stopped', '') else st)
                detail = 'PM2'
            else:
                status = states.get(svc(p['id']) + '.service', 'inactive') or 'inactive'
                detail = {'node': 'systemd', 'go': 'Go binary', 'python': (p.get('mode') or '').capitalize()}[kind]
            rows.append({'type': kind, 'name': p.get('name') or p['id'], 'id': p['id'],
                         'domain': (p.get('domain') or '').split()[0] if p.get('domain') else '',
                         'path': p.get('path') or p.get('work_dir') or os.path.dirname(p.get('exec_file') or ''),
                         'port': str(p.get('port') or ''), 'status': status,
                         'detail': detail + (' · imported' if p.get('imported') else ''), 'page': page})
    # Docker containers
    if os.path.exists('/var/run/docker.sock') or os.path.exists('/run/docker.sock'):
        try:
            r = subprocess.run(['docker', 'ps', '-a', '--format', '{{json .}}'], capture_output=True,
                               text=True, timeout=20)
            for line in r.stdout.splitlines():
                try:
                    c = json.loads(line)
                except ValueError:
                    continue
                names = c.get('Names')
                name = names[0] if isinstance(names, list) else (names or c.get('ID', ''))
                state = (c.get('State') or '').lower()
                ports = c.get('Ports') if isinstance(c.get('Ports'), str) else ''
                rows.append({'type': 'docker', 'name': name, 'domain': '', 'path': '',
                             'port': ', '.join(sorted(set(re.findall(r':(\d+)->', ports or ''))))[:40],
                             'status': 'active' if state == 'running' else (state or 'stopped'),
                             'detail': c.get('Image', ''), 'page': 'docker'})
        except Exception as e:  # noqa: BLE001
            errors.append(f'docker: {e}')
    counts = {}
    for r in rows:
        counts[r['type']] = counts.get(r['type'], 0) + 1
    return jsonify({'ok': True, 'projects': rows, 'counts': counts, 'errors': errors})


# ------------------------------------------------------------------ Scan & import

@projects_bp.route('/api/projects/scan/<kind>')
def scan(kind):
    if not req(): return jsonify({'ok': False}), 401
    if not _admin():
        return jsonify({'ok': False, 'error': 'Only the panel administrator can scan the server'}), 403
    if kind == 'pm2':
        from panel.routes import nodejs_projects as N
        registered = {p.get('pm2_name') or p['id'] for p in N.load_projects() if p.get('pm2')}
        cands = S.scan_pm2(N.pm2_list_raw(), registered)
        return jsonify({'ok': True, 'candidates': cands, 'other_pm2': S.other_pm2_daemons()})
    if kind == 'go':
        cands = S.scan_go()
    elif kind == 'python':
        cands = S.scan_python()
    else:
        return jsonify({'ok': False, 'error': 'Unknown kind'}), 400
    for c in cands:
        c.pop('argv', None)          # the command line is shown as text; env values are never sent
        c['env_keys'] = sorted(S.environ(c['pid']))
    return jsonify({'ok': True, 'candidates': cands})


def _common(d):
    name = str(d.get('name') or '').strip()
    if not _NAME_RE.match(name):
        return None, 'Project name: letters, digits, spaces, dot, dash or underscore (up to 60)'
    return name, None


@projects_bp.route('/api/projects/import/<kind>', methods=['POST'])
def import_project(kind):
    if not req(): return jsonify({'ok': False}), 401
    if not _admin():
        return jsonify({'ok': False, 'error': 'Only the panel administrator can import projects'}), 403
    d = request.get_json() or {}
    name, err = _common(d)
    if err:
        return jsonify({'ok': False, 'error': err}), 400
    domain = str(d.get('domain') or '').strip()
    log = []
    if kind == 'pm2':
        return _import_pm2(d, name, domain)
    try:
        pid_, start = int(d.get('pid')), int(d.get('start'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Choose a process from the scan'}), 400
    cand = S.candidate(kind, pid_, start)
    if not cand:
        return jsonify({'ok': False, 'error': 'That process is no longer running or is not an app the scan '
                                              'offers; scan again'}), 400
    port = str(d.get('port') or (cand['ports'][0] if cand['ports'] else '')).strip()
    if port and not (port.isdigit() and 1 <= int(port) <= 65535 and int(port) in cand['ports']):
        return jsonify({'ok': False, 'error': f'Port {port} is not one the process listens on '
                                              f'({", ".join(map(str, cand["ports"])) or "none"})'}), 400
    env = S.environ(cand['pid'])
    if kind == 'go':
        ok, res = _import_go(cand, name, domain, port, env, log)
    elif kind == 'python':
        ok, res = _import_python(cand, name, domain, port, env, str(d.get('user') or ''), log)
    else:
        return jsonify({'ok': False, 'error': 'Unknown kind'}), 400
    try:
        from panel.routes.auth import audit_event
        audit_event('project_import', f'{kind} {name} from pid {cand["pid"]}: ' + ('ok' if ok else 'failed'))
    except Exception:  # noqa: BLE001
        pass
    if not ok:
        return jsonify({'ok': False, 'error': res, 'log': log}), 400
    return jsonify({'ok': True, 'id': res, 'log': log})


def _import_pm2(d, name, domain):
    from panel.routes import nodejs_projects as N
    pm2_name = str(d.get('pm2_name') or '')
    registered = {p.get('pm2_name') or p['id'] for p in N.load_projects() if p.get('pm2')}
    cand = next((c for c in S.scan_pm2(N.pm2_list_raw(), registered) if c['pm2_name'] == pm2_name), None)
    if not cand:
        return jsonify({'ok': False, 'error': f'PM2 app "{pm2_name}" was not found or is already a project'}), 400
    projects = N.load_projects()
    pid = _unique_id(name, {p['id'] for p in projects})
    port = str(d.get('port') or cand['port'] or '').strip()
    verr = N._validate_fields({'port': port, 'domain': domain, 'env': {}, 'startup_file': ''})
    if verr:
        return jsonify({'ok': False, 'error': verr}), 400
    if domain and not port:
        return jsonify({'ok': False, 'error': 'A domain needs the port the app listens on'}), 400
    script = cand['script']
    p = {'id': pid, 'name': name, 'path': cand['cwd'] or os.path.dirname(script), 'port': port,
         'pm2': True, 'pm2_name': cand['pm2_name'], 'user': cand['user'] or 'root',
         'node_version': cand['node_version'], 'domain': domain,
         'startup_file': os.path.relpath(script, cand['cwd']) if script and cand['cwd'] and
                         script.startswith(cand['cwd'] + '/') else script,
         'run_cmd': '', 'run_opt': '', 'package_manager': 'npm',
         'clusters': cand['instances'] if isinstance(cand['instances'], int) and cand['instances'] > 0 else 1,
         'memory_limit': 1024, 'auto_restart': True, 'env': {}, 'remark': 'Imported from PM2',
         'imported': {'from': 'pm2', 'name': cand['pm2_name'], 't': int(time.time())}}
    warning = None
    if domain:
        ok, res = N.write_proxy_conf(p)
        if not ok:
            warning = res
            p['proxy_warning'] = res
    projects.append(p)
    N.save_projects(projects)
    return jsonify({'ok': True, 'id': pid, 'proxy_warning': warning,
                    'log': [f'PM2 app {cand["pm2_name"]} is now the Node.js project {pid} (it kept running).']})


def _import_go(cand, name, domain, port, env, log):
    from panel.routes import go_projects as G
    projects = G.load_projects()
    pid = _unique_id(name, {p['id'] for p in projects})
    verr = G._validate_project_fields({'port': port, 'domain': domain, 'mem_limit': '', 'cpu_quota': '', 'env': env})
    if verr:
        return False, verr
    if domain and not port:
        return False, 'A domain needs the port the program listens on'
    argv = [cand['exe']] + cand['argv'][1:]          # ExecStart needs the absolute program path
    p = {'id': pid, 'name': name, 'exec_file': cand['exe'],
         'exec_cmd': ' '.join(shlex.quote(a) for a in argv) if len(argv) > 1 else '',
         'work_dir': cand['cwd'] or os.path.dirname(cand['exe']), 'port': port, 'user': cand['user'],
         'domain': domain, 'env': env, 'remark': 'Imported (Scan & import)', 'release_port': False,
         'mem_limit': '', 'cpu_quota': '',
         'imported': {'from': cand['how'], 'cmd': cand['cmd'], 't': int(time.time())}}
    unit = G.svc_name(pid) + '.service'

    def write():
        with open(f'/etc/systemd/system/{unit}', 'w') as f:
            f.write(G._build_unit_file(p))
    ok, err = S.takeover(cand, unit, write, log.append)
    if not ok:
        return False, err
    if domain and port:
        okp, res = G.write_proxy(p)
        if not okp:
            p['proxy_warning'] = res
            log.append('Reverse proxy not written: ' + res)
    projects = G.load_projects()
    projects.append(p)
    G.save_projects(projects)
    log.append(f'{name} runs as {unit}.')
    return True, pid


def _import_python(cand, name, domain, port, env, user, log):
    from panel.routes import python_projects as P
    from panel.routes import go_projects as G
    run_user = user or cand['user']
    u, uerr = P._resolve_user(run_user)
    if uerr:
        return False, (uerr + ' (this app runs as root now: choose the user it should run as)'
                       if cand['user'] == 'root' and not user else uerr)
    projects = P.load_projects()
    pid = _unique_id(name, {p['id'] for p in projects})
    path = os.path.realpath(cand['cwd'] or '/')
    if S._system_path(path):
        return False, f'The app runs from {path}; a project folder there is not allowed'
    if domain and not G._valid_domains(domain):
        return False, 'Invalid domain (one hostname per line)'
    if domain and not port:
        return False, 'A domain needs the port the app listens on'
    argv = list(cand['argv'])
    if not argv[0].startswith('/'):
        argv[0] = cand['exe'] or argv[0]
    p = {'id': pid, 'name': name, 'path': path, 'python': cand.get('python') or '', 'mode': 'command',
         'command': ' '.join(shlex.quote(a) for a in argv), 'port': port, 'workers': 1, 'user': u,
         'domain': domain, 'env': env, 'mem_limit': '', 'cpu_quota': '', 'git_url': '', 'git_branch': '',
         'remark': 'Imported (Scan & import)', 'created': time.time(),
         'venv': cand.get('venv') or '',
         'imported': {'from': cand['how'], 'cmd': cand['cmd'], 'user': cand['user'], 't': int(time.time())}}
    if not p['venv']:
        p.pop('venv')
    unit = P.svc_name(pid) + '.service'

    def write():
        with open(f'/etc/systemd/system/{unit}', 'w') as f:
            f.write(P._unit_text(p))
    ok, err = S.takeover(cand, unit, write, log.append)
    if not ok:
        return False, err
    if domain and port:
        okp, res = G.write_proxy(p, prefix='vortex-py')
        if not okp:
            log.append('Reverse proxy not written: ' + res)
    projects = P.load_projects()
    projects.append(p)
    P.save_projects(projects)
    log.append(f'{name} runs as {unit}.')
    return True, pid
