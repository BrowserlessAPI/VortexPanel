"""Scan & import: find web apps already running on this server that VortexPanel does not
manage yet, and take them over as panel projects.

  scan(kind)      candidates of one kind: 'pm2' (apps in the panel's PM2), 'go' (programs
                  built with Go), 'python' (gunicorn / uvicorn / hypercorn / python app.py)
  candidate(...)  the same candidate again, re-checked from a fresh scan: only a process
                  the scan itself classified (same pid and start time) can be imported, so
                  the import endpoints can never be used to stop an arbitrary process
  takeover(...)   move a Go or Python process under its new VortexPanel systemd service:
                  write the unit, stop the original (its own systemd unit is stopped and
                  disabled but kept; a plain process is ended), start the panel service and
                  check it listens; when it does not, the panel service is removed and the
                  original is started again

What is never offered: programs installed from the operating system's packages, anything
under /usr, /opt/vortexpanel or VortexPanel's own builds, containers, and services the
panel already manages (vortex-go-*, vortex-py-*, vortex-node-*).
"""
import glob
import os
import pwd
import re
import shlex
import signal
import struct
import subprocess
import time

SYSTEM_PREFIXES = ('/usr/', '/bin/', '/sbin/', '/lib/', '/lib64/', '/snap/', '/opt/vortexpanel',
                   '/usr/local/vortex/', '/var/lib/docker/', '/var/lib/containerd/', '/run/containerd/',
                   '/proc/', '/var/lib/snapd/')
MANAGED_UNIT = re.compile(r'^(vortex-(go|py|node)-|vortexpanel)')
CONTAINER_CG = re.compile(r'(docker|containerd|libpod|lxc|kubepods|machine\.slice)')
PY_NAMES = re.compile(r'^(python(\d+(\.\d+)?)?|gunicorn|uvicorn|hypercorn|daphne|waitress-serve)$')
APP_SPEC = re.compile(r'^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_.()]*$')
# environment of the running process carried into the new service; the rest is per-login noise
ENV_SKIP = re.compile(r'^(PATH|HOME|LANG|LANGUAGE|LC_\w+|USER|LOGNAME|SHELL|PWD|OLDPWD|SHLVL|TERM|_|MAIL|'
                      r'INVOCATION_ID|JOURNAL_STREAM|SYSTEMD_EXEC_PID|NOTIFY_SOCKET|LISTEN_\w+|MANAGERPID|'
                      r'XDG_\w+|SSH_\w+|LS_COLORS|MOTD_SHOWN|DBUS_\w+|TMUX\w*|STY|WINDOW|SUDO_\w+|'
                      r'VIRTUAL_ENV|PYTHONUNBUFFERED|PS1|HISTSIZE|HISTFILESIZE|LESSOPEN|LESSCLOSE|'
                      r'PM2_\w+|pm_\w+|NODE_APP_INSTANCE|unique_id|exit_code|status|axm_\w+|'
                      r'instance_var|vizion\w*|watch|autorestart|restart_time|created_at|'
                      r'COLUMNS|LINES|EDITOR|VISUAL|PAGER)$')


def _read(path, binary=False):
    try:
        with open(path, 'rb' if binary else 'r', errors=None if binary else 'replace') as f:
            return f.read()
    except OSError:
        return b'' if binary else ''


def _run(argv, timeout=20):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, errors='replace')
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ''


def _cg_path(pid):
    """The process's cgroup path (unified hierarchy, or systemd's own on a v1 host)."""
    cg = _read(f'/proc/{pid}/cgroup')
    paths = {}
    for line in cg.splitlines():
        parts = line.split(':', 2)
        if len(parts) == 3:
            paths[parts[1]] = parts[2]
    return paths.get('name=systemd') or paths.get('') or ''


_ROOT = None


def _cg_root():
    """Where this machine's own processes start in the cgroup tree: '/' on a normal server,
    '/lxc/<vps>' or '/docker/<id>' when the whole server is itself a container that shares
    the host's cgroup namespace (LXC/OpenVZ VPS). Taken from PID 1 (init.scope)."""
    global _ROOT
    if _ROOT is None:
        p1 = _cg_path(1)
        _ROOT = p1[:-len('/init.scope')] if p1.endswith('/init.scope') else ''
    return _ROOT


def _unit_of(pid):
    """(systemd unit or '', in a container?) from /proc/<pid>/cgroup. Only a container below
    this machine's own cgroup root counts (Docker/Podman/LXC containers on this server)."""
    path = _cg_path(pid)
    root = _cg_root()
    if root and path.startswith(root):
        path = path[len(root):]
    if CONTAINER_CG.search(path):
        return '', True
    for part in reversed(path.split('/')):
        if part.endswith('.service'):
            return part, False
    return '', False


def proc(pid):
    """Facts about one process, or None when it is gone or a kernel thread."""
    pid = int(pid)
    raw = _read(f'/proc/{pid}/cmdline', binary=True)
    if not raw:
        return None
    argv = [a.decode('utf-8', 'replace') for a in raw.rstrip(b'\0').split(b'\0')]
    stat = _read(f'/proc/{pid}/stat')
    try:
        rest = stat[stat.rindex(')') + 2:].split()
        ppid, start = int(rest[1]), int(rest[19])
    except (ValueError, IndexError):
        return None
    try:
        uid = os.stat(f'/proc/{pid}').st_uid
        user = pwd.getpwuid(uid).pw_name
    except (OSError, KeyError):
        uid, user = -1, '?'
    try:
        exe = os.readlink(f'/proc/{pid}/exe')
    except OSError:
        exe = ''
    try:
        cwd = os.readlink(f'/proc/{pid}/cwd')
    except OSError:
        cwd = ''
    unit, container = _unit_of(pid)
    return {'pid': pid, 'ppid': ppid, 'start': start, 'uid': uid, 'user': user, 'argv': argv,
            'exe': exe, 'cwd': cwd, 'unit': unit, 'container': container}


def environ(pid):
    """The process's own environment variables (minus login noise) for the new service."""
    raw = _read(f'/proc/{int(pid)}/environ', binary=True)
    env = {}
    for item in raw.split(b'\0'):
        k, sep, v = item.decode('utf-8', 'replace').partition('=')
        if sep and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', k) and not ENV_SKIP.match(k) and len(v) <= 4000:
            env[k] = v
    return env


def listening():
    """{pid: {ports}} of TCP listening sockets (any address)."""
    rc, out = _run(['ss', '-ltnpH'])
    res = {}
    if rc != 0:
        return res
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        m = re.search(r':(\d+)$', parts[3])
        if not m:
            continue
        port = int(m.group(1))
        for pm in re.finditer(r'pid=(\d+)', line):
            res.setdefault(int(pm.group(1)), set()).add(port)
    return res


def _children(pids_by_ppid, pid):
    out, todo = [], [pid]
    while todo:
        p = todo.pop()
        for c in pids_by_ppid.get(p, ()):
            out.append(c)
            todo.append(c)
    return out


_PKG_CACHE = {}


def package_owned(path):
    """True when an operating system package installed this file (it is not a project)."""
    if not path:
        return False
    if path in _PKG_CACHE:
        return _PKG_CACHE[path]
    owned = False
    if os.path.exists('/usr/bin/dpkg-query') or os.path.exists('/usr/bin/dpkg'):
        rc, _ = _run(['dpkg', '-S', path])
        owned = rc == 0
    elif os.path.exists('/usr/bin/rpm'):
        rc, _ = _run(['rpm', '-qf', path])
        owned = rc == 0
    _PKG_CACHE[path] = owned
    return owned


def is_go_binary(path):
    """A program built with Go: its ELF section table names .go.buildinfo (kept when the
    binary is stripped), or the build-info magic appears near the start."""
    try:
        with open(path, 'rb') as f:
            head = f.read(64)
            if head[:4] != b'\x7fELF':
                return False
            if head[4] == 2:                                     # ELF64
                end = '<' if head[5] == 1 else '>'
                shoff = struct.unpack(end + 'Q', head[0x28:0x30])[0]
                shentsize, shnum, shstrndx = struct.unpack(end + 'HHH', head[0x3A:0x40])
                if shoff and shnum and shentsize >= 64 and shstrndx < shnum:
                    f.seek(shoff)
                    table = f.read(shentsize * shnum)
                    def sec(i):
                        b = table[i * shentsize:(i + 1) * shentsize]
                        name, _t, _fl, _a, off, size = struct.unpack(end + 'IIQQQQ', b[:40])
                        return name, off, size
                    _n, stroff, strsize = sec(shstrndx)
                    f.seek(stroff)
                    names = f.read(min(strsize, 1 << 20))
                    # a section table was read: it decides (no 16 MB read of every other program)
                    return b'.go.buildinfo\0' in names
            # no section table (stripped with sstrip, or 32-bit): look for the build-info magic
            f.seek(0)
            return b'\xff Go buildinf:' in f.read(16 << 20)
    except (OSError, struct.error):
        return False


def _system_path(p):
    return not p or p.startswith(SYSTEM_PREFIXES) or p in ('/', '/root')


def _python_script(argv, cwd):
    """(script or module or app spec, server) for a Python command line."""
    base = os.path.basename(argv[0]) if argv else ''
    if base in ('gunicorn', 'uvicorn', 'hypercorn', 'daphne', 'waitress-serve') or \
            (len(argv) > 2 and argv[1] == '-m' and argv[2] in ('gunicorn', 'uvicorn', 'hypercorn', 'daphne')):
        server = base if base in ('gunicorn', 'uvicorn', 'hypercorn', 'daphne', 'waitress-serve') else argv[2]
        spec = next((a for a in reversed(argv[1:]) if APP_SPEC.match(a)), '')
        return spec, server
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '-m' and i + 1 < len(argv):
            return argv[i + 1], 'module'
        if a in ('-c',):
            return '', ''
        if a.startswith('-'):
            i += 1
            continue
        return (a if a.startswith('/') else os.path.normpath(os.path.join(cwd or '/', a))), 'script'
    return '', ''


def venv_of(path):
    """The virtualenv folder an interpreter or script runs from (bin/../pyvenv.cfg), or ''."""
    if not path or not path.startswith('/'):
        return ''
    d = os.path.dirname(path)
    if os.path.basename(d) == 'bin' and os.path.isfile(os.path.join(os.path.dirname(d), 'pyvenv.cfg')):
        return os.path.dirname(d)
    return ''


def python_version(venv, exe):
    cfg = _read(os.path.join(venv, 'pyvenv.cfg')) if venv else ''
    m = re.search(r'^version(?:_info)?\s*=\s*(\d+)\.(\d+)', cfg, re.M)
    if m:
        return f'{m.group(1)}.{m.group(2)}'
    m = re.search(r'python(\d+)\.(\d+)', exe or '')
    return f'{m.group(1)}.{m.group(2)}' if m else ''


def _suggest_name(*hints):
    for h in hints:
        h = re.sub(r'[^a-z0-9-]+', '-', (h or '').lower()).strip('-')
        if h and h not in ('www', 'wwwroot', 'app', 'src', 'srv', 'bin', 'home', 'opt', 'root', 'var'):
            return h[:40]
    return 'app'


def _base_scan():
    procs, by_ppid = {}, {}
    for d in os.listdir('/proc'):
        if d.isdigit():
            p = proc(d)
            if p:
                procs[p['pid']] = p
                by_ppid.setdefault(p['ppid'], []).append(p['pid'])
    return procs, by_ppid


def _ports(pid, by_ppid, ports):
    s = set(ports.get(pid, ()))
    for c in _children(by_ppid, pid):
        s |= ports.get(c, set())
    return sorted(s)


def _how(p):
    if p['unit'] and p['unit'] not in ('user@0.service',) and not p['unit'].startswith('user@'):
        return {'unit': p['unit']}
    return {'process': True}


def scan_go(procs=None, by_ppid=None, ports=None):
    if procs is None:
        procs, by_ppid = _base_scan()
    ports = ports if ports is not None else listening()
    out = []
    me = os.getpid()
    for p in procs.values():
        exe = p['exe']
        if not exe or exe.endswith(' (deleted)') or p['container'] or p['pid'] == me:
            continue
        if MANAGED_UNIT.match(p['unit']):
            continue
        real = os.path.realpath(exe)
        if _system_path(real) or not os.path.isfile(real):
            continue
        parent = procs.get(p['ppid'])
        if parent and parent['exe'] == exe:
            continue                                            # a child of the same program
        if not is_go_binary(real) or package_owned(real):
            continue
        pp = _ports(p['pid'], by_ppid, ports)
        out.append({'kind': 'go', 'pid': p['pid'], 'start': p['start'], 'user': p['user'],
                    'exe': real, 'argv': p['argv'], 'cmd': ' '.join(shlex.quote(a) for a in p['argv']),
                    'cwd': p['cwd'], 'ports': pp, 'how': _how(p),
                    'name': _suggest_name(os.path.basename(real), os.path.basename(p['cwd']))})
    return out


def scan_python(procs=None, by_ppid=None, ports=None):
    if procs is None:
        procs, by_ppid = _base_scan()
    ports = ports if ports is not None else listening()
    out = []
    me = os.getpid()
    for p in procs.values():
        argv = p['argv']
        if not argv or p['container'] or p['pid'] == me or MANAGED_UNIT.match(p['unit']):
            continue
        base = os.path.basename(argv[0])
        if not PY_NAMES.match(base) and not PY_NAMES.match(os.path.basename(p['exe'] or '')):
            continue
        joined = ' '.join(argv)
        if '/opt/vortexpanel' in joined or '/opt/vortexpanel' in (p['cwd'] or '') or 'multiprocessing' in joined:
            continue
        parent = procs.get(p['ppid'])
        if parent and parent['argv'] == argv:
            continue                                            # gunicorn / uvicorn worker
        script, server = _python_script(argv, p['cwd'])
        if not server:
            continue
        if server == 'script':
            if _system_path(script) or package_owned(script):
                continue
        elif server == 'module':
            if _system_path(p['cwd']):
                continue
        elif _system_path(p['cwd']):
            continue
        interp = argv[0] if argv[0].startswith('/') else (p['exe'] or '')
        if package_owned(os.path.realpath(interp)) and _system_path(p['cwd']):
            continue
        venv = venv_of(argv[0]) or venv_of(p['exe'] or '')
        pp = _ports(p['pid'], by_ppid, ports)
        out.append({'kind': 'python', 'pid': p['pid'], 'start': p['start'], 'user': p['user'],
                    'exe': p['exe'], 'argv': argv, 'cmd': ' '.join(shlex.quote(a) for a in argv),
                    'cwd': p['cwd'], 'ports': pp, 'how': _how(p), 'server': server,
                    'app': script if server not in ('script', 'module') else '',
                    'venv': venv, 'python': python_version(venv, p['exe']),
                    'name': _suggest_name(os.path.basename(p['cwd']), (script or '').split(':')[0].split('.')[0])})
    return out


def scan_pm2(pm2_apps, registered):
    """Apps in the panel's PM2 that no Node.js project points to yet."""
    out = []
    for a in pm2_apps or []:
        env = a.get('pm2_env') or {}
        name = str(a.get('name') or '')
        if not name or name in registered:
            continue
        cwd = env.get('pm_cwd') or ''
        script = env.get('pm_exec_path') or ''
        port = str((env.get('env') or {}).get('PORT') or env.get('PORT') or '')
        ports = sorted(listening().get(int(a.get('pid') or 0), set())) if a.get('pid') else []
        if not port and ports:
            port = str(ports[0])
        out.append({'kind': 'pm2', 'pm2_name': name, 'pm_id': a.get('pm_id'), 'status': env.get('status', ''),
                    'cwd': cwd, 'script': script, 'port': port, 'ports': ports,
                    'node_version': env.get('node_version', ''), 'instances': env.get('instances', 1),
                    'user': env.get('username') or 'root',
                    'name': _suggest_name(name, os.path.basename(cwd))})
    return out


def other_pm2_daemons():
    """PM2 daemons of other users (their apps are not in the panel's PM2)."""
    res = []
    for d in os.listdir('/proc'):
        if not d.isdigit():
            continue
        cmd = _read(f'/proc/{d}/cmdline', binary=True).replace(b'\0', b' ').decode('utf-8', 'replace')
        m = re.match(r'PM2 v[\d.]+: God Daemon \((.+)\)', cmd.strip())
        if m and not m.group(1).startswith('/root/'):
            try:
                user = pwd.getpwuid(os.stat(f'/proc/{d}').st_uid).pw_name
            except (OSError, KeyError):
                user = '?'
            res.append({'user': user, 'home': m.group(1)})
    return res


def candidate(kind, pid, start):
    """The candidate of this kind with this pid and start time from a fresh scan, or None."""
    procs, by_ppid = _base_scan()
    ports = listening()
    lst = scan_go(procs, by_ppid, ports) if kind == 'go' else scan_python(procs, by_ppid, ports)
    for c in lst:
        if c['pid'] == int(pid) and c['start'] == int(start):
            return c
    return None


# ------------------------------------------------------------------ takeover

def _wait(fn, seconds, step=0.5):
    end = time.time() + seconds
    while time.time() < end:
        if fn():
            return True
        time.sleep(step)
    return fn()


def _alive(pid, start):
    p = proc(pid)
    return bool(p) and p['start'] == start


def _port_free(port):
    if not port:
        return True
    return not any(int(port) in s for s in listening().values())


def _listener_in_unit(port, unit):
    for lp, ps in listening().items():
        if int(port) in ps:
            u, _c = _unit_of(lp)
            return u == unit
    return False


def takeover(cand, unit, write_unit, log=print):
    """Stop the original process and start it as `unit` (written by write_unit()). Returns
    (ok, error). On failure the panel unit is removed and the original is started again."""
    port = cand['ports'][0] if cand.get('ports') else None
    env_saved = environ(cand['pid'])
    orig_unit = (cand.get('how') or {}).get('unit', '')
    write_unit()
    subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)

    def restore(reason):
        subprocess.run(['systemctl', 'disable', '--now', unit], capture_output=True)
        try:
            os.remove(f'/etc/systemd/system/{unit}')
        except OSError:
            pass
        subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
        if orig_unit:
            subprocess.run(['systemctl', 'start', orig_unit], capture_output=True)
            log(f'Started {orig_unit} again.')
        elif not _alive(cand['pid'], cand['start']):
            try:
                pw = pwd.getpwnam(cand['user'])
                env = dict(env_saved, PATH='/usr/local/bin:/usr/bin:/bin', HOME=pw.pw_dir, USER=pw.pw_name)
                subprocess.Popen(cand['argv'], cwd=cand['cwd'] or '/', env=env, start_new_session=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 user=pw.pw_uid, group=pw.pw_gid)
                log('Started the original process again (detached, as before).')
            except Exception as e:  # noqa: BLE001
                log(f'Could not start the original process again: {e}. Start it by hand: {cand["cmd"]}')
        return False, reason

    # stop the original
    if orig_unit:
        log(f'Stopping {orig_unit}...')
        subprocess.run(['systemctl', 'stop', orig_unit], capture_output=True, timeout=120)
    else:
        log(f'Ending process {cand["pid"]}...')
        try:
            os.kill(cand['pid'], signal.SIGTERM)
        except ProcessLookupError:
            pass
        if not _wait(lambda: not _alive(cand['pid'], cand['start']), 15):
            try:
                os.kill(cand['pid'], signal.SIGKILL)
            except ProcessLookupError:
                pass
            _wait(lambda: not _alive(cand['pid'], cand['start']), 5)
    if port and not _wait(lambda: _port_free(port), 15):
        return restore(f'port {port} is still in use after stopping the original: something else '
                       '(supervisord, a process manager, a cron job) started it again')
    log(f'Starting {unit}...')
    subprocess.run(['systemctl', 'enable', '--now', unit], capture_output=True, timeout=120)
    up = _wait(lambda: subprocess.run(['systemctl', 'is-active', '--quiet', unit]).returncode == 0, 15)
    if up and port:
        up = _wait(lambda: _listener_in_unit(port, unit), 20)
    if not up:
        tail = subprocess.run(['journalctl', '-u', unit, '-n', '20', '--no-pager', '-o', 'cat'],
                              capture_output=True, text=True).stdout.strip()
        return restore('the new service did not start' + (f' or listen on port {port}' if port else '')
                       + (':\n' + tail if tail else ''))
    if orig_unit:
        subprocess.run(['systemctl', 'disable', orig_unit], capture_output=True)
        log(f'{orig_unit} is stopped and disabled (kept: re-enable it to go back).')
    return True, ''
