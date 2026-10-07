from flask import Blueprint, jsonify, request, session, Response
import subprocess, os, threading, time, json, uuid, re, shutil
try:
    from panel.routes.os_utils import get_os, pkg_install, pkg_update, nginx_install_script, php_install_script, mariadb_install_script, postgresql_install_script, redis_install_script, mongodb_install_script, docker_install_script, nodejs_install_script, panel_cache
    from panel.routes.os_utils import ensure_epel_cmd, selinux_web_booleans_cmd, selinux_port_cmd, selinux_label_cmd, selinux_allow_port
except ImportError:
    from os_utils import get_os, pkg_install, pkg_update, nginx_install_script, php_install_script, mariadb_install_script, postgresql_install_script, redis_install_script, mongodb_install_script, docker_install_script, nodejs_install_script, panel_cache
    from os_utils import ensure_epel_cmd, selinux_web_booleans_cmd, selinux_port_cmd, selinux_label_cmd, selinux_allow_port

modules_bp = Blueprint('modules', __name__)

# Service unit names differ across distros (apache2<->httpd, supervisor<->
# supervisord, mysql<->mysqld). The App Store catalog stores one logical name;
# resolve it to whichever unit actually exists on THIS host so start/stop/
# status/uninstall work on the RHEL family too, not just Debian/Ubuntu.
_SVC_ALIASES = {
    'apache2': ['apache2', 'httpd'], 'httpd': ['httpd', 'apache2'],
    'mysql': ['mysql', 'mysqld'], 'mysqld': ['mysqld', 'mysql'],
    'mariadb': ['mariadb', 'mysqld'],
    'redis-server': ['redis-server', 'redis'], 'redis': ['redis', 'redis-server'],
    'supervisor': ['supervisor', 'supervisord'], 'supervisord': ['supervisord', 'supervisor'],
    'named': ['named', 'bind9', 'named-chroot'], 'bind9': ['bind9', 'named'],
    # EPEL ClamAV has no clamav-daemon unit: the scanner is the clamd@scan instance.
    'clamav-daemon': ['clamav-daemon', 'clamd@scan'],
}

def _newest_pgdg_unit():
    """PGDG on the RHEL family installs postgresql-NN.service (one per major
    version) and no plain postgresql.service. Newest installed one, or ''."""
    try:
        out = subprocess.run(['systemctl', 'list-unit-files', '--no-legend', 'postgresql*.service'],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return ''
    best = None
    for ln in out.splitlines():
        m = re.match(r'^postgresql-(\d+)\.service\b', ln.strip())
        if m and (best is None or int(m.group(1)) > best):
            best = int(m.group(1))
    return f'postgresql-{best}' if best is not None else ''

def _resolve_svc(svc):
    """Return the systemd unit name that actually exists on this host for a
    logical service name, trying distro alternates."""
    if not svc:
        return svc
    for c in _SVC_ALIASES.get(svc, [svc]):
        try:
            rc = subprocess.run(
                f'systemctl list-unit-files {c}.service 2>/dev/null | grep -qi {c} '
                f'|| systemctl cat {c} >/dev/null 2>&1',
                shell=True, timeout=8).returncode
            if rc == 0:
                return c
        except Exception:
            pass
    if svc == 'postgresql':
        pg = _newest_pgdg_unit()
        if pg:
            return pg
    return _SVC_ALIASES.get(svc, [svc])[0]

_APT_UPDATE_RE = re.compile(r"apt-get update(?:[ \t]+-o[ \t]+[^\s;&|)]+|[ \t]+-q+)*")

def os_cmd(apt_cmd):
    """Translate apt-get commands to the current OS package manager"""
    _os = get_os()
    if _os['family'] == 'debian':
        return apt_cmd
    # RHEL/Fedora/AlmaLinux/Rocky
    cmd = apt_cmd
    cmd = cmd.replace('DEBIAN_FRONTEND=noninteractive ', '')
    cmd = cmd.replace('apt-get install -y', 'dnf install -y')
    # One grouped command, so it still works inside `if ! X; then`, `X && Y`
    # and `X 2>file` (the old 'dnf check-update -q; true' split those: `if !`
    # tested `true`, and 'a; true && b' ran b whatever happened before).
    # check-update exits 100 when updates exist -- not an error.
    cmd = _APT_UPDATE_RE.sub('{ dnf check-update -q || true; }', cmd)
    # Strip dpkg-specific options that don't apply to dnf
    import re as _re
    cmd = _re.sub(r"-o Dpkg::Options::='[^']*'\s*", '', cmd)
    cmd = _re.sub(r'-o Dpkg::Options::="[^"]*"\s*', '', cmd)
    cmd = _re.sub(r'-o Dpkg::Options::=\S+\s*', '', cmd)
    cmd = cmd.replace('apt-get remove -y --purge', 'dnf remove -y')
    cmd = cmd.replace('apt-get remove -y', 'dnf remove -y')
    cmd = cmd.replace('apt-get autoremove -y', 'dnf autoremove -y')
    # 'true', not 'true #': most templates are ONE line, so a '#' commented
    # out everything after it -- including their own RHEL branch.
    cmd = cmd.replace('add-apt-repository', 'true')
    cmd = cmd.replace('apt-get -y install', 'dnf install -y')
    # Package name differences
    cmd = cmd.replace('software-properties-common', 'dnf-plugins-core')
    # Longer names first: 'apache2' -> 'httpd' used to run before these and
    # produced httpd-utils / httpdctl / libhttpd-mod-security2 (none exist).
    cmd = cmd.replace('libapache2-mod-security2', 'mod_security')
    cmd = cmd.replace('apache2-utils', 'httpd-tools')
    cmd = cmd.replace('apache2ctl', 'apachectl')
    cmd = cmd.replace('apache2', 'httpd')
    return cmd

def translate_install_cmd(cmd):
    """Translate install command for current OS"""
    _os = get_os()
    if _os['family'] == 'debian':
        return cmd
    return os_cmd(cmd)

def req(): return 'user' in session

# --- Job store: JSONL append-only files shared across all gunicorn workers ----
# Each job = one .jsonl file where every line is a complete JSON object.
# Appending one JSON line is atomic for small writes -- no read-modify-write,
# no corruption, no locks needed between workers.
# Format per line:
#   {"line": "apt-get output..."}          -- progress output line
#   {"done": true, "success": true/false,  -- final status (last line)
#    "installed": true, "installedVer": "x.y.z", "message": "..."}
# Job files are kept after completion (so a browser that lost its stream can
# still fetch the result) and cleaned up after 24 hours.
_JOBS_DIR = '/tmp/vortex_jobs'
os.makedirs(_JOBS_DIR, exist_ok=True)
_JOB_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_finished_jobs = set()

def _job_path(job_id):
    if not _JOB_ID_RE.match(str(job_id or '')):
        return os.path.join(_JOBS_DIR, '__invalid__.jsonl')
    return os.path.join(_JOBS_DIR, f'{job_id}.jsonl')

def _job_cleanup_old(max_age=86400):
    try:
        now = time.time()
        for name in os.listdir(_JOBS_DIR):
            fp = os.path.join(_JOBS_DIR, name)
            try:
                if name.endswith('.jsonl') and now - os.path.getmtime(fp) > max_age:
                    os.remove(fp)
            except Exception:
                pass
    except Exception:
        pass

def _job_create(job_id, **_):
    """Create empty job file so SSE stream knows it exists."""
    os.makedirs(_JOBS_DIR, exist_ok=True)
    _job_cleanup_old()
    # Record which panel worker runs the job, so a job orphaned by a panel
    # restart is reported as such instead of leaving the browser waiting.
    with open(_job_path(job_id), 'w') as f:
        f.write(json.dumps({'meta': {'pid': os.getpid(), 'started': time.time()}}) + '\n')

def _job_append_line(job_id, line):
    """Append one output line. Atomic for small writes."""
    try:
        with open(_job_path(job_id), 'a') as f:
            f.write(json.dumps({'line': line}) + '\n')
    except Exception:
        pass  # non-fatal; best-effort streaming

def _job_finish(job_id, success, installed, inst_ver='', message=''):
    """Append the final status line. The human-readable result message is
    written as a normal output line FIRST, so it is always streamed before
    the browser sees "done" and closes the stream (previously the result
    line was appended after "done" and never reached the browser)."""
    if job_id in _finished_jobs:
        return
    _finished_jobs.add(job_id)
    if message:
        _job_append_line(job_id, f'[VortexPanel] {message}')
    try:
        with open(_job_path(job_id), 'a') as f:
            f.write(json.dumps({
                'done': True, 'success': bool(success),
                'installed': bool(installed), 'installedVer': inst_ver or '',
                'message': message or '',
            }) + '\n')
    except Exception:
        pass

def _job_get(job_id):
    """Read all lines from JSONL job file. Returns dict with lines[], done, etc."""
    path = _job_path(job_id)
    if not os.path.exists(path):
        return None
    lines = []
    done = False
    success = False
    installed = True
    inst_ver = ''
    message = ''
    owner = 0
    try:
        with open(path) as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if 'line' in obj:
                    lines.append(obj['line'])
                elif 'meta' in obj:
                    owner = (obj.get('meta') or {}).get('pid') or 0
                elif obj.get('done'):
                    done = True
                    success = obj.get('success', False)
                    installed = obj.get('installed', True)
                    inst_ver = obj.get('installedVer', '')
                    message = obj.get('message', '')
    except Exception:
        pass
    if not done and owner and not _job_owner_alive(owner):
        done, success = True, False
        message = ('The panel was restarted while this job was running, so its result is unknown. '
                   'Package operations it started may still be finishing -- refresh the App Store in a minute to see the current state.')
    return {'lines': lines, 'done': done, 'success': success,
            'installed': installed, 'installedVer': inst_ver, 'message': message}

def _job_owner_alive(pid):
    """True if the panel worker that started the job is still running."""
    try:
        pid = int(pid)
        if pid == os.getpid():
            return True
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            cmd = f.read().replace(b'\0', b' ').decode(errors='replace')
        return ('gunicorn' in cmd) or ('app.py' in cmd) or ('python' in cmd and 'flask' in cmd)
    except Exception:
        return False

# Shim so existing _jobs[job_id] reads still work (used nowhere new, but safe)
class _JobsShim:
    def get(self, job_id, default=None): return _job_get(job_id) or default
_jobs = _JobsShim()


# --- Package-manager wrappers ---------------------------------------------------
# Every App Store job (install, uninstall, version switch) runs with these
# wrappers first on PATH. They fix three real, confirmed failure modes:
#   1. Another apt/dpkg process holding the lock (the panel's own Security
#      Updates check, unattended-upgrades, a second install) made apt-get fail
#      instantly. Reproduced exactly for the "Can't uninstall Caddy" report:
#      apt-get remove failed in under a second and nothing was removed.
#      The wrapper waits for the lock (up to 10 minutes), says who holds it,
#      and retries, streaming output live the whole time.
#   2. The App Store commands run apt-get with 2>/dev/null, so when apt failed
#      the error text was thrown away and the job window stayed empty. If the
#      caller discarded stderr, the wrapper sends it to stdout instead, so the
#      real reason is always visible. (Deliberate redirects to a log file are
#      left alone.)
#   3. "apt-get remove a b c" aborts entirely when ANY listed package is
#      unknown, so one stale name in an uninstall list removed nothing at all.
#      For remove/purge the wrapper drops names that are not installed.
# It also repairs the "dpkg was interrupted, you must manually run
# dpkg --configure -a" state once, automatically, and retries.
_PKG_WRAP_DIR = '/var/lib/vortexpanel/pkgwrap'

_APT_WRAPPER = r"""#!/bin/bash
# Generated by VortexPanel -- package-manager wrapper for App Store jobs.
REAL="__REAL__"
DPKG_QUERY="$(PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v dpkg-query)"
DPKG="$(PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v dpkg)"
if [ "$(readlink -f /proc/$$/fd/2 2>/dev/null)" = "/dev/null" ]; then exec 2>&1; fi
args=("$@")
sub=""; skip=0
for a in "$@"; do
  if [ $skip = 1 ]; then skip=0; continue; fi
  case "$a" in -o|-c|-t|--option|--config-file|--target-release) skip=1;; -*) ;; *) sub="$a"; break;; esac
done
if [ "$sub" = "remove" ] || [ "$sub" = "purge" ]; then
  new=(); skip=0; seen=0; kept=0; dropped=""
  for a in "${args[@]}"; do
    if [ $skip = 1 ]; then new+=("$a"); skip=0; continue; fi
    case "$a" in -o|-c|-t|--option|--config-file|--target-release) new+=("$a"); skip=1; continue;; -*) new+=("$a"); continue;; esac
    if [ $seen = 0 ]; then new+=("$a"); seen=1; continue; fi
    if [ -n "$DPKG_QUERY" ] && "$DPKG_QUERY" -W -f='${db:Status-Abbrev}\n' "$a" 2>/dev/null | grep -q '^.[^n]'; then
      new+=("$a"); kept=$((kept+1))
    else
      dropped="$dropped $a"
    fi
  done
  if [ $kept = 0 ]; then
    echo "[VortexPanel] apt-get $sub: none of the listed packages are installed --$dropped -- nothing to remove."
    exit 0
  fi
  args=("${new[@]}")
fi
max=${VP_LOCK_WAIT:-600}; t0=$SECONDS; repaired=0
# Once one apt-get in this job has given up on the lock, the rest of the job's
# apt-get calls fail at once instead of each waiting the full time again.
if [ -n "$VP_LOCK_FLAG" ] && [ -f "$VP_LOCK_FLAG" ]; then
  echo "[VortexPanel] Skipped: apt-get $sub (the package manager is still locked)"
  exit 100
fi
# Who holds the apt/dpkg locks right now (never ourselves or an ancestor --
# a maintainer script of our own apt run must not wait on its parent).
is_ancestor() { local p=$$; while [ -n "$p" ] && [ "$p" -gt 1 ]; do [ "$p" = "$1" ] && return 0; p=$(awk '/^PPid:/{print $2}' /proc/$p/status 2>/dev/null); done; return 1; }
lock_holders() {
  command -v lslocks >/dev/null 2>&1 || return 0
  for p in $(lslocks -n -o PID,PATH 2>/dev/null | awk '$2 ~ /^\/var\/lib\/(dpkg\/lock(-frontend)?|apt\/lists\/lock|apt\/archives\/lock)$/ {print $1}' | sort -u); do
    is_ancestor "$p" && continue
    printf "%s (pid %s) " "$(ps -o comm= -p "$p" 2>/dev/null)" "$p"
  done
}
last=-100
while :; do
  h=$(lock_holders)
  [ -z "$h" ] && break
  w=$((SECONDS-t0))
  if [ $w -ge $max ]; then
    echo "[VortexPanel] Gave up after ${w}s: the package manager is still locked by ${h}. Try again when it has finished."
    [ -n "$VP_LOCK_FLAG" ] && : > "$VP_LOCK_FLAG"
    exit 100
  fi
  if [ $((w-last)) -ge 15 ]; then
    echo "[VortexPanel] The package manager is busy: ${h}-- waiting for it to finish... (${w}s of ${max}s)"
    last=$w
  fi
  sleep 3
done
log=$(mktemp 2>/dev/null || echo /tmp/vp_apt_$$.log)
while :; do
  "$REAL" -o DPkg::Lock::Timeout=60 "${args[@]}" 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  [ "$rc" -eq 0 ] && break
  if grep -qE "Could not get lock|Unable to lock|Unable to acquire the dpkg frontend lock|is locked by another process|is held by process" "$log"; then
    waited=$((SECONDS-t0))
    holder=$(lock_holders)
    if [ $waited -ge $max ]; then
      echo "[VortexPanel] Gave up after ${waited}s: the package manager is still locked by: ${holder:-another process}. Try again when it has finished."
      [ -n "$VP_LOCK_FLAG" ] && : > "$VP_LOCK_FLAG"
      break
    fi
    echo "[VortexPanel] The package manager is busy (${holder:-another process}) -- waiting for it to finish... (${waited}s of ${max}s)"
    sleep 10; continue
  fi
  if [ $repaired = 0 ] && grep -q "dpkg --configure -a" "$log" && [ -n "$DPKG" ]; then
    echo "[VortexPanel] A previous package operation was interrupted -- running 'dpkg --configure -a' and retrying"
    DEBIAN_FRONTEND=noninteractive "$DPKG" --configure -a --force-confdef --force-confold 2>&1
    repaired=1; continue
  fi
  break
done
rm -f "$log"
exit $rc
"""

_DPKG_WRAPPER = r"""#!/bin/bash
# Generated by VortexPanel -- waits for the dpkg lock instead of failing.
REAL="__REAL__"
max=${VP_LOCK_WAIT:-600}; waited=0
case " $* " in
  *" -i "*|*" --install "*|*" --configure "*|*" -r "*|*" -P "*|*" --remove "*|*" --purge "*) ;;
  *) exec "$REAL" "$@" ;;
esac
if [ "$(readlink -f /proc/$$/fd/2 2>/dev/null)" = "/dev/null" ]; then exec 2>&1; fi
log=$(mktemp 2>/dev/null || echo /tmp/vp_dpkg_$$.log)
while :; do
  "$REAL" "$@" 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  [ "$rc" -eq 0 ] && break
  if grep -qE "lock was locked by another process|Unable to acquire the dpkg|status database area is locked" "$log" && [ $waited -lt $max ]; then
    echo "[VortexPanel] dpkg is busy with another process -- waiting... (${waited}s of ${max}s)"
    sleep 10; waited=$((waited+10)); continue
  fi
  break
done
rm -f "$log"
exit $rc
"""

_RPM_WRAPPER = r"""#!/bin/bash
# Generated by VortexPanel -- shows dnf/yum errors even when the caller
# discarded stderr (dnf/yum already wait for their own lock).
REAL="__REAL__"
if [ "$(readlink -f /proc/$$/fd/2 2>/dev/null)" = "/dev/null" ]; then exec 2>&1; fi
exec "$REAL" "$@"
"""

def _ensure_pkg_wrappers():
    """(Re)write the wrapper scripts for whichever package tools exist on this
    host. Returns the wrapper directory, or '' if it could not be created
    (jobs then run without wrappers rather than not at all)."""
    try:
        os.makedirs(_PKG_WRAP_DIR, exist_ok=True)
        clean_path = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
        for tool, body in (('apt-get', _APT_WRAPPER), ('dpkg', _DPKG_WRAPPER),
                           ('dnf', _RPM_WRAPPER), ('yum', _RPM_WRAPPER)):
            dest = os.path.join(_PKG_WRAP_DIR, tool)
            real = shutil.which(tool, path=clean_path)
            if not real or not shutil.which('bash', path=clean_path):
                if os.path.exists(dest):
                    os.remove(dest)
                continue
            content = body.replace('__REAL__', real)
            try:
                with open(dest) as f:
                    if f.read() == content and os.access(dest, os.X_OK):
                        continue
            except Exception:
                pass
            tmp = dest + '.tmp'
            with open(tmp, 'w') as f:
                f.write(content)
            os.chmod(tmp, 0o755)
            os.replace(tmp, dest)
        return _PKG_WRAP_DIR
    except Exception:
        return ''

def _job_env(job_id=''):
    env = os.environ.copy()
    if job_id:
        env['VP_LOCK_FLAG'] = _job_path(job_id) + '.lockfail'
    env['DEBIAN_FRONTEND'] = 'noninteractive'
    env['APT_LISTCHANGES_FRONTEND'] = 'none'
    env['UCF_FORCE_CONFFOLD'] = '1'
    env['NEEDRESTART_MODE'] = 'a'   # Ubuntu 22.04+: never block on the needrestart prompt
    env.setdefault('PATH', '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
    wrap = _ensure_pkg_wrappers()
    if wrap:
        env['PATH'] = wrap + ':' + env['PATH']
    return env

_DPKG_PROGRESS_RE = re.compile(r'^\(Reading database \.\.\.\s*(\d+%)?\s*$')

def _run_streaming(job_id, cmd, max_seconds, what='Operation'):
    """Run a shell command, streaming every output line into the job.
    A watchdog kills the whole process group after max_seconds even if the
    command has gone silent (the old per-line check only fired when a new
    line arrived, so a hung download never timed out). Returns
    (returncode, timed_out)."""
    import signal
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, text=True, bufsize=1, env=_job_env(job_id),
                            errors='replace', start_new_session=True)
    timed_out = {'v': False}
    def _kill():
        timed_out['v'] = True
        _job_append_line(job_id, f'[VortexPanel] {what} exceeded {max_seconds // 60} minutes -- stopping it.')
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(proc.pid, sig)
            except Exception:
                pass
            time.sleep(5)
    timer = threading.Timer(max_seconds, _kill)
    timer.daemon = True
    timer.start()
    try:
        for line in proc.stdout:
            line = line.rstrip('\r\n')
            # dpkg's "(Reading database ... 5%" progress arrives as ~20
            # separate lines once \r is split; keep only the final count.
            if _DPKG_PROGRESS_RE.match(line):
                continue
            _job_append_line(job_id, line)
        proc.wait()
    finally:
        timer.cancel()
        try:
            os.remove(_job_path(job_id) + '.lockfail')
        except Exception:
            pass
    return proc.returncode, timed_out['v']

def _start_job_thread(job_id, fn, installed_on_error):
    """Run fn in a background thread. Whatever happens inside it (including
    an unexpected Python exception), the job ALWAYS gets a final "done" line
    -- previously an exception (e.g. TimeoutExpired from systemctl stop) killed
    the thread silently and left the browser waiting forever."""
    def runner():
        try:
            fn()
        except Exception as e:
            _job_append_line(job_id, f'[VortexPanel] Internal error: {type(e).__name__}: {e}')
            _job_finish(job_id, success=False, installed=installed_on_error,
                        message='The operation stopped because of an internal error (shown above).')
        finally:
            if job_id not in _finished_jobs:
                _job_finish(job_id, success=False, installed=installed_on_error,
                            message='The operation ended without reporting a result.')
            try:
                panel_cache.invalidate('modules_list')
            except Exception:
                pass
    threading.Thread(target=runner, daemon=True).start()

def _pkg_lock_holders():
    """Processes (other than this panel) holding the apt/dpkg locks now."""
    out = []
    try:
        r = subprocess.run(['lslocks', '-n', '-o', 'PID,PATH'], capture_output=True, text=True, timeout=10)
    except Exception:
        return out
    paths = ('/var/lib/dpkg/lock-frontend', '/var/lib/dpkg/lock', '/var/lib/apt/lists/lock', '/var/lib/apt/archives/lock')
    seen = set()
    for ln in r.stdout.splitlines():
        parts = ln.split(None, 1)
        if len(parts) == 2 and parts[1].strip() in paths and parts[0] not in seen:
            seen.add(parts[0])
            try:
                with open(f'/proc/{parts[0]}/comm') as f:
                    name = f.read().strip()
            except Exception:
                name = '?'
            out.append(f'{name} (pid {parts[0]})')
    return out

def _wait_pkg_lock(job_id, max_seconds=600):
    """Wait until no other process holds the package-manager lock. Returns
    True when free. Used BEFORE an uninstall touches anything, so a busy
    package manager never leaves an app stopped but still installed."""
    if not shutil.which('apt-get') and not os.path.exists('/var/lib/dpkg'):
        return True
    start = time.time(); last = -100
    while True:
        h = _pkg_lock_holders()
        if not h:
            return True
        w = int(time.time() - start)
        if w >= max_seconds:
            return False
        if w - last >= 15:
            _job_append_line(job_id, f'[VortexPanel] The package manager is busy: {", ".join(h)} -- waiting for it to finish before changing anything... ({w}s of {max_seconds}s)')
            last = w
        time.sleep(3)

def _svc_active(svc):
    if not svc:
        return False
    try:
        return subprocess.run(['systemctl', 'is-active', '--quiet', svc], timeout=15).returncode == 0
    except Exception:
        return False

def _svc_stop(job_id, svc):
    """Stop a service without ever raising. Falls back to systemctl kill if
    a normal stop hangs (a stop that hung past 15s used to raise
    TimeoutExpired and kill the whole uninstall job)."""
    try:
        r = subprocess.run(['systemctl', 'stop', svc], capture_output=True, text=True, timeout=90)
        if r.returncode != 0 and r.stderr.strip() and 'not loaded' not in r.stderr:
            _job_append_line(job_id, r.stderr.strip())
    except subprocess.TimeoutExpired:
        _job_append_line(job_id, f'[VortexPanel] {svc} did not stop within 90s -- forcing it to stop')
        try:
            subprocess.run(['systemctl', 'kill', '--signal=SIGKILL', svc], timeout=30)
        except Exception:
            pass
    except Exception as e:
        _job_append_line(job_id, f'[VortexPanel] Could not stop {svc}: {e}')

def _svc_start(svc):
    try:
        subprocess.run(['systemctl', 'reset-failed', svc], capture_output=True, timeout=30)
        subprocess.run(['systemctl', 'enable', svc], capture_output=True, timeout=60)
        subprocess.run(['systemctl', 'start', svc], capture_output=True, timeout=120)
    except Exception:
        pass
    return _svc_active(svc)

def _system_python_ver():
    """major.minor of the OS's own python3 (never removable from the panel)."""
    for exe in ('/usr/bin/python3', '/usr/libexec/platform-python'):
        if os.path.exists(exe):
            try:
                out = subprocess.run([exe, '-c', 'import sys;print("%d.%d" % sys.version_info[:2])'],
                                     capture_output=True, text=True, timeout=10).stdout.strip()
                if out:
                    return out
            except Exception:
                pass
    return ''

def sh(c, t=10):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()
    except: return ''

def get_version(mod_id, ver=None):
    cmds = {
        'nginx':        "nginx -v 2>&1 | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        # Grouped: 'a | grep | head || b' never ran b (head exits 0).
        'apache2':      "{ apache2 -v 2>/dev/null || httpd -v 2>/dev/null; } | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'openlitespeed':"{ cat /usr/local/lsws/VERSION 2>/dev/null || /usr/local/lsws/bin/lshttpd -v 2>/dev/null; } | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'caddy':        "caddy version 2>/dev/null | awk '{print $1}' | tr -d v",
        'mysql':        "mysqld --version 2>/dev/null | grep -iv mariadb | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'mariadb':      "{ mariadbd --version 2>/dev/null || mysqld --version 2>/dev/null; } | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'mongodb':      "mongod --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'redis':        "redis-server --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'nodejs':       "node --version 2>/dev/null | tr -d 'v'",
        # PHP and PostgreSQL both support multiple versions installed side by
        # side. A fixed priority list here (checking 8.5 before 7.4, or just
        # trusting whatever `psql`/`php` resolves to via update-alternatives)
        # is exactly what caused a real, confirmed bug: installing PHP 7.4
        # on a system that already had 8.5 reported back "Version: 8.5.8" --
        # the 7.4 that was ACTUALLY just installed was never even checked.
        # When the caller knows which version was just requested, check that
        # one specifically; only fall back to the priority list when it
        # isn't known (e.g. refreshing the general module list).
        'php':          (f"php{ver} --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+' | head -1" if ver else
                          "for v in 8.5 8.4 8.3 8.2 8.1 8.0 7.4; do if which php$v >/dev/null 2>&1; then php$v --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+' | head -1; break; fi; done"),
        'postgresql':   (f"psql --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+' | head -1" if not ver else
                          f"(psql -V 2>/dev/null | grep -q '{ver}' && psql --version | grep -oP '[0-9]+\\.[0-9]+' | head -1) || (which psql{ver} >/dev/null 2>&1 && echo {ver}) || (test -d /usr/lib/postgresql/{ver} && echo {ver})"),
        'python':       "python3 --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+'",
        'docker':       "docker --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'composer':     "composer --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'fail2ban':     "fail2ban-client --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'pure-ftpd':    "pure-ftpd --help 2>&1 | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'clamav':       "clamscan --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'bind9':        "named -v 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'supervisor':   "supervisord --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+'",
        'phpmyadmin':   "grep -oP '\"version\": \"\\K[0-9]+[.][0-9]+[.][0-9]+' /usr/share/phpmyadmin/composer.json 2>/dev/null | head -1",
        'roundcube':    "grep -oP '\"version\": \"\\K[0-9]+[.][0-9]+[.][0-9]+' /var/www/roundcube/composer.json 2>/dev/null | head -1",
        'modsecurity':  "{ modsec_rules_check --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1; dpkg-query -W -f='${Version}\\n' libmodsecurity3t64 libmodsecurity3 2>/dev/null; rpm -q --qf '%{VERSION}\\n' libmodsecurity mod_security 2>/dev/null | grep -v 'not installed'; } | grep -m1 .",
    }

    if mod_id == 'php':
        # Debian phpX.Y, Remi SCL and the RHEL system PHP all via php.py.
        try:
            lays = [php_layout(ver)] if ver else installed_php_layouts()
            lay = next((l for l in lays if l and os.path.exists(l['bin'])), None)
        except Exception:
            lay = None
        if lay:
            cmds['php'] = f'"{lay["bin"]}" -n -r "echo PHP_VERSION;" 2>/dev/null'
    cmd = cmds.get(mod_id, '')
    if not cmd: return ''
    v = sh(cmd)
    return v[:20] if v else ''

def is_installed(check_cmd):
    try:
        r = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, timeout=5)
        out = r.stdout.strip()
        if out in ('', '0', 'inactive', 'unknown', 'failed', 'activating'): return False
        return r.returncode == 0
    except: return False

# --- Shell snippets used by several catalog install scripts ----------------------------
# PHP-FPM socket for the phpMyAdmin / Roundcube sites: every layout php.py knows
# (Debian/sury /run/php/phpX.Y-fpm.sock, Remi SCL /var/opt/remi/phpXY/run/
# php-fpm/www.sock, RHEL/Fedora system PHP /run/php-fpm/www.sock) -- previously
# only the Debian sockets were looked for, with a hard-coded
# /run/php/php8.5-fpm.sock fallback that did not exist (every PHP request 502).
# An installed but stopped FPM is started. Sets SOCK ('' = none) and PUSER (the
# pool's user, which must own the app's writable directories). Order of
# preference: $PHP_PREF. A brace group, so it can sit inside an && chain.
_PHP_SOCK_SH = r'''{
VP_FIND_SOCK() {
  SOCK=""
  for v in ${PHP_PREF:-8.4 8.3 8.2 8.1 8.0 7.4 8.5}; do
    vn=$(echo "$v" | tr -d .)
    for s in /run/php/php$v-fpm.sock /var/opt/remi/php$vn/run/php-fpm/www.sock; do
      if [ -S "$s" ]; then SOCK=$s; return 0; fi
    done
  done
  for s in /run/php-fpm/www.sock /run/php/php-fpm.sock; do
    if [ -S "$s" ]; then SOCK=$s; return 0; fi
  done
  return 0
}
VP_FIND_SOCK
if [ -z "$SOCK" ]; then
  for u in $(for v in ${PHP_PREF:-8.4 8.3 8.2 8.1 8.0 7.4 8.5}; do echo "php$v-fpm php$(echo "$v" | tr -d .)-php-fpm"; done) php-fpm; do
    if systemctl cat "$u" >/dev/null 2>&1; then
      echo "[VortexPanel] Starting $u (installed but not running)"
      systemctl enable --now "$u" >/dev/null 2>&1; sleep 2; break
    fi
  done
  VP_FIND_SOCK
fi
PUSER=""
if [ -n "$SOCK" ]; then
  POOLF=$(grep -lsE "^[[:space:]]*listen[[:space:]]*=[[:space:]]*$SOCK[[:space:]]*$" /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf /etc/opt/remi/php*/php-fpm.d/*.conf | head -1)
  [ -n "$POOLF" ] && PUSER=$(sed -n 's/^[[:space:]]*user[[:space:]]*=[[:space:]]*\([^[:space:];]*\).*/\1/p' "$POOLF" | head -1)
fi
if [ -z "$PUSER" ] || ! id "$PUSER" >/dev/null 2>&1; then
  PUSER=$(id -un www-data 2>/dev/null || id -un nginx 2>/dev/null || id -un apache 2>/dev/null || echo nobody)
fi
}'''

# nginx.org packages run nginx as 'nginx' while Debian pools hand the FPM
# socket to www-data (0660): let nginx's user connect to the pool behind $SOCK
# ($POOLF from _PHP_SOCK_SH). RHEL pools grant access with listen.acl_users.
_NGINX_POOL_SH = r'''{
NGINX_USER=$(grep -oE "^[[:space:]]*user[[:space:]]+[^;[:space:]]+" /etc/nginx/nginx.conf 2>/dev/null | awk '{print $2}' | head -1)
if [ -n "$NGINX_USER" ] && [ -n "$POOLF" ] && ! grep -qE "^[[:space:]]*listen\.acl_users" "$POOLF"; then
  CUR=$(sed -n 's/^[[:space:]]*listen\.owner[[:space:]]*=[[:space:]]*//p' "$POOLF" | head -1)
  if [ "$CUR" != "$NGINX_USER" ]; then
    for K in listen.owner listen.group; do
      if grep -qE "^[[:space:]]*$K[[:space:]]*=" "$POOLF"; then sed -i -E "s|^[[:space:]]*$K[[:space:]]*=.*|$K = $NGINX_USER|" "$POOLF"; else echo "$K = $NGINX_USER" >> "$POOLF"; fi
    done
    case "$POOLF" in
      /etc/php/*) U="php$(echo "$POOLF" | cut -d/ -f4)-fpm" ;;
      /etc/opt/remi/*) U="$(echo "$POOLF" | cut -d/ -f5)-php-fpm" ;;
      *) U=php-fpm ;;
    esac
    systemctl restart "$U"
  fi
fi
}'''

# Pure-FTPd only authenticates the panel's virtual users with PureDB enabled
# (same logic as ftp._ensure_puredb_enabled): Debian keeps it off (no auth/
# link), the RHEL/EPEL pure-ftpd.conf has the PureDB line commented out.
_PUREDB_SH = r'''{
# The PureDB file must exist before pure-ftpd starts with PureDB enabled
# ("Invalid configuration file ... pureftpd.pdb: No such file" otherwise).

if [ ! -s /etc/pure-ftpd/pureftpd.pdb ] && command -v pure-pw >/dev/null 2>&1; then
  mkdir -p /etc/pure-ftpd; touch /etc/pure-ftpd/pureftpd.passwd; chmod 600 /etc/pure-ftpd/pureftpd.passwd
  pure-pw mkdb /etc/pure-ftpd/pureftpd.pdb -f /etc/pure-ftpd/pureftpd.passwd >/dev/null 2>&1 || true
fi
if [ -d /etc/pure-ftpd/conf ] && [ -d /etc/pure-ftpd/auth ]; then
  [ -s /etc/pure-ftpd/conf/PureDB ] || echo /etc/pure-ftpd/pureftpd.pdb > /etc/pure-ftpd/conf/PureDB
  if ! readlink /etc/pure-ftpd/auth/* 2>/dev/null | grep -q 'PureDB$'; then ln -sfn ../conf/PureDB /etc/pure-ftpd/auth/50pure; fi
  echo "[VortexPanel] PureDB authentication enabled (panel FTP accounts)"
else
  for C in /etc/pure-ftpd/pure-ftpd.conf /etc/pure-ftpd.conf; do
    [ -f "$C" ] || continue
    if ! grep -qE '^[[:space:]]*PureDB[[:space:]]+[^[:space:]]' "$C"; then
      if grep -qE '^[[:space:]]*#[[:space:]]*PureDB[[:space:]]' "$C"; then
        sed -i -E '0,/^[[:space:]]*#[[:space:]]*PureDB[[:space:]].*/s||PureDB                       /etc/pure-ftpd/pureftpd.pdb|' "$C"
      else
        echo 'PureDB                       /etc/pure-ftpd/pureftpd.pdb' >> "$C"
      fi
      echo "[VortexPanel] PureDB authentication enabled in $C (panel FTP accounts)"
    fi
    break
  done
fi
}'''

# fail2ban's ban action must match the firewall this server really has: the
# upstream .deb keeps banaction = iptables-multiport, and Debian 12/13 minimal
# images have no iptables at all (every ban failed); with firewalld running
# the bans belong in firewalld. Debian 12+ without rsyslog has no auth.log, so
# the sshd jail (enabled by the package) must read the journal or fail2ban
# refuses to start. Written to a file of our own, never over the admin's:
# only when it does not exist or still starts with our marker line.
_F2B_BANACTION_SH = r'''{
F2B_LOCAL=/etc/fail2ban/jail.d/00-vortexpanel.local
if [ -d /etc/fail2ban ] && { [ ! -e "$F2B_LOCAL" ] || head -1 "$F2B_LOCAL" | grep -q "Managed by VortexPanel"; }; then
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then BA=firewallcmd-rich-rules; BAA=firewallcmd-allports
  elif command -v iptables >/dev/null 2>&1; then BA=iptables-multiport; BAA=iptables-allports
  elif command -v nft >/dev/null 2>&1; then BA=nftables-multiport; BAA=nftables-allports
  else BA=iptables-multiport; BAA=iptables-allports; fi
  mkdir -p /etc/fail2ban/jail.d
  [ -e "$F2B_LOCAL" ] && cp -f "$F2B_LOCAL" "$F2B_LOCAL.vpbak"
  {
    echo "# Managed by VortexPanel (ban action for this server's firewall). Delete this line to keep your own edits."
    echo "[DEFAULT]"
    echo "banaction = $BA"
    echo "banaction_allports = $BAA"
    if [ ! -f /var/log/auth.log ] && [ ! -f /var/log/secure ] && python3 -c "import systemd.journal" >/dev/null 2>&1; then
      printf '\n[sshd]\nbackend = systemd\n'
    fi
  } > "$F2B_LOCAL"
  if fail2ban-client -t >/dev/null 2>&1; then
    echo "[VortexPanel] fail2ban ban action: $BA"
    rm -f "$F2B_LOCAL.vpbak"
  else
    echo "[VortexPanel] fail2ban rejected $F2B_LOCAL -- not changed:"
    fail2ban-client -t 2>&1 | tail -5
    if [ -f "$F2B_LOCAL.vpbak" ]; then mv -f "$F2B_LOCAL.vpbak" "$F2B_LOCAL"; else rm -f "$F2B_LOCAL"; fi
  fi
fi
}'''

# Weekly OWASP CRS update. Runs the panel's own update (security.py
# modsec_update_crs: latest release only -- never a v4.0.0 fallback -- unpacked
# into a fresh directory, config-tested, previous ruleset restored on failure,
# no stale rule files left from the old release). Writes $CRS_CRON_FILE.
_CRS_CRON_LINE = ('0 3 * * 0 root mkdir -p /var/log/vortexpanel; cd /opt/vortexpanel && '
                  'venv/bin/python3 -m panel.routes.modules update-crs >> /var/log/vortexpanel/crs-update.log 2>&1')
_CRS_CRON_SH = ("printf '%s\\n' '# Managed by VortexPanel -- weekly OWASP CRS update (tested, rolled back on failure)' "
                "'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' "
                f"'{_CRS_CRON_LINE}' > \"$CRS_CRON_FILE\" && chmod 644 \"$CRS_CRON_FILE\"")

MODULES = [
    # --- Web Servers -----------------------------------------------------------
    {
        'id':'nginx', 'name':'Nginx', 'icon':'/static/icons/nginx.svg', 'category':'Web Server',
        'desc':'High-performance HTTP & reverse proxy server',
        'check':'which nginx 2>/dev/null',
        'versions':[
            {'label':'1.30.5 (Stable - security fix)', 'value':'stable'},
            {'label':'1.31.6 (Mainline - security fix)', 'value':'mainline'},
        ],
        'install_tpl':'''OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian) && \
if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then \
  apt-get install -y curl gnupg2 ca-certificates lsb-release && \
  rm -f /usr/share/keyrings/nginx-archive-keyring.gpg && \
  curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --batch --yes --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg && \
  REPO="http://nginx.org/packages/{ver}/ubuntu" && \
  [ "{ver}" = "stable" ] && REPO="http://nginx.org/packages/ubuntu" || true && \
  echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] $REPO $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list && \
  apt-get update -o APT::Update::Error-Mode=any 2>/dev/null && \
  apt-get install -y nginx && systemctl enable --now nginx; \
elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then \
  if [ -n "$(rpm -E %{?fedora} 2>/dev/null)" ]; then \
    (dnf install -y nginx 2>/dev/null || yum install -y nginx) && systemctl enable --now nginx; \
  else \
  RHEL_VER=$(r=$(rpm -E %{?rhel} 2>/dev/null); echo ${r:-9}) && \
  REPO_PATH="rhel/$RHEL_VER" && \
  [ "{ver}" = "mainline" ] && REPO_PATH="mainline/rhel/$RHEL_VER" || true && \
  printf "[nginx]\nname=nginx repo\nbaseurl=http://nginx.org/packages/%s/\\$basearch/\ngpgcheck=1\nenabled=1\ngpgkey=https://nginx.org/keys/nginx_signing.key\nmodule_hotfixes=true\n" "$REPO_PATH" > /etc/yum.repos.d/nginx.repo && \
  (dnf install -y nginx 2>/dev/null || yum install -y nginx) && \
  systemctl enable --now nginx; \
  fi; \
fi''',
        'install':'(apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y nginx && systemctl enable --now nginx',
        'uninstall':'systemctl stop nginx 2>/dev/null; systemctl disable nginx 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=\'--force-confdef\' -o Dpkg::Options::=\'--force-confold\' nginx nginx-common nginx-full nginx-core 2>/dev/null; dnf remove -y nginx 2>/dev/null; yum remove -y nginx 2>/dev/null; apt-get autoremove -y 2>/dev/null; rm -rf /etc/nginx /usr/share/keyrings/nginx-archive-keyring.gpg /etc/apt/sources.list.d/nginx.list /etc/apt/sources.list.d/nginx-mainline.list /etc/yum.repos.d/nginx.repo 2>/dev/null; apt-get update -qq 2>/dev/null; true',
        'service':'nginx', 'manage':True,
    },
    {
        'id':'apache2', 'name':'Apache2', 'icon':'/static/icons/apache.svg', 'category':'Web Server',
        'desc':'Apache HTTP Server — widely-used web server',
        'check':'which apache2 2>/dev/null || which httpd 2>/dev/null',
        'versions':[
            {'label':'2.4.68 (Latest Stable)', 'value':'2.4.68'},
            {'label':'2.4.67 (Stable)',         'value':'2.4.67'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  export DEBIAN_FRONTEND=noninteractive; '
            '  (command -v add-apt-repository >/dev/null 2>&1 || apt-get install -y software-properties-common); '
            '  add-apt-repository -y ppa:ondrej/apache2 2>/dev/null; '
            '  if ! apt-get update -qq 2>/tmp/vp_apache_repo_err.log; then '
            '    echo "[VortexPanel] ondrej/apache2 has no release for {codename} yet -- using stock apache2"; '
            '    add-apt-repository --remove -y ppa:ondrej/apache2 2>/dev/null; '
            '    rm -f /etc/apt/sources.list.d/ondrej-ubuntu-apache2-*.list /etc/apt/sources.list.d/ondrej-ubuntu-apache2-*.sources 2>/dev/null; '
            '    apt-get update -qq; '
            '  fi; '
            '  (apt-get install -y apache2={ver}.* 2>/dev/null || apt-get install -y apache2) && '
            '  systemctl enable apache2 && systemctl start apache2; '
            'else '
            '  (dnf install -y httpd mod_ssl 2>/dev/null || yum install -y httpd mod_ssl) && '
            '  systemctl enable httpd && systemctl start httpd && __VP_SEL_WEB__; '
            'fi'
        ),
        'install':'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then export DEBIAN_FRONTEND=noninteractive && apt-get install -y apache2 && systemctl enable --now apache2; else (dnf install -y httpd mod_ssl 2>/dev/null || yum install -y httpd mod_ssl) && systemctl enable --now httpd; fi',
        'uninstall':'systemctl stop apache2 httpd 2>/dev/null; systemctl disable apache2 httpd 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold apache2 apache2-utils apache2-bin 2>/dev/null; dnf remove -y httpd mod_ssl 2>/dev/null; yum remove -y httpd mod_ssl 2>/dev/null; apt-get autoremove -y 2>/dev/null; true',
        'service':'apache2', 'manage':True,
    },
    {
        'id':'openlitespeed', 'name':'OpenLiteSpeed', 'icon':'/static/icons/litespeed.svg', 'category':'Web Server',
        'desc':'LiteSpeed open source web server',
        'check':'test -f /usr/local/lsws/bin/lshttpd && echo found',
        'versions':[
            {'label':'1.9.2 (Latest)', 'value':'1.9'},
            {'label':'1.8.5 (Stable)', 'value':'1.8.5'},
            {'label':'1.8.4 (Stable)', 'value':'1.8.4'},
        ],
        'install_tpl':'''OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian) && \
if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then \
  wget -q https://repo.litespeed.sh -O ls_repo.sh && bash ls_repo.sh; \
  if ! apt-get update -o APT::Update::Error-Mode=any 2>/tmp/vp_ols_err.log; then \
    if grep -q litespeedtech.com /tmp/vp_ols_err.log 2>/dev/null; then \
      echo "[VortexPanel] litespeedtech.com has no build for $(. /etc/os-release 2>/dev/null; echo "$VERSION_CODENAME") yet -- retrying with the previous stable codename (bullseye), a confirmed working substitution for this exact situation"; \
      for f in /etc/apt/sources.list.d/*.list; do \
        [ -f "$f" ] && grep -qi litespeedtech "$f" && sed -i "s/$(. /etc/os-release 2>/dev/null; echo "$VERSION_CODENAME")/bullseye/g" "$f"; \
      done; \
    fi; \
    apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; \
  fi; \
  apt-get install -y openlitespeed={ver} 2>/dev/null || apt-get install -y openlitespeed; \
  systemctl enable lsws && systemctl start lsws; \
  LSPHP_VER="lsphp83" && \
  apt-get install -y $LSPHP_VER $LSPHP_VER-common 2>&1 && \
  for ext in mysql curl opcache imagick intl mbstring xml zip gd soap; do \
    apt-get install -y $LSPHP_VER-$ext 2>/dev/null || true; \
  done; \
elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky|cloudlinux"; then \
  RHEL_VER=$(r=$(rpm -E %{?rhel} 2>/dev/null); echo ${r:-9}) && \
  __VP_EPEL__ && \
  (dnf install -y https://rpms.remirepo.net/enterprise/remi-release-${RHEL_VER}.rpm 2>/dev/null || true) && \
  (rpm -Uvh --force http://rpms.litespeedtech.com/centos/litespeed-repo-1.3-1.el${RHEL_VER}.noarch.rpm 2>/dev/null || true) && \
  (dnf install -y openlitespeed 2>/dev/null || yum install -y openlitespeed 2>/dev/null) && \
  systemctl enable lsws && systemctl start lsws; \
  LSPHP_VER="lsphp83" && \
  (dnf install -y $LSPHP_VER $LSPHP_VER-common 2>/dev/null || yum install -y $LSPHP_VER $LSPHP_VER-common 2>/dev/null); \
  for ext in mysqlnd curl opcache imagick intl mbstring xml zip gd soap process bcmath pdo mcrypt; do \
    (dnf install -y $LSPHP_VER-$ext 2>/dev/null || yum install -y $LSPHP_VER-$ext 2>/dev/null || true); \
  done; \
fi; \
mkdir -p /var/log/openlitespeed && chown nobody:$(getent group nogroup >/dev/null 2>&1 && echo nogroup || echo nobody) /var/log/openlitespeed 2>/dev/null; true''',
        'install':'''wget -q https://repo.litespeed.sh -O ls_repo.sh && bash ls_repo.sh && \
(apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y openlitespeed && \
systemctl enable lsws && systemctl start lsws && \
LSPHP_VER="lsphp83" && \
apt-get install -y $LSPHP_VER $LSPHP_VER-common 2>&1 && \
for ext in mysql curl opcache imagick intl mbstring xml zip gd soap; do \
  apt-get install -y $LSPHP_VER-$ext 2>/dev/null || true; \
done; \
mkdir -p /var/log/openlitespeed && chown nobody:$(getent group nogroup >/dev/null 2>&1 && echo nogroup || echo nobody) /var/log/openlitespeed 2>/dev/null; true''',
        'uninstall':(
            'systemctl stop lsws 2>/dev/null; systemctl disable lsws 2>/dev/null; '
            '/usr/local/lsws/admin/misc/uninstall.sh 2>/dev/null; '
            "apt-get remove -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' openlitespeed 2>/dev/null; dnf remove -y openlitespeed 2>/dev/null; yum remove -y openlitespeed 2>/dev/null; "
            'rm -rf /usr/local/lsws; '
            # LiteSpeed's own ls_repo.sh (downloaded from repo.litespeed.sh)
            # writes the actual apt source file under a name that isn't
            # documented/verifiable from here -- same leftover-repo class of
            # bug just found and fixed for MariaDB (a stale repo definition
            # surviving uninstall and interfering with later unrelated
            # installs). Matching by content instead of guessing a filename:
            'grep -l -i litespeed /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null | xargs -r rm -f; '
            'find /etc/apt/sources.list.d/ -iname "*litespeed*" -delete 2>/dev/null; '
            'rm -f /usr/share/keyrings/*litespeed*.gpg /etc/apt/trusted.gpg.d/*litespeed*.gpg 2>/dev/null; '
            'apt-get update -qq 2>/dev/null; true'
        ),
        'service':'lsws', 'manage':True,
    },
    # --- Databases -------------------------------------------------------------
    {
        'id':'caddy', 'name':'Caddy', 'icon':'/static/icons/caddy.svg', 'category':'Web Server',
        'desc':'Auto-HTTPS web server — HTTP/3, zero-config TLS via Lets Encrypt',
        'check':'which caddy 2>/dev/null',
        'versions':[
            {'label':'v2.11.4 (Latest — security)', 'value':'2.11.4'},
            {'label':'v2.11.3 (Stable — security)', 'value':'2.11.3'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl && '
                # FIX: previous version piped the curl'd GPG key into "rm -f" (which ignores
                # stdin and discards it) instead of into "gpg --dearmor" — producing an empty/
                # invalid keyring file. Corrected: remove old file first, then pipe curl -> gpg.
            '  rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg && '
            '  curl -fsSL \'https://dl.cloudsmith.io/public/caddy/stable/gpg.key\' | gpg --batch --no-tty --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && '
            '  curl -fsSL \'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt\' | tee /etc/apt/sources.list.d/caddy-stable.list && '
            '  chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg && '
            '  chmod o+r /etc/apt/sources.list.d/caddy-stable.list && '
            '  (apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y caddy && '
            '  systemctl enable caddy && systemctl start caddy; '
            'elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
                # Caddy's officially documented Fedora/EL method — COPR repo.
            '  (dnf install -y dnf-plugins-core 2>/dev/null || yum install -y dnf-plugins-core 2>/dev/null || true) && '
            '  (dnf copr enable -y @caddy/caddy 2>/dev/null || yum copr enable -y @caddy/caddy 2>/dev/null || true) && '
            '  (dnf install -y caddy 2>/dev/null || yum install -y caddy 2>/dev/null) && '
            '  systemctl enable caddy && systemctl start caddy; '
            'fi'
        ),
        'install':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl && '
            '  rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg && '
            '  curl -fsSL \'https://dl.cloudsmith.io/public/caddy/stable/gpg.key\' | gpg --batch --no-tty --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && '
            '  curl -fsSL \'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt\' | tee /etc/apt/sources.list.d/caddy-stable.list && '
            '  chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg && '
            '  chmod o+r /etc/apt/sources.list.d/caddy-stable.list && '
            '  (apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y caddy && '
            '  systemctl enable caddy && systemctl start caddy; '
            'elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
            '  (dnf install -y dnf-plugins-core 2>/dev/null || yum install -y dnf-plugins-core 2>/dev/null || true) && '
            '  (dnf copr enable -y @caddy/caddy 2>/dev/null || yum copr enable -y @caddy/caddy 2>/dev/null || true) && '
            '  (dnf install -y caddy 2>/dev/null || yum install -y caddy 2>/dev/null) && '
            '  systemctl enable caddy && systemctl start caddy; '
            'fi'
        ),
        'uninstall':'systemctl stop caddy 2>/dev/null; systemctl disable caddy 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold caddy 2>/dev/null; dnf remove -y caddy 2>/dev/null; yum remove -y caddy 2>/dev/null; apt-get autoremove -y 2>/dev/null; rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list 2>/dev/null; apt-get update -qq 2>/dev/null; true && rm -rf /etc/caddy',
        'service':'caddy', 'manage':True,
    },
    {
        'id':'mysql', 'name':'MySQL', 'icon':'/static/icons/mysql.svg', 'category':'Database',
        'desc':'The world\'s most popular open source database',
        'check':'systemctl is-active mysql 2>/dev/null | grep -qx active && ! systemctl is-active mariadb 2>/dev/null | grep -qx active && echo found || (mysqld --version 2>/dev/null | grep -i mysql | grep -iv mariadb | grep -c mysql)',
        'versions':[
            {'label':'Innovation (rolling — currently 26.7.0, latest quarterly release)', 'value':'innovation'},
            {'label':'9.7.2 (LTS)',           'value':'9.7'},
            {'label':'8.4.11 (LTS)',          'value':'8.4'},
            {'label':'8.0.46 (EOL since Apr 2026 — no security patches, not recommended)', 'value':'8.0'},
        ],
        'install_tpl':(
            # Hard guard, independent of the higher-level conflict check:
            # MySQL and MariaDB share the same package namespace
            # (mysql-common, mysql-client) and cannot coexist. Confirmed via
            # a real failure: installing mysql-server while MariaDB was
            # already active caused mysql-server's postinst script to fail
            # with "configure-symlinks: No such file or directory" (it
            # expects Ubuntu's own mysql-common, but MariaDB'"'"'s mysql-common
            # package was already providing that path instead) -- dpkg
            # returned an error, yet a stray mysqld binary from the
            # otherwise-successful mysql-server-core package made the old
            # "is it installed" check falsely report success. Refusing to
            # even attempt this is far safer than relying on dpkg to fail
            # loudly enough afterward.
            # IMPORTANT: this checks whether MariaDB *packages* are
            # present (dpkg -l), not whether the mariadb *service* is
            # currently active -- confirmed via a second real failure
            # that checking only systemctl is-active let this exact
            # conflict through a second time, because MariaDB's packages
            # (and its conflicting mysql-common) were still installed
            # even though the service happened not to be running at
            # that moment. The package-level conflict exists regardless
            # of whether the service is running.
            'if dpkg -l mariadb-server 2>/dev/null | grep -q "^ii" || dpkg -l mysql-common 2>/dev/null | grep "^ii" | grep -qi maria; then '
            '  echo "[VortexPanel] MariaDB is already installed on this server (its packages own mysql-common/mysql-client). MySQL and MariaDB cannot coexist -- uninstall MariaDB first (App Store -> MariaDB -> Uninstall) if you want MySQL instead."; '
            '  exit 1; '
            'fi; '
            # Third layer of the same defense: even with MariaDB genuinely
            # uninstalled, its apt REPOSITORY DEFINITION can persist on a
            # server that had MariaDB installed before this uninstall fix
            # existed -- confirmed live: a leftover mariadb.sources file
            # supplied a conflicting mysql-common during MySQL's dependency
            # resolution even though mariadb-server itself was already gone,
            # producing the exact same postinst crash through a different
            # path. Removing any stale MariaDB repo file before touching
            # apt at all closes that regardless of whether it happened via
            # the uninstall bug or by any other means.
            'rm -f /etc/apt/sources.list.d/mariadb.list /etc/apt/sources.list.d/mariadb.sources; '
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  export DEBIAN_FRONTEND=noninteractive && '
            '  apt-get install -y wget lsb-release gnupg debconf-utils && '
            '  wget -q https://dev.mysql.com/get/mysql-apt-config_0.8.39-1_all.deb -O /tmp/mysql-apt.deb && '
            # mysql-apt-config presents server-track selection as a debconf
            # question (mysql-apt-config/select-server) -- without an answer
            # preseeded, it silently defaults to whichever track it
            # considers primary (confirmed real: requesting 9.7 installed
            # 8.4 instead, with zero indication anything was wrong). MySQL
            # publishes two tracks: mysql-8.0 / mysql-8.4-lts (LTS) for 8.x,
            # and mysql-innovation for the rolling 9.x releases -- there is
            # no per-point-release component like "mysql-9.7" specifically.
            # UNCERTAIN: I have not been able to directly confirm the exact
            # track name for 9.x releases against a real system (never seen
            # "mysql-innovation" appear in an actual log, only inferred from
            # general MySQL release-model knowledge) -- and a separate,
            # also-unverified source suggests 9.7 may now be marketed as its
            # own LTS track rather than Innovation. Rather than commit to
            # either guess, the debconf preseed below uses this as a
            # starting attempt only; the real selection happens afterward by
            # scanning what mysql-apt-config actually generated.
            '  MYSQL_TRACK_GUESS="mysql-8.4-lts"; '
            '  case "{ver}" in 8.0*) MYSQL_TRACK_GUESS="mysql-8.0";; 8.4*) MYSQL_TRACK_GUESS="mysql-8.4-lts";; 9.7*) MYSQL_TRACK_GUESS="mysql-9.7-lts";; innovation) MYSQL_TRACK_GUESS="mysql-innovation";; esac; '
            '  echo "[VortexPanel] debconf preseed attempt: mysql-apt-config/select-server = $MYSQL_TRACK_GUESS"; '
            '  echo "mysql-apt-config mysql-apt-config/select-server select $MYSQL_TRACK_GUESS" | debconf-set-selections; '
            '  DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/mysql-apt.deb && '
            # Self-discovering correction, independent of both the debconf
            # answer and my track-name guesses above: mysql-apt-config
            # writes every ACTUAL track name it knows about into the repo
            # file (commenting out all but the selected one), so scan for
            # what is really there instead of assuming. Priority 1: a track
            # whose name literally contains the requested version string
            # (e.g. would correctly find "mysql-9.7-lts" if that turns out
            # to be real, without me having had to know that in advance).
            # Priority 2: fall back to the LTS/Innovation heuristic only if
            # no exact version match exists.
            '  for f in /etc/apt/sources.list.d/mysql.list /etc/apt/sources.list.d/mysql.sources; do '
            '    if [ ! -f "$f" ]; then echo "[VortexPanel] $f does not exist -- skipping"; continue; fi; '
            '    echo "[VortexPanel] found $f, discovering tracks..."; '
            '    ALL_TRACKS=$(grep -oP "\\s\\Kmysql-[a-zA-Z0-9.-]+$" "$f" | grep -vE "^mysql-(apt-config|tools|common|client|server)$" | sort -u); '
            '    echo "[VortexPanel] discovered tracks: $ALL_TRACKS"; '
            '    MYSQL_TRACK=""; '
            '    for T in $ALL_TRACKS; do case "$T" in *"{ver}"*) MYSQL_TRACK="$T"; break;; esac; done; '
            '    if [ -z "$MYSQL_TRACK" ]; then '
            '      case "{ver}" in '
            '        8.0*) for T in $ALL_TRACKS; do case "$T" in mysql-8.0*) MYSQL_TRACK="$T"; break;; esac; done ;; '
            '        8.4*) for T in $ALL_TRACKS; do case "$T" in mysql-8.4*) MYSQL_TRACK="$T"; break;; esac; done ;; '
            '        9.7*) for T in $ALL_TRACKS; do case "$T" in mysql-9.7*|mysql-9*-lts) MYSQL_TRACK="$T"; break;; esac; done ;; '
            '        innovation) for T in $ALL_TRACKS; do case "$T" in mysql-innovation|mysql-9*) MYSQL_TRACK="$T"; break;; esac; done ;; '
            '      esac; '
            '    fi; '
            '    echo "[VortexPanel] selected track for {ver}: ${MYSQL_TRACK:-<none found>}"; '
            '    if [ -z "$MYSQL_TRACK" ]; then echo "[VortexPanel] no matching track -- leaving $f untouched"; continue; fi; '
            '    sed -i "/\\b${MYSQL_TRACK}\\b/s/^#\\s*//" "$f"; '
            '    for OTHER in $ALL_TRACKS; do '
            '      [ "$OTHER" = "$MYSQL_TRACK" ] && continue; '
            '      sed -i "/\\b${OTHER}\\b/{/^#/!s/^/# /}" "$f"; '
            '    done; '
            '  done; '
            '  echo "[VortexPanel] active (uncommented) lines after track selection:"; '
            '  for f in /etc/apt/sources.list.d/mysql.list /etc/apt/sources.list.d/mysql.sources; do '
            '    [ -f "$f" ] && grep "^deb" "$f"; '
            '  done; '
            # Confirmed via a real failure: every codename attempt (questing,
            # plucky, oracular, noble, jammy) failed with the SAME
            # "EXPKEYSIG B7B3B788A8D3785C" error -- not a missing Release
            # file, an EXPIRED signing key bundled in the old, pinned
            # mysql-apt-config_0.8.39-1 package. Re-fetching that exact key
            # ID from a keyserver gets whatever current version MySQL has
            # published (keyservers reflect renewed expiry dates the stale
            # bundled copy doesn'"'"'t have) -- this is the standard remediation
            # for EXPKEYSIG, not a signature-verification bypass.
            #
            # IMPORTANT: writing the refreshed key to a NEW file in
            # /etc/apt/trusted.gpg.d/ was NOT enough -- confirmed via a real
            # failure on a FRESH Ubuntu 24.04 install (the correct native
            # codename, no fallback even needed) that the exact same
            # EXPKEYSIG error still occurred. mysql-apt-config'"'"'s generated
            # sources file has its own explicit Signed-By= pointing at a
            # specific bundled keyring file, which overrides the global
            # trusted keyring for that repo entirely -- adding a second key
            # elsewhere does nothing if apt never looks there. Discovering
            # whatever path is actually referenced and overwriting THAT
            # exact file, in addition to the trusted.gpg.d fallback for the
            # case where no explicit Signed-By is used at all.
            '  MYSQL_KEYRING_PATH=""; '
            '  for f in /etc/apt/sources.list.d/mysql.list /etc/apt/sources.list.d/mysql.sources; do '
            '    [ -f "$f" ] && MYSQL_KEYRING_PATH=$(grep -oP "(?:signed-by=|Signed-By:\\s*)\\K[^]\\s]+" "$f" 2>/dev/null | head -1) && [ -n "$MYSQL_KEYRING_PATH" ] && break; '
            '  done; '
            '  (gpg --no-default-keyring --keyring /tmp/mysql-refresh.gpg --keyserver keyserver.ubuntu.com --recv-keys B7B3B788A8D3785C 2>/dev/null && '
            '   gpg --no-default-keyring --keyring /tmp/mysql-refresh.gpg --export B7B3B788A8D3785C > /etc/apt/trusted.gpg.d/mysql-refreshed.gpg 2>/dev/null && '
            '   if [ -n "$MYSQL_KEYRING_PATH" ]; then mkdir -p "$(dirname "$MYSQL_KEYRING_PATH")"; gpg --no-default-keyring --keyring /tmp/mysql-refresh.gpg --export B7B3B788A8D3785C > "$MYSQL_KEYRING_PATH" 2>/dev/null; fi) || true; '
            # mysql-apt-config is a pinned package (0.8.39-1, confirmed
            # current as of the user's own check against dev.mysql.com --
            # was previously hardcoded to the much older 0.8.33-1, which may
            # explain why selecting a 9.x track never worked no matter how
            # it was preseeded: a config tool built before 9.x existed would
            # never have had that option to select in the first place) that
            # writes /etc/apt/sources.list.d/mysql.list based on whatever
            # codename it detects -- confirmed via a real failure log:
            # repo.mysql.com genuinely has no release for a brand-new Ubuntu
            # codename yet (404 Not Found), and this stale file was left
            # behind, poisoning every unrelated apt-get update afterward
            # (it broke a completely separate PHP install in the same way
            # already seen for ondrej/php, mariadb, postgresql, etc).
            '  if ! apt-get update -q 2>/tmp/vp_mysql_repo_err.log; then '
            # repo.mysql.com has no build for the running codename yet.
            # Confirmed directly from repo.mysql.com's real directory listing
            # (not a guess): questing, plucky, oracular, noble, jammy all
            # genuinely exist there, with questing (25.10) the most recently
            # updated -- matching what MySQL's own download page shows for
            # both 8.4 and 9.7. Probing newest-first and using the first one
            # whose Release file actually resolves.
            '    RUNNING_CODENAME=$(lsb_release -sc); '
            '    MYSQL_OK=0; '
            '    for CN in questing plucky oracular noble jammy; do '
            '      for f in /etc/apt/sources.list.d/mysql.list /etc/apt/sources.list.d/mysql.sources; do '
            '        [ -f "$f" ] && sed -i "s/${RUNNING_CODENAME}/${CN}/g; s/\\b\\(questing\\|plucky\\|oracular\\|noble\\|jammy\\)\\b/${CN}/g" "$f"; '
            '      done; '
            '      if apt-get update -q 2>/tmp/vp_mysql_${CN}_err.log; then '
            '        echo "[VortexPanel] repo.mysql.com has no build for ${RUNNING_CODENAME} yet -- using its ${CN} build instead (closest available match)"; '
            '        MYSQL_OK=1; break; '
            '      fi; '
            '    done; '
            '    if [ "$MYSQL_OK" != "1" ]; then '
            '      echo "[VortexPanel] repo.mysql.com has no usable build for any recent Ubuntu codename -- removing the broken repo entry, falling back to distro-packaged mysql-server (may not match the exact version requested)"; '
            '      rm -f /etc/apt/sources.list.d/mysql.list /etc/apt/sources.list.d/mysql.sources; '
            '      apt-get update -q; '
            '    fi; '
            '  fi && '
            '  if [ "{ver}" = "innovation" ]; then '
            # No version-suffixed package exists for Innovation at all --
            # confirmed by the real "Unable to locate package
            # mysql-server-9.x" failure this produced under the old value.
            # Whatever "mysql-server" resolves to IS the current quarterly
            # Innovation release; there is nothing more specific to ask for.
            '    apt-get install -y mysql-server; '
            '  else '
            '    apt-get install -y mysql-server-{ver} 2>/dev/null || apt-get install -y mysql-server; '
            '  fi && '
            '  systemctl enable --now mysql; '
            'elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
                # RHEL 8+ ships MySQL directly in the built-in AppStream module stream —
                # no external repo or GPG key needed at all, the safest possible path.
                # Module streams only offer a couple of minor versions (not every {ver}
                # choice maps 1:1) so we pick the closest available stream.
                #
                # IMPORTANT, confirmed just from reading the module-stream mechanism
                # itself (not from a live RHEL-family log -- unlike the Debian/Ubuntu
                # path in this same install_tpl, this branch has NOT been validated
                # against a real system yet): RHEL'"'"'s built-in AppStream module never
                # publishes a 9.x stream at all, so a 9.x request used to silently fall
                # through to the 8.4 case= condition below and install 8.4 instead --
                # same "wrong version installed with no indication" bug already found
                # and fixed on the Debian/Ubuntu side. 9.x now skips the module-stream
                # attempt entirely and goes straight to Oracle'"'"'s own community repo,
                # since that'"'"'s the only place a 9.x release actually exists for
                # RHEL-family systems.
            '  MYSQL_STREAM=""; '
            '  case "{ver}" in 8.0*) MYSQL_STREAM="8.0";; 8.4*) MYSQL_STREAM="8.4";; esac; '
            '  MYSQL_MODULE_OK=1; '
            '  if [ -n "$MYSQL_STREAM" ]; then '
            '    (dnf module reset -y mysql 2>/dev/null; dnf module enable -y mysql:$MYSQL_STREAM 2>/dev/null; '
            '     dnf install -y mysql-server 2>/dev/null) || MYSQL_MODULE_OK=0; '
            '  else '
            '    MYSQL_MODULE_OK=0; '
            '  fi; '
            '  if [ "$MYSQL_MODULE_OK" != "1" ]; then '
                # Oracle's official community-release config RPM, confirmed directly
                # against dev.mysql.com/downloads/repo/yum/ (not a guess this time) --
                # every EL major version and Fedora release has its own distinct
                # filename and build suffix, which the previous single hardcoded
                # "el7-11" filename never accounted for.
            '    EL_MAJOR=$(rpm -E %{?rhel} 2>/dev/null); '
            '    FEDORA_MAJOR=$(rpm -E %{?fedora} 2>/dev/null); '
            '    MYSQL_YUM_CONF=""; '
            '    if [ -n "$FEDORA_MAJOR" ] && [ "$FEDORA_MAJOR" != "%{fedora}" ]; then '
            '      case "$FEDORA_MAJOR" in '
            '        43) MYSQL_YUM_CONF="mysql84-community-release-fc43-2.noarch.rpm";; '
            '        42) MYSQL_YUM_CONF="mysql84-community-release-fc42-4.noarch.rpm";; '
            '      esac; '
            '    elif [ -n "$EL_MAJOR" ] && [ "$EL_MAJOR" != "%{rhel}" ]; then '
            '      case "$EL_MAJOR" in '
            '        10) MYSQL_YUM_CONF="mysql84-community-release-el10-3.noarch.rpm";; '
            '        9)  MYSQL_YUM_CONF="mysql84-community-release-el9-4.noarch.rpm";; '
            '        8)  MYSQL_YUM_CONF="mysql84-community-release-el8-3.noarch.rpm";; '
            '        7)  MYSQL_YUM_CONF="mysql84-community-release-el7-4.noarch.rpm";; '
            '        6)  MYSQL_YUM_CONF="mysql80-community-release-el6-11.noarch.rpm";; '
            '      esac; '
            '    fi; '
            '    if [ -z "$MYSQL_YUM_CONF" ]; then '
            '      echo "[VortexPanel] Could not determine the correct MySQL community-release package for this specific EL/Fedora version -- falling back to the EL9 build as a best-effort guess"; '
            '      MYSQL_YUM_CONF="mysql84-community-release-el9-4.noarch.rpm"; '
            '    fi; '
            '    (dnf install -y "https://dev.mysql.com/get/${MYSQL_YUM_CONF}" 2>/dev/null || '
            '     yum install -y "https://dev.mysql.com/get/${MYSQL_YUM_CONF}" 2>/dev/null); '
                # This config RPM sets up multiple sub-repos (one per MySQL major
                # version/track, similar to how mysql-apt-config works on
                # Debian/Ubuntu) and enables one by default -- self-discover and
                # select the repo matching the requested version instead of
                # assuming which one is on by default, same philosophy as the
                # apt-side fix, since the exact default and sub-repo IDs are NOT
                # independently confirmed here.
            '    for rf in /etc/yum.repos.d/mysql-community.repo /etc/yum.repos.d/mysql-community-source.repo; do '
            '      [ -f "$rf" ] || continue; '
            '      ALL_REPOIDS=$(grep -oE "^\\[[a-zA-Z0-9_-]+\\]" "$rf" | tr -d "[]"); '
            '      TARGET_REPO=""; '
            '      for R in $ALL_REPOIDS; do case "$R" in *"{ver}"*) TARGET_REPO="$R"; break;; esac; done; '
            '      if [ -z "$TARGET_REPO" ]; then '
            '        case "{ver}" in '
            '          8.0*) for R in $ALL_REPOIDS; do case "$R" in *80*) TARGET_REPO="$R"; break;; esac; done ;; '
            '          8.4*) for R in $ALL_REPOIDS; do case "$R" in *84*) TARGET_REPO="$R"; break;; esac; done ;; '
            '          9.7*) for R in $ALL_REPOIDS; do case "$R" in *97*|*9.7*) TARGET_REPO="$R"; break;; esac; done ;; '
            '          innovation) for R in $ALL_REPOIDS; do case "$R" in *innovation*) TARGET_REPO="$R"; break;; esac; done ;; '
            '        esac; '
            '      fi; '
            '      [ -n "$TARGET_REPO" ] && (dnf config-manager --set-enabled "$TARGET_REPO" 2>/dev/null || yum-config-manager --enable "$TARGET_REPO" 2>/dev/null); '
            '      for R in $ALL_REPOIDS; do '
            '        [ "$R" = "$TARGET_REPO" ] && continue; '
            '        case "$R" in *community*) (dnf config-manager --set-disabled "$R" 2>/dev/null || yum-config-manager --disable "$R" 2>/dev/null);; esac; '
            '      done; '
            '    done; '
            '    yum install -y mysql-community-server 2>/dev/null || dnf install -y mysql-community-server 2>/dev/null; '
            '  fi && '
            '  systemctl enable --now mysqld 2>/dev/null || systemctl enable --now mysql 2>/dev/null; '
            'fi'
        ),
        'uninstall':'systemctl stop mysql mysqld 2>/dev/null; systemctl disable mysql mysqld 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold mysql-server mysql-client mysql-common mysql-server-core-* mysql-client-core-* 2>/dev/null; apt-get autoremove -y 2>/dev/null; dnf remove -y mysql-server mysql-community-server 2>/dev/null; yum remove -y mysql-server mysql-community-server 2>/dev/null; rm -rf /etc/mysql /var/lib/mysql',
        'service':'mysql', 'manage':True,
    },
    {
        'id':'mariadb', 'name':'MariaDB', 'icon':'/static/icons/mariadb.svg', 'category':'Database',
        'desc':'Community-developed MySQL fork by MariaDB Foundation',
        'check':'systemctl is-active mariadb 2>/dev/null | grep -q "^active" && echo found || (which mariadbd 2>/dev/null && mariadbd --version 2>/dev/null | grep -c MariaDB)',
        'versions':[
            {'label':'13.0.2 (Latest Stable)', 'value':'13.0'},
            {'label':'12.3.3 (Stable)', 'value':'12.3'},
            {'label':'11.8.9 (LTS)', 'value':'11.8'},
            {'label':'11.4.13 (LTS)', 'value':'11.4'},
            {'label':'10.11.19 (LTS)', 'value':'10.11'},
        ],
        'install_tpl':'''curl -fLsS https://downloads.mariadb.com/MariaDB/mariadb_repo_setup -o /tmp/mariadb_repo.sh && \
bash /tmp/mariadb_repo.sh --mariadb-server-version="mariadb-{ver}" --skip-maxscale; \
for f in /etc/apt/sources.list.d/*.sources; do [ -f "$f" ] || continue; if grep -qi maxscale "$f"; then awk -v RS="" -v ORS="\n\n" \'tolower($0) !~ /maxscale/\' "$f" > "$f.tmp" && mv "$f.tmp" "$f"; fi; done; \
for f in /etc/apt/sources.list.d/*.list; do [ -f "$f" ] || continue; if grep -qi maxscale "$f"; then sed -i \'/[Mm]ax[Ss]cale/d\' "$f"; fi; done; \
if command -v apt-get >/dev/null 2>&1; then apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server; else (dnf install -y MariaDB-server 2>/dev/null || yum install -y MariaDB-server 2>/dev/null || dnf install -y mariadb-server 2>/dev/null || yum install -y mariadb-server); fi && \
systemctl enable --now mariadb''',
        'install':'DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server && systemctl enable mariadb && systemctl start mariadb',
        'uninstall':'systemctl stop mariadb 2>/dev/null; dnf remove -y MariaDB-server MariaDB-client mariadb-server mariadb 2>/dev/null; yum remove -y MariaDB-server mariadb-server 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold mariadb-server mariadb-client mariadb-common mysql-common 2>/dev/null; apt-get autoremove -y 2>/dev/null; rm -rf /etc/mysql /var/lib/mysql /etc/apt/sources.list.d/mariadb.list /etc/apt/sources.list.d/mariadb.sources /etc/apt/keyrings/mariadb-keyring.pgp /usr/share/keyrings/mariadb-keyring*.gpg 2>/dev/null; apt-get update -qq 2>/dev/null; true',
        'service':'mariadb', 'manage':True,
    },
    {
        'id':'mongodb', 'name':'MongoDB', 'icon':'/static/icons/mongodb.svg', 'category':'Database',
        'desc':'Document-oriented NoSQL database',
        'check':'which mongod 2>/dev/null',
        'versions':[
            {'label':'8.0.32 (LTS)', 'value':'8.0'},
            {'label':'8.2.12 (Latest minor release)', 'value':'8.2'},
            {'label':'7.0.43 (LTS)', 'value':'7.0'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  export DEBIAN_FRONTEND=noninteractive && '
            '  apt-get install -y gnupg curl && '
            '  rm -f /usr/share/keyrings/mongodb-server-{ver}.gpg /etc/apt/sources.list.d/mongodb-org-{ver}.list && '
            '  curl -fsSL https://www.mongodb.org/static/pgp/server-{ver}.asc -o /tmp/mongo.key && '
            '  gpg --batch --no-tty --dearmor -o /usr/share/keyrings/mongodb-server-{ver}.gpg /tmp/mongo.key && '
            '  rm -f /tmp/mongo.key && '
            '  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-{ver}.gpg ] '
            'https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/{ver} multiverse" '
            '  > /etc/apt/sources.list.d/mongodb-org-{ver}.list && '
            # MongoDB has no fallback in Ubuntu'"'"'s own archive at all (it'"'"'s
            # never distro-packaged), so unlike Redis there'"'"'s nothing to fall
            # back to if repo.mongodb.org has no release for this codename yet
            # -- but the broken repo file must still be cleaned up, or it
            # poisons every unrelated apt-get update run afterward.
            '  if ! apt-get update -qq 2>/tmp/vp_mongo_repo_err.log; then '
            '    echo "[VortexPanel] repo.mongodb.org has no release for $(lsb_release -cs) yet -- removing the broken repo entry so it does not block other installs"; '
            '    rm -f /etc/apt/sources.list.d/mongodb-org-{ver}.list; '
            '    apt-get update -qq; '
            '    exit 1; '
            '  fi && '
            '  apt-get install -y mongodb-org && '
            '  systemctl enable mongod && systemctl start mongod; '
            'elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
                # Official MongoDB-documented RHEL .repo format (repo.mongodb.org/yum/redhat)
            '  RHEL_VER=$(r=$(rpm -E %{?rhel} 2>/dev/null); echo ${r:-9}) && '
            '  printf "[mongodb-org-{ver}]\\nname=MongoDB Repository\\nbaseurl=https://repo.mongodb.org/yum/redhat/%s/mongodb-org/{ver}/\\$basearch/\\ngpgcheck=1\\nenabled=1\\ngpgkey=https://www.mongodb.org/static/pgp/server-{ver}.asc\\n" "$RHEL_VER" > /etc/yum.repos.d/mongodb-org-{ver}.repo && '
            '  (dnf install -y mongodb-org 2>/dev/null || yum install -y mongodb-org) && '
            '  systemctl enable mongod && systemctl start mongod; '
            'fi'
        ),
        'install':'',  # always uses install_tpl
        'uninstall':'systemctl stop mongod 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold mongodb-org mongodb-org-* 2>/dev/null; dnf remove -y mongodb-org 2>/dev/null; yum remove -y mongodb-org 2>/dev/null; apt-get autoremove -y 2>/dev/null; rm -rf /var/lib/mongodb /var/log/mongodb /usr/share/keyrings/mongodb-server-*.gpg /etc/apt/sources.list.d/mongodb-org-*.list /etc/yum.repos.d/mongodb-org-*.repo 2>/dev/null; apt-get update -qq 2>/dev/null; true',
        'service':'mongod', 'manage':True,
    },
    {
        'id':'postgresql', 'name':'PostgreSQL', 'icon':'/static/icons/postgresql.svg', 'category':'Database',
        'desc':'Advanced open source relational database',
        'check':'which psql 2>/dev/null',
        'versions':[
            {'label':'18.6 (Latest)', 'value':'18'},
            {'label':'17.11 (Stable)', 'value':'17'},
            {'label':'16.15 (Stable)', 'value':'16'},
            {'label':'15.19 (Stable)', 'value':'15'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  export DEBIAN_FRONTEND=noninteractive && '
            '  apt-get install -y gnupg2 curl lsb-release && '
            '  rm -f /usr/share/keyrings/postgresql.gpg /etc/apt/sources.list.d/pgdg.list && '
            '  curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /tmp/pg.asc && '
            '  gpg --batch --no-tty --dearmor -o /usr/share/keyrings/postgresql.gpg /tmp/pg.asc && '
            '  rm -f /tmp/pg.asc && '
            '  PG_CODENAME=$(lsb_release -cs) && '
            '  echo "deb [signed-by=/usr/share/keyrings/postgresql.gpg] '
            'http://apt.postgresql.org/pub/repos/apt ${PG_CODENAME}-pgdg main" '
            '  > /etc/apt/sources.list.d/pgdg.list && '
            # Same failure class already confirmed elsewhere: PGDG is a much
            # more actively-maintained project than the PPAs above, but a
            # brand-new Ubuntu codename can still lag behind by days/weeks
            # before PGDG publishes for it. Leaving a broken pgdg.list in
            # place would poison every future apt-get update on the system.
            '  if ! apt-get update -qq 2>/tmp/vp_pg_repo_err.log; then '
            '    echo "[VortexPanel] apt.postgresql.org has no release for ${PG_CODENAME} yet -- removing pgdg.list so it does not block other installs"; '
            '    rm -f /etc/apt/sources.list.d/pgdg.list; '
            '    apt-get update -qq; '
            '    exit 1; '
            '  fi && '
            '  apt-get install -y postgresql-{ver} postgresql-contrib && '
            '  systemctl enable postgresql && systemctl start postgresql; '
            'elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
                # Official PostgreSQL-documented RHEL method — pgdg-redhat-repo RPM.
                # RHEL/AlmaLinux/Rocky ship an OLDER "postgresql" AppStream module by
                # default which conflicts with PGDG's own versioned packages, so it
                # must be disabled first (this is PostgreSQL's own documented step).
            '  RHEL_VER=$(r=$(rpm -E %{?rhel} 2>/dev/null); echo ${r:-9}) && '
            '  ARCH=$(uname -m) && '
            '  (dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-${RHEL_VER}-${ARCH}/pgdg-redhat-repo-latest.noarch.rpm 2>/dev/null || '
            '   yum install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-${RHEL_VER}-${ARCH}/pgdg-redhat-repo-latest.noarch.rpm 2>/dev/null) && '
            '  dnf -qy module disable postgresql 2>/dev/null; '
            '  (dnf install -y postgresql{ver}-server postgresql{ver}-contrib 2>/dev/null || '
            '   yum install -y postgresql{ver}-server postgresql{ver}-contrib 2>/dev/null) && '
            '  /usr/pgsql-{ver}/bin/postgresql-{ver}-setup initdb 2>/dev/null && '
            '  systemctl enable postgresql-{ver} && systemctl start postgresql-{ver}; '
            'fi'
        ),
        'install':'apt-get install -y postgresql postgresql-contrib && systemctl enable postgresql && systemctl start postgresql',
        'uninstall':'systemctl stop postgresql postgresql-* 2>/dev/null; systemctl disable postgresql postgresql-* 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold postgresql postgresql-* 2>/dev/null; dnf remove -y postgresql-server postgresql-contrib "postgresql*-server" "postgresql*-contrib" 2>/dev/null; yum remove -y postgresql-server postgresql-contrib 2>/dev/null; apt-get autoremove -y 2>/dev/null; rm -rf /etc/postgresql /var/lib/postgresql /var/lib/pgsql /usr/share/keyrings/postgresql.gpg /etc/apt/sources.list.d/pgdg.list /etc/yum.repos.d/pgdg-redhat-repo.repo 2>/dev/null; apt-get update -qq 2>/dev/null; true',
        'service':'postgresql', 'manage':True,
    },
    # --- PHP -------------------------------------------------------------------
    {
        'id':'php', 'name':'PHP', 'icon':'/static/icons/php.svg', 'category':'PHP',
        'desc':'PHP-FPM — multiple versions supported side by side',
        # Debian/sury phpX.Y, RHEL Remi SCL /opt/remi/phpXY and the RHEL
        # module-stream system PHP (/usr/sbin/php-fpm) -- the old check only
        # knew phpX.Y, so every RHEL PHP install was reported as failed.
        'check':('{ which php8.5 php8.4 php8.3 php8.2 php8.1 php8.0 php7.4 2>/dev/null; '
                 'ls /opt/remi/php*/root/usr/bin/php 2>/dev/null; '
                 'test -x /usr/sbin/php-fpm && echo /usr/sbin/php-fpm; } | head -1'),
        'verify_tpl':('command -v php{ver} 2>/dev/null || '
                      '(test -x /opt/remi/php$(echo {ver} | tr -d .)/root/usr/bin/php && echo found) || '
                      '(php -r "echo PHP_MAJOR_VERSION.chr(46).PHP_MINOR_VERSION;" 2>/dev/null | grep -x "{ver}")'),
        'versions':[
            {'label':'8.5.11 (Latest - security release)', 'value':'8.5'},
            {'label':'8.4.26 (Active support)', 'value':'8.4'},
            {'label':'8.3.35 (Security fixes only)', 'value':'8.3'},
            {'label':'8.2.34 (Security fixes only - EOL Dec 2026)', 'value':'8.2'},
            {'label':'8.1.34 (EOL - unpatched)', 'value':'8.1'},
            {'label':'7.4.33 (EOL - unpatched)', 'value':'7.4'},
        ],
        'install_tpl':'''OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then \
apt-get install -y software-properties-common && \
add-apt-repository -y ppa:ondrej/php && apt-get update -q && \
apt-get install -y php{ver} php{ver}-fpm php{ver}-common php{ver}-mysql php{ver}-xml \
php{ver}-curl php{ver}-gd php{ver}-mbstring php{ver}-zip php{ver}-bcmath php{ver}-intl \
php{ver}-soap php{ver}-cli php{ver}-readline && \
systemctl enable php{ver}-fpm && systemctl start php{ver}-fpm && \
WEB_USER=$(grep -oP \'^user\\s+\\K\\S+\' /etc/nginx/nginx.conf 2>/dev/null | tr -d \';\' | head -1) && \
WEB_USER=${WEB_USER:-www-data} && \
POOL=/etc/php/{ver}/fpm/pool.d/www.conf && \
grep -q \'^listen.owner\' $POOL && sed -i "s|^listen.owner.*|listen.owner = $WEB_USER|" $POOL || echo "listen.owner = $WEB_USER" >> $POOL && \
grep -q \'^listen.group\' $POOL && sed -i "s|^listen.group.*|listen.group = $WEB_USER|" $POOL || echo "listen.group = $WEB_USER" >> $POOL && \
systemctl restart php{ver}-fpm; \
else \
RHEL_VER=$(r=$(rpm -E %{?rhel} 2>/dev/null); echo ${r:-9}); VNODOT=$(echo {ver} | tr -d .); \
(dnf install -y https://rpms.remirepo.net/enterprise/remi-release-${RHEL_VER}.rpm 2>/dev/null || yum install -y https://rpms.remirepo.net/enterprise/remi-release-${RHEL_VER}.rpm 2>/dev/null || true) && \
(command -v dnf >/dev/null 2>&1 && dnf install -y dnf-utils 2>/dev/null; true) && \
(dnf install -y php${VNODOT} php${VNODOT}-php-fpm php${VNODOT}-php-mysqlnd php${VNODOT}-php-xml php${VNODOT}-php-gd php${VNODOT}-php-mbstring php${VNODOT}-php-zip php${VNODOT}-php-bcmath php${VNODOT}-php-intl php${VNODOT}-php-soap php${VNODOT}-php-cli 2>/dev/null || \
 yum install -y php${VNODOT} php${VNODOT}-php-fpm php${VNODOT}-php-mysqlnd php${VNODOT}-php-xml php${VNODOT}-php-gd php${VNODOT}-php-mbstring php${VNODOT}-php-zip php${VNODOT}-php-bcmath php${VNODOT}-php-intl php${VNODOT}-php-soap php${VNODOT}-php-cli 2>/dev/null) && \
POOL=/etc/opt/remi/php${VNODOT}/php-fpm.d/www.conf; WEB_USER=nginx; id nginx >/dev/null 2>&1 || WEB_USER=apache; \
[ -f "$POOL" ] && sed -i "s|^listen.owner.*|listen.owner = $WEB_USER|; s|^listen.group.*|listen.group = $WEB_USER|" "$POOL"; \
systemctl enable --now php${VNODOT}-php-fpm; \
fi''',
        'install':'',
        # RHEL: Remi SCL phpXY-* packages, or the module-stream system PHP
        # when it is this version. (The Debian-only command translated to
        # 'dnf remove php8.3 ...' there and removed nothing.)
        'uninstall_tpl':'''if command -v dpkg >/dev/null 2>&1; then
systemctl stop php{ver}-fpm 2>/dev/null || true
systemctl disable php{ver}-fpm 2>/dev/null || true
apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold php{ver} php{ver}-fpm php{ver}-common php{ver}-mysql \
php{ver}-xml php{ver}-curl php{ver}-gd php{ver}-mbstring php{ver}-zip php{ver}-bcmath \
php{ver}-intl php{ver}-soap php{ver}-cli php{ver}-readline php{ver}-* 2>/dev/null || true
apt-get autoremove -y 2>/dev/null || true
else
VN=$(echo {ver} | tr -d .)
if rpm -q php$VN-php-common >/dev/null 2>&1 || rpm -q php$VN-php-cli >/dev/null 2>&1; then
  systemctl disable --now php$VN-php-fpm 2>/dev/null
  dnf remove -y "php$VN" "php$VN-*" || exit 1
elif [ "$(/usr/bin/php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null)" = "{ver}" ]; then
  systemctl disable --now php-fpm 2>/dev/null
  dnf remove -y php-common php-cli php-fpm || exit 1
else
  echo "[VortexPanel] PHP {ver} is not installed from a package this panel manages."
fi
fi''',
        'uninstall':'''for ver in 7.4 8.0 8.1 8.2 8.3 8.4 8.5; do
  systemctl stop php$ver-fpm 2>/dev/null || true
  apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold php$ver php$ver-* 2>/dev/null || true
done
for v in 74 80 81 82 83 84 85; do
  systemctl stop php$v-php-fpm 2>/dev/null || true
  dnf remove -y "php${v}*" 2>/dev/null || yum remove -y "php${v}*" 2>/dev/null || true
done
apt-get autoremove -y 2>/dev/null || true''',
        'manage':False,
    },
    # --- FTP -------------------------------------------------------------------
    {
        'id':'pure-ftpd', 'name':'Pure-FTPd', 'icon':'/static/icons/filezilla.svg', 'category':'FTP',
        'desc':'Simple, fast and secure FTP server',
        'check':'which pure-ftpd 2>/dev/null',
        'versions':[
            {'label':'Latest (distro-packaged; upstream 1.0.54)', 'value':'latest'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  apt-get install -y pure-ftpd pure-ftpd-common; '
            'else '
            # Confirmed via multiple current EPEL/RHEL package sources:
            # pure-ftpd-common does not exist as a separate RPM package on
            # RHEL-family - it's just pure-ftpd there. dnf fails the ENTIRE
            # install command if any one listed package doesn't exist, so
            # this previously failed outright on every RHEL-family system.
            '  __VP_EPEL__ && '
            '  (dnf install -y pure-ftpd 2>/dev/null || yum install -y pure-ftpd 2>/dev/null); '
            'fi && '
            '__VP_PUREDB__ && __VP_SEL_FTP__ && '
            'systemctl enable pure-ftpd && systemctl restart pure-ftpd'
        ),
        'uninstall':'systemctl stop pure-ftpd 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold pure-ftpd pure-ftpd-common 2>/dev/null; dnf remove -y pure-ftpd 2>/dev/null; yum remove -y pure-ftpd 2>/dev/null; apt-get autoremove -y 2>/dev/null; true',
        'service':'pure-ftpd', 'manage':True,
    },
    # --- Admin Tools -----------------------------------------------------------
    {
        'id':'phpmyadmin', 'name':'phpMyAdmin', 'icon':'/static/icons/phpmyadmin.svg', 'category':'Admin Tools',
        'desc':'Web-based MySQL/MariaDB admin — auto-configured at port 8082',
        'check':'test -f /usr/share/phpmyadmin/config.inc.php && echo found',
        'versions':[
            {'label':'5.2.3 (Latest)', 'value':'5.2.3'},
        ],
        # phpMyAdmin 5.2 supports PHP 7.2-8.4 -- prefer those over 8.5.
        # Serves the PHP-FPM socket that really exists (Debian, Remi SCL or
        # RHEL system PHP), on nginx, Caddy, Apache (Debian conf-available,
        # RHEL /etc/httpd/conf.d) -- each config tested and reverted if the
        # web server rejects it; port 8082 is allowed in SELinux.
        'install':r'''PMA_VER=5.2.3
PHP_PREF="8.4 8.3 8.2 8.1 8.0 7.4 8.5"
__VP_PHP_SOCK__
if [ -z "$SOCK" ]; then
  echo "[VortexPanel] No PHP-FPM is installed on this server -- install PHP from the App Store first, then install phpMyAdmin again."
  exit 1
fi
echo "[VortexPanel] Using the PHP-FPM socket $SOCK (pool user $PUSER)"
command -v wget >/dev/null 2>&1 || apt-get install -y wget || exit 1
wget -q --timeout=60 https://files.phpmyadmin.net/phpMyAdmin/$PMA_VER/phpMyAdmin-$PMA_VER-all-languages.tar.gz -O /tmp/pma.tar.gz \
  || { echo "[VortexPanel] Download of phpMyAdmin $PMA_VER failed."; rm -f /tmp/pma.tar.gz; exit 1; }
mkdir -p /usr/share/phpmyadmin
tar -xzf /tmp/pma.tar.gz -C /usr/share/phpmyadmin --strip-components=1 --no-same-owner \
  || { echo "[VortexPanel] The downloaded archive could not be extracted."; rm -f /tmp/pma.tar.gz; exit 1; }
rm -f /tmp/pma.tar.gz
if [ ! -f /usr/share/phpmyadmin/config.inc.php ]; then
  cp /usr/share/phpmyadmin/config.sample.inc.php /usr/share/phpmyadmin/config.inc.php || exit 1
  SECRET=$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)
  sed -i "s|^\$cfg\['blowfish_secret'\] = '[^']*';|\$cfg['blowfish_secret'] = '$SECRET';|" /usr/share/phpmyadmin/config.inc.php
fi
mkdir -p /usr/share/phpmyadmin/tmp
chown "$PUSER" /usr/share/phpmyadmin/tmp && chmod 700 /usr/share/phpmyadmin/tmp
__VP_SEL_PMA__
CONFIGURED=""
if systemctl is-active --quiet nginx; then
  mkdir -p /etc/nginx/conf.d
  rm -f /tmp/vp-pma-nginx.bak
  [ -f /etc/nginx/conf.d/phpmyadmin.conf ] && cp -f /etc/nginx/conf.d/phpmyadmin.conf /tmp/vp-pma-nginx.bak
  cat > /etc/nginx/conf.d/phpmyadmin.conf <<PMAEOF
server {
    listen 8082;
    server_name _;
    root /usr/share/phpmyadmin;
    index index.php;
    location ~ ^/(libraries|templates|tmp|vendor)/ { deny all; }
    location ~ \.php\$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:$SOCK;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
}
PMAEOF
  __VP_NGINX_POOL__
  __VP_SEL_PORT_8082__
  if nginx -t 2>&1; then
    systemctl reload nginx && CONFIGURED=nginx
  else
    echo "[VortexPanel] nginx rejected the phpMyAdmin site (shown above) -- reverted, nginx is unchanged."
    if [ -f /tmp/vp-pma-nginx.bak ]; then mv -f /tmp/vp-pma-nginx.bak /etc/nginx/conf.d/phpmyadmin.conf; else rm -f /etc/nginx/conf.d/phpmyadmin.conf; fi
  fi
elif systemctl is-active --quiet caddy && [ -f /etc/caddy/Caddyfile ]; then
  if grep -q "root \* /usr/share/phpmyadmin" /etc/caddy/Caddyfile; then
    CONFIGURED=caddy
  else
    cp -f /etc/caddy/Caddyfile /tmp/vp-pma-caddy.bak
    printf '\n:8082 {\n  root * /usr/share/phpmyadmin\n  php_fastcgi unix/%s\n  file_server\n}\n' "$SOCK" >> /etc/caddy/Caddyfile
    # Caddy runs as 'caddy': it needs the socket's group to connect.
    G=$(stat -c %G "$SOCK" 2>/dev/null)
    if [ -n "$G" ] && id caddy >/dev/null 2>&1 && ! id -nG caddy | grep -qw "$G"; then usermod -aG "$G" caddy; fi
    __VP_SEL_PORT_8082__
    if caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 && systemctl restart caddy; then
      CONFIGURED=caddy
    else
      echo "[VortexPanel] Caddy rejected the phpMyAdmin site (shown above) -- reverted."
      cp -f /tmp/vp-pma-caddy.bak /etc/caddy/Caddyfile; systemctl restart caddy
    fi
    rm -f /tmp/vp-pma-caddy.bak
  fi
elif [ -d /etc/httpd/conf.d ] && systemctl is-active --quiet httpd; then
  cat > /etc/httpd/conf.d/phpmyadmin.conf <<APACHEEOF
Listen 8082
<VirtualHost *:8082>
  DocumentRoot /usr/share/phpmyadmin
  <Directory /usr/share/phpmyadmin>
    Options FollowSymLinks
    DirectoryIndex index.php
    Require all granted
  </Directory>
  <FilesMatch \.php\$>
    SetHandler "proxy:unix:$SOCK|fcgi://localhost"
  </FilesMatch>
</VirtualHost>
APACHEEOF
  __VP_SEL_PORT_8082__
  if apachectl configtest 2>&1; then
    systemctl reload httpd && CONFIGURED=httpd
  else
    echo "[VortexPanel] Apache rejected the phpMyAdmin site (shown above) -- reverted."
    rm -f /etc/httpd/conf.d/phpmyadmin.conf
  fi
elif systemctl is-active --quiet apache2; then
  a2enmod proxy_fcgi setenvif >/dev/null 2>&1
  cat > /etc/apache2/conf-available/phpmyadmin.conf <<APACHEEOF
Listen 8082
<VirtualHost *:8082>
  DocumentRoot /usr/share/phpmyadmin
  <Directory /usr/share/phpmyadmin>
    Options FollowSymLinks
    DirectoryIndex index.php
    Require all granted
  </Directory>
  <FilesMatch \.php\$>
    SetHandler "proxy:unix:$SOCK|fcgi://localhost"
  </FilesMatch>
</VirtualHost>
APACHEEOF
  a2enconf phpmyadmin >/dev/null 2>&1
  if apache2ctl configtest 2>&1; then
    systemctl reload apache2 && CONFIGURED=apache2
  else
    echo "[VortexPanel] Apache rejected the phpMyAdmin site (shown above) -- reverted."
    a2disconf phpmyadmin >/dev/null 2>&1; rm -f /etc/apache2/conf-available/phpmyadmin.conf
  fi
fi
if [ -n "$CONFIGURED" ]; then
  (command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active" && ufw allow 8082/tcp comment "phpMyAdmin") >/dev/null 2>&1
  (command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1 && firewall-cmd --permanent --add-port=8082/tcp && firewall-cmd --reload) >/dev/null 2>&1
  echo "[VortexPanel] phpMyAdmin is served by $CONFIGURED at http://YOUR-SERVER-IP:8082"
else
  echo "[VortexPanel] phpMyAdmin files are in /usr/share/phpmyadmin, but no running nginx, Caddy or Apache accepted a site for it -- point your web server at that directory (PHP-FPM socket: $SOCK)."
fi
true''',
        'uninstall':r'''rm -rf /usr/share/phpmyadmin
if [ -f /etc/nginx/conf.d/phpmyadmin.conf ]; then rm -f /etc/nginx/conf.d/phpmyadmin.conf; nginx -t >/dev/null 2>&1 && systemctl reload nginx; fi
if [ -f /etc/caddy/Caddyfile ] && grep -q "root \* /usr/share/phpmyadmin" /etc/caddy/Caddyfile; then
  sed -i "/:8082/,/^}/d" /etc/caddy/Caddyfile; systemctl reload caddy 2>/dev/null
fi
if [ -f /etc/httpd/conf.d/phpmyadmin.conf ]; then rm -f /etc/httpd/conf.d/phpmyadmin.conf; apachectl configtest >/dev/null 2>&1 && systemctl reload httpd; fi
if [ -f /etc/apache2/conf-available/phpmyadmin.conf ]; then
  a2disconf phpmyadmin >/dev/null 2>&1; rm -f /etc/apache2/conf-available/phpmyadmin.conf
  apache2ctl configtest >/dev/null 2>&1 && systemctl reload apache2
fi
(command -v ufw >/dev/null 2>&1 && ufw delete allow 8082/tcp) >/dev/null 2>&1
(command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1 && firewall-cmd --permanent --remove-port=8082/tcp && firewall-cmd --reload) >/dev/null 2>&1
true''',
        'manage':False,
    },
    # --- Security --------------------------------------------------------------
    {
        'id':'fail2ban', 'name':'Fail2ban', 'icon':'/static/icons/fail2ban.svg', 'category':'Security',
        'desc':'Intrusion prevention & brute-force protection',
        'check':'which fail2ban-client 2>/dev/null',
        'versions':[
            {'label':'1.1.1 (Latest Stable)', 'value':'latest'},
        ],
        'install':r'''OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian) && \
if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then \
  apt-get install -y python3 python3-pip python3-systemd curl gzip && \
  F2B_VER=$(curl -fsSL https://api.github.com/repos/fail2ban/fail2ban/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+') && \
  F2B_VER=${F2B_VER:-1.1.0} && \
  curl -fsSL https://github.com/fail2ban/fail2ban/releases/download/${F2B_VER}/fail2ban_${F2B_VER#v}-1.upstream1_all.deb -o /tmp/fail2ban.deb 2>/dev/null && \
  dpkg -i /tmp/fail2ban.deb 2>/dev/null; \
  if [ ! -f /lib/systemd/system/fail2ban.service ] && [ ! -f /usr/lib/systemd/system/fail2ban.service ]; then \
    echo "[VortexPanel] Upstream package did not provide a systemd unit -- falling back to the distro package"; \
    apt-get install -y fail2ban; \
  fi && \
  __VP_F2B_BANACTION__ && \
  systemctl enable fail2ban && systemctl restart fail2ban; \
elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then \
  echo "[VortexPanel] fail2ban is not in the default RHEL-family repos -- enabling EPEL first" && \
  __VP_EPEL__ && \
  (dnf install -y fail2ban fail2ban-firewalld 2>/dev/null || yum install -y fail2ban fail2ban-firewalld 2>/dev/null || dnf install -y fail2ban 2>/dev/null || yum install -y fail2ban) && \
  __VP_F2B_BANACTION__ && \
  systemctl enable fail2ban && systemctl restart fail2ban; \
fi''',
        'uninstall':(
            'systemctl stop fail2ban 2>/dev/null; '
            'apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold fail2ban 2>/dev/null; '
            'apt-get autoremove -y 2>/dev/null; '
            'dnf remove -y fail2ban fail2ban-firewalld 2>/dev/null; yum remove -y fail2ban fail2ban-firewalld 2>/dev/null; true'
        ),
        'service':'fail2ban', 'manage':True,
    },
    {
        # Postfix (SMTP) + Dovecot (IMAP, LMTP delivery). The Mail Server page
        # then configures virtual mailboxes (/api/mail/setup).
        'id':'postfix', 'name':'Mail Server', 'icon':'/static/icons/mailserver.svg', 'category':'Mail',
        'desc':'Postfix + Dovecot: email accounts for your domains (IMAP/SMTP)',
        'check':'command -v postfix >/dev/null 2>&1 && command -v doveadm 2>/dev/null',
        'versions':[
            {'label':'Distro-provided Postfix + Dovecot', 'value':'latest'},
        ],
        'install':(
            # Dovecot's default "listen = *, ::" makes it (and its package
            # setup) fail on kernels with IPv6 disabled.
            '[ -e /proc/net/if_inet6 ] || { mkdir -p /etc/dovecot/conf.d && '
            '  printf "# VortexPanel: this kernel has no IPv6\nlisten = *\n" > /etc/dovecot/conf.d/98-vortexpanel-listen.conf; }; '
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  export DEBIAN_FRONTEND=noninteractive && '
            '  echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections && '
            '  echo "postfix postfix/mailname string $(hostname -f 2>/dev/null || hostname)" | debconf-set-selections && '
            '  apt-get install -y postfix dovecot-imapd dovecot-lmtpd && '
            '  systemctl enable postfix dovecot && systemctl restart postfix dovecot; '
            'else '
            '  (dnf install -y postfix dovecot || yum install -y postfix dovecot) && '
            '  systemctl enable postfix dovecot && systemctl restart postfix dovecot; '
            'fi'
        ),
        'uninstall':(
            'systemctl stop dovecot postfix 2>/dev/null; '
            'apt-get remove -y postfix dovecot-core dovecot-imapd dovecot-lmtpd 2>/dev/null; '
            'dnf remove -y postfix dovecot 2>/dev/null; yum remove -y postfix dovecot 2>/dev/null; '
            'rm -f /etc/dovecot/conf.d/98-vortexpanel-listen.conf; '
            'echo "[VortexPanel] Mailboxes in /var/mail/vhosts were kept."; true'
        ),
        'service':'postfix', 'manage':False,
    },
    {
        'id':'clamav', 'name':'ClamAV', 'icon':'/static/icons/clamav.svg', 'category':'Security',
        'desc':'Open source antivirus engine for mail gateways',
        'check':'which clamscan 2>/dev/null',
        'versions':[
            {'label':'Distro-provided (upstream 1.5.4 stable / 1.4.6 LTS)', 'value':'latest'},
        ],
        'install':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  export DEBIAN_FRONTEND=noninteractive && '
            '  apt-get install -y clamav clamav-daemon clamav-freshclam && '
            '  systemctl enable clamav-freshclam 2>/dev/null; systemctl enable clamav-daemon 2>/dev/null; '
            '  (freshclam 2>&1 || true) && '
            '  systemctl start clamav-freshclam 2>/dev/null; systemctl start clamav-daemon 2>/dev/null; '
            'else '
            # Confirmed via multiple current sources: RHEL-family package
            # names genuinely differ, not just a Debian-vs-RHEL prefix -
            # clamav-daemon and clamav-freshclam do not exist as RPM
            # packages at all. The correct names are clamd and
            # clamav-update, and the service unit is clamd@scan (a systemd
            # template unit), not clamav-daemon.
            '  __VP_EPEL__ && '
            '  (dnf install -y clamav clamd clamav-update 2>/dev/null || yum install -y clamav clamd clamav-update 2>/dev/null) && '
            # EPEL ships /etc/clamd.d/scan.conf with the socket commented
            # out -- clamd@scan then refuses to start.
            '  ( [ -f /etc/clamd.d/scan.conf ] && sed -i -e "s|^#\\?LocalSocket /run/clamd.scan/clamd.sock|LocalSocket /run/clamd.scan/clamd.sock|" -e "s|^Example|#Example|" /etc/clamd.d/scan.conf; true ) && '
            '  (freshclam 2>&1 || true) && '
            '  systemctl enable clamd@scan 2>/dev/null; systemctl start clamd@scan 2>/dev/null; '
            'fi; true'
        ),
        'uninstall':'systemctl stop clamav-daemon clamav-freshclam 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold clamav clamav-daemon clamav-freshclam 2>/dev/null; dnf remove -y clamav clamd clamav-update 2>/dev/null; yum remove -y clamav clamd clamav-update 2>/dev/null; apt-get autoremove -y 2>/dev/null; true',
        'service':'clamav-daemon', 'manage':True,
    },
    # --- DNS -------------------------------------------------------------------
    {
        'id':'ddns', 'name':'DDNS Manager', 'icon':'/static/icons/cloudflare.svg', 'category':'DNS',
        'desc':'Dynamic DNS — automatic IP update service via ddclient (Cloudflare, DynDNS and more)',
        'check':'which ddclient 2>/dev/null',
        'versions':[
            {'label':'Latest (apt)', 'value':'latest'},
        ],
        'install':'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then apt-get install -y ddclient; else __VP_EPEL__ && (dnf install -y ddclient 2>/dev/null || yum install -y ddclient); fi',
        'uninstall':'apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold ddclient 2>/dev/null; dnf remove -y ddclient 2>/dev/null; yum remove -y ddclient 2>/dev/null; apt-get autoremove -y 2>/dev/null',
        'manage':False,
    },
        {
        'id':'bind9', 'name':'BIND9 DNS', 'icon':'/static/icons/isc.svg', 'category':'DNS',
        'desc':'Industry standard authoritative DNS server',
        'check':'which named 2>/dev/null',
        'versions':[
            {'label':'9.20.x (Stable - ISC official)', 'value':'9.20'},
            {'label':'9.18.x (Ubuntu repo - upstream EOL Jun 2026)', 'value':'9.18'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian) && '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  apt-get install -y software-properties-common && '
            '  if [ "{ver}" = "9.20" ]; then '
                 # Same failure class already confirmed for ondrej/php and
                 # ondrej/apache2: isc/bind may have no release for a very new
                 # Ubuntu codename, and add-apt-repository writes it regardless,
                 # poisoning every future apt-get update if left behind.
            '    add-apt-repository -y ppa:isc/bind && '
            '    if ! apt-get update -q 2>/tmp/vp_bind_repo_err.log; then '
            '      echo "[VortexPanel] isc/bind has no release for {codename} yet -- removing it, using stock Ubuntu bind9 (9.18) instead"; '
            '      add-apt-repository --remove -y ppa:isc/bind 2>/dev/null; '
            '      rm -f /etc/apt/sources.list.d/isc-ubuntu-bind-*.list /etc/apt/sources.list.d/isc-ubuntu-bind-*.sources 2>/dev/null; '
            '      apt-get update -q; '
            '    fi; '
            '    apt-get install -y bind9 bind9utils bind9-doc; '
            '  else '
            '    apt-get update -q && apt-get install -y bind9 bind9utils bind9-doc; '
            '  fi && '
            '  mkdir -p /etc/bind/zones && '
            '  (systemctl enable named 2>/dev/null || systemctl enable bind9 2>/dev/null) && '
            '  (systemctl start named 2>/dev/null || systemctl start bind9 2>/dev/null); '
            'elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
                 # Package names are 'bind'+'bind-utils' on RHEL-family, NOT
                 # 'bind9' -- confirmed against multiple current, official
                 # RHEL/AlmaLinux/Rocky documentation sources. No verified
                 # ISC-official repo exists for RHEL-family the way it does
                 # for Ubuntu, so this always installs whatever version the
                 # distro's own default repo provides, regardless of {ver} --
                 # honest about that rather than inventing an unverified repo URL.
            '  echo "[VortexPanel] Installing BIND from the distro default repo on RHEL-family (no verified ISC-official RHEL repo for a specific version)"; '
            '  (dnf install -y bind bind-utils 2>/dev/null || yum install -y bind bind-utils) && '
            '  mkdir -p /var/named && '
            '  systemctl enable --now named; '
            'fi'
        ),
        'install':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  apt-get install -y bind9 bind9utils bind9-doc && mkdir -p /etc/bind/zones && systemctl enable bind9 && systemctl start bind9; '
            'else '
            '  (dnf install -y bind bind-utils 2>/dev/null || yum install -y bind bind-utils) && mkdir -p /var/named && systemctl enable --now named; '
            'fi'
        ),
        'uninstall':(
            'systemctl stop named 2>/dev/null; systemctl stop bind9 2>/dev/null; '
            'apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold bind9 bind9utils bind9-doc 2>/dev/null; '
            'dnf remove -y bind bind-utils 2>/dev/null; yum remove -y bind bind-utils 2>/dev/null; '
            'apt-get autoremove -y 2>/dev/null; rm -rf /etc/bind/zones /var/named/*.local 2>/dev/null'
        ),
        'service':'named', 'manage':True,
    },
    # --- Runtimes --------------------------------------------------------------
    {
        'id':'nodejs', 'name':'Node.js', 'icon':'/static/icons/nodejs.svg', 'category':'Runtime',
        'desc':'JavaScript runtime built on Chrome V8 engine',
        'check':'which node 2>/dev/null || which nodejs 2>/dev/null',
        'versions':[
            {'label':'v24 LTS - Active (Krypton, 24.21)', 'value':'24'},
            {'label':'v22 LTS - Maintenance (Jod, 22.23)', 'value':'22'},
            {'label':'v26 Current (26.10, LTS from Oct 2026)', 'value':'26'},
        ],
        'install_tpl':'''OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then mkdir -p /etc/apt/keyrings && \\
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --batch --yes --dearmor -o /etc/apt/keyrings/nodesource.gpg && \\
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_{ver}.x nodistro main" > /etc/apt/sources.list.d/nodesource.list && \\
apt-get update -o APT::Update::Error-Mode=any && \\
DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs; else curl -fsSL https://rpm.nodesource.com/setup_24.x | bash - && (dnf install -y nodejs 2>/dev/null || yum install -y nodejs); fi''',
        'install':'''OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then mkdir -p /etc/apt/keyrings && \\
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --batch --yes --dearmor -o /etc/apt/keyrings/nodesource.gpg && \\
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_24.x nodistro main" > /etc/apt/sources.list.d/nodesource.list && \\
apt-get update -o APT::Update::Error-Mode=any && \\
DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs; else curl -fsSL https://rpm.nodesource.com/setup_24.x | bash - && (dnf install -y nodejs 2>/dev/null || yum install -y nodejs); fi''',
        'uninstall':'apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold nodejs 2>/dev/null; dnf remove -y nodejs 2>/dev/null; yum remove -y nodejs 2>/dev/null; apt-get autoremove -y 2>/dev/null; true && rm -f /etc/apt/sources.list.d/nodesource.list /usr/share/keyrings/nodesource.gpg /usr/share/keyrings/nodesource-repo.gpg /etc/apt/keyrings/nodesource.gpg 2>/dev/null; apt-get update -qq 2>/dev/null; true',
        'manage':False,
    },
    {
        'id':'python', 'name':'Python Manager', 'icon':'/static/icons/python.svg', 'category':'Runtime',
        'desc':'Python 3 runtime + pip + venv',
        # "Installed" = this panel set up Python tooling: either an extra
        # Python version (not the OS's own), or pip + venv for the OS Python.
        # The old check (which python3) was true on every Linux server, so
        # Python always showed "Installed" and every uninstall "failed".
        'check':('SYS=$(/usr/bin/python3 -c "import sys;print(\'%d.%d\' % sys.version_info[:2])" 2>/dev/null); '
                 'for v in 3.10 3.11 3.12 3.13 3.14; do [ "$v" != "$SYS" ] && command -v python$v >/dev/null 2>&1 && echo found && exit 0; done; '
                 'python3 -m pip --version >/dev/null 2>&1 && python3 -c "import ensurepip" >/dev/null 2>&1 && echo found'),
        'verify_tpl':'command -v python{ver} 2>/dev/null',
        'versions':[
            {'label':'3.14 (Latest)', 'value':'3.14'},
            {'label':'3.13 (Stable)', 'value':'3.13'},
            {'label':'3.12 (Security)', 'value':'3.12'},
            {'label':'3.11 (Security)', 'value':'3.11'},
            {'label':'3.10 (Security - EOL Oct 2026)', 'value':'3.10'},
        ],
        'install_tpl':'''OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian)
SYS_PY=$(/usr/bin/python3 -c 'import sys;print("%d.%d" % sys.version_info[:2])' 2>/dev/null)
if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then
  export DEBIAN_FRONTEND=noninteractive
  if [ "{ver}" = "$SYS_PY" ]; then
    echo "[VortexPanel] Python {ver} is this server's own Python -- installing pip, venv and development headers for it"
    apt-get install -y python3-pip python3-venv python3-dev python{ver}-venv python{ver}-dev || exit 1
  else
    if ! apt-cache policy python{ver} 2>/dev/null | grep -q "Candidate: [0-9]"; then
      if grep -qi ubuntu /etc/os-release; then
        apt-get install -y software-properties-common || exit 1
        if ! add-apt-repository -y ppa:deadsnakes/ppa; then
          echo "[VortexPanel] Could not add the deadsnakes PPA (reason above) -- Python {ver} cannot be installed right now."
          exit 1
        fi
        if ! apt-get update -q 2>/tmp/vp_python_repo_err.log; then
          cat /tmp/vp_python_repo_err.log
          echo "[VortexPanel] deadsnakes/ppa has no release for {codename} yet -- removing the broken repo entry so it does not block other installs."
          add-apt-repository --remove -y ppa:deadsnakes/ppa 2>/dev/null
          rm -f /etc/apt/sources.list.d/deadsnakes-ubuntu-ppa-*.list /etc/apt/sources.list.d/deadsnakes-ubuntu-ppa-*.sources 2>/dev/null
          apt-get update -q
          exit 1
        fi
      else
        echo "[VortexPanel] Python {ver} is not packaged for this Debian release (the deadsnakes PPA is Ubuntu-only)."
        exit 1
      fi
    fi
    apt-get install -y python{ver} python{ver}-venv python{ver}-dev || exit 1
  fi
else
  (dnf install -y python{ver} python{ver}-devel python{ver}-pip 2>/dev/null || dnf install -y python{ver} python{ver}-devel || yum install -y python{ver} python{ver}-devel) || exit 1
fi
command -v python{ver} >/dev/null 2>&1 || { echo "[VortexPanel] python{ver} was not found after installation."; exit 1; }
if ! python{ver} -m pip --version >/dev/null 2>&1; then
  python{ver} -m ensurepip --upgrade >/dev/null 2>&1 || \\
  (curl -fsSL https://bootstrap.pypa.io/get-pip.py | python{ver} - --break-system-packages >/dev/null 2>&1) || \\
  echo "[VortexPanel] Note: pip is not set up globally for python{ver} (normal on Debian/Ubuntu). Create a virtual environment instead: python{ver} -m venv /path/to/env -- it includes pip."
fi
echo "[VortexPanel] $(python{ver} --version 2>&1) is ready."''',
        'install':'apt-get install -y python3 python3-pip python3-venv python3-dev',
        'uninstall_tpl':'''SYS_PY=$(/usr/bin/python3 -c 'import sys;print("%d.%d" % sys.version_info[:2])' 2>/dev/null)
if [ "{ver}" = "$SYS_PY" ]; then echo "[VortexPanel] Refusing to remove Python {ver}: it is the operating system's own Python."; exit 1; fi
if command -v dpkg >/dev/null 2>&1; then
  apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold python{ver} python{ver}-venv python{ver}-dev python{ver}-distutils python{ver}-lib2to3 python{ver}-tk python{ver}-gdbm python{ver}-full libpython{ver}-dev
  apt-get autoremove -y
else
  dnf remove -y python{ver} python{ver}-devel python{ver}-pip 2>/dev/null || yum remove -y python{ver} python{ver}-devel
fi
update-alternatives --remove python /usr/bin/python{ver} 2>/dev/null || true''',
        # Remove every EXTRA Python version; the OS's own one is always skipped.
        'uninstall':'''SYS_PY=$(/usr/bin/python3 -c 'import sys;print("%d.%d" % sys.version_info[:2])' 2>/dev/null)
for ver in 3.10 3.11 3.12 3.13 3.14; do
  [ "$ver" = "$SYS_PY" ] && continue
  apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold python$ver python$ver-venv python$ver-dev python$ver-distutils python$ver-lib2to3 2>/dev/null || true
  dnf remove -y python$ver 2>/dev/null || yum remove -y python$ver 2>/dev/null || true
done
apt-get autoremove -y 2>/dev/null || true''',
        'manage':False,
    },
    # --- Containers ------------------------------------------------------------
    {
        'id':'docker', 'name':'Docker', 'icon':'/static/icons/docker.svg', 'category':'Containers',
        'desc':'Container platform — build, ship, run anywhere',
        'check':'which docker 2>/dev/null',
        'versions':[
            {'label':'29.8.1 (Latest - only supported release)', 'value':'29'},
        ],
        'install':'curl -fsSL https://get.docker.com | sh && systemctl enable docker && systemctl start docker',
        'uninstall':'systemctl stop docker 2>/dev/null; systemctl disable docker 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null; dnf remove -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null; yum remove -y docker-ce docker-ce-cli containerd.io 2>/dev/null; apt-get autoremove -y 2>/dev/null; true && rm -f /usr/share/keyrings/docker-archive-keyring.gpg /etc/apt/sources.list.d/docker.list 2>/dev/null; apt-get update -qq 2>/dev/null; true',
        'service':'docker', 'manage':True,
    },
    # --- Dev -------------------------------------------------------------------
    {
        'id':'composer', 'name':'Composer', 'icon':'/static/icons/composer.svg', 'category':'Dev',
        'desc':'PHP dependency & package manager',
        'check':'which composer 2>/dev/null',
        'versions':[
            {'label':'2.10 (Latest Stable)', 'value':'2'},
        ],
        'install_tpl':(
            'curl -fsSL https://getcomposer.org/installer -o /tmp/composer-setup.php && '
            'php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer && '
            'rm /tmp/composer-setup.php && '
            'chmod +x /usr/local/bin/composer'
        ),
        'install':(
            'curl -fsSL https://getcomposer.org/installer -o /tmp/composer-setup.php && '
            'php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer && '
            'rm /tmp/composer-setup.php && '
            'chmod +x /usr/local/bin/composer'
        ),
        'uninstall':'rm -f /usr/local/bin/composer',
        'uninstall':'rm -f /usr/local/bin/composer',
        'manage':False,
    },
    # --- Cache -----------------------------------------------------------------
    {
        'id':'redis', 'name':'Redis', 'icon':'/static/icons/redis.svg', 'category':'Cache',
        'desc':'In-memory data store, cache & message broker',
        'check':'which redis-server 2>/dev/null',
        'versions':[
            {'label':'8.10.2 (Latest - security release)', 'value':'8.10'},
            {'label':'8.8.3 (Stable - security release)', 'value':'8.8'},
            {'label':'7.4.11 (Legacy - security release)', 'value':'7.4'},
        ],
        'install_tpl':'''OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then rm -f /usr/share/keyrings/redis-archive-keyring.gpg && curl -fsSL https://packages.redis.io/gpg | gpg --batch --no-tty --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg && \
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list && \
if ! apt-get update -o APT::Update::Error-Mode=any 2>/tmp/vp_redis_repo_err.log; then \
  echo "[VortexPanel] packages.redis.io has no release for $(lsb_release -cs) yet -- removing it, using distro-packaged redis-server instead"; \
  rm -f /etc/apt/sources.list.d/redis.list; \
  apt-get update -qq; \
fi; \
apt-get install -y redis-server && systemctl enable redis-server && systemctl start redis-server; else (dnf install -y redis 2>/dev/null || (__VP_EPEL__; dnf install -y redis 2>/dev/null) || yum install -y redis) && systemctl enable --now redis; fi''',
        'install':'''OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then rm -f /usr/share/keyrings/redis-archive-keyring.gpg && curl -fsSL https://packages.redis.io/gpg | gpg --batch --no-tty --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg && \
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list && \
apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; \
apt-get install -y redis-server && systemctl enable redis-server && systemctl start redis-server; else (dnf install -y redis 2>/dev/null || (__VP_EPEL__; dnf install -y redis 2>/dev/null) || yum install -y redis) && systemctl enable --now redis; fi''',
        'uninstall':'systemctl stop redis-server redis 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold redis-server redis-tools 2>/dev/null; dnf remove -y redis 2>/dev/null; yum remove -y redis 2>/dev/null; apt-get autoremove -y 2>/dev/null && rm -f /usr/share/keyrings/redis-archive-keyring.gpg /etc/apt/sources.list.d/redis.list 2>/dev/null; apt-get update -qq 2>/dev/null; true',
        'service':'redis-server', 'manage':True,
    },
    # --- Server Tools ----------------------------------------------------------
    {
        'id':'supervisor', 'name':'Supervisor', 'icon':'/static/icons/supervisor.svg', 'category':'Server',
        'desc':'Process control — keep programs running',
        'check':'which supervisord 2>/dev/null',
        'versions':[
            {'label':'4.3.0 (Latest Stable)', 'value':'latest'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  export DEBIAN_FRONTEND=noninteractive && apt-get install -y supervisor && '
            '  (systemctl enable supervisord 2>/dev/null || systemctl enable supervisor) && '
            '  (systemctl start supervisord 2>/dev/null || systemctl start supervisor); '
            'else '
            '  __VP_EPEL__ && '
            '  (dnf install -y supervisor 2>/dev/null || yum install -y supervisor) && '
            '  systemctl enable --now supervisord; '
            'fi'
        ),
        'install':'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then DEBIAN_FRONTEND=noninteractive apt-get install -y supervisor && systemctl enable --now supervisor; else __VP_EPEL__ && (dnf install -y supervisor 2>/dev/null || yum install -y supervisor) && systemctl enable --now supervisord; fi',
        'uninstall':'systemctl stop supervisor supervisord 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold supervisor 2>/dev/null; dnf remove -y supervisor 2>/dev/null; yum remove -y supervisor 2>/dev/null; apt-get autoremove -y 2>/dev/null',
        'service':'supervisor', 'manage':True,
    },
    {
        'id':'memcached', 'name':'Memcached', 'icon':'/static/icons/memcached.svg', 'category':'Cache',
        'desc':'Memcached is a high performance distributed memory object caching system',
        # memcached is packaged natively in every mainstream distro's default repos —
        # no custom keyring/repo dance needed, unlike Redis/nginx/etc.
        'check':'which memcached 2>/dev/null',
        'versions':[
            {'label':'Latest (distro-packaged; upstream 1.6.45)', 'value':'latest'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  apt-get install -y memcached libmemcached-tools || exit 1; '
            'elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
            '  (dnf install -y memcached libmemcached 2>/dev/null || yum install -y memcached libmemcached) || exit 1; '
            'fi; '
            # The packaged default listens on 127.0.0.1 AND ::1. On a server
            # with IPv6 disabled (common on VPS images) memcached then exits
            # with "Address family not supported by protocol" and crash-loops
            # -- confirmed in testing. Listen on IPv4 loopback only there.
            'if ! grep -q 00000000000000000000000000000001 /proc/net/if_inet6 2>/dev/null; then '
            '  if [ -f /etc/memcached.conf ] && grep -q "^-l .*::1" /etc/memcached.conf; then '
            '    sed -i "s/^-l .*/-l 127.0.0.1/" /etc/memcached.conf; '
            '    echo "[VortexPanel] IPv6 is disabled on this server -- memcached set to listen on 127.0.0.1 only"; '
            '  fi; '
            '  if [ -f /etc/sysconfig/memcached ] && grep -q "::1" /etc/sysconfig/memcached; then '
            '    sed -i "s/-l 127.0.0.1,::1/-l 127.0.0.1/" /etc/sysconfig/memcached; '
            '    echo "[VortexPanel] IPv6 is disabled on this server -- memcached set to listen on 127.0.0.1 only"; '
            '  fi; '
            'fi; '
            'systemctl reset-failed memcached 2>/dev/null; '
            'systemctl enable memcached && systemctl restart memcached'
        ),
        'install':'apt-get install -y memcached libmemcached-tools && systemctl enable memcached && systemctl start memcached',
        'uninstall':'systemctl stop memcached 2>/dev/null; systemctl disable memcached 2>/dev/null; apt-get remove -y --purge memcached libmemcached-tools 2>/dev/null; dnf remove -y memcached libmemcached 2>/dev/null; yum remove -y memcached libmemcached 2>/dev/null; apt-get autoremove -y 2>/dev/null; rm -f /etc/memcached.conf /etc/sysconfig/memcached',
        'service':'memcached', 'manage':True,
    },
    {
        'id':'ffmpeg', 'name':'ffmpeg manager', 'icon':'/static/icons/ffmpeg.svg', 'category':'Tools',
        'desc':'Supports installation and management of versions 7.1, 8.1, and nightly master. It is an open source computer program used to record, convert and stream audio and video.',
        # ffmpeg is a CLI tool, not a background service — no 'service' key, no start/stop.
        # Multiple major versions install SIDE BY SIDE (not one-at-a-time like PHP/Node),
        # each to its own directory with its own command alias (ffmpeg3/4/5/6), matching
        # aaPanel's ffmpeg manager UX exactly. Managed via dedicated /api/modules/ffmpeg/versions/*
        # endpoints rather than the generic single install/uninstall pattern.
        'check':'find /www/server/ffmpeg -mindepth 3 -maxdepth 3 -type f -name ffmpeg -path "*/bin/ffmpeg" 2>/dev/null | grep -q . && echo found',
        'versions':[],  # version list is dynamic — served by /api/modules/ffmpeg/versions
        'install_tpl':'',   # installs happen per-version, see dedicated endpoints
        'install':'',
        'uninstall':'',     # uninstalls happen per-version, see dedicated endpoints
        'manage':True,
    },
    # --- Webmail ----------------------------------------------------------------
    {
        'id':'roundcube', 'name':'Roundcube', 'icon':'/static/icons/roundcube.svg', 'category':'Mail',
        'desc':'Modern web-based IMAP email client',
        'check':'test -d /var/www/roundcube && echo found',
        'versions':[
            {'label':'1.7.4 (Latest)', 'value':'1.7.4'},
            {'label':'1.6.19 (LTS)', 'value':'1.6.19'},
        ],
        'install_tpl':r'''OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian)
if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then
  export DEBIAN_FRONTEND=noninteractive
  # Use PHP-FPM, never the "php" metapackage: on Debian/Ubuntu "php" pulls in
  # libapache2-mod-php AND apache2, which then fights nginx for port 80.
  # Reuse the PHP-FPM version already on this server when there is one.
  PV=""
  for v in 8.4 8.3 8.5 8.2 8.1; do
    if [ -S /run/php/php$v-fpm.sock ] || command -v php-fpm$v >/dev/null 2>&1; then PV=$v; break; fi
  done
  if [ -n "$PV" ]; then
    PKGS="php$PV-fpm php$PV-mysql php$PV-curl php$PV-mbstring php$PV-intl php$PV-xml php$PV-zip php$PV-gd php$PV-imagick"
  else
    PKGS="php-fpm php-mysql php-curl php-mbstring php-intl php-xml php-zip php-gd php-imagick"
  fi
  apt-get install -y wget $PKGS || exit 1
else
  __VP_EPEL__
  command -v wget >/dev/null 2>&1 || dnf install -y wget || exit 1
  # Reuse a Remi SCL PHP when one is installed (phpXY-php-fpm), else the
  # system PHP. Optional extensions one by one (dnf aborts the whole
  # transaction on one unknown name).
  VN=""
  for v in 84 83 85 82 81; do
    if [ -x /opt/remi/php$v/root/usr/sbin/php-fpm ]; then VN=$v; break; fi
  done
  if [ -n "$VN" ]; then P="php$VN-php-"; U="php$VN-php-fpm"; else P="php-"; U="php-fpm"; fi
  dnf install -y ${P}fpm ${P}mysqlnd ${P}mbstring ${P}intl ${P}xml ${P}gd || exit 1
  for X in pecl-zip pecl-imagick-im7 pecl-imagick; do
    dnf install -y "$P$X" >/dev/null 2>&1 || echo "[VortexPanel] Note: optional package $P$X is not available -- skipped"
  done
  systemctl enable --now "$U"
fi
echo "[VortexPanel] Downloading Roundcube {ver}..."
wget -q --timeout=60 https://github.com/roundcube/roundcubemail/releases/download/{ver}/roundcubemail-{ver}-complete.tar.gz -O /tmp/roundcube.tar.gz \
  || { echo "[VortexPanel] Download of Roundcube {ver} from github.com failed."; rm -f /tmp/roundcube.tar.gz; exit 1; }
mkdir -p /var/www/roundcube
tar -xzf /tmp/roundcube.tar.gz -C /var/www/roundcube --strip-components=1 || { echo "[VortexPanel] The downloaded archive could not be extracted."; rm -f /tmp/roundcube.tar.gz; exit 1; }
rm -f /tmp/roundcube.tar.gz
[ -f /var/www/roundcube/config/config.inc.php ] || cp /var/www/roundcube/config/config.inc.php.sample /var/www/roundcube/config/config.inc.php
# The site points at a PHP-FPM socket that really exists (Debian, Remi SCL or
# RHEL system PHP); the app is owned by that pool's user (it writes temp/ and
# logs/; the old code chowned to apache/www-data whatever the pool ran as).
PHP_PREF="8.4 8.3 8.5 8.2 8.1"
__VP_PHP_SOCK__
chown -R "$PUSER": /var/www/roundcube/
__VP_SEL_RC__
__VP_SEL_WEBMAIL__
if systemctl is-active --quiet nginx && [ -n "$SOCK" ]; then
  mkdir -p /etc/nginx/conf.d
  __VP_NGINX_POOL__
  __VP_SEL_PORT_8083__
  cat > /etc/nginx/conf.d/roundcube.conf <<RCEOF
server {
    listen 8083;
    server_name _;
    root /var/www/roundcube;
    index index.php;
    client_max_body_size 25m;
    location ~ ^/(config|temp|logs|bin|SQL|installer)/ { deny all; }
    location ~ /\. { deny all; }
    location ~ \.php\$ {
        include fastcgi_params;
        fastcgi_pass unix:$SOCK;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
}
RCEOF
  if nginx -t 2>&1; then
    systemctl reload nginx
    (command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active" && ufw allow 8083/tcp comment "Roundcube") >/dev/null 2>&1
    (command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1 && firewall-cmd --permanent --add-port=8083/tcp && firewall-cmd --reload) >/dev/null 2>&1
    echo "[VortexPanel] Roundcube is served by nginx at http://YOUR-SERVER-IP:8083 -- finish the setup in Settings (IMAP/SMTP server, database)."
  else
    rm -f /etc/nginx/conf.d/roundcube.conf
    echo "[VortexPanel] nginx rejected the Roundcube site config (shown above) -- removed it again, nginx is unchanged."
  fi
elif [ -z "$SOCK" ]; then
  echo "[VortexPanel] Roundcube files are in /var/www/roundcube, but no PHP-FPM socket was found, so no web server site was created."
else
  echo "[VortexPanel] Roundcube files are in /var/www/roundcube. nginx was not found running, so no web server site was created -- point your web server at /var/www/roundcube (PHP-FPM socket: $SOCK)."
fi''',
        'install':'',
        'uninstall':('rm -rf /var/www/roundcube; '
                     'if [ -f /etc/nginx/conf.d/roundcube.conf ]; then rm -f /etc/nginx/conf.d/roundcube.conf; nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null; fi; '
                     '(command -v ufw >/dev/null 2>&1 && ufw delete allow 8083/tcp) >/dev/null 2>&1; '
                     '(command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1 && firewall-cmd --permanent --remove-port=8083/tcp && firewall-cmd --reload) >/dev/null 2>&1; true'),
        'manage':True,
    },
    # --- WAF / Security ---------------------------------------------------------
    {
        'id':'modsecurity', 'name':'ModSecurity WAF', 'icon':'/static/icons/modsecurity.svg', 'category':'Security',
        'desc':'OWASP CRS v4 Web Application Firewall — Nginx/Apache, all distros (Debian/Ubuntu/RHEL/Fedora/AlmaLinux/Rocky)',
        # "Installed" requires the CORE engine to be usable (library + modsecurity.conf) —
        # NOT the CRS ruleset, which is a separate, retriable download step (see install_tpl
        # below). Previously this only checked the library .so file, so a server where the
        # library installed but the LATER modsecurity.conf/CRS download steps failed (e.g.
        # GitHub API rate-limit, network hiccup) would show "Installed" in the App Store
        # while every actual WAF control (Engine Mode toggle, Paranoia level) failed with
        # "not installed" / "CRS setup.conf not found" — a real, confirmed bug.
        # "Installed" requires the library, the config, AND the nginx connector
        # module to actually be loadable by nginx — not just present on disk.
        # Checking only the library+config (as before) is exactly the false-green
        # pattern already fixed once for the CRS chain; the connector needs the
        # same treatment now that it's a from-source build rather than an apt
        # package that either installs cleanly or is simply absent.
        'check':(
            '('
            '(test -f /usr/lib/x86_64-linux-gnu/libmodsecurity.so.3 || '
            'test -f /usr/lib64/libmodsecurity.so.3 || '
            'test -f /usr/lib/aarch64-linux-gnu/libmodsecurity.so.3 || '
            'which modsec_rules_check 2>/dev/null 1>&2) && '
            'test -f /etc/nginx/modsec/modsecurity.conf && '
            '(find /usr/lib/nginx/modules /usr/lib64/nginx/modules -name "ngx_http_modsecurity_module.so" 2>/dev/null | grep -q .) && '
            'grep -q "modsecurity_rules_file" /etc/nginx/nginx.conf 2>/dev/null'
            ') || ('
            'dpkg -l libapache2-mod-security2 2>/dev/null | grep -q "^ii" && '
            'test -f /etc/modsecurity/modsecurity.conf && '
            '(a2query -m security2 2>/dev/null | grep -q enabled || grep -rq "security2" /etc/apache2/mods-enabled/ 2>/dev/null)'
            ') && echo found'
        ),
        'versions':[
            {'label':'v3 + OWASP CRS v4 (Recommended)', 'value':'3'},
            {'label':'v2 + OWASP CRS v4 (Apache legacy)', 'value':'2'},
        ],
        'install_tpl':(
    'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); echo "[VortexPanel] Installing ModSecurity engine..."; WAF_VER="{ver}"; if [ "$WAF_VER" = "2" ]; then apt-get install -y libapache2-mod-security2 2>&1   || echo "[WARN] libapache2-mod-security2 install reported errors"; a2enmod security2 >/dev/null 2>&1 || true; mkdir -p /etc/modsecurity; if [ -f /etc/modsecurity/modsecurity.conf-recommended ]; then   cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf;   sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/" /etc/modsecurity/modsecurity.conf;   sed -i "s#SecUnicodeMapFile unicode.mapping#SecUnicodeMapFile /etc/modsecurity/unicode.mapping#" /etc/modsecurity/modsecurity.conf;   echo "[VortexPanel] OK Core engine config written (Apache)"; else   echo "[ERROR] modsecurity.conf-recommended not found - writing fallback";   printf "SecRuleEngine On\\nSecRequestBodyAccess On\\nSecAuditEngine RelevantOnly\\nSecAuditLog /var/log/modsec_audit.log\\n" > /etc/modsecurity/modsecurity.conf; fi; if [ -f /usr/share/modsecurity-crs/owasp-crs.load ]; then   mv /usr/share/modsecurity-crs/owasp-crs.load /usr/share/modsecurity-crs/owasp-crs.load.disabled-by-vortexpanel 2>/dev/null; fi; echo "[VortexPanel] Downloading OWASP CRS ruleset..."; mkdir -p /etc/modsecurity/crs && CRS_OK=0; for attempt in 1 2 3; do   CRS_TAG=$(curl -s --max-time 10 https://api.github.com/repos/coreruleset/coreruleset/releases/latest     | python3 -c "import json,sys; print(json.load(sys.stdin)[\'tag_name\'])" 2>/dev/null);   CRS_TAG=${CRS_TAG:-v4.0.0};   wget -q --timeout=15 "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_TAG}.tar.gz" -O /tmp/crs.tar.gz     && tar -xzf /tmp/crs.tar.gz -C /etc/modsecurity/crs --strip-components=1 2>/dev/null     && rm -f /tmp/crs.tar.gz && CRS_OK=1 && break;   echo "[VortexPanel] CRS download attempt $attempt failed, retrying..."; sleep 3; done; if [ "$CRS_OK" = "1" ] && [ -f /etc/modsecurity/crs/crs-setup.conf.example ]; then   cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf;   printf "Include /etc/modsecurity/crs/crs-setup.conf\\nInclude /etc/modsecurity/crs/rules/*.conf\\n" > /etc/modsecurity/main.conf;   echo "[VortexPanel] OK OWASP CRS $CRS_TAG installed"; else   printf "" > /etc/modsecurity/main.conf;   echo "[WARN] Could not download CRS after 3 attempts."; fi; CRS_CRON_FILE=/etc/cron.d/vortex-crs-update-apache; __VP_CRS_CRON__; if apache2ctl configtest 2>&1; then   systemctl reload apache2 2>/dev/null || service apache2 reload 2>/dev/null;   echo "[VortexPanel] OK apache2 config test passed"; else   echo "[ERROR] apache2 configtest failed - disabling security2 module";   a2dismod security2 >/dev/null 2>&1;   (apache2ctl configtest 2>&1 && (systemctl reload apache2 2>/dev/null || service apache2 reload 2>/dev/null) && echo "[VortexPanel] OK security2 disabled, apache2 back up")     || echo "[ERROR] apache2 still failing even with security2 disabled"; fi; else CONNECTOR_OK=0; MODULES_PATH=/usr/lib/nginx/modules; if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then   apt-get update -qq && apt-get install -y libmodsecurity-dev build-essential git     zlib1g-dev libssl-dev 2>&1     || echo "[WARN] libmodsecurity/build-tooling install reported errors";   apt-get install -y libpcre2-dev 2>&1 || apt-get install -y libpcre3-dev 2>&1     || echo "[WARN] Neither libpcre2-dev nor libpcre3-dev available on this system — proceeding anyway, nginx\'s own ./configure will report clearly if it actually needs one";   NGINX_VER=$(nginx -v 2>&1 | grep -oP \'nginx/\\K[0-9.]+\');   DETECTED_MP=$(nginx -V 2>&1 | grep -oP -- \'--modules-path=\\K[^ ]+\');   [ -n "$DETECTED_MP" ] && MODULES_PATH="$DETECTED_MP";   if [ -n "$NGINX_VER" ]; then     BUILD_DIR=$(mktemp -d) && cd "$BUILD_DIR" &&     echo "[VortexPanel] Compiling nginx-ModSecurity connector for nginx $NGINX_VER...";     if wget -q "https://nginx.org/download/nginx-${NGINX_VER}.tar.gz" -O nginx.tar.gz         && tar -xzf nginx.tar.gz         && git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity-nginx.git         && cd "nginx-${NGINX_VER}"         && ./configure --with-compat --add-dynamic-module=../ModSecurity-nginx              > /tmp/modsec-connector-configure.log 2>&1         && make modules > /tmp/modsec-connector-make.log 2>&1         && mkdir -p "$MODULES_PATH"         && cp objs/ngx_http_modsecurity_module.so "$MODULES_PATH/"; then       CONNECTOR_OK=1;       echo "[VortexPanel] ✓ Connector compiled for nginx $NGINX_VER — WAF can actually load in nginx";     else       echo "[ERROR] Connector build failed against nginx $NGINX_VER — see /tmp/modsec-connector-configure.log and /tmp/modsec-connector-make.log on this server. nginx.conf will NOT be modified, so nginx stays working; the engine/CRS below still get prepared but the WAF will not actually be active until this is resolved.";     fi;     cd / && rm -rf "$BUILD_DIR";   else     echo "[ERROR] Could not detect installed nginx version via "nginx -v" — skipping connector build. nginx.conf will NOT be modified.";   fi; elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then   __VP_EPEL__;   (dnf install -y gcc make automake autoconf libtool pcre2-devel openssl-devel zlib-devel git 2>&1 || echo "[WARN] build-tooling install reported errors"); NGINX_VER=$(nginx -v 2>&1 | grep -oP \'nginx/\\K[0-9.]+\'); DETECTED_MP=$(nginx -V 2>&1 | grep -oP -- \'--modules-path=\\K[^ ]+\'); [ -n "$DETECTED_MP" ] && MODULES_PATH="$DETECTED_MP"; if [ -n "$NGINX_VER" ]; then   BUILD_DIR=$(mktemp -d) && cd "$BUILD_DIR" &&   echo "[VortexPanel] Compiling nginx-ModSecurity connector for nginx $NGINX_VER (RHEL-family)...";   if wget -q "https://nginx.org/download/nginx-${NGINX_VER}.tar.gz" -O nginx.tar.gz       && tar -xzf nginx.tar.gz       && git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity-nginx.git       && cd "nginx-${NGINX_VER}"       && ./configure --with-compat --add-dynamic-module=../ModSecurity-nginx            > /tmp/modsec-connector-configure.log 2>&1       && make modules > /tmp/modsec-connector-make.log 2>&1       && mkdir -p "$MODULES_PATH"       && cp objs/ngx_http_modsecurity_module.so "$MODULES_PATH/"; then     CONNECTOR_OK=1;     echo "[VortexPanel] ✓ Connector compiled for nginx $NGINX_VER (RHEL-family) — WAF can actually load in nginx";   else     echo "[ERROR] Connector build failed against nginx $NGINX_VER on RHEL-family — see /tmp/modsec-connector-configure.log and /tmp/modsec-connector-make.log on this server.";   fi;   cd / && rm -rf "$BUILD_DIR"; else   echo "[ERROR] Could not detect installed nginx version via nginx -v on RHEL-family — skipping connector build."; fi;   dnf install -y mod_security mod_security_crs 2>&1 || echo "[WARN] mod_security package install reported errors"; fi; echo "[VortexPanel] Writing core engine config..."; mkdir -p /etc/nginx/modsec && CONF_OK=0; for attempt in 1 2 3; do   wget -q https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended     -O /etc/nginx/modsec/modsecurity.conf && CONF_OK=1 && break;   echo "[VortexPanel] modsecurity.conf download attempt $attempt failed, retrying..."; sleep 2; done; if [ "$CONF_OK" = "1" ]; then   sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/" /etc/nginx/modsec/modsecurity.conf;   sed -i "s/SecAuditLogParts ABIJDEFHZ/SecAuditLogParts ABCEFHJKZ/" /etc/nginx/modsec/modsecurity.conf;   wget -q https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping     -O /etc/nginx/modsec/unicode.mapping &&     sed -i "s#SecUnicodeMapFile unicode.mapping#SecUnicodeMapFile /etc/nginx/modsec/unicode.mapping#" /etc/nginx/modsec/modsecurity.conf     || echo "[WARN] Could not download unicode.mapping — nginx -t will fail until this is retried from the WAF page";   echo "[VortexPanel] ✓ Core engine config written — Engine Mode toggle will work"; else   echo "[ERROR] Could not download modsecurity.conf after 3 attempts — writing a minimal fallback config so the engine is still usable";   printf "SecRuleEngine On\\nSecRequestBodyAccess On\\nSecAuditEngine RelevantOnly\\nSecAuditLog /var/log/modsec_audit.log\\n" > /etc/nginx/modsec/modsecurity.conf; fi; echo "[VortexPanel] Downloading OWASP CRS ruleset..."; mkdir -p /etc/nginx/modsec/crs && CRS_OK=0; for attempt in 1 2 3; do   CRS_TAG=$(curl -s --max-time 10 https://api.github.com/repos/coreruleset/coreruleset/releases/latest     | python3 -c "import json,sys; print(json.load(sys.stdin)[\'tag_name\'])" 2>/dev/null);   CRS_TAG=${CRS_TAG:-v4.0.0};   wget -q --timeout=15 "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_TAG}.tar.gz" -O /tmp/crs.tar.gz     && tar -xzf /tmp/crs.tar.gz -C /etc/nginx/modsec/crs --strip-components=1 2>/dev/null     && rm -f /tmp/crs.tar.gz && CRS_OK=1 && break;   echo "[VortexPanel] CRS download attempt $attempt failed, retrying..."; sleep 3; done; if [ "$CRS_OK" = "1" ] && [ -f /etc/nginx/modsec/crs/crs-setup.conf.example ]; then   cp /etc/nginx/modsec/crs/crs-setup.conf.example /etc/nginx/modsec/crs/crs-setup.conf;   echo "[VortexPanel] ✓ OWASP CRS $CRS_TAG installed — Paranoia level control will work"; else   echo "[WARN] Could not download OWASP CRS ruleset after 3 attempts. The core engine (Engine Mode toggle) is still usable, but no attack-pattern rules are loaded yet and Paranoia level will show unavailable until you retry from the WAF page (Repair CRS button)."; fi; if [ "$CRS_OK" = "1" ]; then   printf "Include /etc/nginx/modsec/modsecurity.conf\\nInclude /etc/nginx/modsec/crs/crs-setup.conf\\nInclude /etc/nginx/modsec/crs/rules/*.conf\\n" > /etc/nginx/modsec/main.conf; else   printf "Include /etc/nginx/modsec/modsecurity.conf\\n" > /etc/nginx/modsec/main.conf; fi; cp /etc/nginx/nginx.conf /tmp/nginx.conf.pre-modsecurity 2>/dev/null; if [ "$CONNECTOR_OK" = "1" ]; then   grep -q "ngx_http_modsecurity_module.so" /etc/nginx/nginx.conf 2>/dev/null ||     sed -i "1i load_module ${MODULES_PATH}/ngx_http_modsecurity_module.so;" /etc/nginx/nginx.conf;   grep -q "modsecurity_rules_file" /etc/nginx/nginx.conf 2>/dev/null ||     sed -i "/^http {/a\\    modsecurity on;\\n    modsecurity_rules_file /etc/nginx/modsec/main.conf;"     /etc/nginx/nginx.conf 2>/dev/null || true; else   echo "[VortexPanel] Skipping nginx.conf changes — connector module isn\'t present. nginx stays working; WAF stays inactive until the connector build succeeds."; fi; CRS_CRON_FILE=/etc/cron.d/vortex-crs-update; __VP_CRS_CRON__; if nginx -t 2>&1; then   systemctl reload nginx 2>/dev/null;   echo "[VortexPanel] ✓ nginx config test passed — WAF is actually serving traffic"; else   echo "[ERROR] nginx -t failed after this install — restoring nginx.conf to its pre-install state so the server keeps working. WAF is NOT active; fix the underlying issue and reinstall.";   if [ -f /tmp/nginx.conf.pre-modsecurity ]; then     cp /tmp/nginx.conf.pre-modsecurity /etc/nginx/nginx.conf;     nginx -t 2>&1 && systemctl reload nginx 2>/dev/null && echo "[VortexPanel] ✓ nginx.conf restored, server is back up"       || echo "[ERROR] Restore also failed nginx -t — nginx.conf may have been broken before this install ran too. Manual check required.";   fi; fi; echo "[VortexPanel] ModSecurity install finished. Connector: $([ \\"$CONNECTOR_OK\\" = \\"1\\" ] && echo compiled-and-enabled || echo FAILED — WAF NOT active, see /tmp/modsec-connector-*.log). Engine: $([ \\"$CONF_OK\\" = \\"1\\" ] && echo ready || echo fallback-config). CRS ruleset: $([ \\"$CRS_OK\\" = \\"1\\" ] && echo loaded || echo MISSING — use Repair CRS on the WAF page)."; fi; '
        ),
        'uninstall':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if [ -f /etc/modsecurity/modsecurity.conf ]; then '
                # Apache path -- detected by the actual config file present,
                # not by re-asking which version was originally selected,
                # since that value isn't available at uninstall time and
                # the wrong assumption is exactly what caused this bug:
                # previously uninstall always ran the nginx removal
                # regardless of what was genuinely installed.
            '  if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '    apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold libapache2-mod-security2 modsecurity-crs 2>/dev/null || true; '
            '    apt-get autoremove -y 2>/dev/null || true; '
            '  elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
            '    dnf remove -y mod_security mod_security_crs 2>/dev/null || true; '
            '  fi; '
            '  a2dismod security2 >/dev/null 2>&1 || true; '
            '  rm -rf /etc/modsecurity /etc/cron.d/vortex-crs-update-apache; '
            '  if [ -f /usr/share/modsecurity-crs/owasp-crs.load.disabled-by-vortexpanel ]; then '
            '    mv /usr/share/modsecurity-crs/owasp-crs.load.disabled-by-vortexpanel /usr/share/modsecurity-crs/owasp-crs.load 2>/dev/null || true; '
            '  fi; '
            '  apache2ctl configtest 2>&1 && (systemctl reload apache2 2>/dev/null || service apache2 reload 2>/dev/null) || true; '
            'else '
                # nginx path -- unchanged, already correct for this case.
            '  if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '    apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold libmodsecurity-dev libmodsecurity3t64 libnginx-mod-http-modsecurity 2>/dev/null || true; '
            '    apt-get autoremove -y 2>/dev/null || true; '
            '  elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
            '    dnf remove -y mod_security nginx-mod-modsecurity 2>/dev/null || true; '
            '  fi; '
            '  find /usr/lib/nginx/modules /usr/lib64/nginx/modules -name "ngx_http_modsecurity_module.so" -delete 2>/dev/null; '
            '  rm -rf /etc/nginx/modsec /etc/cron.d/vortex-crs-update; '
            '  sed -i "/modsecurity/d" /etc/nginx/nginx.conf 2>/dev/null || true; '
            '  nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true; '
            'fi'
        ),
        'manage':False,
    },
    # --- Load Balancer ----------------------------------------------------------
    {
        'id':'caddy-waf', 'name':'Caddy WAF', 'icon':'/static/icons/caddy.svg', 'category':'Security',
        'desc':'fabriziosalmi/caddy-waf — regex rules, IP/DNS/GeoIP filtering, rate limiting, Tor blocking (Caddy only, requires rebuilding Caddy)',
        # This is fundamentally different from every other App Store module:
        # caddy-waf is a compile-time Go module, not an installable package -
        # it only exists inside a Caddy binary that was built with it included
        # via xcaddy. "Installed" therefore means the WAF module is genuinely
        # loadable by the CURRENT running Caddy binary, not that some file
        # exists on disk - matching the same false-green lesson already
        # learned and fixed for ModSecurity's connector.
        'check':'which caddy >/dev/null 2>&1 && caddy list-modules 2>/dev/null | grep -q "^http.handlers.waf" && echo found',
        'versions':[
            {'label':'Latest (main branch)', 'value':'latest'},
        ],
        'install_tpl':'''set -e
if ! command -v caddy >/dev/null 2>&1; then
  echo "[VortexPanel] Caddy is not installed. Install Caddy from the App Store first — caddy-waf only makes sense as an addition to an existing Caddy install."
  exit 1
fi

# 1. Ensure a sufficient Go toolchain is present. caddy-waf's own go.mod
# requires Go 1.25+, which is newer than every mainstream distro's own
# package repo currently ships (confirmed: Ubuntu 24.04's own golang-go
# is only 1.22) - so this checks the actual installed version rather than
# assuming the distro package is new enough, and downloads Go's own
# official binary release directly when it isn't.
if ! command -v go >/dev/null 2>&1; then
  (apt-get install -y golang-go 2>/dev/null || dnf install -y golang 2>/dev/null || yum install -y golang 2>/dev/null)
fi
export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin"

# 2. Install xcaddy - the only supported way to add this module, since it
# is explicitly not registered in Caddy's own official package registry
# (confirmed: "caddy add-package ... will fail with HTTP 400").
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# 3. Build a new Caddy binary WITH the WAF module, to a temporary location -
# never touching the live binary until the new one is proven to work. This
# is the step that protects every site on the server: if the build fails or
# produces something broken, nothing about the running Caddy has changed yet.
BUILD_DIR=$(mktemp -d) && cd "$BUILD_DIR"
echo "[VortexPanel] Building Caddy with the caddy-waf module (this can take a few minutes)..."
"$(go env GOPATH)/bin/xcaddy" build --with github.com/fabriziosalmi/caddy-waf --output ./caddy-new \\
  > /tmp/caddy-waf-build.log 2>&1

if [ ! -f ./caddy-new ]; then
  echo "[ERROR] xcaddy build failed - see /tmp/caddy-waf-build.log on this server for details."
  cd / && rm -rf "$BUILD_DIR"
  exit 1
fi

# 4. Validate the new binary BEFORE going anywhere near the live one: it
# must actually run, and it must actually contain the WAF module - a
# binary that merely exists is not the same as one that works.
if ! ./caddy-new version >/dev/null 2>&1; then
  echo "[ERROR] The newly built Caddy binary does not even run - aborting without touching the live install."
  cd / && rm -rf "$BUILD_DIR"
  exit 1
fi
if ! ./caddy-new list-modules 2>/dev/null | grep -q "^http.handlers.waf"; then
  echo "[ERROR] The newly built binary does not actually contain the waf module - aborting without touching the live install."
  cd / && rm -rf "$BUILD_DIR"
  exit 1
fi

# 5. Back up the current, known-working binary before replacing it.
CADDY_BIN=$(command -v caddy)
BACKUP_PATH="${CADDY_BIN}.pre-waf-backup-$(date +%Y%m%d%H%M%S)"
cp "$CADDY_BIN" "$BACKUP_PATH"

# 6. Atomic swap - mv on the same filesystem is atomic, so there is no
# window where the binary is half-written or missing.
chmod +x ./caddy-new
mv ./caddy-new "$CADDY_BIN"
cd / && rm -rf "$BUILD_DIR"

# 7. Confirm the existing Caddyfile still validates with the new binary,
# then restart - and if Caddy does not come back up cleanly, automatically
# roll back to the backed-up binary and restart again, rather than leaving
# every site on this server down because of a WAF install.
mkdir -p /etc/caddy/waf
curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/main/rules.json -o /etc/caddy/waf/rules.json 2>/dev/null || echo '[]' > /etc/caddy/waf/rules.json
curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/main/ip_blacklist.txt -o /etc/caddy/waf/ip_blacklist.txt 2>/dev/null || touch /etc/caddy/waf/ip_blacklist.txt
curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/main/dns_blacklist.txt -o /etc/caddy/waf/dns_blacklist.txt 2>/dev/null || touch /etc/caddy/waf/dns_blacklist.txt

ROLLED_BACK=0
if [ -f /etc/caddy/Caddyfile ] && ! caddy validate --config /etc/caddy/Caddyfile >/tmp/caddy-waf-validate.log 2>&1; then
  echo "[ERROR] The existing Caddyfile does not validate against the new binary - see /tmp/caddy-waf-validate.log. Rolling back."
  cp "$BACKUP_PATH" "$CADDY_BIN"
  ROLLED_BACK=1
fi

if [ "$ROLLED_BACK" = "0" ]; then
  systemctl restart caddy 2>/dev/null
  sleep 2
  if ! systemctl is-active --quiet caddy 2>/dev/null; then
    echo "[ERROR] Caddy failed to come back up with the new binary - rolling back to the pre-WAF backup and restarting."
    cp "$BACKUP_PATH" "$CADDY_BIN"
    systemctl restart caddy 2>/dev/null
    ROLLED_BACK=1
  fi
fi

if [ "$ROLLED_BACK" = "1" ]; then
  echo "[VortexPanel] Rolled back — Caddy is running on its previous binary, unmodified. The WAF module was NOT installed. Backup remains at ${BACKUP_PATH} for inspection."
  exit 1
fi

echo "[VortexPanel] \u2713 caddy-waf installed — Caddy rebuilt, validated, and running with the WAF module. Previous binary backed up to ${BACKUP_PATH}."''',
        'uninstall':(
            'CADDY_BIN=$(command -v caddy); '
            'LATEST_BACKUP=$(ls -t ${CADDY_BIN}.pre-waf-backup-* 2>/dev/null | head -1); '
            'if [ -n "$LATEST_BACKUP" ]; then '
            '  cp "$LATEST_BACKUP" "$CADDY_BIN" && systemctl restart caddy 2>/dev/null && '
            '  echo "[VortexPanel] Restored the pre-WAF Caddy binary from backup."; '
            'else '
            '  echo "[VortexPanel] No pre-WAF backup binary found. Caddy keeps running with its current binary; to get a clean binary without the WAF module, uninstall and reinstall Caddy from the App Store."; '
            'fi; '
            'systemctl is-active --quiet caddy 2>/dev/null || systemctl start caddy 2>/dev/null; '
            'if [ -z "$LATEST_BACKUP" ]; then exit 1; fi'
        ),
        'manage':True, 'service':'caddy',
    },
    {
        'id':'nginx-lb', 'name':'Nginx Load Balancer', 'icon':'/static/icons/nginx.svg', 'category':'Web Server',
        'desc':'Configure Nginx upstream load balancing (Round Robin, Least Conn, IP Hash)',
        'check':'test -f /etc/nginx/conf.d/loadbalancer.conf && echo found',
        'versions':[
            {'label':'Round Robin (Default)', 'value':'roundrobin'},
            {'label':'Least Connections',     'value':'leastconn'},
            {'label':'IP Hash (Sticky)',       'value':'iphash'},
        ],
        'install_tpl':'''# Create Nginx load balancer config with {ver} method
if ! command -v nginx >/dev/null 2>&1; then
  echo "[VortexPanel] nginx is not installed. Install Nginx from the App Store first."
  exit 1
fi
mkdir -p /etc/nginx/conf.d/
cat > /etc/nginx/conf.d/loadbalancer.conf << 'LBEOF'
# VortexPanel Load Balancer Configuration
# Method: {ver}
# Edit upstream servers below to match your backend servers

upstream vortex_backend {{
    # {ver} load balancing
    # Add/remove servers as needed
    server 127.0.0.1:8001 weight=1;
    server 127.0.0.1:8002 weight=1;
    server 127.0.0.1:8003 weight=1;

    # Health check - mark server down if it fails
    # server 127.0.0.1:8004 down;

    # Keepalive connections to upstream
    keepalive 32;
}}

# Uncomment to use Least Connections:
# upstream vortex_backend {{ least_conn; server ...; }}

# Uncomment to use IP Hash (sticky sessions):
# upstream vortex_backend {{ ip_hash; server ...; }}

server {{
    listen 80;
    server_name _;

    location / {{
        proxy_pass http://vortex_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503;
    }}
}}
LBEOF
if nginx -t; then
  systemctl reload nginx
else
  rm -f /etc/nginx/conf.d/loadbalancer.conf
  echo "[VortexPanel] nginx rejected the load balancer config (shown above) -- removed it again, nginx is unchanged."
  exit 1
fi''',
        'install':'',
        'uninstall':'rm -f /etc/nginx/conf.d/loadbalancer.conf && systemctl reload nginx 2>/dev/null || true',
        'manage':False,
    },

    # --- CDN --------------------------------------------------------------------
    {
        'id':'cdn', 'name':'CDN Manager', 'icon':'/static/icons/cloudflare.svg', 'category':'Network',
        'desc':'Connect Cloudflare, BunnyCDN, Akamai, CloudFront, KeyCDN, StackPath, Google CDN, Sucuri',
        'check':'echo found',
        'builtin':True,
        'versions':[{'label':'Built-in', 'value':'builtin'}],
        'install':'mkdir -p /opt/vortexpanel && echo "{}" > /opt/vortexpanel/cdn_config.json',
        'uninstall':'rm -f /opt/vortexpanel/cdn_config.json',
        'manage':False,
    },
]

# --- Shared shell snippets referenced by marker in the catalog commands ------------
# (kept as markers so the long one-line templates stay readable). Expanded once,
# at import, into every string field of MODULES.
_VP_SNIPPETS = {
    '__VP_EPEL__': ensure_epel_cmd(),
    '__VP_SEL_WEB__': selinux_web_booleans_cmd(proxy=True, db=True),
    '__VP_SEL_WEBMAIL__': selinux_web_booleans_cmd(proxy=True, db=True, mail=True),
    '__VP_SEL_FTP__': selinux_web_booleans_cmd(proxy=False, db=False, ftp=True),
    '__VP_SEL_PORT_8082__': selinux_port_cmd(8082),
    '__VP_SEL_PORT_8083__': selinux_port_cmd(8083),
    '__VP_SEL_PMA__': selinux_label_cmd('/usr/share/phpmyadmin', writable=False) + '; ' +
                      selinux_label_cmd('/usr/share/phpmyadmin/tmp', writable=True),
    '__VP_SEL_RC__': selinux_label_cmd('/var/www/roundcube/temp', writable=True) + '; ' +
                     selinux_label_cmd('/var/www/roundcube/logs', writable=True),
    '__VP_PHP_SOCK__': _PHP_SOCK_SH,
    '__VP_PUREDB__': _PUREDB_SH,
    '__VP_NGINX_POOL__': _NGINX_POOL_SH,
    '__VP_F2B_BANACTION__': _F2B_BANACTION_SH,
    '__VP_CRS_CRON__': _CRS_CRON_SH,
}

def _expand_snippets(mods):
    for m in mods:
        for k, v in list(m.items()):
            if isinstance(v, str) and '__VP_' in v:
                for mk, sv in _VP_SNIPPETS.items():
                    v = v.replace(mk, sv)
                m[k] = v

_expand_snippets(MODULES)

# --- App catalog override -------------------------------------------------------
# Lets version labels/descriptions be refreshed independently of a full panel
# update (which requires a git pull + service restart for even a one-line
# version bump). This ONLY ever supplies cosmetic/display metadata - name,
# desc, and the versions list shown in the UI. install_tpl, check commands,
# service names, and everything that actually executes on the system always
# comes from this file's own MODULES list, reviewed and shipped with the
# panel itself. A stale or malformed override can only ever show wrong text
# in the UI - it can never change what an install/uninstall/switch-version
# action actually does.
_CATALOG_OVERRIDE_PATH = '/opt/vortexpanel/data/app_catalog_override.json'

def _load_catalog_override():
    try:
        with open(_CATALOG_OVERRIDE_PATH) as f:
            data = json.load(f)
        apps = data.get('apps', {})
        if not isinstance(apps, dict):
            return {}
        return apps
    except Exception:
        return {}

def _get_mod(mod_id):
    m = next((mod for mod in MODULES if mod['id'] == mod_id), None)
    if not m:
        return None
    override = _load_catalog_override().get(mod_id)
    if not override:
        return m
    # Return a shallow copy with only display fields overridden - never
    # mutate the original MODULES entry, and never let the override supply
    # install_tpl/check/service/uninstall, even if a malformed or malicious
    # file included those keys.
    merged = dict(m)
    if isinstance(override.get('desc'), str):
        merged['desc'] = override['desc']
    if isinstance(override.get('versions'), list):
        base_values = {v.get('value') for v in m.get('versions', [])}
        override_by_value = {
            v['value']: v['label']
            for v in override['versions']
            if isinstance(v, dict) and isinstance(v.get('label'), str) and isinstance(v.get('value'), str)
        }
        # Relabel in place, preserving the base list's own values and order -
        # this can only ever change the TEXT shown for a version the panel
        # already knows how to install, never add one it doesn't.
        merged['versions'] = [
            {'label': override_by_value.get(v.get('value'), v.get('label')), 'value': v.get('value')}
            for v in m.get('versions', [])
        ]
    return merged


# --- Conflict groups — only one from each group can be installed ---------------
CONFLICT_GROUPS = {
    'webserver': ['nginx', 'apache2', 'openlitespeed', 'caddy'],
    'database':  ['mysql', 'mariadb', 'mongodb', 'postgresql'],
}

def get_conflict(mod_id):
    """Return (group, installed_member) if a conflicting app is installed"""
    for group, members in CONFLICT_GROUPS.items():
        if mod_id not in members:
            continue
        for member in members:
            if member == mod_id:
                continue
            mod = _get_mod(member)
            if mod and is_installed(mod['check']):
                return group, member
    return None, None

def _parse_ver_tuple(s):
    """Extract a comparable (major, minor, patch, ...) tuple from the start
    of a version string. Returns None if nothing numeric is found."""
    m = re.match(r'^(\d+(?:\.\d+)*)', s.strip())
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split('.'))

def _check_update_available(installed_ver, versions):
    """Given an installed version string and the module's versions list,
    find the catalog entry on the SAME major.minor track and report whether
    it's a newer patch. Comparing against the single highest-listed version
    would be wrong for apps with genuinely separate tracks (nginx stable vs
    mainline) that a user picked intentionally - this only ever suggests an
    update within the track already running, never a track switch."""
    inst = _parse_ver_tuple(installed_ver) if installed_ver else None
    if not inst:
        return False, ''
    best_same_track = None
    for v in versions:
        cat = _parse_ver_tuple(v.get('label', ''))
        if not cat:
            continue
        if cat[:2] == inst[:2] and cat > inst:
            if best_same_track is None or cat > best_same_track:
                best_same_track = cat
    if best_same_track:
        return True, '.'.join(str(x) for x in best_same_track)
    return False, ''


@modules_bp.route('/api/modules/catalog/refresh', methods=['POST'])
def refresh_catalog():
    if not req(): return jsonify({'ok': False}), 401
    import urllib.request
    url = 'https://raw.githubusercontent.com/BrowserlessAPI/VortexPanel/main/app_catalog.json'
    try:
        req_obj = urllib.request.Request(url)
        req_obj.add_header('User-Agent', 'VortexPanel/3.0')
        with urllib.request.urlopen(req_obj, timeout=10) as resp:
            raw = resp.read().decode()
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Could not reach GitHub: {e}'}), 502

    try:
        data = json.loads(raw)
    except Exception:
        return jsonify({'ok': False, 'error': 'Fetched file was not valid JSON'}), 502

    if not isinstance(data, dict) or not isinstance(data.get('apps'), dict):
        return jsonify({'ok': False, 'error': 'Fetched file did not have the expected {apps: {...}} shape'}), 502

    # Strict validation before ever writing to disk - only well-formed
    # entries survive, matching exactly what _get_mod()'s merge logic
    # already expects and safely ignores anything else.
    clean_apps = {}
    known_ids = {m['id'] for m in MODULES}
    skipped = []
    for app_id, entry in data['apps'].items():
        if app_id not in known_ids:
            skipped.append(app_id)  # catalog can be ahead of this panel version - fine, just ignored until an update
            continue
        if not isinstance(entry, dict):
            continue
        clean = {}
        if isinstance(entry.get('desc'), str):
            clean['desc'] = entry['desc']
        if isinstance(entry.get('versions'), list):
            clean['versions'] = [
                {'label': v['label'], 'value': v['value']}
                for v in entry['versions']
                if isinstance(v, dict) and isinstance(v.get('label'), str) and isinstance(v.get('value'), str)
            ]
        if clean:
            clean_apps[app_id] = clean

    os.makedirs(os.path.dirname(_CATALOG_OVERRIDE_PATH), exist_ok=True)
    with open(_CATALOG_OVERRIDE_PATH, 'w') as f:
        json.dump({'catalog_version': data.get('catalog_version', 1), 'apps': clean_apps}, f)

    panel_cache.invalidate('modules_list')
    return jsonify({'ok': True, 'updated_apps': len(clean_apps), 'skipped_unknown': skipped})


@modules_bp.route('/api/modules')
def list_modules():
    if not req(): return jsonify({'ok':False}), 401
    cached = panel_cache.get('modules_list')
    if cached: return jsonify(cached)
    result = []
    for base_m in MODULES:
        m = _get_mod(base_m['id'])  # merged with any catalog override
        installed   = is_installed(m['check'])
        svc_status  = ''
        installed_ver = ''
        has_update = False
        latest_same_track = ''
        if installed:
            svc = _resolve_svc(m.get('service',''))
            if svc:
                try:
                    r = subprocess.run(['systemctl', 'is-active', svc], capture_output=True, text=True, timeout=10)
                    svc_status = (r.stdout.strip().splitlines() or [''])[0]
                except Exception:
                    svc_status = ''
            installed_ver = get_version(m['id'])
            has_update, latest_same_track = _check_update_available(installed_ver, m.get('versions', []))
        result.append({
            'id': m['id'], 'name': m['name'], 'icon': m['icon'],
            'category': m['category'], 'desc': m['desc'],
            'installed': installed, 'svcStatus': svc_status,
            'installedVer': installed_ver,
            'hasUpdate': has_update, 'latestSameTrack': latest_same_track,
            'versions': m.get('versions', []),
            'manage': m.get('manage', False),
            'builtin': m.get('builtin', False),
            'conflict_group': next((g for g,ms in CONFLICT_GROUPS.items() if m['id'] in ms), None),
        })
    response = {'ok':True, 'modules':result}
    panel_cache.set('modules_list', response, ttl=30)
    return jsonify(response)

@modules_bp.route('/api/modules/<mod_id>/install', methods=['POST'])
def install_module(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    mod = _get_mod(mod_id)
    if not mod: return jsonify({'ok':False, 'error':'Module not found'}), 404

    # FFmpeg is a multi-version manager — it has no single install command.
    # Tell the frontend to open the Settings/Versions modal instead.
    if mod_id == 'ffmpeg':
        return jsonify({'ok': False, 'open_settings': True,
                        'error': 'ffmpeg manager uses per-version installation — open Settings to choose a version.'}), 400

    d   = request.get_json() or {}
    ver = d.get('version','')

    if mod.get('versions') and not ver:
        return jsonify({'ok':False, 'error':'Version required'}), 400
    # Check for conflicts
    conflict_group, conflict_mod = get_conflict(mod_id)
    if conflict_group and conflict_mod:
        conflict_name = next((m['name'] for m in MODULES if m['id']==conflict_mod), conflict_mod)
        return jsonify({'ok':False, 'error':'Cannot install: '+conflict_name+' is already installed. Please uninstall it first before installing a different '+conflict_group+'.', 'conflict':conflict_mod, 'conflict_group':conflict_group}), 409

    # OS-aware install command selection
    _os = get_os()
    _os_key = 'install_' + _os['family']  # e.g. install_rhel, install_fedora
    # Priority: OS-specific > install_tpl > install
    if _os['family'] != 'debian' and mod.get(_os_key):
        tpl = mod[_os_key]
    elif _os['family'] != 'debian' and mod.get('install_rhel') and _os['family'] == 'rhel':
        tpl = mod['install_rhel']
    else:
        tpl = mod.get('install_tpl', mod.get('install',''))
    cmd = tpl.replace('{ver}', ver).replace('{codename}', _os.get('codename','noble')) if tpl else ''
    if not cmd: cmd = mod.get('install','')
    if mod_id == 'nginx': cmd = nginx_install_script(ver or 'stable')
    elif mod_id == 'mariadb': cmd = mariadb_install_script(ver or '11.7')
    elif mod_id == 'postgresql': cmd = postgresql_install_script(ver or '17')
    elif mod_id == 'redis': cmd = redis_install_script()
    elif mod_id == 'mongodb': cmd = mongodb_install_script(ver or '8.0')
    elif mod_id == 'docker': cmd = docker_install_script()
    elif mod_id == 'nodejs': cmd = nodejs_install_script(ver or '22')
    elif mod_id == 'php': cmd = php_install_script(ver or '8.3')
    if not cmd: return jsonify({'ok':False, 'error':'No install command defined'}), 400

    job_id = str(uuid.uuid4())[:8]
    _job_create(job_id, initial_installed=False)
    verify_tpl = mod.get('verify_tpl', '')
    verify_cmd = verify_tpl.replace('{ver}', ver) if (verify_tpl and ver) else ''

    def run_job():
        _job_append_line(job_id, f'[VortexPanel] Installing {mod["name"]}{" " + ver if ver else ""}...')
        rc, timed_out = _run_streaming(job_id, translate_install_cmd(cmd), 1800, 'Installation')

        check_ok  = is_installed(mod['check'])
        verify_ok = is_installed(verify_cmd) if verify_cmd else True
        installed = (rc == 0) and check_ok and verify_ok and not timed_out
        svc = _resolve_svc(mod.get('service', '')) if installed else ''
        svc_note = ''
        if svc and not _svc_active(svc):
            # Installed but the service will not run -- say so instead of a
            # plain green "Installed" (memcached on an IPv6-less server was
            # reported installed while its service crash-looped).
            _svc_start(svc)
            if not _svc_active(svc):
                try:
                    tail = subprocess.run(f'journalctl -u {svc} -n 15 --no-pager -o cat 2>/dev/null',
                                          shell=True, capture_output=True, text=True, timeout=15).stdout.strip()
                except Exception:
                    tail = ''
                if tail:
                    _job_append_line(job_id, f'[VortexPanel] Last log lines of {svc}:')
                    for l in tail.splitlines():
                        _job_append_line(job_id, '  ' + l)
                svc_note = f' Warning: the {svc} service is installed but is not running -- see its log above, or use Settings > Service.'
        inst_ver = get_version(mod['id'], ver) if installed else ''
        if installed:
            msg = 'Installed successfully' + (f' -- version {inst_ver}' if inst_ver else '') + '.' + svc_note
        elif timed_out:
            msg = 'Installation was stopped because it took longer than 30 minutes.'
        elif rc < 0:
            msg = 'Installation was interrupted before it finished (the panel was restarted or the process was stopped). Run the install again.'
        elif rc != 0:
            msg = f'Installation failed (exit code {rc}). The reason is in the output above.'
        elif not verify_ok:
            msg = f'Installation failed: {mod["name"]} {ver} was not found on the system after the install finished.'
        else:
            msg = f'Installation failed: {mod["name"]} was not found on the system after the install commands ran. The reason is in the output above.'
        _job_finish(job_id, success=installed, installed=check_ok if not installed else True,
                    inst_ver=inst_ver, message=msg)

    _start_job_thread(job_id, run_job, installed_on_error=False)
    return jsonify({'ok':True, 'job_id':job_id, 'action':'install'})

# Apps whose uninstall must NOT stop their 'service' first (the service
# belongs to another app that has to keep running).
_NO_PRESTOP = {'caddy-waf'}

@modules_bp.route('/api/modules/<mod_id>/uninstall', methods=['POST'])
def uninstall_module(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    mod = _get_mod(mod_id)
    if not mod: return jsonify({'ok':False, 'error':'Not found'}), 404

    # FFmpeg is a multi-version manager -- redirect to Settings to manage individual versions
    if mod_id == 'ffmpeg':
        return jsonify({'ok': False, 'open_settings': True,
                        'error': 'Use the ffmpeg manager Settings to uninstall individual versions.'}), 400
    if mod.get('builtin'):
        return jsonify({'ok': False, 'error': f'{mod["name"]} is built into the panel and cannot be uninstalled.'}), 400

    d   = request.get_json() or {}
    ver = str(d.get('version', '') or '').strip()
    if ver and not re.match(r'^[0-9A-Za-z._-]{1,20}$', ver):
        return jsonify({'ok': False, 'error': 'Invalid version'}), 400

    # The OS's own Python must never be removed from here: on Ubuntu/Debian
    # removing python3.X (the default) also removes python3, apt tooling,
    # netplan, cloud-init, certbot, fail2ban... -- confirmed: the old
    # no-version uninstall purged python3 and python3-minimal.
    if mod_id == 'python':
        sysv = _system_python_ver()
        if not ver:
            return jsonify({'ok': False, 'error': 'Choose which Python version to remove.'}), 400
        if sysv and ver == sysv:
            return jsonify({'ok': False, 'error': f'Python {ver} is the operating system\'s own Python and cannot be removed -- '
                                                  'removing it would break the server (apt, networking tools, certbot and the panel itself).'}), 400

    # Support version-specific uninstall (PHP, Python)
    tpl = mod.get('uninstall_tpl','')
    if tpl and ver:
        cmd = tpl.replace('{ver}', ver)
    else:
        cmd = mod.get('uninstall','')

    if not cmd: return jsonify({'ok':False, 'error':'No uninstall command defined'}), 400

    job_id = str(uuid.uuid4())[:8]
    _job_create(job_id, initial_installed=True)

    def run_job():
        _job_append_line(job_id, f'[VortexPanel] Removing {mod["name"]}{" " + ver if ver else ""}...')
        try:
            lock_wait = int(os.environ.get('VP_LOCK_WAIT', '600'))
        except ValueError:
            lock_wait = 600
        if not _wait_pkg_lock(job_id, lock_wait):
            _job_finish(job_id, success=False, installed=True,
                        message=f'Nothing was changed: the package manager stayed busy ({", ".join(_pkg_lock_holders()) or "another process"}) '
                                f'for {str(lock_wait // 60) + " minutes" if lock_wait >= 120 else str(lock_wait) + " seconds"}. Try the uninstall again when it has finished.')
            return

        # Stop the service first so dpkg does not hang on restart triggers.
        # Only for apps that really have a service (previously every app,
        # e.g. "systemctl stop php", "systemctl stop roundcube").
        svc = _resolve_svc(mod.get('service', '')) if (mod.get('service') and mod_id not in _NO_PRESTOP) else ''
        was_active = _svc_active(svc) if svc else False
        if svc:
            _job_append_line(job_id, f'[VortexPanel] Stopping {svc} service...')
            _svc_stop(job_id, svc)

        rc, timed_out = _run_streaming(job_id, translate_install_cmd(cmd), 1200, 'Uninstall')

        if ver and mod_id == 'php':
            # php_layout knows the RHEL layouts too (Remi SCL has no php8.3
            # command, so `command -v php8.3` reported every RHEL removal as
            # done, even a failed one).
            still_installed = php_layout(ver) is not None
        elif ver and mod_id == 'python':
            still_installed = bool(sh(f'command -v python{ver} 2>/dev/null'))
        else:
            still_installed = is_installed(mod['check'])
        removed = not still_installed and not timed_out

        if removed:
            msg = f'{mod["name"]}{" " + ver if ver else ""} removed successfully.'
        else:
            msg = f'{mod["name"]}{" " + ver if ver else ""} could NOT be fully removed -- the reason is in the output above.'
            if svc and was_active:
                # Never leave a half-removed app stopped: bring it back so
                # the sites that depend on it keep working.
                if _svc_start(svc):
                    msg += f' Its {svc} service has been started again so your sites keep running.'
                else:
                    msg += f' Its {svc} service could not be started again -- check Settings > Service.'
        installed_flag = is_installed(mod['check']) if mod_id == 'php' else still_installed
        _job_finish(job_id, success=removed, installed=installed_flag, message=msg)

    _start_job_thread(job_id, run_job, installed_on_error=True)
    return jsonify({'ok':True, 'job_id':job_id, 'action':'uninstall'})

@modules_bp.route('/api/modules/python/installed')
def python_installed_versions():
    """Python versions present on this host, for the uninstall picker. The
    OS's own version is flagged and cannot be removed."""
    if not req(): return jsonify({'ok': False}), 401
    sysv = _system_python_ver()
    found = []
    for v in ('3.8', '3.9', '3.10', '3.11', '3.12', '3.13', '3.14', '3.15'):
        if shutil.which(f'python{v}'):
            found.append({'value': v, 'label': f'Python {v}' + (' (system -- cannot be removed)' if v == sysv else ''),
                          'system': v == sysv})
    return jsonify({'ok': True, 'versions': found, 'system': sysv})

@modules_bp.route('/api/modules/job/<job_id>/status')
def job_status(job_id):
    """Polling fallback for the job window when the live stream drops."""
    if not req(): return jsonify({'ok': False}), 401
    j = _job_get(job_id)
    if j is None:
        return jsonify({'ok': False, 'error': 'Job not found'}), 404
    try:
        since = max(0, int(request.args.get('since', 0)))
    except Exception:
        since = 0
    return jsonify({'ok': True, 'total': len(j['lines']), 'lines': j['lines'][since:],
                    'done': j['done'], 'success': j['success'], 'installed': j['installed'],
                    'installedVer': j['installedVer'], 'message': j['message']})

@modules_bp.route('/api/modules/job/<job_id>')
def job_stream(job_id):
    if not req(): return jsonify({'ok': False}), 401
    # EventSource reconnects send Last-Event-ID: resume after that line
    # instead of replaying (or losing) output.
    try:
        resume_from = int(request.headers.get('Last-Event-ID', '0') or 0)
    except Exception:
        resume_from = 0

    def generate():
        path = _job_path(job_id)
        # Wait up to 5s for the job file to appear (handles race between
        # POST creating the job and the EventSource connecting)
        for _ in range(50):
            if os.path.exists(path):
                break
            time.sleep(0.1)
        else:
            yield f'data: {json.dumps({"error": "Job not found"})}\n\n'
            return

        yield 'retry: 3000\n\n'
        sent_lines = 0     # output lines already emitted (incl. skipped on resume)
        consumed = 0       # raw JSONL rows already processed
        last_change = time.time()
        last_ping = time.time()
        deadline = time.time() + 3 * 3600
        while time.time() < deadline:
            try:
                with open(path) as f:
                    rows = f.readlines()
            except Exception:
                rows = None
            if rows is None:
                yield f'data: {json.dumps({"error": "Job output is no longer available"})}\n\n'
                return
            if len(rows) > consumed:
                last_change = time.time()
            for raw in rows[consumed:]:
                consumed += 1
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if 'line' in obj:
                    sent_lines += 1
                    if sent_lines > resume_from:
                        yield f'id: {sent_lines}\ndata: {json.dumps({"line": obj["line"]})}\n\n'
                elif obj.get('done'):
                    yield f'id: {sent_lines}\ndata: {json.dumps({"done": True, "success": obj.get("success", False), "installed": obj.get("installed", True), "installedVer": obj.get("installedVer", ""), "message": obj.get("message", "")})}\n\n'
                    return
            now = time.time()
            if now - last_change > 10 and int(now) % 10 == 0:
                j = _job_get(job_id)
                if j and j['done'] and j['message'].startswith('The panel was restarted'):
                    yield f'data: {json.dumps({"done": True, "success": False, "installed": True, "installedVer": "", "message": j["message"]})}\n\n'
                    return
            if now - last_change > 3600:
                yield f'data: {json.dumps({"done": True, "success": False, "installed": True, "installedVer": "", "message": "No output for 60 minutes -- the job appears to have stopped (was the panel restarted?). Refresh the App Store to see the current state."})}\n\n'
                return
            if now - last_ping > 15:
                # SSE comment: keeps proxies (nginx, Cloudflare) from closing
                # an idle stream during long silent steps (apt, compiles).
                last_ping = now
                yield ': keep-alive\n\n'
            time.sleep(0.3)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@modules_bp.route('/api/modules/<mod_id>/control', methods=['POST'])
def control_module(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    action = (request.get_json() or {}).get('action','status')
    mod = _get_mod(mod_id)
    if not mod: return jsonify({'ok':False}), 404
    svc = _resolve_svc(mod.get('service',''))
    if svc and action in ('start','stop','restart','reload'):
        # Timeouts: a hanging stop/start used to block the gunicorn worker forever.
        try:
            subprocess.run(['systemctl', action, svc], capture_output=True, timeout=120)
        except subprocess.TimeoutExpired:
            pass
        time.sleep(0.8)
        try:
            status = subprocess.run(['systemctl', 'is-active', svc], capture_output=True, text=True,
                                    timeout=15).stdout.strip()
        except Exception:
            status = 'unknown'
        return jsonify({'ok':True, 'status':status})
    return jsonify({'ok':False, 'error':'No service defined'})


# --- FFMPEG MANAGER -----------------------------------------------------------------
# Source: BtbN/FFmpeg-Builds on GitHub — officially listed on https://www.ffmpeg.org/download.html#build-linux
# Provides GPL static builds for both x86_64 (linux64) and aarch64 (linuxarm64).
#
# URL scheme (VERIFIED LIVE from GitHub expanded_assets on 2026-07-03):
#   https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/<filename>
#
# Static build filenames (no "shared" suffix = statically linked, no dependencies):
#   ffmpeg-n8.1-latest-linux64-gpl-8.1.tar.xz       x86_64 v8.1 stable
#   ffmpeg-n8.1-latest-linuxarm64-gpl-8.1.tar.xz    arm64  v8.1 stable
#   ffmpeg-n7.1-latest-linux64-gpl-7.1.tar.xz       x86_64 v7.1 stable
#   ffmpeg-n7.1-latest-linuxarm64-gpl-7.1.tar.xz    arm64  v7.1 stable
#   ffmpeg-master-latest-linux64-gpl.tar.xz          x86_64 latest nightly (master)
#   ffmpeg-master-latest-linuxarm64-gpl.tar.xz       arm64  latest nightly (master)
#
# Archive internal structure (verified from build.sh + linux-install-static.sh):
#   ffmpeg-n7.1.X-linux64-gpl-7.1/
#     bin/ffmpeg       <- the binary we care about
#     bin/ffprobe
#     bin/ffplay
#     doc/, man/, presets/
#
# Multiple versions install SIDE BY SIDE to /www/server/ffmpeg/ffmpeg-{ver}/
# Each accessible via a command alias: ffmpeg7, ffmpeg8, ffmpegmaster
# Matching aaPanel's ffmpeg manager UX exactly.

FFMPEG_BASE_DIR = '/www/server/ffmpeg'
FFMPEG_BASE_URL = 'https://github.com/BtbN/FFmpeg-Builds/releases/download/latest'

# Version map — "display" is what the user sees, "branch" is the BtbN branch name
# "ver_suffix" is the version number appended at the end of the filename for stable releases
FFMPEG_VERSIONS = [
    {'version': '8.1',    'label': 'ffmpeg-8.1 (Latest Stable)', 'branch': 'n8.1',   'suffix': '8.1',  'alias': 'ffmpeg8'},
    {'version': '7.1',    'label': 'ffmpeg-7.1 (Previous Stable)','branch': 'n7.1',   'suffix': '7.1',  'alias': 'ffmpeg7'},
    {'version': 'master', 'label': 'ffmpeg-master (Nightly)',       'branch': 'master', 'suffix': None,   'alias': 'ffmpegmaster'},
]

def _ffmpeg_arch():
    """Map uname -m to BtbN's Linux target name.
    linux64 = x86_64, linuxarm64 = aarch64 (arm64).
    Verified from BtbN README: targets are linux64 / linuxarm64."""
    m = subprocess.run('uname -m', shell=True, capture_output=True, text=True).stdout.strip()
    return {'x86_64': 'linux64', 'aarch64': 'linuxarm64', 'arm64': 'linuxarm64'}.get(m, 'linux64')

def _ffmpeg_dir(version):
    return os.path.join(FFMPEG_BASE_DIR, f'ffmpeg-{version}')

def _ffmpeg_url(v):
    """Build the exact BtbN download URL for a given version + current arch.
    Pattern verified live from GitHub expanded_assets 2026-07-03."""
    arch = _ffmpeg_arch()
    branch = v['branch']
    suffix = v['suffix']
    if suffix:
        # Stable release: ffmpeg-n7.1-latest-linux64-gpl-7.1.tar.xz
        fname = f'ffmpeg-{branch}-latest-{arch}-gpl-{suffix}.tar.xz'
    else:
        # Master nightly: ffmpeg-master-latest-linux64-gpl.tar.xz
        fname = f'ffmpeg-{branch}-latest-{arch}-gpl.tar.xz'
    return f'{FFMPEG_BASE_URL}/{fname}', fname

@modules_bp.route('/api/modules/ffmpeg/versions')
def ffmpeg_list_versions():
    if not req(): return jsonify({'ok': False}), 401
    out = []
    for v in FFMPEG_VERSIONS:
        d = _ffmpeg_dir(v['version'])
        binary = os.path.join(d, 'bin', 'ffmpeg')
        url, fname = _ffmpeg_url(v)
        out.append({
            'version': v['version'],
            'label':   v['label'],
            'installed': os.path.isfile(binary),
            'path':     d,
            'binary':   binary,
            'command':  v['alias'],
            'url':      url,
        })
    return jsonify({'ok': True, 'versions': out})

@modules_bp.route('/api/modules/ffmpeg/versions/<version>/detail')
def ffmpeg_version_detail(version):
    if not req(): return jsonify({'ok': False}), 401
    v = next((x for x in FFMPEG_VERSIONS if x['version'] == version), None)
    if not v: return jsonify({'ok': False, 'error': 'Unknown version'})
    d = _ffmpeg_dir(version)
    binary = os.path.join(d, 'bin', 'ffmpeg')
    if not os.path.isfile(binary):
        return jsonify({'ok': False, 'error': 'Not installed'})
    # Get exact installed version string from the binary
    ver_out = subprocess.run(f'"{binary}" -version', shell=True,
                              capture_output=True, text=True, timeout=5)
    ver_str = ver_out.stdout.splitlines()[0] if ver_out.stdout else ''
    return jsonify({'ok': True, 'path': d, 'full_command': binary,
                    'command': v['alias'], 'version_string': ver_str})

@modules_bp.route('/api/modules/ffmpeg/versions/<version>/install', methods=['POST'])
def ffmpeg_install_version(version):
    if not req(): return jsonify({'ok': False}), 401
    v = next((x for x in FFMPEG_VERSIONS if x['version'] == version), None)
    if not v: return jsonify({'ok': False, 'error': 'Unknown version'})

    dest_dir = _ffmpeg_dir(version)
    binary = os.path.join(dest_dir, 'bin', 'ffmpeg')
    if os.path.isfile(binary):
        return jsonify({'ok': False, 'error': f'ffmpeg {version} is already installed'})

    url, fname = _ffmpeg_url(v)
    arch = _ffmpeg_arch()
    tmp_archive = f'/tmp/{fname}'
    job_id = str(uuid.uuid4())[:8]
    _job_create(job_id)

    def run_job():
        try:
            _job_append_line(job_id, f'[VortexPanel] FFmpeg {version} — {arch} build')
            _job_append_line(job_id, f'[VortexPanel] Source: BtbN/FFmpeg-Builds (listed on ffmpeg.org/download.html#build-linux)')
            _job_append_line(job_id, f'[VortexPanel] Downloading: {url}')

            # Download with progress visible in the job terminal
            dl = subprocess.run(
                f'curl -fL --progress-bar --connect-timeout 30 --max-time 1200 "{url}" -o "{tmp_archive}"',
                shell=True, capture_output=True, text=True, executable='/bin/bash'
            )
            if dl.returncode != 0 or not os.path.isfile(tmp_archive):
                _job_append_line(job_id, f'[ERROR] Download failed: {dl.stderr.strip() or dl.stdout.strip()}')
                _job_finish(job_id, False, False)
                return

            file_size = os.path.getsize(tmp_archive)
            _job_append_line(job_id, f'[VortexPanel] Downloaded {round(file_size/1024/1024, 1)} MB — extracting...')

            os.makedirs(dest_dir, exist_ok=True)

            # BtbN archives have ONE top-level directory (e.g. ffmpeg-n7.1.7-linux64-gpl-7.1/)
            # containing bin/, doc/, man/, presets/ — strip it with --strip-components=1
            ext = subprocess.run(
                f'tar -xJf "{tmp_archive}" -C "{dest_dir}" --strip-components=1',
                shell=True, capture_output=True, text=True, timeout=120
            )
            subprocess.run(f'rm -f "{tmp_archive}"', shell=True)

            if ext.returncode != 0:
                _job_append_line(job_id, f'[ERROR] Extract failed: {ext.stderr.strip()}')
                shutil.rmtree(dest_dir, ignore_errors=True)
                _job_append_line(job_id, '[VortexPanel] Cleaned up partial install directory')
                _job_finish(job_id, False, False)
                return

            if not os.path.isfile(binary):
                _job_append_line(job_id, '[ERROR] ffmpeg binary not found after extraction — archive structure may have changed')
                shutil.rmtree(dest_dir, ignore_errors=True)
                _job_append_line(job_id, '[VortexPanel] Cleaned up partial install directory')
                _job_finish(job_id, False, False)
                return

            # Make all binaries executable
            subprocess.run(f'chmod +x "{dest_dir}/bin/"*', shell=True)

            # Verify the binary executes correctly before declaring success
            verify = subprocess.run(f'"{binary}" -version',
                                     shell=True, capture_output=True, text=True, timeout=10)
            if verify.returncode != 0:
                _job_append_line(job_id, f'[ERROR] Binary failed to execute: {verify.stderr.strip()[:300]}')
                shutil.rmtree(dest_dir, ignore_errors=True)
                _job_append_line(job_id, '[VortexPanel] Cleaned up partial install directory')
                _job_finish(job_id, False, False)
                return

            # Create command alias so user can type e.g. "ffmpeg8" anywhere
            alias_path = f'/usr/local/bin/{v["alias"]}'
            subprocess.run(f'ln -sf "{binary}" "{alias_path}"', shell=True)

            # Also symlink ffprobe and ffplay with version suffix if present
            for tool in ('ffprobe', 'ffplay'):
                tool_bin = os.path.join(dest_dir, 'bin', tool)
                if os.path.isfile(tool_bin):
                    subprocess.run(f'ln -sf "{tool_bin}" "/usr/local/bin/{tool}{v["alias"][6:]}"', shell=True)

            ver_line = verify.stdout.splitlines()[0] if verify.stdout else ''
            _job_append_line(job_id, f'[VortexPanel] ✓ Verified: {ver_line}')
            _job_append_line(job_id, f'[VortexPanel] ✓ Installed to {dest_dir}/bin/ffmpeg')
            _job_append_line(job_id, f'[VortexPanel] ✓ Command alias: {v["alias"]} -> {binary}')
            _job_finish(job_id, True, True, version)

        except Exception as e:
            _job_append_line(job_id, f'[ERROR] Unexpected error: {str(e)}')
            _job_finish(job_id, False, False)
            subprocess.run(f'rm -f "{tmp_archive}"', shell=True)

    threading.Thread(target=run_job, daemon=True).start()
    return jsonify({'ok': True, 'job_id': job_id})

@modules_bp.route('/api/modules/ffmpeg/versions/<version>/uninstall', methods=['POST'])
def ffmpeg_uninstall_version(version):
    if not req(): return jsonify({'ok': False}), 401
    v = next((x for x in FFMPEG_VERSIONS if x['version'] == version), None)
    if not v: return jsonify({'ok': False, 'error': 'Unknown version'})
    d = _ffmpeg_dir(version)
    binary = os.path.join(d, 'bin', 'ffmpeg')
    if not os.path.isdir(d):
        return jsonify({'ok': False, 'error': f'ffmpeg {version} is not installed'})
    subprocess.run(f'rm -rf "{d}"', shell=True)
    alias_path = f'/usr/local/bin/{v["alias"]}'
    subprocess.run(f'rm -f "{alias_path}"', shell=True)
    # Remove ffprobe/ffplay aliases too
    for tool in ('probe', 'play'):
        subprocess.run(f'rm -f "/usr/local/bin/ff{tool}{v["alias"][6:]}"', shell=True)
    return jsonify({'ok': True})

@modules_bp.route('/api/modules/ffmpeg/reset', methods=['POST'])
def ffmpeg_reset():
    """Full removal — deletes every installed version, every command alias, and the
    base directory itself. This is the only genuine 'uninstall ffmpeg manager
    completely' action: since ffmpeg has no single install/uninstall command
    (each version is managed independently), this exists specifically to recover
    from stuck states — e.g. a leftover empty directory from a previously
    interrupted install that made the App Store list falsely show 'installed'
    with nothing actually usable underneath."""
    if not req(): return jsonify({'ok': False}), 401
    removed = []
    for v in FFMPEG_VERSIONS:
        d = _ffmpeg_dir(v['version'])
        if os.path.isdir(d):
            removed.append(v['version'])
        shutil.rmtree(d, ignore_errors=True)
        subprocess.run(f'rm -f "/usr/local/bin/{v["alias"]}"', shell=True)
        for tool in ('probe', 'play'):
            subprocess.run(f'rm -f "/usr/local/bin/ff{tool}{v["alias"][6:]}"', shell=True)
    # Remove the base directory entirely (covers stale/empty dirs from any
    # interrupted install, even ones that don't match a known version)
    shutil.rmtree(FFMPEG_BASE_DIR, ignore_errors=True)
    return jsonify({'ok': True, 'removed_versions': removed})

# Apps whose Settings > Switch Version list must match the App Store catalog
# (the Settings endpoints carried their own hard-coded, outdated lists: e.g.
# MySQL "9.3", MongoDB "6.0", PostgreSQL without 18, nginx 1.30.4/1.31.3).
_SWITCH_FROM_CATALOG = {'nginx', 'apache2', 'openlitespeed', 'mysql', 'mariadb', 'postgresql',
                        'mongodb', 'redis', 'nodejs', 'bind9'}

import glob as _glob, ipaddress as _ipaddress
try:
    from panel.routes.php import (php_layout, installed_php_layouts, php_layout_for_path, php_loaded_modules,
                                  php_svc_status, php_apply_file, php_ini_set, php_save_ini_values,
                                  php_install_ext, php_uninstall_ext, valid_php_ver)
except ImportError:
    from php import (php_layout, installed_php_layouts, php_layout_for_path, php_loaded_modules,
                     php_svc_status, php_apply_file, php_ini_set, php_save_ini_values,
                     php_install_ext, php_uninstall_ext, valid_php_ver)

# --- Settings helpers -------------------------------------------------------------
def _st_run(cmd, t=60):
    """Run a shell command. Returns (returncode, stdout+stderr); never raises."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t, errors='replace')
        return r.returncode, ((r.stdout or '') + (r.stderr or '')).strip()
    except subprocess.TimeoutExpired:
        return 124, f'timed out after {t}s'
    except Exception as e:
        return 1, str(e)

def _st_family():
    try:
        return 'debian' if get_os().get('family') == 'debian' else 'rhel'
    except Exception:
        return 'debian'

def _st_read(path, default=''):
    try:
        with open(path, errors='replace') as f:
            return f.read()
    except Exception:
        return default

def _st_tail(path, n=100):
    if not path or not os.path.exists(path):
        return ''
    rc, out = _st_run(f'tail -n {int(n)} "{path}" 2>/dev/null', 15)
    return out

def _st_journal(unit, n=80):
    rc, out = _st_run(f'journalctl -u {unit} -n {int(n)} --no-pager 2>/dev/null', 20)
    return out if out and '-- No entries --' not in out else ''

def _st_status(*names):
    """systemctl is-active of the first unit that exists among the logical
    names (resolved per distro). Never returns multi-line output."""
    first = ''
    for n in names:
        unit = _resolve_svc(n)
        rc, out = _st_run(f'systemctl is-active {unit} 2>/dev/null', 10)
        st = (out.splitlines() or ['inactive'])[0].strip() or 'inactive'
        if st == 'active':
            return 'active'
        first = first or st
    return first or 'inactive'

def _st_restore(path, old):
    try:
        if old is None:
            os.remove(path)
        else:
            with open(path, 'w') as f:
                f.write(old)
    except Exception:
        pass

def _st_apply(changes, test_cmd=None, svc=None, action='reload'):
    """Write config file(s) {path: content}, run test_cmd, then reload/restart
    svc when it is running and confirm it still runs. On any failure every
    file is restored (and the service restarted on the old config).
    Returns (ok, message)."""
    olds = {}
    for path, content in changes.items():
        d = os.path.dirname(path)
        if d and not os.path.isdir(d):
            for p, o in olds.items():
                _st_restore(p, o)
            return False, f'{d} does not exist on this server.'
        try:
            with open(path) as f:
                olds[path] = f.read()
        except FileNotFoundError:
            olds[path] = None
        with open(path, 'w') as f:
            f.write(content)
    def _undo():
        for p, o in olds.items():
            _st_restore(p, o)
    if test_cmd:
        rc, out = _st_run(test_cmd, 90)
        if rc != 0:
            _undo()
            return False, 'Configuration test failed -- the previous file was restored:\n' + out[-1500:]
    if svc:
        unit = _resolve_svc(svc)
        if not _svc_active(unit):
            return True, f'Saved. {unit} is not running, so the change takes effect when it starts.'
        rc, out = _st_run(f'systemctl {action} {unit} 2>&1', 240)
        if rc == 0:
            time.sleep(1)
        if rc != 0 or not _svc_active(unit):
            tail = _st_journal(unit, 15)
            _undo()
            # The failed start usually tripped systemd's start limit (the unit
            # auto-restarts several times in a row); without reset-failed the
            # restart on the restored config is refused and the service stays
            # down ("Start request repeated too quickly").
            _st_run(f'systemctl reset-failed {unit} 2>&1', 30)
            _st_run(f'systemctl restart {unit} 2>&1', 240)
            time.sleep(1)
            back = _svc_active(unit)
            return False, (f'{unit} failed to {action} with the new configuration -- the previous file was '
                           f'restored and ' + (f'{unit} is running again.' if back else
                                               f'{unit} could NOT be started again -- check its log.') +
                           '\n' + (out or tail)[-1500:])
    return True, ''

_ST_VAL_RE = re.compile(r'^[A-Za-z0-9._:/-]{1,128}$')
_ST_SIZE_RE = re.compile(r'^\d{1,12}[KkMmGgTt]?$')
_ST_INT_RE = re.compile(r'^\d{1,9}$')

def _st_valid_port(p):
    try:
        p = int(str(p).strip())
        return 0 < p < 65536
    except (TypeError, ValueError):
        return False

def _st_ip_or_net(x):
    try:
        _ipaddress.ip_network(x, strict=False)
        return True
    except ValueError:
        return False

# --- per-app file locations ---------------------------------------------------------
def _st_nginx_conf():
    return next((p for p in ['/etc/nginx/nginx.conf', '/www/server/nginx/conf/nginx.conf'] if os.path.exists(p)),
                '/etc/nginx/nginx.conf')

def _st_apache():
    if os.path.exists('/etc/apache2/apache2.conf') or not os.path.exists('/etc/httpd/conf/httpd.conf'):
        mpm = sorted(_glob.glob('/etc/apache2/mods-enabled/mpm_*.conf'))
        return {'conf': '/etc/apache2/apache2.conf', 'svc': 'apache2', 'bin': 'apache2',
                'test': 'apache2ctl configtest 2>&1', 'log': '/var/log/apache2/error.log',
                'mpm': mpm[0] if mpm else ''}
    return {'conf': '/etc/httpd/conf/httpd.conf', 'svc': 'httpd', 'bin': 'httpd',
            'test': 'apachectl configtest 2>&1', 'log': '/var/log/httpd/error_log', 'mpm': ''}

_OLS_CONF = '/usr/local/lsws/conf/httpd_config.conf'

_MYSQL_CNF = {
    'mysql':   ['/etc/mysql/mysql.conf.d/mysqld.cnf', '/etc/my.cnf.d/mysql-server.cnf', '/etc/my.cnf',
                '/etc/mysql/my.cnf'],
    'mariadb': ['/etc/mysql/mariadb.conf.d/50-server.cnf', '/etc/my.cnf.d/mariadb-server.cnf',
                '/etc/my.cnf.d/server.cnf', '/etc/my.cnf', '/etc/mysql/my.cnf'],
}
_MYSQLD_SECTION_RE = re.compile(r'^[ \t]*\[(mysqld|mariadb|server)\][ \t]*$', re.M)

def _st_mysql_flavor(mod_id):
    rc, out = _st_run('mysqld --version 2>/dev/null; mariadbd --version 2>/dev/null; mariadb --version 2>/dev/null', 15)
    if 'mariadb' in out.lower():
        return 'mariadb'
    if out.strip():
        return 'mysql'
    return 'mariadb' if mod_id == 'mariadb' else 'mysql'

def _st_mysql_cnf(flavor):
    existing = [p for p in _MYSQL_CNF[flavor] if os.path.exists(p)]
    for p in existing:
        if _MYSQLD_SECTION_RE.search(_st_read(p)):
            return p
    return existing[0] if existing else _MYSQL_CNF[flavor][0]

def _st_mysql_svc(flavor):
    return _resolve_svc('mariadb' if flavor == 'mariadb' else 'mysql')

def _st_redis_conf():
    return next((p for p in ['/etc/redis/redis.conf', '/etc/redis.conf'] if os.path.exists(p)), '/etc/redis/redis.conf')

def _st_memcached_conf():
    for p in ('/etc/memcached.conf', '/etc/sysconfig/memcached'):
        if os.path.exists(p):
            return p, ('sysconfig' if 'sysconfig' in p else 'flags')
    return ('/etc/memcached.conf', 'flags') if _st_family() == 'debian' else ('/etc/sysconfig/memcached', 'sysconfig')

def _st_pg():
    """Newest PostgreSQL cluster config: Debian /etc/postgresql/<v>/main,
    RHEL PGDG /var/lib/pgsql/<v>/data, RHEL AppStream /var/lib/pgsql/data."""
    def _v(p):
        m = re.search(r'/(\d+(?:\.\d+)?)/', p)
        return _parse_ver_tuple(m.group(1)) if m else (0,)
    deb = sorted(_glob.glob('/etc/postgresql/*/main/postgresql.conf'), key=_v)
    if deb:
        conf = deb[-1]
        ver = re.search(r'/etc/postgresql/([^/]+)/', conf).group(1)
        unit = f'postgresql@{ver}-main'
        return {'conf': conf, 'ver': ver, 'svc': unit, 'status_svcs': [unit, 'postgresql'],
                'all': deb, 'hba': os.path.join(os.path.dirname(conf), 'pg_hba.conf')}
    rh = sorted(_glob.glob('/var/lib/pgsql/*/data/postgresql.conf'), key=_v)
    if rh:
        conf = rh[-1]
        ver = re.search(r'/var/lib/pgsql/([^/]+)/', conf).group(1)
        return {'conf': conf, 'ver': ver, 'svc': f'postgresql-{ver}', 'status_svcs': [f'postgresql-{ver}'],
                'all': rh, 'hba': os.path.join(os.path.dirname(conf), 'pg_hba.conf')}
    conf = '/var/lib/pgsql/data/postgresql.conf'
    if os.path.exists(conf):
        return {'conf': conf, 'ver': '', 'svc': 'postgresql', 'status_svcs': ['postgresql'], 'all': [conf],
                'hba': '/var/lib/pgsql/data/pg_hba.conf'}
    return {'conf': '', 'ver': '', 'svc': 'postgresql', 'status_svcs': ['postgresql'], 'all': [], 'hba': ''}

def _st_bind():
    if _st_family() == 'debian' or os.path.isdir('/etc/bind'):
        return {'conf': '/etc/bind/named.conf', 'local': '/etc/bind/named.conf.local',
                'options': '/etc/bind/named.conf.options', 'zones_dir': '/etc/bind/zones', 'base': '/etc/bind'}
    return {'conf': '/etc/named.conf', 'local': '/etc/named.rfc1912.zones', 'options': '/etc/named.conf',
            'zones_dir': '/var/named', 'base': '/var/named'}

def _st_supervisor():
    if os.path.exists('/etc/supervisor/supervisord.conf'):
        return '/etc/supervisor/supervisord.conf', 'supervisor'
    if os.path.exists('/etc/supervisord.conf'):
        return '/etc/supervisord.conf', 'supervisord'
    return '/etc/supervisor/supervisord.conf', 'supervisor'

def _st_allowed_conf(mod_id):
    """Config files the generic Config tab may write for this app:
    (allowed paths, test command, service, reload action)."""
    if mod_id == 'nginx':
        return [_st_nginx_conf()], 'nginx -t 2>&1', 'nginx', 'reload'
    if mod_id == 'apache2':
        a = _st_apache()
        return [a['conf']], a['test'], a['svc'], 'reload'
    if mod_id == 'openlitespeed':
        return [_OLS_CONF], None, 'lsws', 'restart'
    if mod_id in ('mysql', 'mariadb'):
        fl = _st_mysql_flavor(mod_id)
        return [p for p in _MYSQL_CNF[fl] if os.path.exists(p)], None, _st_mysql_svc(fl), 'restart'
    if mod_id == 'redis':
        return [_st_redis_conf()], None, 'redis-server', 'restart'
    if mod_id == 'memcached':
        return [_st_memcached_conf()[0]], None, 'memcached', 'restart'
    if mod_id == 'mongodb':
        return ['/etc/mongod.conf'], None, 'mongod', 'restart'
    if mod_id == 'supervisor':
        p, svc = _st_supervisor()
        return [p], None, svc, 'restart'
    if mod_id in ('pure-ftpd', 'pure_ftpd'):
        return [p for p in ('/etc/pure-ftpd/pure-ftpd.conf', '/etc/pure-ftpd.conf') if os.path.exists(p)], None, 'pure-ftpd', 'restart'
    if mod_id == 'bind9':
        b = _st_bind()
        files = [b['conf'], b['local'], b['options']]
        return list(dict.fromkeys(files)), f'named-checkconf {b["conf"]} 2>&1', 'named', 'reload'
    return [], None, None, None

def _st_same_file(a, b):
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except Exception:
        return False

def _st_caddy():
    try:
        from panel.routes import caddy as _c
    except ImportError:
        import caddy as _c
    return _c

def _st_redis_cli(conf_content):
    """redis-cli argument prefix + env with the password from redis.conf, so
    the Settings page still works when requirepass is set."""
    m = re.search(r'^\s*port\s+(\d+)', conf_content, re.M)
    port = m.group(1) if m else '6379'
    args = ['redis-cli']
    if port == '0':
        s = re.search(r'^\s*unixsocket\s+(\S+)', conf_content, re.M)
        if s:
            args += ['-s', s.group(1)]
    else:
        args += ['-p', port]
    env = os.environ.copy()
    pw = re.search(r'^\s*requirepass\s+(.+?)\s*$', conf_content, re.M)
    if pw:
        env['REDISCLI_AUTH'] = pw.group(1).strip().strip('"').strip("'")
    def cli(*a):
        try:
            r = subprocess.run(args + list(a), capture_output=True, text=True, timeout=10, env=env)
            return r.stdout.strip() if r.returncode == 0 else ''
        except Exception:
            return ''
    return cli

# --- phpMyAdmin / Roundcube PHP socket ------------------------------------------------
_PMA_CONFS = (('/etc/nginx/conf.d/phpmyadmin.conf', 'nginx'),
              ('/etc/httpd/conf.d/phpmyadmin.conf', 'httpd'),
              ('/etc/apache2/conf-available/phpmyadmin.conf', 'apache2'))

def _st_pma_conf():
    """(path, kind) of the web server config serving phpMyAdmin, ('', '') if none."""
    for p, kind in _PMA_CONFS:
        if os.path.exists(p):
            return p, kind
    try:
        cad = _st_caddy()
        if '/usr/share/phpmyadmin' in _st_read(cad.CADDYFILE):
            return cad.CADDYFILE, 'caddy'
    except Exception:
        pass
    return '', ''

def _st_php_sock_versions():
    """PHP versions whose FPM socket exists right now (every layout php.py knows)."""
    return [l['ver'] for l in installed_php_layouts() if os.path.exists(l['sock'])]

def _st_conf_php(conf_text):
    """PHP version a site config's FPM socket belongs to ('' if unknown)."""
    for l in installed_php_layouts():
        if l['sock'] and l['sock'] in (conf_text or ''):
            return l['ver']
    m = re.search(r'php(\d+\.\d+)-fpm\.sock', conf_text or '')
    return m.group(1) if m else ''

# FPM socket reference inside nginx (fastcgi_pass unix:...;), Apache
# (proxy:unix:...|fcgi) and Caddy (php_fastcgi unix/...) site configs.
_SOCK_REF_RE = re.compile(r'(fastcgi_pass\s+unix:|proxy:unix:|php_fastcgi\s+unix/)(/[^\s;|"]+\.sock)')

# --- PHP -------------------------------------------------------------------------------
_PHP_SETTINGS_EXTS = [
    {'name':'fileinfo','type':'Universal','desc':'Get file MIME type and encoding'},
    {'name':'memcached','type':'Cache','desc':'Advanced distributed caching'},
    {'name':'redis','type':'Cache','desc':'Redis key-value store client'},
    {'name':'apcu','type':'Cache','desc':'In-memory user data cache'},
    {'name':'imagick','type':'Universal','desc':'ImageMagick graphics library'},
    {'name':'exif','type':'General','desc':'Read image EXIF information'},
    {'name':'intl','type':'Universal','desc':'Internationalization support'},
    {'name':'mbstring','type':'Universal','desc':'Multibyte string handling'},
    {'name':'zip','type':'Universal','desc':'ZIP file support'},
    {'name':'gd','type':'Universal','desc':'GD graphics library'},
    {'name':'curl','type':'Universal','desc':'cURL HTTP client'},
    {'name':'opcache','type':'Cache','desc':'PHP opcode cache'},
    {'name':'xdebug','type':'Debug','desc':'Debugger and profiler'},
    {'name':'sodium','type':'Security','desc':'Modern cryptography'},
    {'name':'xml','type':'Universal','desc':'XML parsing'},
]

_PHP_CONFIG_KEYS = ['short_open_tag', 'max_execution_time', 'memory_limit', 'post_max_size', 'upload_max_filesize',
                    'max_file_uploads', 'display_errors', 'date.timezone', 'max_input_time', 'disable_functions',
                    'session.gc_maxlifetime']
_FPM_PROFILE_KEYS = ['pm', 'pm.max_children', 'pm.start_servers', 'pm.min_spare_servers', 'pm.max_spare_servers',
                     'pm.max_requests', 'request_slowlog_timeout', 'request_terminate_timeout']

def _st_kv(content, key):
    m = re.search(rf'^[ \t]*{re.escape(key)}[ \t]*=[ \t]*(.*?)[ \t]*$', content, re.M)
    return m.group(1).strip().strip('"') if m else ''

def _st_php_payload(lay, all_layouts):
    ini_content = _st_read(lay['ini'])
    fpm_content = _st_read(lay['pool'])
    defaults = {'short_open_tag': 'Off', 'max_execution_time': '30', 'memory_limit': '128M',
                'post_max_size': '8M', 'upload_max_filesize': '2M', 'max_file_uploads': '20',
                'display_errors': 'Off', 'date.timezone': 'UTC', 'max_input_time': '60',
                'disable_functions': '', 'session.gc_maxlifetime': '1440'}
    config = {k: (_st_kv(ini_content, k) or defaults[k]) for k in _PHP_CONFIG_KEYS}
    fpm_profile = {
        'pm':                   _st_kv(fpm_content, 'pm') or 'dynamic',
        'pm.max_children':      _st_kv(fpm_content, 'pm.max_children') or '5',
        'pm.start_servers':     _st_kv(fpm_content, 'pm.start_servers') or '2',
        'pm.min_spare_servers': _st_kv(fpm_content, 'pm.min_spare_servers') or '1',
        'pm.max_spare_servers': _st_kv(fpm_content, 'pm.max_spare_servers') or '3',
        'listen':               _st_kv(fpm_content, 'listen') or lay['sock'],
        'request_slowlog_timeout': _st_kv(fpm_content, 'request_slowlog_timeout') or '0',
    }
    loaded = php_loaded_modules(lay)
    extensions = [{**e, 'installed': e['name'] in loaded} for e in _PHP_SETTINGS_EXTS]
    logs = _st_tail(lay['log'], 100) or _st_journal(lay['svc'], 80) or 'No logs'
    rc, vfull = _st_run(f'"{lay["bin"]}" -r "echo PHP_VERSION;" 2>/dev/null', 15) if os.path.exists(lay['bin']) else (1, '')
    vfull = vfull.strip().splitlines()[-1] if rc == 0 and vfull.strip() else lay['ver']
    status = php_svc_status(lay)
    return {'ok': True, 'status': status, 'version': vfull, 'sel_ver': lay['ver'],
            'service': lay['svc'],
            'php_versions': [{'version': l['ver'], 'status': php_svc_status(l), 'ini_path': l['ini'],
                              'fpm_conf': l['pool'], 'service': l['svc']} for l in all_layouts],
            'ini_path': lay['ini'], 'ini_content': ini_content,
            'fpm_conf': lay['pool'], 'fpm_content': fpm_content,
            'config': config, 'fpm_profile': fpm_profile,
            'extensions': extensions, 'logs': logs,
            'phpinfo': {'version': lay['ver'],
                        'install_path': os.path.dirname(os.path.dirname(lay['bin'])),
                        'ini_path': lay['ini'],
                        'loaded': '\n'.join(sorted(loaded))}}


@modules_bp.route('/api/modules/<mod_id>/settings')
def get_module_settings(mod_id):
    if not req(): return jsonify({'ok': False}), 401
    try:
        resp = _get_module_settings_impl(mod_id)
    except Exception as e:
        # One unreadable file or odd command output must not turn the whole
        # Settings dialog into an HTTP 500.
        return jsonify({'ok': False, 'error': f'Could not read the {mod_id} settings: {type(e).__name__}: {e}'})
    try:
        if mod_id in _SWITCH_FROM_CATALOG and isinstance(resp, Response) and resp.is_json:
            data = resp.get_json()
            mod = _get_mod(mod_id)
            if isinstance(data, dict) and data.get('ok') and 'versions' in data and mod and mod.get('versions'):
                data['versions'] = mod['versions']
                return jsonify(data)
    except Exception:
        pass
    return resp

def _get_module_settings_impl(mod_id):
    if not req(): return jsonify({'ok': False}), 401
    _re = re
    def sh(cmd, t=15):
        try: return subprocess.check_output(cmd,shell=True,text=True,stderr=subprocess.DEVNULL,timeout=t).strip()
        except Exception: return ''

    if mod_id == 'nginx':
        status  = _st_status('nginx')
        version = sh('nginx -v 2>&1 | grep -oE "[0-9]+\\.[0-9]+\\.[0-9]+" | head -1') or ''
        conf_path = _st_nginx_conf()
        conf_content = _st_read(conf_path)
        log_path = next((p for p in ['/var/log/nginx/error.log','/www/wwwlogs/nginx_error.log'] if os.path.exists(p)), '')
        logs = _st_tail(log_path, 100) if log_path else 'No error log found'
        def nget(pat, default):
            m = _re.search(pat, conf_content, _re.M)
            return m.group(1) if m else default
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs,'log_path':log_path,
            'versions':[{'label':'Stable','value':'stable'},{'label':'Mainline','value':'mainline'}],
            'optimization':{
                'worker_processes':    nget(r'^\s*worker_processes\s+([^;\s]+)', 'auto'),
                'worker_connections':  nget(r'^\s*worker_connections\s+(\d+)', '1024'),
                'keepalive_timeout':   nget(r'^\s*keepalive_timeout\s+([^;\s]+)', '65'),
                'client_max_body_size':nget(r'^\s*client_max_body_size\s+([^;\s]+)', '1m'),
                'gzip':                nget(r'^\s*gzip\s+([^;\s]+)', 'off'),
            }})

    elif mod_id == 'apache2':
        a = _st_apache()
        status  = _st_status('apache2')
        version = sh(f"{a['bin']} -v 2>/dev/null | grep -oE '[0-9]+[.][0-9]+[.][0-9]+' | head -1") or ''
        conf_content = _st_read(a['conf'])
        logs = _st_tail(a['log'], 100) or _st_journal(_resolve_svc('apache2')) or 'No logs'
        mpm_content = _st_read(a['mpm']) if a['mpm'] else ''
        def aget(content, key):
            m = _re.search(rf'^\s*{key}\s+(\S+)', content, _re.M)
            return m.group(1) if m else ''
        optimization = {}
        for k in _APACHE_KEYS:
            v = aget(conf_content, k)
            if v: optimization[k] = v
        for k in _APACHE_MPM_KEYS:
            v = aget(mpm_content, k)
            if v: optimization[k] = v
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':a['conf'],'conf_content':conf_content,'logs':logs,'log_path':a['log'],
            'optimization':optimization})

    elif mod_id == 'openlitespeed':
        status   = _st_status('lsws')
        version  = sh("grep -oE '[0-9]+[.][0-9]+[.][0-9]+' /usr/local/lsws/VERSION 2>/dev/null | head -1") or ''
        conf_path = _OLS_CONF
        conf_content = _st_read(conf_path)
        log_path = '/usr/local/lsws/logs/error.log'
        logs = _st_tail(log_path, 100) or 'No logs'
        def lsget(key):
            m = _re.search(rf'^\s*{key}\s+(\S+)', conf_content, _re.M)
            return m.group(1) if m else ''
        optimization = {k: (lsget(k) or dv) for k, dv in _OLS_KEYS.items()}
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,
            'logs':logs,'log_path':log_path,
            'optimization':optimization,'versions':[]})

    elif mod_id in ('mysql', 'mariadb'):
        flavor = _st_mysql_flavor(mod_id)
        unit = _st_mysql_svc(flavor)
        status  = _st_status(unit)
        version = sh("mysqld --version 2>/dev/null | grep -oE '[0-9]+[.][0-9]+[.][0-9]+' | head -1") or \
                  sh("mariadb --version 2>/dev/null | grep -oE '[0-9]+[.][0-9]+[.][0-9]+' | head -1") or \
                  sh("mysql --version 2>/dev/null | grep -oE '[0-9]+[.][0-9]+[.][0-9]+' | head -1") or ''
        conf_path = _st_mysql_cnf(flavor)
        conf_content = _st_read(conf_path)
        def mvar(var):
            return sh("mysql -e 'SHOW VARIABLES LIKE \"" + var + "\"' 2>/dev/null | awk 'NR==2{print $2}'") or ''
        def mstat(stat):
            return sh("mysql -e 'SHOW STATUS LIKE \"" + stat + "\"' 2>/dev/null | awk 'NR==2{print $2}'") or ''
        log_path = mvar('log_error')
        if not log_path or not log_path.startswith('/'):
            log_path = next((p for p in ['/var/log/mysql/error.log', '/var/log/mysqld.log', '/var/log/mysql/mysqld.log',
                                         '/var/log/mariadb/mariadb.log'] if os.path.exists(p)), '/var/log/mysql/error.log')
        logs = _st_tail(log_path, 100) or _st_journal(unit) or 'No logs'
        slow_path = mvar('slow_query_log_file')
        slow_log = _st_tail(slow_path, 100) if slow_path.startswith('/') else ''
        slow_log = slow_log or 'Slow query log is empty or not enabled.'
        port    = mvar('port') or '3306'
        datadir = mvar('datadir') or '/var/lib/mysql'
        uptime  = mstat('Uptime') or ''
        launch_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - int(uptime))) if uptime.isdigit() else ''
        if mod_id == 'mysql':
            current_status = {
                'launch_time':       launch_time,
                'total_connections': mstat('Connections'),
                'send':              mstat('Bytes_sent'),
                'receive':           mstat('Bytes_received'),
                'query_per_sec':     mstat('Questions'),
                'threads_connected': mstat('Threads_connected'),
            }
        else:
            current_status = {
                'uptime':            uptime,
                'queries':           mstat('Queries'),
                'slow_queries':      mstat('Slow_queries'),
                'threads_connected': mstat('Threads_connected'),
                'connections':       mstat('Connections'),
            }
        defaults = {'key_buffer_size': '8M', 'tmp_table_size': '16M', 'innodb_buffer_pool_size': '128M',
                    'innodb_log_buffer_size': '8M', 'sort_buffer_size': '2M', 'read_buffer_size': '128K',
                    'thread_cache_size': '10', 'max_connections': '151', 'table_open_cache': '2000'}
        optimization = {k: (mvar(k) or dv) for k, dv in defaults.items()}
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,
            'logs':logs,'log_path':log_path,'slow_log':slow_log,
            'port':port,'datadir':datadir,
            'current_status':current_status,'optimization':optimization,'versions':[]})

    elif mod_id == 'redis':
        status  = _st_status('redis-server')
        version = sh("redis-server --version 2>/dev/null | grep -oE '[0-9]+[.][0-9]+[.][0-9]+' | head -1") or ''
        conf_path = _st_redis_conf()
        conf_content = _st_read(conf_path)
        log_m = _re.search(r'^\s*logfile\s+"?([^"\s]+)', conf_content, _re.M)
        logs = (_st_tail(log_m.group(1), 100) if log_m else '') or \
               _st_tail('/var/log/redis/redis-server.log', 100) or _st_tail('/var/log/redis/redis.log', 100) or \
               _st_journal(_resolve_svc('redis-server')) or 'No logs'
        cli = _st_redis_cli(conf_content)
        info = cli('INFO')
        def rget(key):
            for line in info.split('\n'):
                if line.startswith(key + ':'): return line.split(':', 1)[1].strip()
            return ''
        def rcfg(key):
            lines = cli('CONFIG', 'GET', key).split('\n')
            if len(lines) > 1:
                return lines[1]
            m = _re.search(rf'^\s*{_re.escape(key)}\s+(.+?)\s*$', conf_content, _re.M)
            return m.group(1).strip('"') if m else ''
        current_status = {k: rget(k) for k in ('uptime_in_days', 'tcp_port', 'connected_clients', 'used_memory_human',
                                                'used_memory_rss_human', 'mem_fragmentation_ratio',
                                                'total_connections_received', 'total_commands_processed',
                                                'keyspace_hits', 'keyspace_misses')}
        optimization = {
            'bind':        rcfg('bind') or '127.0.0.1',
            'port':        rcfg('port') or '6379',
            'timeout':     rcfg('timeout') or '0',
            'maxclients':  rcfg('maxclients') or '10000',
            'databases':   rcfg('databases') or '16',
            'requirepass': rcfg('requirepass') or '',
            'maxmemory':   rcfg('maxmemory') or '0',
        }
        persistence = {
            'dir':         rcfg('dir') or '/var/lib/redis',
            'aof_enabled': rcfg('appendonly') or 'no',
            'appendfsync': rcfg('appendfsync') or 'everysec',
            'rdb_saves':   rcfg('save'),
        }
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs,
            'current_status':current_status,'optimization':optimization,'persistence':persistence,
            'versions':[]})

    elif mod_id == 'memcached':
        status  = _st_status('memcached')
        version = sh("memcached -h 2>/dev/null | head -1 | grep -oE '[0-9]+[.][0-9]+[.][0-9]+'") or ''
        conf_path, fmt = _st_memcached_conf()
        conf_content = _st_read(conf_path)
        if fmt == 'flags':
            def mcfg(flag, default):
                m = _re.search(rf'^-{flag}\s+(\S+)', conf_content, _re.M)
                return m.group(1) if m else default
            bind_ip, port, cache_mb, maxconn = mcfg('l', '127.0.0.1'), mcfg('p', '11211'), mcfg('m', '64'), mcfg('c', '1024')
        else:
            def scfg(key, default):
                m = _re.search(rf'^{key}="?([^"\n]*)"?', conf_content, _re.M)
                return m.group(1).strip() if m and m.group(1).strip() else default
            opts = scfg('OPTIONS', '')
            lm = _re.search(r'-l\s+(\S+)', opts)
            bind_ip = lm.group(1) if lm else '0.0.0.0'
            port, cache_mb, maxconn = scfg('PORT', '11211'), scfg('CACHESIZE', '64'), scfg('MAXCONN', '1024')

        def memcached_stats():
            import socket
            host = (bind_ip.split(',')[0] or '127.0.0.1')
            if host in ('0.0.0.0', '::', ''):
                host = '127.0.0.1'
            try:
                with socket.create_connection((host, int(port or 11211)), timeout=2) as s:
                    s.sendall(b'stats\r\n')
                    data = b''
                    s.settimeout(2)
                    while b'END\r\n' not in data:
                        chunk = s.recv(4096)
                        if not chunk: break
                        data += chunk
                    return data.decode(errors='ignore')
            except Exception:
                return ''

        raw_stats = memcached_stats()
        def sget(key):
            m = _re.search(rf'STAT {key} (\S+)', raw_stats)
            return m.group(1) if m else '0'

        def fmt_bytes(n):
            try: n = float(n)
            except (TypeError, ValueError): return '0.00 B'
            for unit in ['B','KB','MB','GB']:
                if n < 1024: return f'{n:.2f} {unit}'
                n /= 1024
            return f'{n:.2f} TB'

        def _int(x):
            try: return int(x)
            except (TypeError, ValueError): return 0
        cmd_get    = _int(sget('cmd_get'))
        get_hits   = _int(sget('get_hits'))
        hit_rate   = round(get_hits / cmd_get, 2) if cmd_get else 0

        current_status = {
            'bind': bind_ip, 'port': port, 'maxconn': maxconn, 'cachesize': cache_mb,
            'curr_connections': sget('curr_connections'),
            'cmd_get': sget('cmd_get'), 'get_hits': sget('get_hits'), 'get_misses': sget('get_misses'),
            'bytes_read':    fmt_bytes(sget('bytes_read')),
            'bytes_written': fmt_bytes(sget('bytes_written')),
            'bytes':         fmt_bytes(sget('bytes')),
            'curr_items': sget('curr_items'), 'evictions': sget('evictions'),
            'hit_rate': hit_rate,
        }
        optimization = {'bind': bind_ip, 'port': port, 'cachesize': cache_mb, 'maxconn': maxconn}
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,
            'current_status':current_status,'optimization':optimization,
            'versions':[{'label':f'Memcached {version} (upgrade to the newest packaged build)' if version else 'Latest packaged build','value':'latest'}]})

    elif mod_id == 'php':
        layouts = installed_php_layouts()
        if not layouts:
            return jsonify({'ok': True, 'status': 'not installed', 'version': '', 'sel_ver': '',
                            'php_versions': [], 'config': {}, 'fpm_profile': {}, 'extensions': [],
                            'logs': 'No PHP version is installed.'})
        return jsonify(_st_php_payload(layouts[0], layouts))

    elif mod_id in ('pure-ftpd', 'pure_ftpd'):
        status  = _st_status('pure-ftpd')
        version = sh('pure-ftpd --help 2>&1 | grep -oE "[0-9]+[.][0-9]+[.][0-9]+" | head -1') or ''
        paths   = ['/etc/pure-ftpd/pure-ftpd.conf','/etc/pure-ftpd.conf']
        conf_path = next((p for p in paths if os.path.exists(p)), paths[0])
        conf_content = _st_read(conf_path)
        # Debian: one value per file in /etc/pure-ftpd/conf ("Bind" = "IP,port").
        # RHEL: "Bind IP,port" inside pure-ftpd.conf.
        bind = _st_read('/etc/pure-ftpd/conf/Bind').strip()
        if not bind:
            m = _re.search(r'^\s*Bind\s+(\S+)', conf_content, _re.M)
            bind = m.group(1) if m else ''
        port = bind.split(',')[-1].strip() if bind else '21'
        if not port.isdigit(): port = '21'
        users = []
        for line in (sh('pure-pw list 2>/dev/null') or '').split('\n'):
            parts = line.split()
            if parts:
                users.append({'user': parts[0], 'home': parts[1] if len(parts) > 1 else '/www/wwwroot', 'status': 'active'})
        logs = _st_journal('pure-ftpd') or 'No logs'
        ftp_addr = sh("hostname -I 2>/dev/null | awk '{print $1}'") or 'YOUR-IP'
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,
            'port':port,'users':users,'logs':logs,
            'ftp_addr':'ftp://' + ftp_addr + ':' + port,
            'versions':[{'label':'Latest packaged build','value':'latest'}]})

    elif mod_id == 'fail2ban':
        status  = _st_status('fail2ban')
        version = sh('fail2ban-client --version 2>/dev/null | grep -oE "[0-9]+[.][0-9]+[.][0-9]+" | head -1') or ''
        black_ips = _st_read(_F2B_BLACK_FILE)
        white_ips = _st_read(_F2B_WHITE_FILE, '127.0.0.1/8')
        jails_raw = sh('fail2ban-client status 2>/dev/null') or ''
        jail_line = _re.findall(r'Jail list:\s+(.+)', jails_raw)
        jails = []
        if jail_line:
            for jail in jail_line[0].replace(' ', '').split(','):
                if not jail or not _re.match(r'^[A-Za-z0-9_.-]+$', jail): continue
                jail_status = sh('fail2ban-client status ' + jail + ' 2>/dev/null') or ''
                banned = _re.findall(r'Banned IP list:\s+(.+)', jail_status)
                banned_ips = banned[0].split() if banned else []
                currently  = _re.search(r'Currently banned:\s+(\d+)', jail_status)
                jails.append({'name': jail, 'banned_ips': banned_ips,
                              'currently': currently.group(1) if currently else '0'})
        logs = _st_tail('/var/log/fail2ban.log', 80) or _st_journal('fail2ban') or 'No logs'
        return jsonify({'ok':True,'status':status,'version':version,
            'jails':jails,'black_ips':black_ips,'white_ips':white_ips,'logs':logs})

    elif mod_id == 'supervisor':
        conf_path, svc = _st_supervisor()
        status  = _st_status(svc)
        version = sh('supervisord --version 2>/dev/null') or ''
        conf_content = _st_read(conf_path)
        logs = _st_tail('/var/log/supervisor/supervisord.log', 80) or _st_journal(_resolve_svc(svc)) or 'No logs'
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs})

    elif mod_id == 'clamav':
        status  = _st_status('clamav-daemon', 'clamd@scan')
        version = sh('clamscan --version 2>/dev/null | grep -oE "[0-9]+[.][0-9]+[.][0-9]+" | head -1') or ''
        logs    = _st_tail('/var/log/clamav/clamav.log', 80) or _st_journal('clamav-daemon') or \
                  _st_journal('clamd@scan') or 'No logs'
        return jsonify({'ok':True,'status':status,'version':version,'logs':logs})

    elif mod_id == 'postgresql':
        pg = _st_pg()
        status  = _st_status(*pg['status_svcs'])
        version = sh('psql --version 2>/dev/null | grep -oE "[0-9]+[.][0-9]+" | head -1') or pg['ver']
        conf_content = _st_read(pg['conf']) if pg['conf'] else ''
        logs = _st_journal(_resolve_svc(pg['svc'])) or _st_journal('postgresql') or 'No logs'
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':pg['conf'],'conf_content':conf_content,'logs':logs,'versions':[]})

    elif mod_id == 'mongodb':
        status  = _st_status('mongod')
        version = sh('mongod --version 2>/dev/null | grep -oE "[0-9]+[.][0-9]+[.][0-9]+" | head -1') or ''
        conf_path = '/etc/mongod.conf'
        conf_content = _st_read(conf_path)
        logs = _st_tail('/var/log/mongodb/mongod.log', 80) or _st_journal('mongod') or 'No logs'
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs,'versions':[]})

    elif mod_id == 'phpmyadmin':
        pma_conf, kind = _st_pma_conf()
        cc = _st_read(pma_conf) if pma_conf else ''
        if kind == 'caddy':
            m = _re.search(r'(?:^|\n)[ \t]*:(\d+)\s*\{\s*root \* /usr/share/phpmyadmin', cc)
        else:
            m = _re.search(r'(?i)listen\s+(\d+)', cc)
        port = m.group(1) if m else '8082'
        return jsonify({'ok':True,'installed':os.path.isdir('/usr/share/phpmyadmin'),
            'port':port,'url':'http://YOUR-IP:' + port,
            'php_versions':_st_php_sock_versions(),'current_php':_st_conf_php(cc),
            'conf_path':pma_conf or '/etc/nginx/conf.d/phpmyadmin.conf'})

    elif mod_id == 'roundcube':
        rc_dir = _RC_DIR
        rc_conf = _RC_CONF
        nginx_conf = '/etc/nginx/conf.d/roundcube.conf'
        conf_content = _st_read(rc_conf, None)
        def rc_get(key):
            m = _re.search(r"^\s*\$config\['" + _re.escape(key) + r"'\]\s*=\s*'((?:[^'\\]|\\.)*)'", conf_content or '', _re.M)
            if not m:
                m = _re.search(r"^\s*\$config\['" + _re.escape(key) + r"'\]\s*=\s*(\d+)", conf_content or '', _re.M)
            if not m:
                return ''
            return m.group(1).replace("\\'", "'").replace('\\\\', '\\')
        cc = _st_read(nginx_conf)
        port = '8083'
        m = _re.search(r'listen\s+(\d+)', cc)
        if m: port = m.group(1)
        current_php = _st_conf_php(cc)
        php_versions = _st_php_sock_versions()
        skins = []
        try: skins = [d for d in os.listdir(rc_dir+'/skins') if os.path.isdir(rc_dir+'/skins/'+d)]
        except Exception: pass
        logs = _st_tail(f'{rc_dir}/logs/errors.log', 80) or _st_tail(f'{rc_dir}/logs/errors', 80) or 'No logs found'
        return jsonify({'ok':True,
            'port':port, 'url': 'http://YOUR-IP:'+port,
            'imap_host':rc_get('imap_host') or 'localhost', 'smtp_host':rc_get('smtp_host') or 'localhost',
            'smtp_port':rc_get('smtp_port') or '587',
            'skin':rc_get('skin') or 'elastic', 'db_dsn':rc_get('db_dsnw') or '',
            'current_php':current_php, 'php_versions':php_versions,
            'skins':skins, 'conf_path':rc_conf,
            'conf_content':conf_content if conf_content is not None else '# Config file not found',
            'logs':logs, 'rc_dir':rc_dir})

    elif mod_id == 'docker':
        status  = _st_status('docker')
        version = sh('docker version --format "{{.Server.Version}}" 2>/dev/null') or ''
        info    = sh('docker info 2>/dev/null | head -25') or ''
        return jsonify({'ok':True,'status':status,'version':version,'info':info})

    elif mod_id == 'caddy':
        c = _st_caddy()
        status   = _st_status('caddy')
        version  = sh("caddy version 2>/dev/null | awk '{print $1}' | tr -d v") or ''
        conf_path = c.CADDYFILE
        conf_content = _st_read(conf_path)
        log_path = '/var/log/caddy/caddy.log'
        logs = _st_tail(log_path, 100) or _st_journal('caddy', 100) or 'No logs'
        g = c.get_global_options()
        def cget(key):
            m = _re.search(rf'^\s*{key}\s+(\S+)', g, _re.M)
            return m.group(1) if m else ''
        global_opts = {
            'email':      cget('email'),
            'http_port':  cget('http_port') or '80',
            'https_port': cget('https_port') or '443',
            'admin':      cget('admin') or 'localhost:2019',
        }
        names = []
        for base in c.caddy_cert_dirs():
            for dname in sorted(os.listdir(base)):
                if os.path.isdir(os.path.join(base, dname)):
                    names.append(f'{dname}  ({os.path.basename(base)})')
        tls_certs = '\n'.join(names[:200]) or 'No certificates found'
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs,'log_path':log_path,
            'global_opts':global_opts,'tls_certs':tls_certs})

    elif mod_id == 'nodejs':
        version = sh('node --version 2>/dev/null | tr -d v') or ''
        npm_ver = sh('npm --version 2>/dev/null') or ''
        node_path = sh('command -v node 2>/dev/null') or ''
        npm_path  = sh('command -v npm 2>/dev/null') or ''
        info = f'Node.js {version}\nnpm {npm_ver}\nnode: {node_path}\nnpm: {npm_path}'
        return jsonify({'ok':True,'status':'active' if node_path else 'inactive',
            'version':version,'info':info, 'versions':[]})

    elif mod_id == 'bind9':
        b = _st_bind()
        status  = _st_status('named', 'bind9')
        version = sh("named -v 2>/dev/null | grep -oE '[0-9]+[.][0-9]+[.][0-9]+' | head -1") or ''
        zones_dir = b['zones_dir']
        if os.path.isdir('/etc/bind'):
            os.makedirs(zones_dir, exist_ok=True)
        def _count(path):
            if not path.startswith('/'):
                path = os.path.join(b['base'], path)
            return sum(1 for l in _st_read(path).splitlines() if _re.search(r'\sIN\s', l))
        zones = []
        for conf_file in [b['local'], b['conf']]:
            raw = _st_read(conf_file)
            for m in _re.finditer(r'zone\s+"([^"]+)"\s*(?:IN\s*)?\{[^}]*?file\s+"([^"]+)"', raw, _re.DOTALL):
                domain, zone_file = m.group(1), m.group(2)
                if domain in ('.', 'localhost', '127.in-addr.arpa', '0.in-addr.arpa', '255.in-addr.arpa') or \
                   domain.endswith('.ip6.arpa') or domain in [z['domain'] for z in zones]:
                    continue
                zones.append({'domain': domain, 'file': zone_file, 'records': _count(zone_file)})
        if os.path.isdir(zones_dir):
            for f_name in sorted(os.listdir(zones_dir)):
                if f_name.startswith('db.'):
                    domain = f_name[3:]
                    if domain not in [z['domain'] for z in zones]:
                        zones.append({'domain': domain, 'file': f'{zones_dir}/{f_name}',
                                      'records': _count(f'{zones_dir}/{f_name}')})
        conf_content = _st_read(b['conf'])
        logs = _st_journal(_resolve_svc('named')) or 'No logs'
        return jsonify({'ok':True, 'status':status, 'version':version,
            'zones': zones, 'conf_path': b['conf'], 'conf_content': conf_content,
            'logs': logs, 'zones_dir': zones_dir, 'versions': []})

    elif mod_id == 'ddns':
        cfg_file = '/opt/vortexpanel/ddns_config.json'
        cfg = {}
        try:
            with open(cfg_file) as f: cfg = json.load(f) or {}
        except Exception:
            cfg = {}
        log = _st_tail('/opt/vortexpanel/ddns.log', 100)
        ip = sh("curl -s --max-time 5 https://api.ipify.org 2>/dev/null || curl -s --max-time 5 https://ifconfig.me/ip 2>/dev/null") or 'Unknown'
        return jsonify({'ok':True, 'status':'active' if cfg.get('enabled') else 'inactive',
            'version':'', 'domains': cfg.get('domains',[]),
            'enabled': cfg.get('enabled', False),
            'current_ip': ip, 'interval': cfg.get('interval', 300),
            'log': log})

    elif mod_id == 'modsecurity':
        # ModSecurity has no standalone systemd service -- it's a shared
        # module loaded into whichever webserver is active.
        from panel.routes.security import _modsec_installed, _connector_present, _modsec_conf, _modsec_target
        installed = _modsec_installed()
        connector = _connector_present()
        target = _modsec_target()
        engine_state = 'not installed'
        conf = _modsec_conf()
        if os.path.exists(conf):
            m = _re.search(r'^SecRuleEngine\s+(\S+)', _st_read(conf), _re.MULTILINE)
            engine_state = m.group(1) if m else 'unknown'
        if target == 'apache':
            webserver_name = 'apache2'
            webserver_status = _st_status('apache2')
        else:
            webserver_name = 'nginx'
            webserver_status = _st_status('nginx')
        return jsonify({'ok':True,
            'modsec_installed': installed,
            'connector_loaded': connector,
            'engine_state': engine_state,
            'webserver_name': webserver_name,
            'webserver_status': webserver_status,
            'nginx_status': webserver_status})

    # Generic fallback
    mod = _get_mod(mod_id)
    if not mod: return jsonify({'ok':False,'error':'Module not found'}), 404
    svc    = _resolve_svc(mod.get('service') or mod_id)
    status = _st_status(svc)
    version= get_version(mod_id) or ''
    return jsonify({'ok':True,'status':status,'version':version})


# --- Settings: constants used by GET and POST ------------------------------------------
_APACHE_KEYS = ['Timeout', 'KeepAlive', 'MaxKeepAliveRequests', 'KeepAliveTimeout']
_APACHE_MPM_KEYS = ['StartServers', 'MinSpareThreads', 'MaxSpareThreads', 'ThreadsPerChild', 'MaxRequestWorkers',
                    'MinSpareServers', 'MaxSpareServers', 'MaxConnectionsPerChild']
_OLS_KEYS = {'maxConnections': '10000', 'maxSSLConnections': '10000', 'connTimeout': '300',
             'maxKeepAliveReq': '10000', 'enableGzipCompress': '1', 'gzipCompressLevel': '6'}
_NGINX_OPT = {   # key -> (context, value regex)
    'worker_processes':     ('main',   r'^(auto|\d{1,4})$'),
    'worker_connections':   ('events', r'^\d{1,7}$'),
    'keepalive_timeout':    ('http',   r'^\d{1,6}[smh]?$'),
    'client_max_body_size': ('http',   r'^\d{1,9}[kKmMgG]?$'),
    'gzip':                 ('http',   r'^(on|off)$'),
}
_MYSQL_OPT_KEYS = ['key_buffer_size', 'tmp_table_size', 'innodb_buffer_pool_size', 'innodb_log_buffer_size',
                   'sort_buffer_size', 'read_buffer_size', 'thread_cache_size', 'max_connections',
                   'table_open_cache', 'port']
_RC_DIR = '/var/www/roundcube'
_RC_CONF = _RC_DIR + '/config/config.inc.php'
_F2B_BLACK_FILE = '/etc/fail2ban/ip.blacklist'
_F2B_WHITE_FILE = '/etc/fail2ban/ip.whitelist'
_F2B_BLACK_JAIL = 'vortexpanel-blacklist'
_F2B_BLACK_CONF = '/etc/fail2ban/jail.d/zz-vortexpanel-blacklist.local'
_F2B_WHITE_CONF = '/etc/fail2ban/jail.d/zz-vortexpanel-whitelist.local'

def _st_set_directive(content, key, val):
    """Replace the first active `key value` line; None when the key is absent."""
    pat = re.compile(r'^([ \t]*)' + re.escape(key) + r'[ \t]+[^\n]*$', re.M)
    m = pat.search(content)
    if not m:
        return None
    return content[:m.start()] + m.group(1) + key + ' ' + val + content[m.end():]


# --- Switch Version --------------------------------------------------------------------
_VP_PICK = (
    "VP_PICK() { apt-cache madison \"$1\" 2>/dev/null | awk -F'|' -v src=\"$3\" "
    "'{v=$2; gsub(/ /,\"\",v); if (src==\"\" || index($3,src)>0) print v}' | grep -E \"$2\" | head -1; }\n"
    "VP_RPICK() { dnf -q list --showduplicates \"$1\" 2>/dev/null | awk -v n=\"$1\" "
    "'index($1, n\".\")==1 {print $2}' | grep -E \"$2\" | sort -V | tail -1; }\n"
)

def _st_key_dl(url, keyring):
    """Download+dearmor a signing key to a temp file and only then replace the
    keyring, so a failed download never breaks the existing repo."""
    return (f'curl -fsSL --connect-timeout 20 --max-time 90 "{url}" -o /tmp/vp_switch_key.asc && '
            'gpg --batch --no-tty --yes --dearmor -o /tmp/vp_switch_key.gpg /tmp/vp_switch_key.asc && '
            f'mkdir -p "$(dirname {keyring})" && mv -f /tmp/vp_switch_key.gpg {keyring} || '
            f'{{ echo "[VortexPanel] Could not download the signing key from {url}."; rm -f /tmp/vp_switch_key.*; exit 1; }}\n'
            'rm -f /tmp/vp_switch_key.asc\n')

_SWITCH_NO_DOWNGRADE = {'mysql', 'mariadb', 'mongodb', 'redis', 'postgresql'}
_SWITCH_DEBIAN_ONLY = {
    'mysql': 'On RHEL-family servers MySQL comes from the AppStream module or the MySQL community repository; '
             'switch it with dnf (dnf module switch-to mysql:<stream>) after a full backup.',
    'mariadb': 'MariaDB RPM packages cannot be upgraded across major versions in place; back up with mariadb-dump, '
               'remove the old MariaDB-server, install the new version and restore.',
    'postgresql': 'On RHEL-family servers each PostgreSQL major version is a separate postgresqlNN-server package '
                  'with its own data directory; install the new version and migrate with pg_upgrade.',
    'bind9': 'On RHEL-family servers BIND only comes from the distribution repository, which carries one version.',
}

def _st_target_tuple(mod_id, ver):
    if mod_id == 'mysql' and ver == 'innovation':
        return (99,)
    return _parse_ver_tuple(ver)

def _st_switch_ok(mod_id, ver, got):
    if not got:
        return False
    if ver == 'latest':
        return True
    if mod_id == 'nginx':
        t = _parse_ver_tuple(got)
        return bool(t and len(t) > 1 and (t[1] % 2 == (0 if ver == 'stable' else 1)))
    if mod_id == 'mysql' and ver == 'innovation':
        t = _parse_ver_tuple(got)
        return bool(t and t[0] >= 9)
    return got == ver or got.startswith(ver + '.') or got.startswith(ver + '-')

def _st_switch_script(mod_id, ver, mod):
    """Shell script that moves an installed app to `ver` on THIS distro, or
    (None, reason) when that cannot be done safely here."""
    osi = get_os()
    fam = _st_family()
    cn = osi.get('codename') or ''
    is_ubuntu = osi.get('id') != 'debian'
    vre = ver.replace('.', '\\.')
    if fam != 'debian' and mod_id in _SWITCH_DEBIAN_ONLY:
        return None, f'Switching {mod["name"] if mod else mod_id} versions from the panel is only supported on Debian/Ubuntu. ' + _SWITCH_DEBIAN_ONLY[mod_id]
    if fam == 'debian' and not cn and mod_id in ('nginx', 'redis'):
        return None, 'The OS codename could not be detected (VERSION_CODENAME missing in /etc/os-release).'
    S = _VP_PICK
    if mod_id == 'nginx':
        if fam == 'debian':
            dpath = 'ubuntu' if is_ubuntu else 'debian'
            src = f'nginx.org/packages/{dpath}' if ver == 'stable' else f'nginx.org/packages/mainline/{dpath}'
            S += _st_key_dl('https://nginx.org/keys/nginx_signing.key', '/usr/share/keyrings/nginx-archive-keyring.gpg')
            S += (f'echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://{src} {cn} nginx" > /etc/apt/sources.list.d/nginx.list\n'
                  'apt-get update -qq || { echo "[VortexPanel] apt-get update failed (see above)."; exit 1; }\n'
                  f'V=$(VP_PICK nginx . "{src}")\n'
                  f'[ -n "$V" ] || {{ echo "[VortexPanel] nginx.org has no {ver} build for {cn}."; exit 1; }}\n'
                  'echo "[VortexPanel] Installing nginx $V"\n'
                  'apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold "nginx=$V" || exit 1\n')
        else:
            sub = '' if ver == 'stable' else 'mainline/'
            S += (f"cat > /etc/yum.repos.d/nginx.repo <<'EOF'\n[nginx-{ver}]\nname=nginx {ver} repo\n"
                  f"baseurl=http://nginx.org/packages/{sub}rhel/$releasever/$basearch/\ngpgcheck=1\nenabled=1\n"
                  "gpgkey=https://nginx.org/keys/nginx_signing.key\nmodule_hotfixes=true\nEOF\n"
                  'dnf -y distro-sync nginx || exit 1\n')
        S += 'nginx -t || exit 1\nsystemctl restart nginx || exit 1\n'
        return S, None
    if mod_id == 'apache2':
        if fam == 'debian':
            if is_ubuntu:
                S += ('(command -v add-apt-repository >/dev/null 2>&1 || apt-get install -y software-properties-common)\n'
                      'add-apt-repository -y ppa:ondrej/apache2 || echo "[VortexPanel] ppa:ondrej/apache2 is unavailable -- using the distribution packages"\n'
                      'if ! apt-get update -qq; then add-apt-repository --remove -y ppa:ondrej/apache2 2>/dev/null; '
                      'rm -f /etc/apt/sources.list.d/ondrej-ubuntu-apache2-*; apt-get update -qq || exit 1; fi\n')
            else:
                S += 'apt-get update -qq || exit 1\n'
            S += (f'V=$(VP_PICK apache2 "^([0-9]+:)?{vre}-" "")\n'
                  f'[ -n "$V" ] || {{ echo "[VortexPanel] Apache {ver} is not available from the configured repositories. Available:"; apt-cache madison apache2; exit 1; }}\n'
                  'apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold "apache2=$V" "apache2-bin=$V" "apache2-data=$V" "apache2-utils=$V" || exit 1\n'
                  'apache2ctl configtest || exit 1\nsystemctl restart apache2 || exit 1\n')
        else:
            S += (f'V=$(VP_RPICK httpd "^([0-9]+:)?{vre}-")\n'
                  f'[ -n "$V" ] || {{ echo "[VortexPanel] httpd {ver} is not available from the enabled repositories (RHEL-family repositories usually carry one build). Available:"; dnf -q list --showduplicates httpd; exit 1; }}\n'
                  'dnf -y install "httpd-$V" || dnf -y downgrade "httpd-$V" || exit 1\n'
                  'apachectl configtest || exit 1\nsystemctl restart httpd || exit 1\n')
        return S, None
    if mod_id == 'openlitespeed':
        S += ('curl -fsSL --max-time 90 https://repo.litespeed.sh -o /tmp/vp_ls_repo.sh || { echo "[VortexPanel] Could not download the LiteSpeed repository script."; exit 1; }\n'
              'bash /tmp/vp_ls_repo.sh || exit 1\nrm -f /tmp/vp_ls_repo.sh\n')
        if fam == 'debian':
            S += ('apt-get update -qq || exit 1\n'
                  f'V=$(VP_PICK openlitespeed "^([0-9]+:)?{vre}([.-]|$)" "")\n'
                  f'[ -n "$V" ] || {{ echo "[VortexPanel] OpenLiteSpeed {ver} is not available. Available:"; apt-cache madison openlitespeed; exit 1; }}\n'
                  'apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold "openlitespeed=$V" || exit 1\n')
        else:
            S += (f'V=$(VP_RPICK openlitespeed "^([0-9]+:)?{vre}([.-]|$)")\n'
                  f'[ -n "$V" ] || {{ echo "[VortexPanel] OpenLiteSpeed {ver} is not available. Available:"; dnf -q list --showduplicates openlitespeed; exit 1; }}\n'
                  'dnf -y install "openlitespeed-$V" || dnf -y downgrade "openlitespeed-$V" || exit 1\n')
        S += '/usr/local/lsws/bin/lswsctrl restart || systemctl restart lsws || exit 1\n'
        return S, None
    if mod_id == 'mysql':
        tpl = (mod or {}).get('install_tpl', '')
        if not tpl:
            return None, 'No MySQL install recipe in the catalog.'
        return tpl.replace('{ver}', ver).replace('{codename}', cn) + '\n', None
    if mod_id == 'mariadb':
        return mariadb_install_script(ver) + ' && systemctl restart mariadb\n', None
    if mod_id == 'postgresql':
        if os.path.isdir(f'/usr/lib/postgresql/{ver}/bin'):
            return None, f'PostgreSQL {ver} is already installed.'
        return postgresql_install_script(ver) + '\npg_lsclusters 2>/dev/null; true\n', None
    if mod_id == 'mongodb':
        S = ('echo "[VortexPanel] Note: MongoDB upgrades one release series at a time and needs '
             'featureCompatibilityVersion set to the current series first (db.adminCommand({setFeatureCompatibilityVersion: ...}))."\n')
        S += mongodb_install_script(ver)
        if fam != 'debian':
            S += ' && dnf -y upgrade "mongodb-org*"'
        S += ' && systemctl restart mongod\n'
        return S, None
    if mod_id == 'redis':
        if fam == 'debian':
            S += _st_key_dl('https://packages.redis.io/gpg', '/usr/share/keyrings/redis-archive-keyring.gpg')
            S += (f'echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb {cn} main" > /etc/apt/sources.list.d/redis.list\n'
                  f'apt-get update -qq || {{ echo "[VortexPanel] packages.redis.io has no release for {cn} -- removing it again."; rm -f /etc/apt/sources.list.d/redis.list; apt-get update -qq; exit 1; }}\n'
                  f'V=$(VP_PICK redis-server "^([0-9]+:)?{vre}\\." "packages.redis.io")\n'
                  f'[ -n "$V" ] || {{ echo "[VortexPanel] packages.redis.io has no Redis {ver} for {cn}. Available:"; apt-cache madison redis-server; exit 1; }}\n'
                  'apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold "redis-server=$V" "redis-tools=$V" || exit 1\n'
                  'systemctl restart redis-server || exit 1\n')
        else:
            S += (f'dnf -y module reset redis && dnf -y module enable "redis:remi-{ver}" || '
                  f'{{ echo "[VortexPanel] The Remi repository has no redis:remi-{ver} module stream for this OS."; exit 1; }}\n'
                  'dnf -y distro-sync redis || exit 1\nsystemctl restart redis || exit 1\n')
        return S, None
    if mod_id == 'nodejs':
        if fam == 'debian':
            S += _st_key_dl('https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key', '/etc/apt/keyrings/nodesource.gpg')
            S += ('rm -f /etc/apt/sources.list.d/nodejs.list /etc/apt/sources.list.d/nodesource.sources\n'
                  f'echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_{ver}.x nodistro main" > /etc/apt/sources.list.d/nodesource.list\n'
                  'apt-get update -qq || exit 1\n'
                  f'V=$(VP_PICK nodejs "^([0-9]+:)?{vre}\\." "nodesource.com")\n'
                  f'[ -n "$V" ] || {{ echo "[VortexPanel] NodeSource has no Node.js {ver} build."; exit 1; }}\n'
                  'apt-get install -y --allow-downgrades "nodejs=$V" || exit 1\n')
        else:
            S += (f'curl -fsSL --max-time 90 https://rpm.nodesource.com/setup_{ver}.x -o /tmp/vp_nodesource.sh || exit 1\n'
                  'bash /tmp/vp_nodesource.sh || exit 1\nrm -f /tmp/vp_nodesource.sh\n'
                  'dnf -y distro-sync nodejs || exit 1\n')
        return S, None
    if mod_id == 'bind9':
        if is_ubuntu:
            if ver == '9.20':
                S += ('(command -v add-apt-repository >/dev/null 2>&1 || apt-get install -y software-properties-common)\n'
                      'add-apt-repository -y ppa:isc/bind || exit 1\n'
                      f'apt-get update -qq || {{ echo "[VortexPanel] ppa:isc/bind has no release for {cn} -- removing it."; add-apt-repository --remove -y ppa:isc/bind; apt-get update -qq; exit 1; }}\n')
            else:
                S += ('add-apt-repository --remove -y ppa:isc/bind >/dev/null 2>&1\n'
                      'rm -f /etc/apt/sources.list.d/isc-ubuntu-bind-*\n'
                      'apt-get update -qq || exit 1\n')
        else:
            S += 'apt-get update -qq || exit 1\n'
        unit = _resolve_svc('named')
        S += (f'V=$(VP_PICK bind9 "^([0-9]+:)?{vre}\\." "")\n'
              f'[ -n "$V" ] || {{ echo "[VortexPanel] BIND {ver} is not available for this OS release. Available:"; apt-cache madison bind9; exit 1; }}\n'
              "PKGS=$(dpkg-query -W -f='${Status} ${Package}\\n' 'bind9*' 2>/dev/null | awk '$3==\"installed\"{print $4}' | grep -E '^bind9(-libs|-utils|-host|-dnsutils|-doc)?$')\n"
              'ARGS=""; for p in $PKGS; do ARGS="$ARGS $p=$V"; done\n'
              '[ -n "$ARGS" ] || ARGS="bind9=$V"\n'
              'apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold $ARGS || exit 1\n'
              f'named-checkconf || exit 1\nsystemctl restart {unit} || exit 1\n')
        return S, None
    if mod_id in ('memcached', 'pure-ftpd') and ver == 'latest':
        if fam == 'debian':
            S = (f'apt-get update -qq || exit 1\n'
                 f'apt-get install -y --only-upgrade -o Dpkg::Options::=--force-confold {mod_id} || exit 1\n')
        else:
            S = f'dnf -y upgrade {mod_id} || exit 1\n'
        S += f'systemctl restart {mod_id} || exit 1\n'
        return S, None
    return None, f'Version switch is not supported for {mod_id}.'


@modules_bp.route('/api/modules/<mod_id>/settings', methods=['POST'])
def save_module_settings(mod_id):
    """Save app-specific settings."""
    if not req(): return jsonify({'ok': False}), 401
    try:
        resp = _save_module_settings_impl(mod_id)
    except Exception as e:
        return jsonify({'ok': False, 'error': f'{type(e).__name__}: {e}'}), 500
    if resp is None:
        return jsonify({'ok': False, 'error': 'This setting is not supported for this app.'}), 400
    return resp

def _save_module_settings_impl(mod_id):
    d = request.get_json(silent=True) or {}
    action = d.get('action', 'save_config')
    ver = str(d.get('version', '') or '')
    mod = _get_mod(mod_id)  # needed by switch_version closure

    def sh(cmd, t=30):
        try:
            return subprocess.check_output(cmd, shell=True, text=True,
                                           stderr=subprocess.STDOUT, timeout=t).strip()
        except subprocess.CalledProcessError as e:
            return e.output or ''
        except Exception: return ''

    def _res(ok, msg='', **extra):
        body = {'ok': bool(ok), **extra}
        if ok:
            body['message'] = msg or 'Saved.'
        else:
            body['error'] = msg or 'Failed.'
        return jsonify(body), (200 if ok else 400)

    # ---- PHP -------------------------------------------------------------------
    if action == 'get_ver_data':
        lay = php_layout(ver)
        if not lay:
            return _res(False, f'PHP {ver} is not installed.')
        return jsonify(_st_php_payload(lay, installed_php_layouts()))

    if action in ('install_php_ext', 'uninstall_php_ext'):
        fn = php_install_ext if action == 'install_php_ext' else php_uninstall_ext
        ok, msg = fn(ver, d.get('ext', ''))
        return _res(ok, msg)

    if action == 'save_php_config':
        lay = php_layout(ver)
        if not lay:
            return _res(False, f'PHP {ver} is not installed.')
        cfg = d.get('config') or {}
        if not isinstance(cfg, dict):
            return _res(False, 'Invalid settings.')
        cfg = {k: v for k, v in cfg.items() if k in _PHP_CONFIG_KEYS}
        if not cfg:
            return _res(False, 'No supported settings given.')
        ok, msg = php_save_ini_values(lay, cfg)
        return _res(ok, msg or f'Saved and PHP {ver} FPM reloaded.')

    if action == 'save_fpm_profile':
        lay = php_layout(ver)
        if not lay:
            return _res(False, f'PHP {ver} is not installed.')
        prof = d.get('fpm_profile') or {}
        if not isinstance(prof, dict):
            return _res(False, 'Invalid FPM profile.')
        content = _st_read(lay['pool'], None)
        if content is None:
            return _res(False, f'FPM pool file {lay["pool"]} not found.')
        note = ''
        for k, v in prof.items():
            v = str(v).strip()
            if k == 'listen':
                if v and v != (_st_kv(content, 'listen') or lay['sock']):
                    note = ' The listen socket was not changed (websites use it); edit it in the FPM file tab if you really need to.'
                continue
            if k not in _FPM_PROFILE_KEYS or v == '':
                continue
            if k == 'pm':
                if v not in ('static', 'dynamic', 'ondemand'):
                    return _res(False, 'pm must be static, dynamic or ondemand.')
            elif not re.match(r'^\d{1,7}[smhd]?$', v):
                return _res(False, f'Invalid value for {k}: {v}')
            content = php_ini_set(content, k, v)
        ok, msg = php_apply_file(lay, lay['pool'], content, test='fpm')
        return _res(ok, (msg or f'Saved and PHP {ver} FPM reloaded.') + note if ok else msg)

    if action == 'save_fpm_content' or (action == 'save_config' and mod_id == 'php'):
        conf_path = d.get('conf_path', '')
        content = d.get('content', '')
        if not conf_path or not isinstance(content, str) or not content.strip():
            return _res(False, 'Missing conf_path or content')
        lay = php_layout_for_path(conf_path)
        if not lay:
            return _res(False, 'That file does not belong to an installed PHP version.')
        is_ini = any(lay.get(k) and _st_same_file(conf_path, lay[k]) for k in ('ini', 'ini_cli'))
        ok, msg = php_apply_file(lay, conf_path, content, test='ini' if is_ini else 'fpm')
        return _res(ok, msg or f'Saved and PHP {lay["ver"]} FPM reloaded.')

    # ---- Roundcube mail settings -----------------------------------------------------
    if action == 'save_config' and mod_id == 'roundcube' and not d.get('conf_path'):
        c = _st_read(_RC_CONF, None)
        if c is None:
            return _res(False, f'{_RC_CONF} not found -- is Roundcube installed?')
        fields = {'imap_host': d.get('imap_host'), 'smtp_host': d.get('smtp_host'),
                  'smtp_port': d.get('smtp_port'), 'skin': d.get('skin'), 'db_dsnw': d.get('db_dsn')}
        for k, v in fields.items():
            if v is None or str(v).strip() == '':
                continue
            v = str(v).strip()
            if '\n' in v or '\r' in v or len(v) > 500:
                return _res(False, f'Invalid value for {k}.')
            if k == 'smtp_port':
                if not _st_valid_port(v):
                    return _res(False, 'Invalid SMTP port.')
                line = f"$config['{k}'] = {int(v)};"
            else:
                if k == 'skin' and not os.path.isdir(os.path.join(_RC_DIR, 'skins', v)):
                    return _res(False, f'Skin {v} is not installed.')
                esc = v.replace('\\', '\\\\').replace("'", "\\'")
                line = f"$config['{k}'] = '{esc}';"
            pat = re.compile(r"^[ \t]*\$config\['" + re.escape(k) + r"'\][ \t]*=.*?;[ \t]*$", re.M)
            if pat.search(c):
                c = pat.sub(lambda _m: line, c, count=1)
            elif c.rstrip().endswith('?>'):
                c = c.rstrip()[:-2].rstrip('\n') + '\n' + line + '\n?>\n'
            else:
                c = c.rstrip('\n') + '\n' + line + '\n'
        phpbin = shutil.which('php') or next((l['bin'] for l in installed_php_layouts() if os.path.exists(l['bin'])), '')
        ok, msg = _st_apply({_RC_CONF: c}, test_cmd=f'"{phpbin}" -l {_RC_CONF} 2>&1' if phpbin else None)
        return _res(ok, msg or 'Roundcube configuration saved.')

    # ---- Generic config file ----------------------------------------------------------
    if action == 'save_config':
        conf_path = d.get('conf_path', '')
        content   = d.get('content', '')
        if not conf_path or not isinstance(content, str) or not content.strip():
            return _res(False, 'Missing conf_path or content')
        if mod_id == 'caddy':
            c = _st_caddy()
            if not _st_same_file(conf_path, c.CADDYFILE):
                return _res(False, 'Only the main Caddyfile can be edited here.')
            ok, msg = c.apply_caddy_file(c.CADDYFILE, content)
            return _res(ok, msg or 'Caddyfile saved and Caddy reloaded.')
        if mod_id == 'postgresql':
            pg = _st_pg()
            if not pg['conf'] or not any(_st_same_file(conf_path, p) for p in pg['all']):
                return _res(False, 'That file is not a PostgreSQL cluster configuration on this server.')
            return _res(*_st_pg_apply(conf_path, content))
        allowed, test_cmd, svc, act = _st_allowed_conf(mod_id)
        if not allowed:
            return _res(False, f'Editing the configuration of {mod_id} is not supported here.')
        target = next((p for p in allowed if _st_same_file(conf_path, p)), None)
        if not target:
            return _res(False, 'That file is not a configuration file of this app.')
        ok, msg = _st_apply({target: content}, test_cmd=test_cmd, svc=svc, action=act)
        return _res(ok, msg or 'Configuration saved and service reloaded.')

    elif action == 'save_optimization':
        opts = d.get('optimization') or {}
        if not isinstance(opts, dict):
            return _res(False, 'Invalid optimization settings.')
        opts = {str(k): str(v).strip() for k, v in opts.items() if v is not None}
        return _res(*_st_save_optimization(mod_id, opts))

    elif action == 'switch_version':
        if not ver:
            return jsonify({'ok': False, 'error': 'No version specified'}), 400
        allowed_vers = [str(v.get('value')) for v in ((mod or {}).get('versions') or [])]
        if mod_id in ('memcached', 'pure-ftpd'):
            allowed_vers = ['latest']
        if ver not in allowed_vers:
            return jsonify({'ok': False, 'error': f'Unknown version {ver} for {mod_id}'}), 400
        cur_ver = get_version(mod_id) if mod_id != 'postgresql' else ''
        if mod_id in _SWITCH_NO_DOWNGRADE and cur_ver:
            cur_t, tgt_t = _parse_ver_tuple(cur_ver), _st_target_tuple(mod_id, ver)
            if cur_t and tgt_t and tgt_t < cur_t[:len(tgt_t)]:
                name = mod['name'] if mod else mod_id
                return jsonify({'ok': False, 'error': f'{name} {cur_ver} is installed. Downgrading to {ver} in place is not '
                                f'supported by its data format and can make existing data unreadable. Back up the data, '
                                f'uninstall, install {ver} and restore instead.'}), 400
        script, why = _st_switch_script(mod_id, ver, mod)
        if not script:
            return jsonify({'ok': False, 'error': why}), 400

        # Run as a streaming job -- same system as install/uninstall
        job_id = str(uuid.uuid4())[:8]
        _job_create(job_id, initial_installed=True)

        def run_switch():
            mod_name = mod['name'] if mod else mod_id
            _job_append_line(job_id, f'[VortexPanel] Switching {mod_name} to version {ver}...')
            rc, timed_out = _run_streaming(job_id, script, 1800, 'Version switch')
            if mod_id == 'postgresql':
                new_ver = ver if os.path.exists(f'/usr/lib/postgresql/{ver}/bin/postgres') else ''
                matched = bool(new_ver)
            else:
                new_ver = get_version(mod_id)
                matched = True if ver == 'latest' else _st_switch_ok(mod_id, ver, new_ver)
            success = (rc == 0) and not timed_out and matched
            svc = _resolve_svc(mod.get('service', '')) if mod and mod.get('service') else ''
            note = ''
            if svc and not _svc_active(svc):
                if _svc_start(svc):
                    note = f' The {svc} service was stopped afterwards and has been started again.'
                else:
                    note = f' Warning: the {svc} service is not running -- check Settings > Service.'
            if success and mod_id == 'postgresql':
                msg = (f'PostgreSQL {ver} is installed next to the existing version. Your databases are still in the '
                       f'old cluster (see pg_lsclusters above); the new cluster is empty. To move them: '
                       f'pg_dropcluster --stop {ver} main && pg_upgradecluster <old-version> main.')
            elif success:
                msg = f'Switched to {new_ver or ver} successfully.'
            elif timed_out:
                msg = 'Version switch was stopped because it took longer than 30 minutes.'
            elif rc != 0:
                msg = f'Version switch failed (exit code {rc}) -- the reason is in the output above. Running version: {new_ver or "unknown"}.'
            else:
                msg = f'Version switch did not take effect: {ver} was requested but {new_ver or "an unknown version"} is installed.'
            _job_finish(job_id, success=success, installed=True, inst_ver=new_ver, message=msg + note)

        _start_job_thread(job_id, run_switch, installed_on_error=True)
        return jsonify({'ok': True, 'job_id': job_id, 'action': 'switch_version'})

    elif action == 'setup_private_dns':
        b = _st_bind()
        if b['options'] != '/etc/bind/named.conf.options':
            return _res(False, 'Private DNS setup edits /etc/bind/named.conf.options (Debian/Ubuntu layout). '
                               'On this server edit the options block of /etc/named.conf in the Config tab.')
        raw = str(d.get('networks', '127.0.0.1;'))
        nets = [n.strip() for n in raw.replace('\n', ';').replace(',', ';').split(';') if n.strip()]
        for n in nets:
            if n not in ('any', 'none', 'localhost', 'localnets') and not _st_ip_or_net(n.lstrip('!')):
                return _res(False, f'Invalid network: {n}')
        if not nets:
            return _res(False, 'Enter at least one network.')
        old = _st_read(b['options'])
        fm = re.search(r'forwarders\s*\{[^}]*\}\s*;', _st_named_mask(old))
        fwd = re.search(r'.*', old[fm.start():fm.end()], re.S) if fm else None
        acl = '\n'.join('        ' + n + ';' for n in nets)
        conf = ('options {\n    directory "/var/cache/bind";\n    recursion yes;\n'
                f'    allow-query {{\n{acl}\n    }};\n    allow-recursion {{\n{acl}\n    }};\n')
        if fwd:
            conf += '    ' + fwd.group(0) + '\n'
        conf += '    dnssec-validation auto;\n    listen-on { any; };\n    listen-on-v6 { any; };\n};\n'
        return _res(*_st_apply({b['options']: conf}, test_cmd=f'named-checkconf {b["conf"]} 2>&1',
                               svc='named', action='reload'))

    elif action == 'set_forwarders':
        b = _st_bind()
        raw = str(d.get('forwarders', ''))
        fwds = [f.strip() for f in raw.replace('\n', ';').replace(',', ';').split(';') if f.strip()]
        for f_ in fwds:
            try:
                _ipaddress.ip_address(f_)
            except ValueError:
                return _res(False, f'Invalid forwarder address: {f_}')
        c = _st_read(b['options'], None)
        if c is None:
            return _res(False, f'{b["options"]} not found.')
        block = 'forwarders {\n' + ''.join(f'        {f_};\n' for f_ in fwds) + '    };'
        masked = _st_named_mask(c)   # ignore the commented-out example block
        m = re.search(r'forwarders\s*\{[^}]*\}\s*;', masked)
        if m:
            c = c[:m.start()] + (block if fwds else '') + c[m.end():]
        elif fwds:
            m = re.search(r'options\s*\{', masked)
            if not m:
                return _res(False, f'No options {{ }} block in {b["options"]}.')
            c = c[:m.end()] + '\n    ' + block + c[m.end():]
        return _res(*_st_apply({b['options']: c}, test_cmd=f'named-checkconf {b["conf"]} 2>&1',
                               svc='named', action='reload'))

    elif action == 'save_global_opts':
        c = _st_caddy()
        opts = d.get('opts') or {}
        if not isinstance(opts, dict):
            return _res(False, 'Invalid options.')
        content = _st_read(c.CADDYFILE, None)
        if content is None:
            return _res(False, 'Caddyfile not found')
        checks = {'email': r'^[^\s{}"#]+@[^\s{}"#]+$', 'http_port': r'^\d{1,5}$', 'https_port': r'^\d{1,5}$',
                  'admin': r'^(off|[A-Za-z0-9.\[\]:_-]{1,100})$'}
        for k, v in opts.items():
            if k not in checks:
                return _res(False, f'Unsupported global option: {k}')
            if v and not re.match(checks[k], str(v).strip()):
                return _res(False, f'Invalid value for {k}')
        blocks = c._blocks(content)
        has_global = bool(blocks) and blocks[0][0] == '' and \
            all(l.strip().startswith('#') or not l.strip() for l in content[:blocks[0][1]].splitlines())
        if has_global:
            _a, s, e = blocks[0]
            ob = content.index('{', s)
            body = content[ob + 1:e - 1]
        else:
            s = e = 0
            body = '\n'
        for k in checks:
            if k not in opts:
                continue
            v = str(opts[k] or '').strip()
            pat = re.compile(rf'^[ \t]*{k}(?:[ \t]+[^\n]*)?$\n?', re.M)
            if v:
                if pat.search(body):
                    body = pat.sub(lambda _m: f'\t{k} {v}\n', body, count=1)
                else:
                    body = body.rstrip('\n') + f'\n\t{k} {v}\n'
            else:
                body = pat.sub('', body, count=1)
        block = '{' + ('\n' if not body.startswith('\n') else '') + body.rstrip('\n') + '\n}'
        new = content[:s] + block + content[e:] if e else block + '\n\n' + content
        ok, msg = c.apply_caddy_file(c.CADDYFILE, new)
        return _res(ok, msg or 'Global options saved and Caddy reloaded.')

    elif action == 'export_certs':
        c = _st_caddy()
        exported = []
        for base in c.caddy_cert_dirs():
            for domain in sorted(os.listdir(base)):
                src = os.path.join(base, domain)
                if not os.path.isdir(src) or not re.match(r'^[A-Za-z0-9_.*-]+$', domain):
                    continue
                dest = os.path.join('/etc/ssl/vortexpanel', domain)
                os.makedirs(dest, mode=0o700, exist_ok=True)
                os.chmod(dest, 0o700)
                copied = False
                for fn in os.listdir(src):
                    if fn.endswith(('.crt', '.key', '.pem')):
                        dp = os.path.join(dest, fn)
                        shutil.copyfile(os.path.join(src, fn), dp)
                        os.chmod(dp, 0o600 if fn.endswith('.key') else 0o644)
                        copied = True
                if copied and domain not in exported:
                    exported.append(domain)
        if exported:
            return jsonify({'ok': True, 'exported': exported})
        return jsonify({'ok': False, 'error': 'No certificates found to export'})

    elif action == 'pma_set_port':
        port = str(d.get('port', '8082')).strip()
        if not _st_valid_port(port):
            return _res(False, 'Invalid port.')
        port = str(int(port))

        def _update_firewall(old_port, new_port):
            if old_port and old_port != new_port:
                sh(f'ufw status 2>/dev/null | grep -q "Status: active" && ufw delete allow {old_port}/tcp 2>/dev/null; '
                   f'firewall-cmd --state >/dev/null 2>&1 && firewall-cmd --permanent --remove-port={old_port}/tcp 2>/dev/null && firewall-cmd --reload 2>/dev/null; true')
            sh(f'ufw status 2>/dev/null | grep -q "Status: active" && ufw allow {new_port}/tcp comment "phpMyAdmin" 2>/dev/null; '
               f'firewall-cmd --state >/dev/null 2>&1 && firewall-cmd --permanent --add-port={new_port}/tcp 2>/dev/null && firewall-cmd --reload 2>/dev/null; true')

        conf, kind = _st_pma_conf()
        if not conf:
            return _res(False, 'phpMyAdmin config not found for any supported web server (nginx, Apache, Caddy)')
        # SELinux: the web server cannot bind a port outside http_port_t.
        selinux_allow_port(port)
        if kind == 'nginx':
            c = _st_read(conf)
            m = re.search(r'listen\s+(\d+)', c)
            old_port = m.group(1) if m else None
            c = re.sub(r'listen\s+\d+', f'listen {port}', c)
            ok, msg = _st_apply({conf: c}, test_cmd='nginx -t 2>&1', svc='nginx', action='reload')
        elif kind in ('httpd', 'apache2'):
            a = _st_apache()
            c = _st_read(conf)
            m = re.search(r'Listen\s+(\d+)', c)
            old_port = m.group(1) if m else None
            c = re.sub(r'Listen\s+\d+', f'Listen {port}', c)
            c = re.sub(r'<VirtualHost \*:\d+>', f'<VirtualHost *:{port}>', c)
            ok, msg = _st_apply({conf: c}, test_cmd=a['test'], svc=a['svc'], action='reload')
        else:
            cad = _st_caddy()
            c = _st_read(cad.CADDYFILE)
            m = re.search(r'(^|\n)[ \t]*:(\d+)(\s*\{\s*root \* /usr/share/phpmyadmin)', c)
            if not m:
                return _res(False, 'The phpMyAdmin site block was not found in the Caddyfile.')
            old_port = m.group(2)
            c = c[:m.start()] + f'{m.group(1)}:{port}{m.group(3)}' + c[m.end():]
            ok, msg = cad.apply_caddy_file(cad.CADDYFILE, c)
        if ok: _update_firewall(old_port, port)
        return _res(ok, msg, port=port)

    elif action in ('pma_set_php', 'set_php'):
        php_ver = str(d.get('php_version' if action == 'pma_set_php' else 'version', '') or '')
        if not valid_php_ver(php_ver):
            return _res(False, 'PHP version missing or invalid')
        lay = php_layout(php_ver)
        if not lay:
            return _res(False, f'PHP {php_ver} is not installed.')
        sock = lay['sock']
        if not os.path.exists(sock):
            return _res(False, f'PHP {php_ver}-FPM is not running ({sock} not found).')
        if action == 'set_php':
            conf, kind = '/etc/nginx/conf.d/roundcube.conf', 'nginx'
            if not os.path.exists(conf):
                return _res(False, 'Roundcube nginx config not found')
        else:
            conf, kind = _st_pma_conf()
            if not conf:
                return _res(False, 'phpMyAdmin config not found for any supported web server (nginx, Apache, Caddy)')
        old = _st_read(conf)
        if kind == 'caddy':
            # only the phpMyAdmin block of the Caddyfile
            new = re.sub(r'(root \* /usr/share/phpmyadmin[^}]*?php_fastcgi\s+unix/)/[^\s;|"]+\.sock',
                         lambda m_: m_.group(1) + sock, old, flags=re.DOTALL)
        else:
            new = _SOCK_REF_RE.sub(lambda m_: m_.group(1) + sock, old)
        if new == old and sock not in old:
            return _res(False, f'No PHP-FPM socket reference found in {conf}.')
        if kind == 'caddy':
            cad = _st_caddy()
            return _res(*cad.apply_caddy_file(conf, new))
        if kind == 'nginx':
            return _res(*_st_apply({conf: new}, test_cmd='nginx -t 2>&1', svc='nginx', action='reload'))
        a = _st_apache()
        return _res(*_st_apply({conf: new}, test_cmd=a['test'], svc=a['svc'], action='reload'))

    elif action in ('ftp_add_user', 'ftp_del_user'):
        try:
            from panel.routes import ftp as _ftp
        except ImportError:
            import ftp as _ftp
        if action == 'ftp_add_user':
            return _ftp.create_account()
        return _ftp.delete_account(str(d.get('user', '')))

    elif action in ('fail2ban_save_blacklist', 'fail2ban_save_whitelist'):
        return _res(*_st_f2b_lists(action == 'fail2ban_save_blacklist', str(d.get('ips', ''))))

    return jsonify({'ok': False, 'error': 'Unknown action'}), 400


def _st_named_mask(c):
    """named.conf text with comments (//, #, /* */) blanked out, same length,
    so regex positions map 1:1 onto the original."""
    def blank(m_):
        return re.sub(r'[^\n]', ' ', m_.group(0))
    return re.sub(r'/\*.*?\*/|//[^\n]*|#[^\n]*', blank, c, flags=re.S)

def _st_pg_apply(conf_path, content):
    """Save postgresql.conf, reload the cluster and roll back when PostgreSQL
    reports errors for the new file (pg_file_settings)."""
    old = _st_read(conf_path, None)
    with open(conf_path, 'w') as f:
        f.write(content)
    pg = _st_pg()
    unit = _resolve_svc(pg['svc'])
    if not _svc_active(unit):
        return True, f'Saved. {unit} is not running, so the change takes effect when it starts.'
    _st_run(f'systemctl reload {unit} 2>&1', 60)
    m = re.search(r'^\s*port\s*=\s*(\d+)', content, re.M)
    port = m.group(1) if m else '5432'
    rc, out = _st_run(f"runuser -u postgres -- psql -p {port} -tAc \"SELECT sourcefile||':'||sourceline||' '||error "
                      "FROM pg_file_settings WHERE error IS NOT NULL\" 2>&1", 30)
    if rc == 0 and out.strip():
        _st_restore(conf_path, old)
        _st_run(f'systemctl reload {unit} 2>&1', 60)
        return False, 'PostgreSQL rejected the new configuration -- the previous file was restored:\n' + out[-1500:]
    note = ''
    rc2, pend = _st_run(f"runuser -u postgres -- psql -p {port} -tAc \"SELECT string_agg(name, ', ') FROM pg_settings "
                        "WHERE pending_restart\" 2>/dev/null", 30)
    if rc2 == 0 and pend.strip():
        note = f' These settings need a PostgreSQL restart to take effect: {pend.strip()}.'
    return True, 'Saved and PostgreSQL reloaded.' + note


def _st_save_optimization(mod_id, opts):
    """Apply the Optimization tab of one app. Returns (ok, message)."""
    if mod_id == 'memcached':
        conf_path, fmt = _st_memcached_conf()
        c = _st_read(conf_path)
        vals = {}
        for k in ('bind', 'port', 'cachesize', 'maxconn'):
            if k not in opts or opts[k] == '':
                continue
            v = opts[k]
            if k == 'bind':
                if not all(_st_ip_or_net(x) for x in v.split(',')):
                    return False, 'Invalid bind address.'
            elif k == 'port':
                if not _st_valid_port(v): return False, 'Invalid port.'
            elif not _ST_INT_RE.match(v):
                return False, f'Invalid value for {k}.'
            vals[k] = v
        if fmt == 'flags':
            for k, flag in (('bind', 'l'), ('port', 'p'), ('cachesize', 'm'), ('maxconn', 'c')):
                if k not in vals: continue
                pat = re.compile(rf'^-{flag}\s+\S+[ \t]*\n?', re.M)
                ms = list(pat.finditer(c))
                if ms:
                    first = ms[0]
                    # keep the first occurrence, drop duplicates (two -l lines
                    # with the same address make memcached fail to bind)
                    for m_ in reversed(ms[1:]):
                        c = c[:m_.start()] + c[m_.end():]
                    c = c[:first.start()] + f'-{flag} {vals[k]}\n' + c[first.end():]
                else:
                    c = c.rstrip('\n') + f'\n-{flag} {vals[k]}\n'
        else:
            def setvar(c, key, val):
                pat = re.compile(rf'^{key}=.*$', re.M)
                line = f'{key}="{val}"'
                return pat.sub(lambda _m: line, c, count=1) if pat.search(c) else c.rstrip('\n') + f'\n{line}\n'
            if 'port' in vals: c = setvar(c, 'PORT', vals['port'])
            if 'cachesize' in vals: c = setvar(c, 'CACHESIZE', vals['cachesize'])
            if 'maxconn' in vals: c = setvar(c, 'MAXCONN', vals['maxconn'])
            if 'bind' in vals:
                m = re.search(r'^OPTIONS="?([^"\n]*)"?\s*$', c, re.M)
                opt = m.group(1) if m else ''
                opt = re.sub(r'-l\s+\S+', f'-l {vals["bind"]}', opt) if re.search(r'-l\s+\S+', opt) else (opt + f' -l {vals["bind"]}').strip()
                c = setvar(c, 'OPTIONS', opt)
        ok, msg = _st_apply({conf_path: c}, svc='memcached', action='restart')
        return ok, msg or 'Saved and memcached restarted.'

    if mod_id == 'apache2':
        a = _st_apache()
        changes, missing = {}, []
        for path, keys in ((a['conf'], _APACHE_KEYS), (a['mpm'], _APACHE_MPM_KEYS)):
            if not path or not os.path.exists(path):
                missing += [k for k in keys if k in opts]
                continue
            c = _st_read(path)
            for k in keys:
                if k not in opts or opts[k] == '': continue
                v = opts[k]
                if not re.match(r'^(On|Off|on|off|\d{1,7})$', v):
                    return False, f'Invalid value for {k}.'
                new = _st_set_directive(c, k, v)
                if new is None:
                    missing.append(k)
                else:
                    c = new
            changes[path] = c
        if not changes:
            return False, 'Apache configuration file not found.'
        ok, msg = _st_apply(changes, test_cmd=a['test'], svc=a['svc'], action='reload')
        if ok and missing:
            msg = (msg + ' ' if msg else 'Saved. ') + 'Not present in the config (unchanged): ' + ', '.join(missing)
        return ok, msg or 'Saved and Apache reloaded.'

    if mod_id == 'openlitespeed':
        c = _st_read(_OLS_CONF, None)
        if c is None:
            return False, f'{_OLS_CONF} not found.'
        missing = []
        for k, v in opts.items():
            if k not in _OLS_KEYS:
                continue
            if not _ST_INT_RE.match(v):
                return False, f'Invalid value for {k}.'
            new = _st_set_directive(c, k, v)
            if new is None:
                missing.append(k)
            else:
                c = new
        ok, msg = _st_apply({_OLS_CONF: c}, svc='lsws', action='restart')
        if ok and missing:
            msg = (msg + ' ' if msg else 'Saved. ') + 'Not present in the config (unchanged): ' + ', '.join(missing)
        return ok, msg or 'Saved and OpenLiteSpeed restarted.'

    if mod_id == 'nginx':
        conf = _st_nginx_conf()
        c = _st_read(conf, None)
        if c is None:
            return False, f'{conf} not found.'
        for k, v in opts.items():
            if k not in _NGINX_OPT:
                continue
            ctx, vre = _NGINX_OPT[k]
            if not re.match(vre, v):
                return False, f'Invalid value for {k}: {v}'
            pat = re.compile(rf'^([ \t]*){k}[ \t]+[^;\n]*;', re.M)
            if pat.search(c):
                c = pat.sub(lambda m_: f'{m_.group(1)}{k} {v};', c, count=1)
            elif ctx == 'main':
                c = f'{k} {v};\n' + c
            else:
                m = re.search(rf'^[ \t]*{ctx}\s*\{{', c, re.M)
                if not m:
                    return False, f'No {ctx} {{ }} block in {conf}.'
                c = c[:m.end()] + f'\n    {k} {v};' + c[m.end():]
        ok, msg = _st_apply({conf: c}, test_cmd='nginx -t 2>&1', svc='nginx', action='reload')
        return ok, msg or 'Saved and nginx reloaded.'

    if mod_id in ('mysql', 'mariadb'):
        flavor = _st_mysql_flavor(mod_id)
        cnf = _st_mysql_cnf(flavor)
        c = _st_read(cnf, None)
        if c is None:
            return False, f'{cnf} not found.'
        for key, val in opts.items():
            if key not in _MYSQL_OPT_KEYS or not val:
                continue
            if key == 'port':
                if not _st_valid_port(val): return False, 'Invalid port.'
            elif not _ST_SIZE_RE.match(val):
                return False, f'Invalid value for {key}: {val}'
            pat = re.compile(rf'^([ \t]*){key}[ \t]*=[^\n]*$', re.M)
            if pat.search(c):
                c = pat.sub(lambda m_: f'{m_.group(1)}{key} = {val}', c, count=1)
            else:
                m = re.search(r'^[ \t]*\[mysqld\][ \t]*$', c, re.M) or _MYSQLD_SECTION_RE.search(c)
                if m:
                    c = c[:m.end()] + f'\n{key} = {val}' + c[m.end():]
                else:
                    c = c.rstrip('\n') + f'\n\n[mysqld]\n{key} = {val}\n'
        ok, msg = _st_apply({cnf: c}, svc=_st_mysql_svc(flavor), action='restart')
        name = 'MariaDB' if flavor == 'mariadb' else 'MySQL'
        return ok, msg or f'Saved to {cnf} and {name} restarted.'

    if mod_id == 'redis':
        conf = _st_redis_conf()
        c = _st_read(conf, None)
        if c is None:
            return False, f'{conf} not found.'
        checks = {'bind': r'^[0-9A-Fa-f:.\-* ]{1,200}$', 'port': r'^\d{1,5}$', 'timeout': r'^\d{1,9}$',
                  'maxclients': r'^\d{1,9}$', 'databases': r'^\d{1,5}$', 'requirepass': r'^[^\s"\'\\]{0,128}$',
                  'maxmemory': r'^\d{1,15}([kKmMgG][bB]?)?$'}
        for k, v in opts.items():
            if k not in checks:
                continue
            if not re.match(checks[k], v):
                return False, f'Invalid value for {k}.'
            pat = re.compile(rf'^[ \t]*{k}[ \t]+[^\n]*$', re.M)
            if k == 'requirepass' and v == '':
                c = pat.sub(lambda m_: '# ' + m_.group(0).strip(), c)
                continue
            if v == '':
                continue
            if pat.search(c):
                c = pat.sub(lambda m_: f'{k} {v}', c, count=1)
            else:
                c = c.rstrip('\n') + f'\n{k} {v}\n'
        ok, msg = _st_apply({conf: c}, svc='redis-server', action='restart')
        return ok, msg or 'Saved and Redis restarted.'

    return False, f'The Optimization tab is not supported for {mod_id}.'


def _st_f2b_lists(black, raw):
    """Save the fail2ban Black/White IP lists and apply them."""
    entries = []
    for x in raw.replace(',', '\n').split('\n'):
        x = x.strip()
        if not x or x.startswith('#'):
            continue
        if not _st_ip_or_net(x):
            return False, f'Invalid IP address or range: {x}'
        if x not in entries:
            entries.append(x)
    if not shutil.which('fail2ban-client'):
        return False, 'fail2ban is not installed.'
    list_file = _F2B_BLACK_FILE if black else _F2B_WHITE_FILE
    old_entries = [l.strip() for l in _st_read(list_file).splitlines() if l.strip()]
    changes = {list_file: '\n'.join(entries) + ('\n' if entries else '')}
    if black:
        changes[_F2B_BLACK_CONF] = (
            '# Managed by VortexPanel (fail2ban Settings > Black IP)\n'
            f'[{_F2B_BLACK_JAIL}]\nenabled   = true\nfilter    =\nbackend   = auto\n'
            'banaction = %(banaction_allports)s\nbantime   = -1\n')
    else:
        changes[_F2B_WHITE_CONF] = (
            '# Managed by VortexPanel (fail2ban Settings > White IP)\n'
            '[DEFAULT]\nignoreip = 127.0.0.1/8 ::1' + ''.join(' ' + e for e in entries) + '\n')
    ok, msg = _st_apply(changes, test_cmd='fail2ban-client -t 2>&1')
    if not ok:
        return False, msg
    if not _svc_active('fail2ban'):
        return True, 'Saved. fail2ban is not running, so the list takes effect when it starts.'
    rc, out = _st_run('fail2ban-client reload 2>&1', 60)
    if rc != 0:
        return False, 'Saved, but fail2ban could not reload: ' + out[-500:]
    if not black:
        return True, 'White IP list saved; these addresses are never banned.'
    failed = []
    for ip in old_entries:
        if ip not in entries and _st_ip_or_net(ip):
            _st_run(f'fail2ban-client set {_F2B_BLACK_JAIL} unbanip {ip} 2>&1', 20)
    for ip in entries:
        rc, out = _st_run(f'fail2ban-client set {_F2B_BLACK_JAIL} banip {ip} 2>&1', 20)
        if rc != 0:
            failed.append(ip)
    if failed:
        return False, 'Saved, but fail2ban could not ban: ' + ', '.join(failed)
    return True, f'Black IP list saved; {len(entries)} address(es) banned on all ports.'


# --- Weekly OWASP CRS update (cron) ------------------------------------------------------
def _cli_update_crs():
    """Entry point of the weekly cron job (python3 -m panel.routes.modules
    update-crs): runs the panel's own CRS update (security.modsec_update_crs:
    newest release only, fresh directory, config test, previous ruleset
    restored on failure). The old cron line fell back to CRS v4.0.0 when the
    GitHub API was rate-limited, untarred over the live tree (stale rule
    files from the previous release stayed) and reloaded without rollback."""
    from flask import Flask
    try:
        from panel.routes import security as _sec
    except ImportError:
        import security as _sec
    stamp = time.strftime('%Y-%m-%d %H:%M:%S')
    if not _sec._modsec_installed():
        print(f'{stamp} ModSecurity is not installed -- nothing to update.')
        return 0
    latest = _sec._crs_latest_tag()
    if latest and latest.lstrip('v') == _sec._crs_version():
        print(f'{stamp} OWASP CRS {latest} is already installed.')
        return 0
    app = Flask('vortexpanel-crs-update')
    app.secret_key = os.urandom(32)
    with app.test_request_context('/api/security/modsecurity/update-crs', method='POST'):
        session['user'] = 'cron'
        rv = _sec.modsec_update_crs()
        resp = rv[0] if isinstance(rv, tuple) else rv
        data = resp.get_json(silent=True) or {}
    if data.get('ok'):
        print(f'{stamp} OWASP CRS updated to {data.get("version")} (config test passed, web server reloaded).')
        return 0
    print(f'{stamp} OWASP CRS update failed, the installed ruleset was kept: {data.get("error")}')
    return 1


def _migrate_crs_cron():
    """Rewrite cron files written by older installs (shell pipeline with the
    v4.0.0 fallback) to the panel-based job. Only files that still carry the
    old generated line are touched."""
    for path in ('/etc/cron.d/vortex-crs-update', '/etc/cron.d/vortex-crs-update-apache'):
        try:
            with open(path) as f:
                old = f.read()
        except OSError:
            continue
        if 'coreruleset/archive/refs/tags' not in old or 'update-crs' in old:
            continue
        try:
            tmp = path + '.vp-tmp'
            with open(tmp, 'w') as f:
                f.write('# Managed by VortexPanel -- weekly OWASP CRS update (tested, rolled back on failure)\n'
                        'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n'
                        + _CRS_CRON_LINE + '\n')
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except OSError:
            pass

try:
    _migrate_crs_cron()
except Exception:
    pass


if __name__ == '__main__':
    import sys
    if sys.argv[1:2] == ['update-crs']:
        sys.exit(_cli_update_crs())
    print('usage: python3 -m panel.routes.modules update-crs')
    sys.exit(2)
