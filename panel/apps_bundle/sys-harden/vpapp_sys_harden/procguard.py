"""Process guard: finds processes that look like malware.

Signals (any one is enough to list a process; severity decides auto-kill):
  critical  known miner/botnet names, mining-pool URLs in the command line,
            a deleted binary that ran from a temp folder
  high      binary running from /tmp, /var/tmp, /dev/shm or /run/user
            a shell whose input is a network socket (reverse shell)
  medium    binary deleted from disk while still running (outside package updates)
"""
import os
import re
import shutil
import time

from panel import appkit

APP = 'sys-harden'
TEMP_DIRS = ('/tmp/', '/var/tmp/', '/dev/shm/', '/run/user/', '/run/shm/')
MINERS = re.compile(r'(^|/)(xmrig|xmr-stak|kdevtmpfsi|kinsing|minerd|cpuminer|cryptonight|ethminer|nbminer|t-rex|'
                    r'lolminer|phoenixminer|nanominer|xmrigdaemon|srbminer|teamredminer|sysrv|kthreaddi|'
                    r'dbused|solrd|kerberods|networkservice|sysupdate)(\s|$|\.)', re.I)
POOL = re.compile(r'stratum\+(tcp|ssl)://|--donate-level|nicehash|moneroocean|supportxmr|minexmr|2miner|f2pool|'
                  r'c3pool|hashvault|xmrpool', re.I)
SHELLS = ('bash', 'sh', 'dash', 'zsh', 'ksh', 'python', 'python3', 'perl', 'nc', 'ncat', 'socat', 'php')


def _read(path, binary=False):
    try:
        with open(path, 'rb' if binary else 'r') as f:
            return f.read()
    except OSError:
        return b'' if binary else ''


def _fd0_socket(pid):
    try:
        return os.readlink(f'/proc/{pid}/fd/0').startswith('socket:')
    except OSError:
        return False


def _ppid_name(pid):
    st = _read(f'/proc/{pid}/stat')
    try:
        ppid = int(st.rsplit(')', 1)[1].split()[1])
        return ppid, _read(f'/proc/{ppid}/comm').strip()
    except (IndexError, ValueError):
        return 0, ''


def scan(whitelist=()):
    """[{pid, name, exe, cmd, user, severity, reason}] for suspicious processes."""
    me = os.getpid()
    out = []
    try:
        pids = [int(p) for p in os.listdir('/proc') if p.isdigit()]
    except OSError:
        return out
    for pid in pids:
        if pid in (1, me):
            continue
        try:
            exe = os.readlink(f'/proc/{pid}/exe')
        except OSError:
            continue      # kernel thread or gone
        cmd = _read(f'/proc/{pid}/cmdline', True).replace(b'\0', b' ').decode('utf-8', 'replace').strip()[:400]
        name = _read(f'/proc/{pid}/comm').strip()
        real = exe.replace(' (deleted)', '')
        if any(real == w or real.startswith(w.rstrip('/') + '/') for w in whitelist if w):
            continue
        deleted = exe.endswith(' (deleted)')
        in_temp = real.startswith(TEMP_DIRS)
        sev, why = '', ''
        if MINERS.search(real) or MINERS.search(name + ' ') or POOL.search(cmd):
            sev, why = 'critical', 'Looks like a cryptocurrency miner'
        elif deleted and in_temp:
            sev, why = 'critical', 'Program deleted itself after starting from a temporary folder'
        elif in_temp:
            sev, why = 'high', 'Program running from a temporary folder'
        elif name in SHELLS and _fd0_socket(pid):
            ppid, pname = _ppid_name(pid)
            if pname not in ('sshd', 'systemd', 'gunicorn', 'python3', 'tmux: server', 'screen', 'node', 'docker-init'):
                sev, why = 'high', f'Shell reading from a network socket (parent: {pname or ppid})'
        elif deleted and not real.startswith(('/usr/', '/lib', '/opt/vortexpanel/', '/snap/')):
            sev, why = 'medium', 'Program was deleted from disk while still running'
        if not sev:
            continue
        try:
            uid = os.stat(f'/proc/{pid}').st_uid
            import pwd
            user = pwd.getpwuid(uid).pw_name
        except (OSError, KeyError):
            user = '?'
        out.append({'pid': pid, 'name': name, 'exe': exe, 'cmd': cmd, 'user': user, 'severity': sev, 'reason': why})
    order = {'critical': 0, 'high': 1, 'medium': 2}
    return sorted(out, key=lambda r: (order[r['severity']], r['pid']))


def quarantine_dir():
    d = os.path.join(appkit.data_dir(APP), 'quarantine')
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def kill(pid, quarantine=True):
    """SIGKILL the process; move its binary (if still on disk) into quarantine. (ok, detail)."""
    try:
        exe = os.readlink(f'/proc/{pid}/exe')
    except OSError:
        exe = ''
    try:
        os.kill(int(pid), 9)
    except ProcessLookupError:
        return False, 'process already gone'
    except OSError as e:
        return False, str(e)
    detail = f'killed {pid}'
    real = exe.replace(' (deleted)', '')
    if quarantine and real and os.path.isfile(real) and real.startswith(TEMP_DIRS):
        dest = os.path.join(quarantine_dir(), f'{int(time.time())}-{os.path.basename(real)}')
        try:
            shutil.move(real, dest)
            os.chmod(dest, 0)
            detail += f'; binary moved to quarantine ({os.path.basename(dest)})'
        except OSError as e:
            detail += f'; could not quarantine the binary: {e}'
    return True, detail
