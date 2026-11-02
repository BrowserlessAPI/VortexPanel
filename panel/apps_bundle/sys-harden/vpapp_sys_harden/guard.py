"""Protection areas: what each one watches, and monitor / lock.

Monitor: a baseline (size, mtime, mode, owner, inode and sha256 of small files)
is compared every scan; additions, removals and changes become events.
Lock: chattr +i on the area's files. The App records exactly which files it
locked and only ever unlocks those, so files someone made immutable by hand
are left alone. A lock can be paused (all locks lifted) for N minutes for
maintenance; the service re-locks when the pause ends.
"""
import glob
import hashlib
import os
import stat
import time

from panel import appkit

APP = 'sys-harden'
MAX_FILES = 25000
HASH_MAX = 2 * 1024 * 1024

# id -> definition. 'lock_warn' explains what a lock blocks; lockable False = monitor only
AREAS = {
    'users': {
        'label': 'User protection', 'icon': 'users', 'severity': 'high',
        'desc': 'User and group accounts, passwords and sudo rights. Attackers add a user or a sudo rule to keep access.',
        'paths': ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow', '/etc/sudoers', '/etc/sudoers.d'],
        'lockable': True,
        'lock_warn': 'While locked nobody can add users, change passwords or edit sudo rules: this includes '
                     'Hosting accounts, FTP users and packages that create a system user. Pause the lock first.'},
    'ssh': {
        'label': 'SSH protection', 'icon': 'key', 'severity': 'high',
        'desc': 'SSH server settings and authorized keys. A planted key is the most common way back into a server.',
        'paths': ['/etc/ssh/sshd_config', '/etc/ssh/sshd_config.d', '/root/.ssh/authorized_keys', '/root/.ssh/authorized_keys2',
                  '/home/*/.ssh/authorized_keys'],
        'lockable': True,
        'lock_warn': 'While locked you cannot add SSH keys or change SSH settings (also from the panel\'s Security page).'},
    'cron': {
        'label': 'Crontab protection', 'icon': 'clock', 'severity': 'high',
        'desc': 'Scheduled tasks. Miners and backdoors re-install themselves from cron.',
        'paths': ['/etc/crontab', '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly',
                  '/var/spool/cron', '/etc/anacrontab'],
        'lockable': True,
        'lock_warn': 'While locked the panel\'s Cron Jobs page and packages cannot add or change cron jobs.',
        'ignore': ['/var/spool/cron/crontabs/.', '/etc/cron.d/vortex', '/var/spool/cron/atjobs', '/var/spool/cron/atspool']},
    'services': {
        'label': 'Service protection', 'icon': 'server', 'severity': 'medium',
        'desc': 'Systemd services and timers. New unknown services are a common persistence trick.',
        'paths': ['/etc/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system', '/etc/init.d', '/etc/rc.local'],
        'lockable': False,
        'ignore': ['/etc/systemd/system/vortexpanel', '/etc/systemd/system/multi-user.target.wants/vortexpanel',
                   '/etc/systemd/system/timers.target.wants/vortexpanel']},
    'env': {
        'label': 'Environment protection', 'icon': 'terminal', 'severity': 'high',
        'desc': 'Shell start-up files and the dynamic linker. ld.so.preload is how user-space rootkits hide.',
        'paths': ['/etc/ld.so.preload', '/etc/ld.so.conf', '/etc/ld.so.conf.d', '/etc/profile', '/etc/profile.d', '/etc/bash.bashrc',
                  '/etc/bashrc', '/etc/environment', '/root/.bashrc', '/root/.profile', '/root/.bash_profile'],
        'lockable': True,
        'lock_warn': 'While locked shell start-up files cannot be changed (also by software installers that add to PATH).'},
    'binaries': {
        'label': 'System binaries', 'icon': 'cpu', 'severity': 'medium',
        'desc': 'Programs in /bin, /sbin, /usr/bin and /usr/sbin. A replaced ls, ps or sshd hides an intruder.',
        'paths': ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
        'lockable': False},
}
MODES = ('off', 'monitor', 'lock')
DEFAULT_MODES = {'users': 'monitor', 'ssh': 'monitor', 'cron': 'monitor', 'services': 'monitor', 'env': 'monitor',
                 'binaries': 'monitor'}


# ----------------------------------------------------------------- settings

def config():
    c = appkit.read_json(APP, 'config.json', {})
    modes = dict(DEFAULT_MODES)
    modes.update({k: v for k, v in (c.get('modes') or {}).items() if k in AREAS and v in MODES})
    for k, v in list(modes.items()):
        if v == 'lock' and not AREAS[k]['lockable']:
            modes[k] = 'monitor'
    custom = [x for x in (c.get('custom') or []) if isinstance(x, dict) and x.get('path')]
    return {'modes': modes, 'custom': custom, 'paused_until': int(c.get('paused_until') or 0),
            'scan_minutes': appkit.clamp_int(c.get('scan_minutes'), 1, 1440, 5),
            'notify': bool(c.get('notify', True)), 'auto_kill': bool(c.get('auto_kill', False)),
            'proc_whitelist': [p for p in (c.get('proc_whitelist') or []) if isinstance(p, str)][:200]}


def save_config(c):
    appkit.write_json(APP, 'config.json', c)


def area_paths(aid, cfg=None):
    """Concrete existing paths of an area (globs expanded)."""
    if aid.startswith('custom:'):
        cfg = cfg or config()
        p = aid[7:]
        return [p] if os.path.exists(p) else []
    out = []
    for p in AREAS[aid]['paths']:
        for q in (glob.glob(p) if any(c in p for c in '*?[') else [p]):
            if os.path.exists(q) or os.path.islink(q):
                out.append(q)
    return out


def all_areas(cfg=None):
    cfg = cfg or config()
    ids = list(AREAS)
    ids += ['custom:' + c['path'] for c in cfg['custom']]
    return ids


def area_mode(aid, cfg):
    if aid.startswith('custom:'):
        for c in cfg['custom']:
            if 'custom:' + c['path'] == aid:
                return c.get('mode', 'monitor')
        return 'off'
    return cfg['modes'].get(aid, 'off')


# ---------------------------------------------------------------- snapshots

def _ignored(aid, path):
    ig = AREAS.get(aid, {}).get('ignore') or []
    return any(path.startswith(x) for x in ig)


def _walk(paths, aid):
    for root in paths:
        if os.path.isdir(root) and not os.path.islink(root):
            for dp, dns, fns in os.walk(root):
                dns[:] = [d for d in dns if not os.path.islink(os.path.join(dp, d))]
                yield dp
                for fn in fns:
                    p = os.path.join(dp, fn)
                    if not _ignored(aid, p):
                        yield p
        else:
            yield root


def _sha(p, st):
    if not stat.S_ISREG(st.st_mode) or st.st_size > HASH_MAX:
        return ''
    h = hashlib.sha256()
    try:
        with open(p, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
    except OSError:
        return ''
    return h.hexdigest()[:32]


def snapshot(aid, prev=None, cfg=None):
    """{path: [size, mtime_ns, mode, uid, gid, ino, sha]}. Files whose stat is unchanged
    against prev keep their stored hash (cheap rescans of /usr/bin)."""
    prev = prev or {}
    out = {}
    n = 0
    for p in _walk(area_paths(aid, cfg), aid):
        n += 1
        if n > MAX_FILES:
            break
        try:
            st = os.lstat(p)
        except OSError:
            continue
        key = [st.st_size, st.st_mtime_ns, st.st_mode, st.st_uid, st.st_gid, st.st_ino]
        old = prev.get(p)
        if old and old[:6] == key:
            out[p] = old
        else:
            out[p] = key + [_sha(p, st)]
    return out


def diff(old, new):
    """[(kind, path, detail)] kind: added | removed | modified | permissions."""
    out = []
    for p in sorted(set(new) - set(old)):
        out.append(('added', p, ''))
    for p in sorted(set(old) - set(new)):
        out.append(('removed', p, ''))
    for p in sorted(set(old) & set(new)):
        a, b = old[p], new[p]
        if a[6] != b[6] or (a[0] != b[0]) or (not b[6] and a[1] != b[1] and stat.S_ISREG(b[2])):
            out.append(('modified', p, f'size {a[0]} -> {b[0]}'))
        elif a[2] != b[2] or a[3] != b[3] or a[4] != b[4]:
            out.append(('permissions', p, f'mode {oct(a[2] & 0o7777)} -> {oct(b[2] & 0o7777)}, owner {a[3]}:{a[4]} -> {b[3]}:{b[4]}'))
    return out


def baseline_name(aid):
    return 'baseline-' + hashlib.sha1(aid.encode()).hexdigest()[:12] + '.json'


def load_baseline(aid):
    """{path: stat} or None when no baseline was recorded yet. An EMPTY baseline is
    real data (e.g. root had no authorized_keys): the first file added must be reported."""
    d = appkit.read_json(APP, baseline_name(aid), {})
    if 'files' not in d:
        return None
    return d['files'] or {}


def save_baseline(aid, snap):
    appkit.write_json(APP, baseline_name(aid), {'area': aid, 't': int(time.time()), 'files': snap})


# -------------------------------------------------------------------- locks

def locked():
    """{path: area} the App made immutable."""
    return appkit.read_json(APP, 'locked.json', {})


def _set_locked(d):
    appkit.write_json(APP, 'locked.json', d)


def _chattr(flag, paths):
    bad = []
    for i in range(0, len(paths), 200):
        chunk = paths[i:i + 200]
        rc, _, err = appkit.run(['chattr', flag] + chunk, timeout=120)      # absolute paths only
        if rc != 0:
            bad.append(err.strip()[-300:])
    return bad


_FS_IOC_GETFLAGS = 0x80086601
_FS_IMMUTABLE_FL = 0x10


def _is_immutable(p):
    """Immutable flag via the ioctl lsattr uses (no process per file); lsattr as fallback."""
    import fcntl
    import struct
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError:
        fd = None
    if fd is not None:
        try:
            buf = fcntl.ioctl(fd, _FS_IOC_GETFLAGS, b'\0' * 8)
            return bool(struct.unpack('i', buf[:4])[0] & _FS_IMMUTABLE_FL)
        except OSError:
            pass
        finally:
            os.close(fd)
    rc, out, _ = appkit.run(['lsattr', '-d', p], timeout=10)
    return bool(rc == 0 and out and 'i' in out.split()[0])


def lock_area(aid, cfg=None):
    """chattr +i on the area's regular files and folders not already immutable. (count, errors).
    The API and the service both call this: chattr and the locked.json update are one
    critical section, otherwise a stale write could forget a lock forever."""
    with appkit.locked(APP, 'locks'):
        return _lock_area(aid, cfg)


def _lock_area(aid, cfg=None):
    if not appkit.have('chattr'):
        return 0, ['chattr is not available on this server']
    cur = locked()
    todo = []
    for p in _walk(area_paths(aid, cfg), aid):
        if p in cur or os.path.islink(p):
            continue
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
            continue
        if _is_immutable(p):
            continue          # someone else's lock: not ours to manage
        todo.append(p)
    errs = _chattr('+i', todo)
    if not errs:
        for p in todo:
            cur[p] = aid
    else:
        # record only what really became immutable
        for p in todo:
            if _is_immutable(p):
                cur[p] = aid
    _set_locked(cur)
    return len(todo), errs


def unlock_area(aid=None):
    """Remove the App's own locks (of one area, or all). (count, errors)."""
    with appkit.locked(APP, 'locks'):
        return _unlock_area(aid)


def _unlock_area(aid=None):
    cur = locked()
    mine = [p for p, a in cur.items() if aid is None or a == aid]
    exist = [p for p in mine if os.path.exists(p)]
    errs = _chattr('-i', exist) if exist else []
    for p in mine:
        if not os.path.exists(p) or not _is_immutable(p):
            cur.pop(p, None)
    _set_locked(cur)
    return len(mine), errs


def pause(minutes):
    c = appkit.read_json(APP, 'config.json', {})
    c['paused_until'] = int(time.time()) + int(minutes) * 60 if minutes else 0
    save_config(c)
    if minutes:
        unlock_area(None)


def paused():
    return config()['paused_until'] > time.time()


def enforce_locks(cfg=None):
    """Bring the locks in line with the configuration (called by the service)."""
    cfg = cfg or config()
    if cfg['paused_until'] > time.time():
        if locked():
            unlock_area(None)
        return
    cur = locked()
    for aid in all_areas(cfg):
        mode = area_mode(aid, cfg)
        if mode == 'lock':
            lock_area(aid, cfg)
        elif any(a == aid for a in cur.values()):
            unlock_area(aid)
    # areas removed from the configuration
    known = set(all_areas(cfg))
    for a in set(cur.values()) - known:
        unlock_area(a)
