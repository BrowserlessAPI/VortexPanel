"""Disk usage analyzer: which folders and files take the space, with drill-down
and delete.

A scan runs `du -x` (one filesystem, directories only, NUL separated so any
file name is safe) plus a search for the largest files, in a background
thread. The result is cached in data/diskscan/, so browsing the tree is
instant; deleting from the tree subtracts the freed space from every parent.
"""
from flask import Blueprint, jsonify, request
import os, re, json, time, shutil, hashlib, threading, subprocess, uuid

disk_bp = Blueprint('diskusage', __name__)

CACHE_DIR = '/opt/vortexpanel/data/diskscan'
KEEP_MIN = 1024 * 1024          # folders smaller than 1 MiB are summed, not listed
LARGEST_MIN = 50 * 1024 * 1024  # "largest files" threshold
_FS_SKIP = {'tmpfs', 'devtmpfs', 'squashfs', 'overlay', 'proc', 'sysfs', 'cgroup', 'cgroup2', 'devpts',
            'mqueue', 'debugfs', 'tracefs', 'securityfs', 'pstore', 'bpf', 'autofs', 'efivarfs', 'fusectl',
            'configfs', 'hugetlbfs', 'binfmt_misc', 'nsfs', 'ramfs', 'rpc_pipefs', 'fuse.lxcfs'}

# Deleting anything inside these trees from the analyzer is refused: they hold
# the operating system, package databases and live database files.
_NO_DELETE_TREES = ('/usr', '/bin', '/sbin', '/lib', '/lib32', '/lib64', '/libx32', '/boot', '/etc',
                    '/proc', '/sys', '/dev', '/run', '/snap', '/var/lib/dpkg', '/var/lib/rpm',
                    '/var/lib/apt', '/var/lib/dnf', '/var/lib/mysql', '/var/lib/postgresql', '/var/lib/pgsql',
                    '/var/lib/mongodb', '/var/lib/docker', '/var/lib/containerd', '/var/lib/systemd')


def req():
    from panel.routes.auth import check_ip_and_session
    return check_ip_and_session()


def _norm(p):
    p = os.path.normpath('/' + str(p or '/').lstrip('/'))
    return p


def deletable(path):
    """(ok, reason) for deleting `path` from the analyzer."""
    from panel.routes.files import _is_protected
    p = _norm(path)
    if p.count('/') < 2 or p == '/':
        return False, 'Top-level folders cannot be deleted here'
    if _is_protected(p, follow=not os.path.islink(p)):
        return False, f'{p} is a protected system path'
    real = os.path.realpath(p) if not os.path.islink(p) else p
    for t in _NO_DELETE_TREES:
        if real == t or real.startswith(t + '/') or p == t or p.startswith(t + '/'):
            return False, f'Files under {t} belong to the system or a database server and are not deleted from here'
    if (p.startswith('/opt/vortexpanel/') or real.startswith('/opt/vortexpanel/')) and \
            not (p.startswith('/opt/vortexpanel/backups/') or p.startswith('/opt/vortexpanel/update_backups/')):
        return False, 'Panel files cannot be deleted here (backups can)'
    return True, ''


def _cache_path(root):
    return os.path.join(CACHE_DIR, hashlib.sha1(root.encode()).hexdigest()[:16] + '.json')


def _load(root):
    try:
        with open(_cache_path(root)) as f:
            return json.load(f)
    except Exception:
        return None


def _save(root, data):
    os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
    tmp = _cache_path(root) + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f)
    os.replace(tmp, _cache_path(root))


def _job_save(job_id, state):
    from panel.routes.job_state import save_job
    save_job('disk_' + job_id, state)


def _job_load(job_id):
    from panel.routes.job_state import load_job
    return load_job('disk_' + job_id)


def mounts():
    out = []
    seen = set()
    try:
        with open('/proc/mounts') as f:
            lines = f.read().splitlines()
    except OSError:
        lines = []
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mp, fs = parts[0], parts[1].replace('\\040', ' '), parts[2]
        if fs in _FS_SKIP or mp.startswith(('/proc', '/sys', '/dev', '/run', '/snap')):
            continue
        try:
            st = os.statvfs(mp)
        except OSError:
            continue
        key = (st.f_blocks, st.f_bfree, dev)
        if key in seen or st.f_blocks == 0:
            continue
        seen.add(key)
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = (st.f_blocks - st.f_bfree) * st.f_frsize
        out.append({'mount': mp, 'device': dev, 'fs': fs, 'total': total, 'used': used, 'free': free,
                    'percent': round(used * 100 / total, 1) if total else 0,
                    'inodes_percent': round((st.f_files - st.f_ffree) * 100 / st.f_files, 1) if st.f_files else 0})
    out.sort(key=lambda m: m['mount'])
    return out


def _scan(job_id, root):
    state = {'done': False, 'success': False, 'root': root, 'started': int(time.time()), 'phase': 'folders',
             'error': ''}
    _job_save(job_id, state)
    cmd = ['du', '-x', '-B1', '-0', root]
    if shutil.which('ionice'):
        cmd = ['ionice', '-c3'] + cmd
    if shutil.which('nice'):
        cmd = ['nice', '-n', '10'] + cmd
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    dirs = {}
    buf = b''
    count = 0
    while True:
        chunk = p.stdout.read(1 << 20)
        if not chunk:
            break
        buf += chunk
        *recs, buf = buf.split(b'\0')
        for rec in recs:
            size, _, path = rec.partition(b'\t')
            try:
                sz = int(size)
            except ValueError:
                continue
            count += 1
            name = path.decode('utf-8', 'surrogateescape')
            if sz >= KEEP_MIN or name == root:
                dirs[name] = sz
        if count % 20000 < 50:
            state['folders'] = count
            _job_save(job_id, state)
    err = p.stderr.read().decode('utf-8', 'replace')
    p.wait()
    # du exits 1 when some folders could not be read; the rest is still right
    if p.returncode not in (0, 1) or root not in dirs and not os.path.isdir(root):
        state.update({'done': True, 'error': (err.strip().splitlines() or ['du failed'])[-1][:300]})
        _job_save(job_id, state)
        return
    total = dirs.get(root, 0)
    state.update({'phase': 'files', 'folders': count})
    _job_save(job_id, state)
    largest = []
    try:
        r = subprocess.run(['find', root, '-xdev', '-type', 'f', '-size', f'+{LARGEST_MIN // 1024}k',
                            '-printf', r'%s\t%T@\t%p\0'], capture_output=True, timeout=3600)
        for rec in r.stdout.split(b'\0'):
            parts = rec.split(b'\t', 2)
            if len(parts) == 3:
                try:
                    largest.append({'path': parts[2].decode('utf-8', 'surrogateescape'), 'size': int(parts[0]),
                                    'mtime': int(float(parts[1]))})
                except ValueError:
                    pass
    except Exception:
        pass
    largest.sort(key=lambda e: e['size'], reverse=True)
    unreadable = len([l for l in err.splitlines() if 'Permission denied' in l or 'cannot' in l])
    _save(root, {'root': root, 'scanned': int(time.time()), 'total': total, 'folders': count, 'dirs': dirs,
                 'largest': largest[:100], 'unreadable': unreadable,
                 'seconds': int(time.time()) - state['started']})
    state.update({'done': True, 'success': True, 'total': total})
    _job_save(job_id, state)


_running = {}


@disk_bp.route('/api/disk/mounts')
def disk_mounts():
    if not req(): return jsonify({'ok': False}), 401
    out = mounts()
    for m in out:
        c = _load(m['mount'])
        m['scanned'] = c['scanned'] if c else None
    return jsonify({'ok': True, 'mounts': out})


@disk_bp.route('/api/disk/scan', methods=['POST'])
def disk_scan():
    if not req(): return jsonify({'ok': False}), 401
    root = _norm((request.get_json() or {}).get('path', '/'))
    if not os.path.isdir(root) or os.path.islink(root):
        return jsonify({'ok': False, 'error': 'Folder not found'}), 404
    if root.startswith(('/proc', '/sys', '/dev', '/run')):
        return jsonify({'ok': False, 'error': 'That folder is not on a disk'}), 400
    jid = _running.get(root)
    if jid:
        j = _job_load(jid)
        if j and not j.get('done'):
            return jsonify({'ok': True, 'job_id': jid, 'already': True})
    jid = uuid.uuid4().hex[:12]
    _running[root] = jid
    threading.Thread(target=_scan, args=(jid, root), daemon=True).start()
    return jsonify({'ok': True, 'job_id': jid})


@disk_bp.route('/api/disk/scan/<job_id>')
def disk_scan_status(job_id):
    if not req(): return jsonify({'ok': False}), 401
    if not re.fullmatch(r'[0-9a-f]{12}', job_id):
        return jsonify({'ok': False, 'error': 'Invalid job'}), 400
    j = _job_load(job_id)
    if not j:
        return jsonify({'ok': False, 'error': 'Job not found'}), 404
    return jsonify(dict(j, ok=True))


@disk_bp.route('/api/disk/tree')
def disk_tree():
    if not req(): return jsonify({'ok': False}), 401
    root = _norm(request.args.get('root', '/'))
    path = _norm(request.args.get('path', root))
    data = _load(root)
    if not data:
        return jsonify({'ok': True, 'scanned': None})
    if not (path == root or path.startswith(root.rstrip('/') + '/')):
        return jsonify({'ok': False, 'error': 'Path is outside the scanned folder'}), 400
    dirs = data['dirs']
    size = dirs.get(path, 0)
    prefix = path.rstrip('/') + '/'
    children = []
    for p, sz in dirs.items():
        if p != path and p.startswith(prefix) and '/' not in p[len(prefix):]:
            ok, why = deletable(p)
            children.append({'name': p[len(prefix):], 'path': p, 'size': sz, 'dir': True,
                             'deletable': ok, 'why': why})
    children.sort(key=lambda c: c['size'], reverse=True)
    listed = sum(c['size'] for c in children)
    # Large files sitting directly in this folder
    files = []
    for f in data.get('largest', []):
        if os.path.dirname(f['path']) == path.rstrip('/') or (path == '/' and os.path.dirname(f['path']) == '/'):
            ok, why = deletable(f['path'])
            files.append({'name': os.path.basename(f['path']), 'path': f['path'], 'size': f['size'], 'dir': False,
                          'deletable': ok, 'why': why})
    rest = max(0, size - listed - sum(f['size'] for f in files))
    crumbs = []
    cur = path
    while True:
        crumbs.append({'name': os.path.basename(cur) or cur, 'path': cur})
        if cur == root or cur == '/':
            break
        cur = os.path.dirname(cur)
    crumbs.reverse()
    return jsonify({'ok': True, 'root': root, 'path': path, 'size': size, 'total': data['total'],
                    'scanned': data['scanned'], 'seconds': data.get('seconds'), 'unreadable': data.get('unreadable', 0),
                    'items': children + sorted(files, key=lambda f: f['size'], reverse=True), 'other': rest,
                    'crumbs': crumbs})


@disk_bp.route('/api/disk/largest')
def disk_largest():
    if not req(): return jsonify({'ok': False}), 401
    root = _norm(request.args.get('root', '/'))
    data = _load(root)
    if not data:
        return jsonify({'ok': True, 'files': [], 'scanned': None})
    out = []
    for f in data.get('largest', []):
        if not os.path.exists(f['path']):
            continue
        ok, why = deletable(f['path'])
        out.append(dict(f, deletable=ok, why=why))
    return jsonify({'ok': True, 'files': out, 'scanned': data['scanned']})


@disk_bp.route('/api/disk/delete', methods=['POST'])
def disk_delete():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    root = _norm(d.get('root', '/'))
    path = _norm(d.get('path', ''))
    ok, why = deletable(path)
    if not ok:
        return jsonify({'ok': False, 'error': why}), 403
    if not os.path.lexists(path):
        return jsonify({'ok': False, 'error': 'Not found (already deleted?)'}), 404
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            r = subprocess.run(['du', '-sxB1', path], capture_output=True, text=True, timeout=600)
            freed = int((r.stdout.split() or ['0'])[0])
            shutil.rmtree(path)
        else:
            freed = os.lstat(path).st_blocks * 512
            os.unlink(path)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
    # Keep the cached tree right without a rescan.
    data = _load(root)
    if data:
        dirs = data['dirs']
        for p in [p for p in dirs if p == path or p.startswith(path.rstrip('/') + '/')]:
            dirs.pop(p, None)
        cur = os.path.dirname(path)
        while True:
            if cur in dirs:
                dirs[cur] = max(0, dirs[cur] - freed)
            if cur == root or cur == '/' or not cur:
                break
            cur = os.path.dirname(cur)
        data['largest'] = [f for f in data.get('largest', [])
                           if f['path'] != path and not f['path'].startswith(path.rstrip('/') + '/')]
        data['total'] = dirs.get(root, data['total'])
        _save(root, data)
    try:
        from panel.routes.auth import audit_event
        audit_event('disk_delete', path)
    except Exception:
        pass
    return jsonify({'ok': True, 'freed': freed})
