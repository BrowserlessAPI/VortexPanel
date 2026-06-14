import os, json, time
from flask import jsonify

try:
    from panel.routes.websites_core import websites_bp, req, sh, get_webroot, _get_site_path, INTEGRITY_DIR
except ImportError:
    from websites_core import websites_bp, req, sh, get_webroot, _get_site_path, INTEGRITY_DIR


def _scan_hashes(path):
    out = sh(f'find "{path}" -type f -printf "%T@ %s %p\\n" 2>/dev/null | sort -k3', t=60)
    files = {}
    for line in out.splitlines():
        parts = line.split(' ', 2)
        if len(parts) != 3: continue
        mtime, size, fpath = parts
        files[fpath] = {'mtime': mtime, 'size': size}
    return files


def _hash_file(path):
    out = sh(f'sha256sum "{path}" 2>/dev/null', t=15)
    return out.split()[0] if out else ''


@websites_bp.route('/api/websites/<domain>/integrity/status')
def integrity_status(domain):
    if not req(): return jsonify({'ok':False}), 401
    baseline_file = os.path.join(INTEGRITY_DIR, domain+'.json')
    exists = os.path.exists(baseline_file)
    created = ''
    file_count = 0
    if exists:
        try:
            with open(baseline_file) as f: data = json.load(f)
            created = data.get('created','')
            file_count = len(data.get('files',{}))
        except: pass
    return jsonify({'ok':True, 'enabled':exists, 'created':created, 'file_count':file_count})


@websites_bp.route('/api/websites/<domain>/integrity/baseline', methods=['POST'])
def integrity_baseline(domain):
    if not req(): return jsonify({'ok':False}), 401
    path = _get_site_path(domain)
    if not os.path.isdir(path):
        return jsonify({'ok':False,'error':'Site path not found'}),404
    out = sh(f'find "{path}" -type f -exec sha256sum {{}} + 2>/dev/null', t=120)
    files = {}
    for line in out.splitlines():
        parts = line.split('  ', 1)
        if len(parts) != 2: continue
        h, fp = parts
        files[fp] = h
    os.makedirs(INTEGRITY_DIR, exist_ok=True)
    with open(os.path.join(INTEGRITY_DIR, domain+'.json'), 'w') as f:
        json.dump({'path':path, 'created':time.strftime('%Y-%m-%d %H:%M:%S'), 'files':files}, f)
    return jsonify({'ok':True, 'file_count':len(files)})


@websites_bp.route('/api/websites/<domain>/integrity/baseline', methods=['DELETE'])
def integrity_disable(domain):
    if not req(): return jsonify({'ok':False}), 401
    baseline_file = os.path.join(INTEGRITY_DIR, domain+'.json')
    if os.path.exists(baseline_file): os.remove(baseline_file)
    return jsonify({'ok':True})


@websites_bp.route('/api/websites/<domain>/integrity/scan')
def integrity_scan(domain):
    if not req(): return jsonify({'ok':False}), 401
    baseline_file = os.path.join(INTEGRITY_DIR, domain+'.json')
    if not os.path.exists(baseline_file):
        return jsonify({'ok':False,'error':'No baseline found. Create one first.'}),400
    with open(baseline_file) as f: data = json.load(f)
    old_files = data.get('files',{})
    path = data.get('path') or _get_site_path(domain)
    out = sh(f'find "{path}" -type f -exec sha256sum {{}} + 2>/dev/null', t=120)
    new_files = {}
    for line in out.splitlines():
        parts = line.split('  ', 1)
        if len(parts) != 2: continue
        h, fp = parts
        new_files[fp] = h
    added    = [f for f in new_files if f not in old_files]
    removed  = [f for f in old_files if f not in new_files]
    modified = [f for f in new_files if f in old_files and new_files[f] != old_files[f]]
    return jsonify({
        'ok':True,
        'scanned_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'baseline_created': data.get('created',''),
        'added': sorted(added)[:200],
        'removed': sorted(removed)[:200],
        'modified': sorted(modified)[:200],
        'total_files': len(new_files),
        'clean': not (added or removed or modified),
    })

