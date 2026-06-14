from flask import Blueprint, jsonify, request, session, send_file
import os, shutil, mimetypes, base64

files_bp = Blueprint('files', __name__)
def req(): return 'user' in session
ROOT = '/'
def get_webroot():
    import os
    for p in ['/www/wwwroot','/var/www/html','/var/www','/srv/www']:
        if os.path.isdir(p): return p
    os.makedirs('/www/wwwroot', exist_ok=True)
    return '/www/wwwroot'
MAX_EDIT_SIZE = 1024*1024  # 1MB

def safe_path(p):
    p = os.path.normpath('/' + (p or '/'))
    return p

@files_bp.route('/api/files/list')
def list_files():
    if not req(): return jsonify({'ok':False}),401
    path = safe_path(request.args.get('path', get_webroot()))
    if not os.path.isdir(path): return jsonify({'ok':False,'error':'Not a directory'}),400
    items = []
    try:
        for name in sorted(os.listdir(path)):
            fp = os.path.join(path, name)
            st = os.stat(fp)
            items.append({
                'name': name,
                'path': fp,
                'type': 'dir' if os.path.isdir(fp) else 'file',
                'size': st.st_size,
                'mtime': int(st.st_mtime),
                'perms': oct(st.st_mode)[-3:],
            })
    except PermissionError: return jsonify({'ok':False,'error':'Permission denied'}),403
    return jsonify({'ok':True,'path':path,'items':items})

@files_bp.route('/api/files/read')
def read_file():
    if not req(): return jsonify({'ok':False}),401
    path = safe_path(request.args.get('path',''))
    if not os.path.isfile(path): return jsonify({'ok':False,'error':'Not a file'}),404
    if os.path.getsize(path) > MAX_EDIT_SIZE:
        return jsonify({'ok':False,'error':'File too large to edit (max 1MB)'}),400
    try:
        with open(path, 'r', errors='replace') as f: content = f.read()
        return jsonify({'ok':True,'content':content,'path':path})
    except Exception as e: return jsonify({'ok':False,'error':str(e)}),500

@files_bp.route('/api/files/write', methods=['POST'])
def write_file():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    path = safe_path(d.get('path',''))
    content = d.get('content','')
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path,'w') as f: f.write(content)
        return jsonify({'ok':True})
    except Exception as e: return jsonify({'ok':False,'error':str(e)}),500

@files_bp.route('/api/files/delete', methods=['POST'])
def delete_file():
    if not req(): return jsonify({'ok':False}),401
    path = safe_path((request.get_json() or {}).get('path',''))
    try:
        if os.path.isdir(path): shutil.rmtree(path)
        else: os.unlink(path)
        return jsonify({'ok':True})
    except Exception as e: return jsonify({'ok':False,'error':str(e)}),500

@files_bp.route('/api/files/mkdir', methods=['POST'])
def make_dir():
    if not req(): return jsonify({'ok':False}),401
    path = safe_path((request.get_json() or {}).get('path',''))
    os.makedirs(path, exist_ok=True)
    return jsonify({'ok':True})

@files_bp.route('/api/files/rename', methods=['POST'])
def rename_file():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    src = safe_path(d.get('src',''))
    dst = safe_path(d.get('dst',''))
    try:
        shutil.move(src, dst)
        return jsonify({'ok':True})
    except Exception as e: return jsonify({'ok':False,'error':str(e)}),500

@files_bp.route('/api/files/chmod', methods=['POST'])
def chmod_file():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    path = safe_path(d.get('path',''))
    mode = int(d.get('mode','755'), 8)
    os.chmod(path, mode)
    return jsonify({'ok':True})

@files_bp.route('/api/files/upload', methods=['POST'])
def upload_file():
    if not req(): return jsonify({'ok':False}),401
    path = safe_path(request.form.get('path','/tmp'))
    f = request.files.get('file')
    if not f: return jsonify({'ok':False,'error':'No file'}),400
    dest = os.path.join(path, f.filename)
    f.save(dest)
    return jsonify({'ok':True,'path':dest})

import subprocess, fnmatch, time, urllib.request, threading

@files_bp.route('/api/files/copy', methods=['POST'])
def copy_file():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    src = safe_path(d.get('src',''))
    dst = safe_path(d.get('dst',''))
    try:
        if os.path.isdir(src): shutil.copytree(src, dst)
        else: shutil.copy2(src, dst)
        return jsonify({'ok':True})
    except Exception as e: return jsonify({'ok':False,'error':str(e)}),500

@files_bp.route('/api/files/move', methods=['POST'])
def move_file():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    src = safe_path(d.get('src',''))
    dst = safe_path(d.get('dst',''))
    try:
        shutil.move(src, dst)
        return jsonify({'ok':True})
    except Exception as e: return jsonify({'ok':False,'error':str(e)}),500

@files_bp.route('/api/files/compress', methods=['POST'])
def compress_file():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    paths  = [safe_path(p) for p in d.get('paths',[])]
    output = safe_path(d.get('output',''))
    fmt    = d.get('format','zip')
    if not paths or not output: return jsonify({'ok':False,'error':'paths and output required'}),400
    try:
        parent = os.path.dirname(paths[0])
        names  = ' '.join(f'"{os.path.relpath(p, parent)}"' for p in paths)
        if fmt == 'zip':
            r = subprocess.run(f'cd "{parent}" && zip -r "{output}" {names}', shell=True, capture_output=True, text=True)
        else:
            r = subprocess.run(f'cd "{parent}" && tar -czf "{output}" {names}', shell=True, capture_output=True, text=True)
        if r.returncode != 0: return jsonify({'ok':False,'error':r.stderr}),500
        return jsonify({'ok':True,'output':output})
    except Exception as e: return jsonify({'ok':False,'error':str(e)}),500

@files_bp.route('/api/files/extract', methods=['POST'])
def extract_file():
    if not req(): return jsonify({'ok':False}),401
    d   = request.get_json() or {}
    src = safe_path(d.get('path',''))
    dst = safe_path(d.get('dest', os.path.dirname(src)))
    os.makedirs(dst, exist_ok=True)
    try:
        if src.endswith('.zip'):
            r = subprocess.run(f'unzip -o "{src}" -d "{dst}"', shell=True, capture_output=True, text=True)
            # Fallback for AES-encrypted (compression method 99) or other zips unzip can't handle
            if r.returncode != 0 or 'unsupported compression method' in (r.stderr + r.stdout).lower():
                r7 = subprocess.run(f'7z x "{src}" -o"{dst}" -y', shell=True, capture_output=True, text=True)
                if r7.returncode == 0:
                    return jsonify({'ok': True, 'error': ''})
                err = (r.stderr or r.stdout)[:300] + ' | 7z: ' + (r7.stderr or r7.stdout)[:300]
                return jsonify({'ok': False, 'error': err})
        elif src.endswith(('.tar.gz', '.tgz')):
            r = subprocess.run(f'tar -xzf "{src}" -C "{dst}"', shell=True, capture_output=True, text=True)
        elif src.endswith('.tar.bz2'):
            r = subprocess.run(f'tar -xjf "{src}" -C "{dst}"', shell=True, capture_output=True, text=True)
        elif src.endswith('.tar.xz'):
            r = subprocess.run(f'tar -xJf "{src}" -C "{dst}"', shell=True, capture_output=True, text=True)
        elif src.endswith('.tar'):
            r = subprocess.run(f'tar -xf "{src}" -C "{dst}"', shell=True, capture_output=True, text=True)
        elif src.endswith(('.7z', '.rar')):
            r = subprocess.run(f'7z x "{src}" -o"{dst}" -y', shell=True, capture_output=True, text=True)
        else:
            r = subprocess.run(f'tar -xzf "{src}" -C "{dst}"', shell=True, capture_output=True, text=True)
        return jsonify({'ok': r.returncode==0, 'error': r.stderr[:300] if r.returncode!=0 else ''})
    except Exception as e: return jsonify({'ok':False,'error':str(e)}),500

@files_bp.route('/api/files/search')
def search_files():
    if not req(): return jsonify({'ok':False}),401
    path    = safe_path(request.args.get('path', get_webroot()))
    keyword = request.args.get('q','').strip()
    in_file = request.args.get('content','false') == 'true'
    if not keyword: return jsonify({'ok':True,'results':[]})
    results = []
    try:
        if in_file:
            out = subprocess.run(f'grep -r -l --include="*" -m 1 "{keyword}" "{path}" 2>/dev/null | head -50',
                                  shell=True, capture_output=True, text=True, timeout=15).stdout
            for line in out.strip().split('\n'):
                if line.strip(): results.append({'path':line.strip(),'type':'file','name':os.path.basename(line.strip())})
        else:
            out = subprocess.run(f'find "{path}" -maxdepth 6 -iname "*{keyword}*" 2>/dev/null | head -100',
                                  shell=True, capture_output=True, text=True, timeout=10).stdout
            for line in out.strip().split('\n'):
                if line.strip():
                    fp = line.strip()
                    results.append({'path':fp,'type':'dir' if os.path.isdir(fp) else 'file','name':os.path.basename(fp)})
    except Exception as e: pass
    return jsonify({'ok':True,'results':results})

@files_bp.route('/api/files/size')
def calc_size():
    if not req(): return jsonify({'ok':False}),401
    path = safe_path(request.args.get('path',''))
    try:
        if os.path.isfile(path): return jsonify({'ok':True,'size':os.path.getsize(path)})
        out = subprocess.run(f'du -sb "{path}" 2>/dev/null | cut -f1', shell=True, capture_output=True, text=True).stdout.strip()
        return jsonify({'ok':True,'size':int(out) if out else 0})
    except: return jsonify({'ok':True,'size':0})

@files_bp.route('/api/files/remote-download', methods=['POST'])
def remote_download():
    if not req(): return jsonify({'ok':False}),401
    d    = request.get_json() or {}
    url  = d.get('url','').strip()
    dest = safe_path(d.get('dest', get_webroot()))
    if not url: return jsonify({'ok':False,'error':'URL required'}),400
    fname = url.split('/')[-1].split('?')[0] or 'download'
    fpath = os.path.join(dest, fname)
    def do_dl():
        try:
            urllib.request.urlretrieve(url, fpath)
        except Exception as e:
            pass
    threading.Thread(target=do_dl, daemon=True).start()
    return jsonify({'ok':True,'filename':fname,'path':fpath,'message':'Download started in background'})

@files_bp.route('/api/files/properties')
def file_properties():
    if not req(): return jsonify({'ok':False}),401
    path = safe_path(request.args.get('path',''))
    if not os.path.exists(path): return jsonify({'ok':False,'error':'Not found'}),404
    st = os.stat(path)
    import pwd, grp, time as t
    try: owner = pwd.getpwuid(st.st_uid).pw_name
    except: owner = str(st.st_uid)
    try: group = grp.getgrgid(st.st_gid).gr_name
    except: group = str(st.st_gid)
    size = 0
    if os.path.isdir(path):
        out = subprocess.run(f'du -sb "{path}" 2>/dev/null | cut -f1', shell=True, capture_output=True, text=True).stdout.strip()
        size = int(out) if out.isdigit() else 0
    else:
        size = st.st_size
    return jsonify({'ok':True,'props':{
        'path':path,'name':os.path.basename(path),
        'type':'directory' if os.path.isdir(path) else 'file',
        'size':size,'perms':oct(st.st_mode)[-3:],
        'owner':owner,'group':group,
        'mtime':t.strftime('%Y-%m-%d %H:%M:%S', t.localtime(st.st_mtime)),
        'atime':t.strftime('%Y-%m-%d %H:%M:%S', t.localtime(st.st_atime)),
    }})

@files_bp.route('/api/files/lint', methods=['POST'])
def lint_file():
    """Basic syntax check for PHP, Python, JS"""
    if not req(): return jsonify({'ok':False}),401
    d    = request.get_json() or {}
    path = safe_path(d.get('path',''))
    ext  = os.path.splitext(path)[1].lower()
    errors = []
    try:
        if ext == '.php':
            r = subprocess.run(f'php -l "{path}" 2>&1', shell=True, capture_output=True, text=True, timeout=10)
            if r.returncode != 0:
                for line in r.stdout.split('\n'):
                    if 'error' in line.lower() or 'Parse' in line:
                        errors.append(line.strip())
        elif ext == '.py':
            r = subprocess.run(f'python3 -m py_compile "{path}" 2>&1', shell=True, capture_output=True, text=True, timeout=10)
            if r.returncode != 0:
                errors.append(r.stderr.strip())
        elif ext in ('.json',):
            r = subprocess.run(f'python3 -c "import json,sys; json.load(open(sys.argv[1]))" "{path}" 2>&1', shell=True, capture_output=True, text=True)
            if r.returncode != 0: errors.append(r.stdout.strip())
    except Exception as e:
        errors.append(str(e))
    return jsonify({'ok':True,'errors':errors,'clean':len(errors)==0})

@files_bp.route('/api/files/scan', methods=['POST'])
def scan_file():
    from flask import session as _session
    if 'user' not in _session: return jsonify({'ok':False}), 401
    import subprocess, json as _json
    d = request.get_json() or {}
    path = d.get('path','').strip()
    if not path or not os.path.exists(path):
        return jsonify({'ok':False,'error':'Path not found'})
    
    # Use clamdscan if socket available, else clamscan
    socket = '/var/run/clamav/clamd.sock'
    if os.path.exists(socket):
        cmd = f'clamdscan --config-file=/usr/local/etc/clamav/clamd.conf --no-summary "{path}" 2>&1'
    else:
        cmd = f'clamscan --database=/var/lib/clamav --recursive "{path}" 2>&1'
    
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        output = r.stdout + r.stderr
        # Parse results
        infected = []
        for line in output.split('\n'):
            if 'FOUND' in line:
                parts = line.rsplit(':', 1)
                if len(parts) == 2:
                    infected.append({'file': parts[0].strip(), 'virus': parts[1].replace('FOUND','').strip()})
        clean = r.returncode == 0
        return jsonify({'ok':True, 'clean':clean, 'infected':infected, 'output':output, 'path':path})
    except subprocess.TimeoutExpired:
        return jsonify({'ok':False,'error':'Scan timed out (5 min limit)'})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)})
