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
