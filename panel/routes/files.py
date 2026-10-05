from flask import Blueprint, jsonify, request, session
import os, shutil, stat as _stat
import subprocess, urllib.request, urllib.parse, threading, zipfile, gzip

files_bp = Blueprint('files', __name__)
def req(): return 'user' in session
ROOT = '/'
def get_webroot():
    """The panel's web root (/www/wwwroot) -- one implementation for the
    whole panel (websites_core -> os_utils.get_webroot())."""
    try:
        from panel.routes.websites_core import get_webroot as _gw
    except ImportError:
        from websites_core import get_webroot as _gw
    return _gw()
MAX_EDIT_SIZE = 1024*1024  # 1MB

def safe_path(p):
    p = os.path.normpath('/' + (p or '/'))
    if p.startswith('//'): p = '/' + p.lstrip('/')
    return p

# The file manager is deliberately server-wide (root), but a single misclick
# must not be able to delete/move/chmod the OS itself.
_PROTECTED = {'/', '/bin', '/boot', '/dev', '/etc', '/home', '/lib', '/lib32', '/lib64', '/libx32',
              '/media', '/mnt', '/opt', '/proc', '/root', '/run', '/sbin', '/srv', '/sys', '/tmp',
              '/usr', '/var', '/var/lib', '/var/log', '/var/www', '/www', '/www/wwwroot',
              '/opt/vortexpanel', '/etc/nginx', '/etc/ssh', '/etc/systemd', '/usr/local',
              '/var/lib/mysql', '/var/lib/postgresql', '/var/lib/pgsql', '/var/lib/mongodb'}

def _is_protected(path, follow=True):
    """True for the protected paths themselves (resolved through symlinks when
    follow=True), not for things inside them. Deleting/moving a symlink only
    touches the link, so those callers pass follow=False for links."""
    cands = {path.rstrip('/') or '/'}
    if follow:
        try: cands.add(os.path.realpath(path))
        except OSError: pass
    return any(c in _PROTECTED for c in cands)

def _protected_resp(path):
    return jsonify({'ok':False,'error':f'{path} is a protected system path'}), 403

def _err(e, code=500):
    return jsonify({'ok':False,'error':str(e)}), code

@files_bp.route('/api/files/list')
def list_files():
    if not req(): return jsonify({'ok':False}),401
    path = safe_path(request.args.get('path', get_webroot()))
    if not os.path.isdir(path): return jsonify({'ok':False,'error':'Not a directory'}),400
    items = []
    try:
        names = sorted(os.listdir(path))
    except PermissionError: return jsonify({'ok':False,'error':'Permission denied'}),403
    except OSError as e: return _err(e)
    for name in names:
        fp = os.path.join(path, name)
        # A broken symlink (or a file deleted mid-listing) used to make
        # os.stat raise and turn the whole directory listing into a 500.
        try:
            st = os.stat(fp)
        except OSError:
            try: st = os.lstat(fp)
            except OSError: continue
        items.append({
            'name': name,
            'path': fp,
            'type': 'dir' if _stat.S_ISDIR(st.st_mode) else 'file',
            'size': st.st_size,
            'mtime': int(st.st_mtime),
            'perms': oct(st.st_mode)[-3:],
            'link': os.path.islink(fp),
        })
    return jsonify({'ok':True,'path':path,'items':items})

def _looks_binary(path):
    try:
        with open(path, 'rb') as f: chunk = f.read(8192)
    except OSError:
        return False
    return b'\x00' in chunk

@files_bp.route('/api/files/read')
def read_file():
    if not req(): return jsonify({'ok':False}),401
    path = safe_path(request.args.get('path',''))
    if not os.path.isfile(path): return jsonify({'ok':False,'error':'Not a file'}),404
    if os.path.getsize(path) > MAX_EDIT_SIZE:
        return jsonify({'ok':False,'error':'File too large to edit (max 1MB)'}),400
    # Reading a binary file with errors='replace' and saving it back from the
    # editor silently corrupts it - refuse instead.
    if _looks_binary(path):
        return jsonify({'ok':False,'error':'This looks like a binary file and cannot be edited'}),400
    try:
        with open(path, 'r', encoding='utf-8', errors='replace', newline='') as f: content = f.read()
        return jsonify({'ok':True,'content':content,'path':path})
    except Exception as e: return _err(e)

@files_bp.route('/api/files/write', methods=['POST'])
def write_file():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    path = safe_path(d.get('path',''))
    content = d.get('content','')
    if not isinstance(content, str): return jsonify({'ok':False,'error':'Invalid content'}),400
    if os.path.isdir(path): return jsonify({'ok':False,'error':'Path is a directory'}),400
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path,'w', encoding='utf-8', newline='') as f: f.write(content)
        return jsonify({'ok':True})
    except Exception as e: return _err(e)

@files_bp.route('/api/files/delete', methods=['POST'])
def delete_file():
    if not req(): return jsonify({'ok':False}),401
    path = safe_path((request.get_json() or {}).get('path',''))
    if _is_protected(path, follow=not os.path.islink(path)): return _protected_resp(path)
    try:
        # A symlink to a directory: remove the link, never the target tree
        # (rmtree refuses symlinks and the delete used to fail outright).
        if os.path.islink(path) or not os.path.isdir(path): os.unlink(path)
        else: shutil.rmtree(path)
        return jsonify({'ok':True})
    except FileNotFoundError: return jsonify({'ok':False,'error':'Not found'}),404
    except Exception as e: return _err(e)

@files_bp.route('/api/files/mkdir', methods=['POST'])
def make_dir():
    if not req(): return jsonify({'ok':False}),401
    path = safe_path((request.get_json() or {}).get('path',''))
    try:
        os.makedirs(path, exist_ok=True)
    except Exception as e: return _err(e)
    return jsonify({'ok':True})

def _move(src, dst):
    if _is_protected(src, follow=not os.path.islink(src)): return _protected_resp(src)
    if not os.path.lexists(src): return jsonify({'ok':False,'error':'Source not found'}),404
    try:
        shutil.move(src, dst)
        return jsonify({'ok':True})
    except Exception as e: return _err(e)

@files_bp.route('/api/files/rename', methods=['POST'])
def rename_file():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    return _move(safe_path(d.get('src','')), safe_path(d.get('dst','')))

@files_bp.route('/api/files/chmod', methods=['POST'])
def chmod_file():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    path = safe_path(d.get('path',''))
    raw = str(d.get('mode','755')).strip()
    try:
        mode = int(raw, 8)
        if not 0 <= mode <= 0o7777: raise ValueError
    except ValueError:
        return jsonify({'ok':False,'error':'Invalid mode - use octal like 755 or 0644'}),400
    if _is_protected(path): return _protected_resp(path)
    try:
        os.chmod(path, mode)
    except Exception as e: return _err(e)
    return jsonify({'ok':True})

@files_bp.route('/api/files/upload', methods=['POST'])
def upload_file():
    if not req(): return jsonify({'ok':False}),401
    path = safe_path(request.form.get('path','/tmp'))
    f = request.files.get('file')
    if not f: return jsonify({'ok':False,'error':'No file'}),400
    # Client-supplied filename: keep only the last component (no '../x').
    name = os.path.basename((f.filename or '').replace('\\', '/'))
    if not name or name in ('.', '..'): return jsonify({'ok':False,'error':'Invalid file name'}),400
    if not os.path.isdir(path): return jsonify({'ok':False,'error':'Target directory does not exist'}),400
    dest = os.path.join(path, name)
    try:
        f.save(dest)
    except Exception as e: return _err(e)
    return jsonify({'ok':True,'path':dest})

@files_bp.route('/api/files/copy', methods=['POST'])
def copy_file():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    src = safe_path(d.get('src',''))
    dst = safe_path(d.get('dst',''))
    if not os.path.lexists(src): return jsonify({'ok':False,'error':'Source not found'}),404
    try:
        if os.path.isdir(src) and not os.path.islink(src):
            rs, rd = os.path.realpath(src), os.path.realpath(dst)
            if rd == rs or rd.startswith(rs.rstrip('/') + '/'):
                return jsonify({'ok':False,'error':'Cannot copy a directory into itself'}),400
            # symlinks=True copies links as links (following them could pull
            # in an entire unrelated tree, e.g. a link to /).
            shutil.copytree(src, dst, symlinks=True)
        else: shutil.copy2(src, dst, follow_symlinks=False)
        return jsonify({'ok':True})
    except Exception as e: return _err(e)

@files_bp.route('/api/files/move', methods=['POST'])
def move_file():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    return _move(safe_path(d.get('src','')), safe_path(d.get('dst','')))

@files_bp.route('/api/files/compress', methods=['POST'])
def compress_file():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    paths  = [safe_path(p) for p in (d.get('paths') or [])]
    output = safe_path(d.get('output',''))
    fmt    = d.get('format','zip')
    if not paths or not d.get('output'): return jsonify({'ok':False,'error':'paths and output required'}),400
    parent = os.path.dirname(paths[0])
    if any(os.path.dirname(p) != parent for p in paths):
        return jsonify({'ok':False,'error':'All items must be in the same directory'}),400
    names  = [os.path.basename(p) for p in paths]
    try:
        if fmt == 'zip':
            if shutil.which('zip'):
                r = subprocess.run(['zip', '-r', '-y', output, '--'] + names, cwd=parent,
                                   capture_output=True, text=True, timeout=3600)
                if r.returncode != 0: return jsonify({'ok':False,'error':(r.stderr or r.stdout)[:500]}),500
            else:
                # zip is not installed on minimal images - use Python's zipfile
                with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
                    for n in names:
                        full = os.path.join(parent, n)
                        if os.path.isdir(full) and not os.path.islink(full):
                            for root, dirs, files in os.walk(full):
                                for fn in files:
                                    fpath = os.path.join(root, fn)
                                    if os.path.isfile(fpath):
                                        zf.write(fpath, os.path.relpath(fpath, parent))
                        elif os.path.isfile(full):
                            zf.write(full, n)
        else:
            r = subprocess.run(['tar', '-czf', output, '--'] + names, cwd=parent,
                               capture_output=True, text=True, timeout=3600)
            if r.returncode != 0: return jsonify({'ok':False,'error':r.stderr[:500]}),500
        return jsonify({'ok':True,'output':output})
    except subprocess.TimeoutExpired: return jsonify({'ok':False,'error':'Compression timed out'}),500
    except Exception as e: return _err(e)

def _zip_extract_py(src, dst):
    real = os.path.realpath(dst)
    with zipfile.ZipFile(src) as zf:
        for m in zf.infolist():
            target = os.path.realpath(os.path.join(real, m.filename))
            if target != real and not target.startswith(real.rstrip('/') + '/'):
                raise ValueError(f'Archive contains an unsafe path: {m.filename}')
        zf.extractall(real)

def _run(cmd, timeout=3600):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stderr or r.stdout or '')
    except FileNotFoundError:
        return 127, f'{cmd[0]} is not installed'
    except subprocess.TimeoutExpired:
        return 124, 'Timed out'

@files_bp.route('/api/files/extract', methods=['POST'])
def extract_file():
    if not req(): return jsonify({'ok':False}),401
    d   = request.get_json() or {}
    src = safe_path(d.get('path',''))
    dst = safe_path(d.get('dest') or os.path.dirname(src))
    if not os.path.isfile(src): return jsonify({'ok':False,'error':'Archive not found'}),404
    try:
        os.makedirs(dst, exist_ok=True)
        low = src.lower()
        if low.endswith('.zip'):
            rc, out = _run(['unzip', '-o', src, '-d', dst])
            if rc == 0 and 'unsupported compression method' not in out.lower():
                return jsonify({'ok': True, 'error': ''})
            errs = ['unzip: ' + out[:300]]
            # unzip missing (minimal images) or failed: Python zipfile, then 7z
            # (AES-encrypted / method 99 zips).
            try:
                _zip_extract_py(src, dst)
                return jsonify({'ok': True, 'error': ''})
            except Exception as e:
                errs.append('zipfile: ' + str(e)[:200])
            rc7, out7 = _run(['7z', 'x', src, f'-o{dst}', '-y'])
            if rc7 == 0:
                return jsonify({'ok': True, 'error': ''})
            errs.append('7z: ' + out7[:300])
            return jsonify({'ok': False, 'error': ' | '.join(errs)})
        elif low.endswith(('.tar.gz', '.tgz')):
            rc, out = _run(['tar', '-xzf', src, '-C', dst])
        elif low.endswith(('.tar.bz2', '.tbz2')):
            rc, out = _run(['tar', '-xjf', src, '-C', dst])
        elif low.endswith(('.tar.xz', '.txz')):
            rc, out = _run(['tar', '-xJf', src, '-C', dst])
        elif low.endswith('.tar'):
            rc, out = _run(['tar', '-xf', src, '-C', dst])
        elif low.endswith('.gz'):
            # plain gzip (e.g. dump.sql.gz): decompress next to the target
            outp = os.path.join(dst, os.path.basename(src)[:-3])
            with gzip.open(src, 'rb') as fi, open(outp, 'wb') as fo:
                shutil.copyfileobj(fi, fo, 1024 * 1024)
            rc, out = 0, ''
        elif low.endswith(('.7z', '.rar')):
            rc, out = _run(['7z', 'x', src, f'-o{dst}', '-y'])
        else:
            # let tar auto-detect the compression
            rc, out = _run(['tar', '-xf', src, '-C', dst])
        return jsonify({'ok': rc==0, 'error': out[:300] if rc!=0 else ''})
    except Exception as e: return _err(e)

@files_bp.route('/api/files/search')
def search_files():
    if not req(): return jsonify({'ok':False}),401
    path    = safe_path(request.args.get('path', get_webroot()))
    keyword = request.args.get('q','').strip()
    in_file = request.args.get('content','false') == 'true'
    if not keyword: return jsonify({'ok':True,'results':[]})
    if path in ('/', '/proc', '/sys', '/dev'):
        return jsonify({'ok':False,'error':'Search a more specific directory than '+path,'results':[]})
    results = []
    # capture_output=True together with stderr=DEVNULL raised ValueError on
    # every call, which the old bare except turned into "no files found".
    try:
        if in_file:
            out = subprocess.run(['grep', '-r', '-l', '-I', '-F', '-m', '1', '-e', keyword, '--', path],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                 errors='replace', timeout=30).stdout
            for line in out.strip().split('\n')[:50]:
                if line.strip(): results.append({'path':line.strip(),'type':'file','name':os.path.basename(line.strip())})
        else:
            out = subprocess.run(['find', path, '-maxdepth', '6', '-iname', '*' + keyword + '*'],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                 errors='replace', timeout=30).stdout
            for line in out.strip().split('\n')[:100]:
                if line.strip():
                    fp = line.strip()
                    results.append({'path':fp,'type':'dir' if os.path.isdir(fp) else 'file','name':os.path.basename(fp)})
    except subprocess.TimeoutExpired:
        return jsonify({'ok':False,'error':'Search timed out - narrow the directory','results':results})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e),'results':results})
    return jsonify({'ok':True,'results':results})

def _du(path):
    try:
        out = subprocess.run(['du', '-sb', path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, timeout=120).stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        return None
    return int(out.split()[0]) if out and out.split()[0].isdigit() else None

@files_bp.route('/api/files/size')
def calc_size():
    if not req(): return jsonify({'ok':False}),401
    path = safe_path(request.args.get('path',''))
    if os.path.isfile(path): return jsonify({'ok':True,'size':os.path.getsize(path)})
    if not os.path.isdir(path): return jsonify({'ok':False,'error':'Not found'}),404
    size = _du(path)
    if size is None: return jsonify({'ok':False,'error':'Could not calculate size'})
    return jsonify({'ok':True,'size':size})

@files_bp.route('/api/files/remote-download', methods=['POST'])
def remote_download():
    if not req(): return jsonify({'ok':False}),401
    d    = request.get_json() or {}
    url  = d.get('url','').strip()
    dest = safe_path(d.get('dest') or get_webroot())
    if not url: return jsonify({'ok':False,'error':'URL required'}),400
    if urllib.parse.urlparse(url).scheme not in ('http', 'https'):
        return jsonify({'ok':False,'error':'Only http:// and https:// URLs are supported'}),400
    if not os.path.isdir(dest): return jsonify({'ok':False,'error':'Destination directory does not exist'}),400
    fname = os.path.basename(urllib.parse.unquote(urllib.parse.urlparse(url).path)) or 'download'
    if fname in ('.', '..'): fname = 'download'
    fpath = os.path.join(dest, fname)
    def do_dl():
        # Bounded socket timeout (urlretrieve had none and could hang forever)
        # and a .part file so a failed download never leaves a truncated file
        # under the real name.
        part = fpath + '.part'
        try:
            rq = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (VortexPanel)'})
            with urllib.request.urlopen(rq, timeout=60) as resp, open(part, 'wb') as out:
                shutil.copyfileobj(resp, out, 1024 * 1024)
            os.replace(part, fpath)
        except Exception:
            try: os.unlink(part)
            except OSError: pass
    threading.Thread(target=do_dl, daemon=True).start()
    return jsonify({'ok':True,'filename':fname,'path':fpath,'message':'Download started in background'})

@files_bp.route('/api/files/properties')
def file_properties():
    if not req(): return jsonify({'ok':False}),401
    path = safe_path(request.args.get('path',''))
    if not os.path.lexists(path): return jsonify({'ok':False,'error':'Not found'}),404
    try: st = os.stat(path)
    except OSError: st = os.lstat(path)
    import pwd, grp, time as t
    try: owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError: owner = str(st.st_uid)
    try: group = grp.getgrgid(st.st_gid).gr_name
    except KeyError: group = str(st.st_gid)
    if os.path.isdir(path):
        size = _du(path) or 0
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
    """Basic syntax check for PHP, Python, JSON"""
    if not req(): return jsonify({'ok':False}),401
    d    = request.get_json() or {}
    path = safe_path(d.get('path',''))
    ext  = os.path.splitext(path)[1].lower()
    errors = []
    try:
        if ext == '.php':
            php_bin = shutil.which('php')
            if not php_bin:
                # remi-only RHEL: no php on PATH, use an installed version
                try:
                    from panel.routes.php import installed_php_layouts
                    lays = installed_php_layouts()
                    php_bin = lays[0]['bin'] if lays else None
                except Exception:
                    php_bin = None
            if not php_bin:
                return jsonify({'ok':True,'errors':[],'clean':True,'skipped':'php-cli is not installed'})
            r = subprocess.run([php_bin, '-l', path], capture_output=True, text=True, timeout=10)
            if r.returncode != 0:
                for line in (r.stdout + '\n' + r.stderr).split('\n'):
                    if 'error' in line.lower() or 'Parse' in line:
                        errors.append(line.strip())
                if not errors: errors.append((r.stdout or r.stderr).strip()[:300])
        elif ext == '.py':
            # compile() in-process: `python3 -m py_compile` wrote __pycache__/
            # directories into the user's site on every lint.
            with open(path, 'rb') as f: src = f.read()
            try:
                compile(src, path, 'exec', dont_inherit=True)
            except SyntaxError as e:
                errors.append(f'{e.msg} (line {e.lineno})')
            except ValueError as e:
                errors.append(str(e))
        elif ext in ('.json',):
            import json as _json
            try:
                with open(path, encoding='utf-8') as f: _json.load(f)
            except ValueError as e:
                errors.append(str(e))
    except Exception as e:
        errors.append(str(e))
    return jsonify({'ok':True,'errors':errors,'clean':len(errors)==0})

def _clamd_config():
    for p in ('/etc/clamav/clamd.conf', '/etc/clamd.d/scan.conf', '/usr/local/etc/clamav/clamd.conf'):
        if os.path.isfile(p): return p
    return None

def _clamd_running():
    for unit in ('clamav-daemon', 'clamd@scan'):
        try:
            r = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True, timeout=10)
            if r.stdout.strip() == 'active': return True
        except (OSError, subprocess.TimeoutExpired): pass
    return False

@files_bp.route('/api/files/scan', methods=['POST'])
def scan_file():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    path = safe_path((d.get('path') or '').strip())
    if not path or not os.path.exists(path):
        return jsonify({'ok':False,'error':'Path not found'})

    # clamdscan when the daemon is up (Debian: clamav-daemon + /etc/clamav/clamd.conf,
    # RHEL: clamd@scan + /etc/clamd.d/scan.conf). --fdpass lets clamd (running as
    # the clamav user) scan files it cannot open itself. Otherwise clamscan.
    conf = _clamd_config()
    if shutil.which('clamdscan') and conf and _clamd_running():
        cmd = ['clamdscan', f'--config-file={conf}', '--fdpass', '--multiscan', '--no-summary', path]
    elif shutil.which('clamscan'):
        cmd = ['clamscan', '--recursive', '--no-summary', path]
    else:
        return jsonify({'ok':False,'error':'ClamAV is not installed'})

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        output = r.stdout + r.stderr
        # Parse results
        infected = []
        for line in output.split('\n'):
            if line.rstrip().endswith('FOUND'):
                parts = line.rsplit(':', 1)
                if len(parts) == 2:
                    infected.append({'file': parts[0].strip(), 'virus': parts[1].replace('FOUND','').strip()})
        # exit codes: 0 clean, 1 virus found, 2 error
        if r.returncode >= 2 and not infected:
            return jsonify({'ok':False,'error':'Scan failed: ' + output.strip()[-400:],'output':output})
        return jsonify({'ok':True, 'clean':r.returncode == 0, 'infected':infected, 'output':output, 'path':path})
    except subprocess.TimeoutExpired:
        return jsonify({'ok':False,'error':'Scan timed out (30 min limit)'})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)})
