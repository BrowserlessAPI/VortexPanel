from flask import Blueprint, jsonify, request, session
import subprocess, os, glob, time, threading

backups_bp = Blueprint('backups', __name__)
def req(): return 'user' in session
def sh(c,t=300):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL,timeout=t).strip()
    except: return ''

BACKUP_DIR = '/opt/vortexpanel/backups'

@backups_bp.route('/api/backups')
def list_backups():
    if not req(): return jsonify({'ok':False}),401
    os.makedirs(BACKUP_DIR, exist_ok=True)
    files = []
    for f in sorted(glob.glob(f'{BACKUP_DIR}/*.tar.gz'), reverse=True):
        st = os.stat(f)
        files.append({'name':os.path.basename(f),'size':st.st_size,'mtime':int(st.st_mtime),'path':f})
    return jsonify({'ok':True,'backups':files})

@backups_bp.route('/api/backups/create', methods=['POST'])
def create_backup():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    target = d.get('target','webroot')  # webroot | database | full
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = time.strftime('%Y%m%d_%H%M%S')
    name = f'{target}_{ts}.tar.gz'
    path = f'{BACKUP_DIR}/{name}'
    def do_backup():
        if target == 'webroot':
            sh(f'tar -czf {path} /www/wwwroot/ 2>/dev/null', t=600)
        elif target == 'database':
            sh(f'mysqldump --all-databases | gzip > {path}', t=300)
        elif target == 'full':
            sh(f'tar -czf {path} /www/wwwroot/ /etc/nginx/ 2>/dev/null', t=600)
    threading.Thread(target=do_backup, daemon=True).start()
    return jsonify({'ok':True,'name':name,'message':'Backup started in background'})

@backups_bp.route('/api/backups/<name>', methods=['DELETE'])
def delete_backup(name):
    if not req(): return jsonify({'ok':False}),401
    path = os.path.join(BACKUP_DIR, name)
    if os.path.exists(path): os.unlink(path)
    return jsonify({'ok':True})
