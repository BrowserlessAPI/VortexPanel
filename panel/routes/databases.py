from flask import Blueprint, jsonify, request, session
import subprocess, re

databases_bp = Blueprint('databases', __name__)
def req(): return 'user' in session
def mysql(q, db=None):
    cmd = f'mysql -u root -e "{q}"'
    if db: cmd = f'mysql -u root {db} -e "{q}"'
    try: return subprocess.check_output(cmd,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
    except: return ''

@databases_bp.route('/api/databases')
def list_dbs():
    if not req(): return jsonify({'ok':False}),401
    raw = mysql("SHOW DATABASES;")
    dbs = []
    skip = {'information_schema','performance_schema','mysql','sys'}
    for line in raw.split('\n')[1:]:
        name = line.strip()
        if name and name not in skip:
            size = mysql(f"SELECT ROUND(SUM(data_length+index_length)/1024/1024,2) FROM information_schema.tables WHERE table_schema='{name}';")
            try: size_mb = float(size.split('\n')[-1])
            except: size_mb = 0.0
            tables = mysql(f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{name}';")
            try: tcount = int(tables.split('\n')[-1])
            except: tcount = 0
            dbs.append({'name':name,'size_mb':size_mb,'tables':tcount})
    return jsonify({'ok':True,'databases':dbs})

@databases_bp.route('/api/databases', methods=['POST'])
def create_db():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    name = re.sub(r'[^a-zA-Z0-9_]','',d.get('name',''))
    user = re.sub(r'[^a-zA-Z0-9_]','',d.get('user',name+'_user'))
    pwd  = d.get('password','')
    if not name: return jsonify({'ok':False,'error':'Name required'}),400
    mysql(f"CREATE DATABASE IF NOT EXISTS `{name}`;")
    if user and pwd:
        mysql(f"CREATE USER IF NOT EXISTS '{user}'@'localhost' IDENTIFIED BY '{pwd}';")
        mysql(f"GRANT ALL PRIVILEGES ON `{name}`.* TO '{user}'@'localhost'; FLUSH PRIVILEGES;")
    return jsonify({'ok':True,'name':name})

@databases_bp.route('/api/databases/<name>', methods=['DELETE'])
def drop_db(name):
    if not req(): return jsonify({'ok':False}),401
    mysql(f"DROP DATABASE IF EXISTS `{name}`;")
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/users')
def list_users():
    if not req(): return jsonify({'ok':False}),401
    raw = mysql("SELECT user,host FROM mysql.user WHERE user NOT IN ('root','mysql.sys','mysql.infoschema','mysql.session') ORDER BY user;")
    users = []
    for line in raw.split('\n')[1:]:
        parts = line.strip().split('\t')
        if len(parts)>=2: users.append({'user':parts[0],'host':parts[1]})
    return jsonify({'ok':True,'users':users})

@databases_bp.route('/api/databases/users', methods=['POST'])
def create_user():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    user = re.sub(r'[^a-zA-Z0-9_]','',d.get('user',''))
    pwd  = d.get('password','')
    db   = d.get('database','')
    mysql(f"CREATE USER IF NOT EXISTS '{user}'@'localhost' IDENTIFIED BY '{pwd}';")
    if db: mysql(f"GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'localhost'; FLUSH PRIVILEGES;")
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/users/<user>', methods=['DELETE'])
def drop_user(user):
    if not req(): return jsonify({'ok':False}),401
    mysql(f"DROP USER IF EXISTS '{user}'@'localhost';")
    return jsonify({'ok':True})
