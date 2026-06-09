from flask import Blueprint, jsonify, request, session
import subprocess, re, os

databases_bp = Blueprint('databases', __name__)
def req(): return 'user' in session

def mysql_cmd(query, db=None):
    """Try multiple ways to connect to MySQL/MariaDB"""
    cmds = [
        f'mysql -u root -e "{query}"',
        f'mysql -u root --socket=/var/run/mysqld/mysqld.sock -e "{query}"',
        f'mysql -u root --socket=/tmp/mysql.sock -e "{query}"',
    ]
    if db:
        cmds = [c.replace('-e "', f'{db} -e "') for c in cmds]
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                return r.stdout.strip(), None
        except: pass
    # Try with sudo
    try:
        r = subprocess.run(f'mysql -e "{query}"', shell=True, capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return r.stdout.strip(), None
    except: pass
    return '', 'MySQL connection failed — is MySQL/MariaDB installed and running?'

@databases_bp.route('/api/databases')
def list_dbs():
    if not req(): return jsonify({'ok':False}), 401
    raw, err = mysql_cmd("SHOW DATABASES;")
    if err:
        return jsonify({'ok':False, 'error':err, 'databases':[]})
    skip = {'information_schema','performance_schema','mysql','sys','Database'}
    dbs  = []
    for line in raw.split('\n'):
        name = line.strip()
        if not name or name in skip: continue
        size_raw, _ = mysql_cmd(f"SELECT ROUND(SUM(data_length+index_length)/1024/1024,2) FROM information_schema.tables WHERE table_schema='{name}';")
        try: size_mb = float(size_raw.split('\n')[-1])
        except: size_mb = 0.0
        tcount_raw, _ = mysql_cmd(f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{name}';")
        try: tcount = int(tcount_raw.split('\n')[-1])
        except: tcount = 0
        dbs.append({'name':name, 'size_mb':size_mb, 'tables':tcount})
    return jsonify({'ok':True, 'databases':dbs})

@databases_bp.route('/api/databases', methods=['POST'])
def create_db():
    if not req(): return jsonify({'ok':False}), 401
    d    = request.get_json() or {}
    name = re.sub(r'[^a-zA-Z0-9_]','', d.get('name',''))
    user = re.sub(r'[^a-zA-Z0-9_]','', d.get('user', name+'_user'))
    pwd  = d.get('password','')
    if not name: return jsonify({'ok':False,'error':'Database name required'}), 400
    _, err = mysql_cmd(f"CREATE DATABASE IF NOT EXISTS `{name}`;")
    if err: return jsonify({'ok':False, 'error':err}), 500
    if user and pwd:
        mysql_cmd(f"CREATE USER IF NOT EXISTS '{user}'@'localhost' IDENTIFIED BY '{pwd}';")
        mysql_cmd(f"GRANT ALL PRIVILEGES ON `{name}`.* TO '{user}'@'localhost'; FLUSH PRIVILEGES;")
    return jsonify({'ok':True, 'name':name, 'user':user})

@databases_bp.route('/api/databases/<name>', methods=['DELETE'])
def drop_db(name):
    if not req(): return jsonify({'ok':False}), 401
    mysql_cmd(f"DROP DATABASE IF EXISTS `{name}`;")
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/users')
def list_users():
    if not req(): return jsonify({'ok':False}), 401
    raw, err = mysql_cmd("SELECT user,host FROM mysql.user WHERE user NOT IN ('root','mysql.sys','mysql.infoschema','mysql.session','') ORDER BY user;")
    if err: return jsonify({'ok':False, 'error':err, 'users':[]})
    users = []
    for line in raw.split('\n')[1:]:
        parts = line.strip().split('\t')
        if len(parts)>=2 and parts[0]: users.append({'user':parts[0],'host':parts[1]})
    return jsonify({'ok':True, 'users':users})

@databases_bp.route('/api/databases/users', methods=['POST'])
def create_user():
    if not req(): return jsonify({'ok':False}), 401
    d    = request.get_json() or {}
    user = re.sub(r'[^a-zA-Z0-9_]','', d.get('user',''))
    pwd  = d.get('password','')
    db   = d.get('database','')
    mysql_cmd(f"CREATE USER IF NOT EXISTS '{user}'@'localhost' IDENTIFIED BY '{pwd}';")
    if db: mysql_cmd(f"GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'localhost'; FLUSH PRIVILEGES;")
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/users/<user>', methods=['DELETE'])
def drop_user(user):
    if not req(): return jsonify({'ok':False}), 401
    mysql_cmd(f"DROP USER IF EXISTS '{user}'@'localhost'; FLUSH PRIVILEGES;")
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/<name>/export')
def export_db(name):
    if not req(): return jsonify({'ok':False}), 401
    import subprocess, tempfile, os
    tmp = tempfile.mktemp(suffix='.sql')
    cmds = [
        f'mysqldump -u root {name} > {tmp}',
        f'mysqldump -u root --socket=/var/run/mysqld/mysqld.sock {name} > {tmp}',
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        if r.returncode == 0 and os.path.exists(tmp):
            from flask import send_file
            return send_file(tmp, as_attachment=True, download_name=f'{name}.sql', mimetype='application/sql')
    return jsonify({'ok':False,'error':'Export failed'}), 500

@databases_bp.route('/api/databases/<name>/import', methods=['POST'])
def import_db(name):
    if not req(): return jsonify({'ok':False}), 401
    from flask import request as req2
    f = req2.files.get('file')
    if not f: return jsonify({'ok':False,'error':'No file uploaded'}), 400
    import tempfile, subprocess
    tmp = tempfile.mktemp(suffix='.sql')
    f.save(tmp)
    cmds = [
        f'mysql -u root {name} < {tmp}',
        f'mysql -u root --socket=/var/run/mysqld/mysqld.sock {name} < {tmp}',
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            import os; os.unlink(tmp)
            return jsonify({'ok':True})
    import os; os.unlink(tmp)
    return jsonify({'ok':False,'error':'Import failed'}), 500

@databases_bp.route('/api/databases/users/<user>/password', methods=['PUT'])
def change_password(user):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    pwd = d.get('password','')
    if not pwd: return jsonify({'ok':False,'error':'Password required'})
    mysql_cmd(f"ALTER USER '{user}'@'localhost' IDENTIFIED BY '{pwd}'; FLUSH PRIVILEGES;")
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/users/<user>/grant', methods=['POST'])
def grant_db(user):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    db = d.get('database','')
    host = d.get('host','localhost')
    if not db: return jsonify({'ok':False,'error':'Database required'})
    mysql_cmd(f"GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'{host}'; FLUSH PRIVILEGES;")
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/users/<user>/privileges')
def get_privileges(user):
    if not req(): return jsonify({'ok':False}), 401
    raw, err = mysql_cmd(f"SHOW GRANTS FOR '{user}'@'localhost';")
    if err: raw, err = mysql_cmd(f"SHOW GRANTS FOR '{user}'@'%';")
    return jsonify({'ok':True,'grants':raw})

@databases_bp.route('/api/databases/info')
def db_info():
    if not req(): return jsonify({'ok':False}), 401
    version_raw, err = mysql_cmd("SELECT VERSION();")
    if err: return jsonify({'ok':False,'error':err,'installed':False})
    version = version_raw.split('\n')[-1].strip() if version_raw else ''
    uptime_raw, _ = mysql_cmd("SHOW STATUS LIKE 'Uptime';")
    uptime = uptime_raw.split('\n')[-1].split('\t')[-1].strip() if uptime_raw else '0'
    conn_raw, _ = mysql_cmd("SHOW STATUS LIKE 'Threads_connected';")
    connections = conn_raw.split('\n')[-1].split('\t')[-1].strip() if conn_raw else '0'
    size_raw, _ = mysql_cmd("SELECT ROUND(SUM(data_length+index_length)/1024/1024,2) FROM information_schema.tables;")
    total_size = size_raw.split('\n')[-1].strip() if size_raw else '0'
    return jsonify({'ok':True,'installed':True,'version':version,
        'uptime':uptime,'connections':connections,'total_size_mb':total_size})
