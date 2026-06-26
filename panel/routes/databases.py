from flask import Blueprint, jsonify, request, session, send_file
import subprocess, re, os, tempfile, threading

databases_bp = Blueprint('databases', __name__)
def req(): return 'user' in session

def sh(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return '', str(e), 1

# --- Engine detection -----------------------------------------------------------
def detect_engines():
    engines = []
    # MariaDB — check first, takes priority over mysql binary
    out, _, rc = sh('systemctl is-active mariadb 2>/dev/null')
    mariadb_active = rc == 0 and out.strip() == 'active'
    if mariadb_active:
        ver, _, _ = sh('mariadbd --version 2>/dev/null | grep -oP "[0-9]+\\.[0-9]+\\.[0-9]+" | head -1')
        if not ver: ver, _, _ = sh('mariadb --version 2>/dev/null | grep -oP "[0-9]+\\.[0-9]+\\.[0-9]+" | head -1')
        engines.append({'id':'mariadb','name':'MariaDB','icon':'🦭','version':ver,'active':True})
    # MySQL — only if MariaDB is NOT active (avoid double detection)
    if not mariadb_active:
        out, _, rc = sh('systemctl is-active mysql 2>/dev/null || systemctl is-active mysqld 2>/dev/null')
        if rc == 0 and out.strip() == 'active':
            ver, _, _ = sh('mysql --version 2>/dev/null | grep -oP "[0-9]+\\.[0-9]+\\.[0-9]+" | head -1')
            engines.append({'id':'mysql','name':'MySQL','icon':'🐬','version':ver,'active':True})
    # PostgreSQL
    out, _, rc = sh('systemctl is-active postgresql 2>/dev/null')
    if rc == 0 and out.strip() == 'active':
        ver, _, _ = sh('psql --version 2>/dev/null | grep -oP "[0-9]+\\.[0-9]+" | head -1')
        engines.append({'id':'postgresql','name':'PostgreSQL','icon':'🐘','version':ver,'active':True})
    # MongoDB
    out, _, rc = sh('systemctl is-active mongod 2>/dev/null')
    if rc == 0 and out.strip() == 'active':
        ver, _, _ = sh('mongod --version 2>/dev/null | grep -oP "[0-9]+\\.[0-9]+\\.[0-9]+" | head -1')
        engines.append({'id':'mongodb','name':'MongoDB','icon':'🍃','version':ver,'active':True})
    return engines

# --- MySQL/MariaDB helpers ------------------------------------------------------
def mysql_cmd(query, db=None, timeout=15):
    import shutil as _sh, tempfile as _tmp
    bin_name = 'mariadb' if _sh.which('mariadb') else 'mysql'
    # Write query to temp file to avoid shell escaping issues
    tf = _tmp.NamedTemporaryFile(mode='w', suffix='.sql', delete=False)
    if db:
        tf.write(f'USE `{db}`;\n')
    tf.write(query + '\n')
    tf.flush(); tf.close()
    sockets = ['/run/mysqld/mysqld.sock', '/var/run/mysqld/mysqld.sock', '/tmp/mysql.sock']
    cmds = []
    for sock in sockets:
        if os.path.exists(sock):
            cmds.append(f'{bin_name} -u root --socket={sock} < {tf.name}')
    cmds.append(f'{bin_name} -u root < {tf.name}')
    for cmd in cmds:
        out, err, rc = sh(cmd, timeout)
        if rc == 0:
            os.unlink(tf.name)
            return out, None
    os.unlink(tf.name)
    return '', 'MySQL/MariaDB connection failed'

def mysql_dbs():
    raw, err = mysql_cmd('SHOW DATABASES;')
    if err: return [], err
    skip = {'information_schema','performance_schema','mysql','sys','Database'}
    dbs = []
    for line in raw.split('\n'):
        name = line.strip()
        if not name or name in skip: continue
        size_raw, _ = mysql_cmd(f"SELECT ROUND(SUM(data_length+index_length)/1024/1024,2) FROM information_schema.tables WHERE table_schema='{name}';")
        try: size_mb = float(size_raw.split('\n')[-1])
        except: size_mb = 0.0
        tcount_raw, _ = mysql_cmd(f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{name}';")
        try: tcount = int(tcount_raw.split('\n')[-1])
        except: tcount = 0
        dbs.append({'name':name,'size_mb':size_mb,'tables':tcount,'engine':'mysql'})
    return dbs, None

# --- PostgreSQL helpers ---------------------------------------------------------
def pg_cmd(query, db='postgres'):
    out, err, rc = sh(f'sudo -u postgres psql -d {db} -c "{query}" -t 2>/dev/null')
    if rc == 0: return out, None
    return '', f'PostgreSQL error: {err}'

def pg_dbs():
    raw, err = pg_cmd("SELECT datname FROM pg_database WHERE datistemplate=false ORDER BY datname;")
    if err: return [], err
    dbs = []
    for line in raw.split('\n'):
        name = line.strip()
        if not name: continue
        size_raw, _ = pg_cmd(f"SELECT pg_size_pretty(pg_database_size('{name}'));")
        size = size_raw.strip() if size_raw else '0'
        dbs.append({'name':name,'size_mb':size,'tables':0,'engine':'postgresql'})
    return dbs, None

# --- MongoDB helpers ------------------------------------------------------------
def mongo_dbs():
    out, err, rc = sh("mongosh --quiet --eval 'db.adminCommand({listDatabases:1}).databases.forEach(d=>print(d.name+\"\\t\"+d.sizeOnDisk))' 2>/dev/null")
    if rc != 0:
        out, err, rc = sh("mongo --quiet --eval 'db.adminCommand({listDatabases:1}).databases.forEach(d=>print(d.name+\"\\t\"+d.sizeOnDisk))' 2>/dev/null")
    if rc != 0: return [], 'MongoDB connection failed'
    skip = {'admin','config','local'}
    dbs = []
    for line in out.split('\n'):
        parts = line.strip().split('\t')
        if not parts[0] or parts[0] in skip: continue
        size_mb = round(int(parts[1])/1024/1024, 2) if len(parts) > 1 else 0
        dbs.append({'name':parts[0],'size_mb':size_mb,'tables':0,'engine':'mongodb'})
    return dbs, None

# --- API Routes -----------------------------------------------------------------
@databases_bp.route('/api/databases/engines')
def get_engines():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, 'engines': detect_engines()})

@databases_bp.route('/api/databases')
def list_dbs():
    if not req(): return jsonify({'ok':False}), 401
    engine  = request.args.get('engine', 'auto')
    engines = detect_engines()

    if not engines:
        return jsonify({'ok':True,'databases':[],'engines':[],'no_engine':True})

    # Auto-select first available engine, or validate requested engine exists
    available_ids = [e['id'] for e in engines]
    if engine == 'auto' or engine not in available_ids:
        engine = available_ids[0]

    if engine in ('mysql','mariadb'):
        dbs, err = mysql_dbs()
        if err:
            return jsonify({'ok':False,'error':err,'databases':[],'engines':engines,'active_engine':engine})
        ver_raw, _ = mysql_cmd('SELECT VERSION();')
        ver   = ver_raw.split('\n')[-1].strip() if ver_raw else ''
        conns_raw, _ = mysql_cmd("SHOW STATUS LIKE 'Threads_connected';")
        conns = conns_raw.split('\n')[-1].split('\t')[-1].strip() if conns_raw else '0'
        size_raw, _  = mysql_cmd("SELECT ROUND(SUM(data_length+index_length)/1024/1024,2) FROM information_schema.tables;")
        total = size_raw.split('\n')[-1].strip() if size_raw else '0'
        return jsonify({'ok':True,'databases':dbs,'engines':engines,'active_engine':engine,
            'info':{'version':ver,'connections':conns,'total_size_mb':total}})

    elif engine == 'postgresql':
        dbs, err = pg_dbs()
        if err:
            return jsonify({'ok':False,'error':err,'databases':[],'engines':engines,'active_engine':engine})
        ver_raw, _, _ = pg_cmd('SELECT version();')
        ver = ver_raw.strip().split(' ')[1] if ver_raw else ''
        return jsonify({'ok':True,'databases':dbs,'engines':engines,'active_engine':engine,
            'info':{'version':ver,'connections':'N/A','total_size_mb':'N/A'}})

    elif engine == 'mongodb':
        dbs, err = mongo_dbs()
        if err:
            return jsonify({'ok':False,'error':err,'databases':[],'engines':engines,'active_engine':engine})
        ver, _, _ = sh('mongod --version 2>/dev/null | grep -oP "[0-9]+[.][0-9]+[.][0-9]+" | head -1')
        return jsonify({'ok':True,'databases':dbs,'engines':engines,'active_engine':engine,
            'info':{'version':ver or '','connections':'N/A','total_size_mb':'N/A'}})

    return jsonify({'ok':True,'databases':[],'engines':engines,'active_engine':engine})

@databases_bp.route('/api/databases', methods=['POST'])
def create_db():
    if not req(): return jsonify({'ok':False}), 401
    d      = request.get_json() or {}
    name   = re.sub(r'[^a-zA-Z0-9_]','', d.get('name',''))
    user   = re.sub(r'[^a-zA-Z0-9_]','', d.get('user', ''))
    pwd    = d.get('password','') or d.get('pass','')
    engine = d.get('engine','mysql')
    if not name: return jsonify({'ok':False,'error':'Database name required'})

    if engine in ('mysql','mariadb'):
        _, err = mysql_cmd(f'CREATE DATABASE IF NOT EXISTS `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;')
        if err: return jsonify({'ok':False,'error':err})
        if user and pwd:
            mysql_cmd(f"CREATE USER IF NOT EXISTS '{user}'@'localhost' IDENTIFIED BY '{pwd}';")
            mysql_cmd(f"GRANT ALL PRIVILEGES ON `{name}`.* TO '{user}'@'localhost'; FLUSH PRIVILEGES;")
        return jsonify({'ok':True,'name':name})

    elif engine == 'postgresql':
        _, err, rc = sh(f"sudo -u postgres createdb '{name}' 2>/dev/null")
        if rc != 0: return jsonify({'ok':False,'error':err or 'Failed to create PostgreSQL database'})
        if user and pwd:
            sh(f"sudo -u postgres psql -c \"CREATE USER {user} WITH PASSWORD '{pwd}';\" 2>/dev/null")
            sh(f"sudo -u postgres psql -c \"GRANT ALL PRIVILEGES ON DATABASE {name} TO {user};\" 2>/dev/null")
        return jsonify({'ok':True,'name':name})

    elif engine == 'mongodb':
        out, err, rc = sh(f"mongosh --quiet --eval 'use {name}; db.createCollection(\"_init\"); db._init.drop();' 2>/dev/null")
        if rc != 0: return jsonify({'ok':False,'error':err or 'Failed to create MongoDB database'})
        return jsonify({'ok':True,'name':name})

    return jsonify({'ok':False,'error':'Unknown engine'})

@databases_bp.route('/api/databases/<name>', methods=['DELETE'])
def drop_db(name):
    if not req(): return jsonify({'ok':False}), 401
    engine = request.args.get('engine','mysql')
    if engine in ('mysql','mariadb'):
        mysql_cmd(f'DROP DATABASE IF EXISTS `{name}`;')
    elif engine == 'postgresql':
        sh(f"sudo -u postgres dropdb '{name}' 2>/dev/null")
    elif engine == 'mongodb':
        sh(f"mongosh --quiet --eval 'use {name}; db.dropDatabase();' 2>/dev/null")
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/<name>/export')
def export_db(name):
    if not req(): return jsonify({'ok':False}), 401
    engine = request.args.get('engine','mysql')
    tmp = tempfile.mktemp(suffix='.sql')
    if engine in ('mysql','mariadb'):
        sockets = ['/var/run/mysqld/mysqld.sock','/run/mysqld/mysqld.sock']
        cmd = f'mysqldump -u root {name} > {tmp}'
        for sock in sockets:
            if os.path.exists(sock):
                cmd = f'mysqldump -u root --socket={sock} {name} > {tmp}'
                break
        _, _, rc = sh(cmd, 60)
    elif engine == 'postgresql':
        _, _, rc = sh(f"sudo -u postgres pg_dump {name} > {tmp} 2>/dev/null", 60)
    elif engine == 'mongodb':
        tmp = tempfile.mkdtemp()
        _, _, rc = sh(f"mongodump --db {name} --out {tmp} 2>/dev/null", 60)
        import shutil
        archive = tempfile.mktemp(suffix='.tar.gz')
        sh(f'tar -czf {archive} -C {tmp} .', 30)
        shutil.rmtree(tmp)
        return send_file(archive, as_attachment=True, download_name=f'{name}.tar.gz')
    else:
        return jsonify({'ok':False,'error':'Unknown engine'})
    if rc == 0 and os.path.exists(tmp):
        return send_file(tmp, as_attachment=True, download_name=f'{name}.sql', mimetype='application/sql')
    return jsonify({'ok':False,'error':'Export failed'}), 500

@databases_bp.route('/api/databases/<name>/import', methods=['POST'])
def import_db(name):
    if not req(): return jsonify({'ok':False}), 401
    engine = request.args.get('engine','mysql')
    f = request.files.get('file')
    if not f: return jsonify({'ok':False,'error':'No file uploaded'})
    tmp = tempfile.mktemp(suffix='.sql')
    f.save(tmp)
    if engine in ('mysql','mariadb'):
        sockets = ['/var/run/mysqld/mysqld.sock','/run/mysqld/mysqld.sock']
        cmd = f'mysql -u root {name} < {tmp}'
        for sock in sockets:
            if os.path.exists(sock):
                cmd = f'mysql -u root --socket={sock} {name} < {tmp}'
                break
        _, _, rc = sh(cmd, 120)
    elif engine == 'postgresql':
        _, _, rc = sh(f"sudo -u postgres psql {name} < {tmp} 2>/dev/null", 120)
    else:
        rc = 1
    os.unlink(tmp)
    return jsonify({'ok': rc == 0, 'error': 'Import failed' if rc != 0 else None})

@databases_bp.route('/api/databases/users')
def list_users():
    if not req(): return jsonify({'ok':False}), 401
    engine = request.args.get('engine','auto')
    if engine == 'auto':
        engines = detect_engines()
        if not engines: return jsonify({'ok':True,'users':[]})
        engine = engines[0]['id']
    if engine in ('mysql','mariadb'):
        raw, err = mysql_cmd("SELECT user,host FROM mysql.user WHERE user NOT IN ('root','mysql.sys','mysql.infoschema','mysql.session','') ORDER BY user;")
        if err: return jsonify({'ok':False,'error':err,'users':[]})
        users = []
        for line in raw.split('\n')[1:]:
            parts = line.strip().split('\t')
            if len(parts)>=2 and parts[0]:
                u, h = parts[0], parts[1]
                grants_raw, _ = mysql_cmd(f"SHOW GRANTS FOR '{u}'@'{h}';")
                dbs = []
                for gline in grants_raw.split('\n'):
                    m = re.search(r'ON `?([A-Za-z0-9_\\*]+)`?\.\*', gline)
                    if m and m.group(1) != '*':
                        dbs.append(m.group(1))
                users.append({'user':u,'host':h,'databases':dbs})
        return jsonify({'ok':True,'users':users})
    elif engine == 'postgresql':
        raw, err = pg_cmd("SELECT usename FROM pg_user WHERE usename != 'postgres' ORDER BY usename;")
        if err: return jsonify({'ok':False,'error':err,'users':[]})
        users = [{'user':l.strip(),'host':'localhost'} for l in raw.split('\n') if l.strip()]
        return jsonify({'ok':True,'users':users})
    elif engine == 'mongodb':
        out, err, rc = sh("mongosh --quiet --eval 'db.getSiblingDB(\"admin\").system.users.find({},{user:1,db:1}).forEach(u=>print(u.user+\"\\t\"+u.db))' 2>/dev/null")
        users = []
        for line in out.split('\n'):
            parts = line.strip().split('\t')
            if parts[0]: users.append({'user':parts[0],'host':parts[1] if len(parts)>1 else 'admin'})
        return jsonify({'ok':True,'users':users})
    return jsonify({'ok':True,'users':[]})

@databases_bp.route('/api/databases/users', methods=['POST'])
def create_user():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    user   = re.sub(r'[^a-zA-Z0-9_]','', d.get('user',''))
    pwd    = d.get('password','')
    db     = d.get('database','')
    host   = d.get('host','localhost')
    engine = d.get('engine','mysql')
    if not user or not pwd: return jsonify({'ok':False,'error':'Username and password required'})
    if engine in ('mysql','mariadb'):
        mysql_cmd(f"CREATE USER IF NOT EXISTS '{user}'@'{host}' IDENTIFIED BY '{pwd}';")
        if db: mysql_cmd(f"GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'{host}'; FLUSH PRIVILEGES;")
        else: mysql_cmd("FLUSH PRIVILEGES;")
    elif engine == 'postgresql':
        sh(f"sudo -u postgres psql -c \"CREATE USER {user} WITH PASSWORD '{pwd}';\" 2>/dev/null")
        if db: sh(f"sudo -u postgres psql -c \"GRANT ALL PRIVILEGES ON DATABASE {db} TO {user};\" 2>/dev/null")
    elif engine == 'mongodb':
        roles = f'[{{role:"readWrite",db:"{db}"}}]' if db else '[{role:"read",db:"admin"}]'
        sh(f"mongosh --quiet --eval 'db.getSiblingDB(\"admin\").createUser({{user:\"{user}\",pwd:\"{pwd}\",roles:{roles}}})' 2>/dev/null")
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/users/<user>', methods=['DELETE'])
def drop_user(user):
    if not req(): return jsonify({'ok':False}), 401
    engine = request.args.get('engine','mysql')
    host   = request.args.get('host','localhost')
    if engine in ('mysql','mariadb'):
        mysql_cmd(f"DROP USER IF EXISTS '{user}'@'{host}'; FLUSH PRIVILEGES;")
    elif engine == 'postgresql':
        sh(f"sudo -u postgres psql -c \"DROP USER IF EXISTS {user};\" 2>/dev/null")
    elif engine == 'mongodb':
        sh(f"mongosh --quiet --eval 'db.getSiblingDB(\"admin\").dropUser(\"{user}\")' 2>/dev/null")
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/users/<user>/password', methods=['PUT'])
def change_password(user):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    pwd    = d.get('password','')
    engine = d.get('engine','mysql')
    host   = d.get('host','localhost')
    if not pwd: return jsonify({'ok':False,'error':'Password required'})
    if engine in ('mysql','mariadb'):
        mysql_cmd(f"ALTER USER '{user}'@'{host}' IDENTIFIED BY '{pwd}'; FLUSH PRIVILEGES;")
    elif engine == 'postgresql':
        sh(f"sudo -u postgres psql -c \"ALTER USER {user} WITH PASSWORD '{pwd}';\" 2>/dev/null")
    elif engine == 'mongodb':
        sh(f"mongosh --quiet --eval 'db.getSiblingDB(\"admin\").updateUser(\"{user}\",{{pwd:\"{pwd}\"}})' 2>/dev/null")
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/users/<user>/grant', methods=['POST'])
def grant_db(user):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    db     = d.get('database','')
    host   = d.get('host','localhost')
    engine = d.get('engine','mysql')
    if not db: return jsonify({'ok':False,'error':'Database required'})
    if engine in ('mysql','mariadb'):
        mysql_cmd(f"GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'{host}'; FLUSH PRIVILEGES;")
    elif engine == 'postgresql':
        sh(f"sudo -u postgres psql -c \"GRANT ALL PRIVILEGES ON DATABASE {db} TO {user};\" 2>/dev/null")
    elif engine == 'mongodb':
        sh(f"mongosh --quiet --eval 'db.getSiblingDB(\"admin\").grantRolesToUser(\"{user}\",[{{role:\"readWrite\",db:\"{db}\"}}])' 2>/dev/null")
    return jsonify({'ok':True})
