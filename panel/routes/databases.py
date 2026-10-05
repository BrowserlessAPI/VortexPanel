from flask import Blueprint, jsonify, request, session, send_file
import subprocess, re, os, tempfile, shlex, shutil, json

databases_bp = Blueprint('databases', __name__)
def req(): return 'user' in session

def sh(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return '', str(e), 1

# --- Name validation ------------------------------------------------------------
_IDENT_RE = re.compile(r'^[A-Za-z0-9_$]+$')
# Database names: what the panel creates ([A-Za-z0-9_]) plus '-' and '$', which
# databases created outside the panel commonly use. Never a leading '-' (would
# be read as an option by mysqldump/pg_dump/createdb).
_DBNAME_RE = re.compile(r'^[A-Za-z0-9_$][A-Za-z0-9_$-]{0,63}$')
# MySQL account host part: localhost, IPs, hostnames, '%' wildcards, IPv6.
_HOST_RE = re.compile(r'^[A-Za-z0-9.%_:-]{1,255}$')
_MONGO_NAME_RE = re.compile(r'^[A-Za-z0-9_.-]+$')

_SYSTEM_DBS = {
    'mysql':      {'mysql', 'information_schema', 'performance_schema', 'sys'},
    'postgresql': {'postgres', 'template0', 'template1'},
    'mongodb':    {'admin', 'config', 'local'},
}

def _valid_ident(s):
    """Identifier used inside backticks / double quotes in a query we build."""
    return bool(s) and bool(_IDENT_RE.match(s)) and len(s) <= 64

def _valid_dbname(s):
    return bool(s) and bool(_DBNAME_RE.match(s))

def _valid_host(s):
    return bool(s) and bool(_HOST_RE.match(s))

def _valid_mongo_name(s):
    return bool(s) and bool(_MONGO_NAME_RE.match(s)) and len(s) <= 120 and not s.startswith('system.')

def _engine_family(engine):
    return 'mysql' if engine in ('mysql', 'mariadb') else engine

# --- Engine detection -----------------------------------------------------------
def _unit_active(*units):
    """True if any of the given systemd units is active. `systemctl is-active a b`
    prints one state per unit, so check each line instead of the whole output
    (the old `is-active mysql || is-active mysqld` printed "inactive\\nactive"
    on RHEL and never matched)."""
    out, _, _ = sh('systemctl is-active ' + ' '.join(units) + ' 2>/dev/null')
    return any(l.strip() == 'active' for l in out.split('\n'))

def _pg_active():
    if _unit_active('postgresql'):
        return True
    # PGDG packages on RHEL ship versioned units (postgresql-16.service)
    out, _, _ = sh("systemctl list-units --type=service --state=active --no-legend --plain 'postgresql*' 2>/dev/null")
    return bool(out.strip())

def detect_engines():
    engines = []
    # MariaDB - check first, takes priority over mysql binary
    mariadb_active = _unit_active('mariadb')
    if mariadb_active:
        ver, _, _ = sh('mariadbd --version 2>/dev/null | grep -oP "[0-9]+\\.[0-9]+\\.[0-9]+" | head -1')
        if not ver: ver, _, _ = sh('mariadb --version 2>/dev/null | grep -oP "[0-9]+\\.[0-9]+\\.[0-9]+" | head -1')
        engines.append({'id':'mariadb','name':'MariaDB','icon':'database','version':ver,'active':True})
    # MySQL - only if MariaDB is NOT active (avoid double detection)
    if not mariadb_active and _unit_active('mysql', 'mysqld'):
        ver, _, _ = sh('mysql --version 2>/dev/null | grep -oP "[0-9]+\\.[0-9]+\\.[0-9]+" | head -1')
        engines.append({'id':'mysql','name':'MySQL','icon':'database','version':ver,'active':True})
    # PostgreSQL
    if _pg_active():
        ver, _, _ = sh('psql --version 2>/dev/null | grep -oP "[0-9]+\\.[0-9]+" | head -1')
        engines.append({'id':'postgresql','name':'PostgreSQL','icon':'database','version':ver,'active':True})
    # MongoDB
    if _unit_active('mongod'):
        ver, _, _ = sh('mongod --version 2>/dev/null | grep -oP "[0-9]+\\.[0-9]+\\.[0-9]+" | head -1')
        engines.append({'id':'mongodb','name':'MongoDB','icon':'database','version':ver,'active':True})
    return engines

def _sql_escape(v):
    """Escape a single-quote-delimited MySQL/MariaDB string literal."""
    return (v or '').replace('\\', '\\\\').replace("'", "''")

def _pg_escape(v):
    """PostgreSQL string literal: standard_conforming_strings is on by default,
    so backslashes are literal and must NOT be doubled (doing so silently
    changed any password containing a backslash)."""
    return (v or '').replace("'", "''")

def _mk_tmp(suffix, mode=0o600):
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    os.chmod(path, mode)
    return path

def _unlink(path):
    try: os.unlink(path)
    except OSError: pass

def _send_and_delete(path, download_name, mimetype):
    """Open the file, unlink it, stream the open handle. The temp file is gone
    from /tmp as soon as the download finishes (previously every export left a
    full dump behind in /tmp forever)."""
    fh = open(path, 'rb')
    _unlink(path)
    return send_file(fh, as_attachment=True, download_name=download_name, mimetype=mimetype)

# --- MySQL/MariaDB helpers ------------------------------------------------------
_MYSQL_AUTH = {'args': None}
_MYSQL_CONN_ERR = re.compile(r"ERROR (1045|1698|2002|2003|2005)|error: (1045|2002|2003)|Access denied|Can't connect", re.I)

def _mysql_bin(kind='client'):
    if kind == 'dump':
        return 'mariadb-dump' if shutil.which('mariadb-dump') else 'mysqldump'
    return 'mariadb' if shutil.which('mariadb') else 'mysql'

def _mysql_auth_candidates():
    """Connection options to try, in order. The panel runs as root (HOME=/root),
    so /root/.my.cnf is honoured automatically by every variant. Socket auth
    (unix_socket / auth_socket) covers stock MariaDB and Ubuntu MySQL; on
    Debian/Ubuntu MySQL with a root password the debian-sys-maint account in
    /etc/mysql/debian.cnf is the last resort (--defaults-file must be first)."""
    cands = []
    for sock in ('/run/mysqld/mysqld.sock', '/var/run/mysqld/mysqld.sock',
                 '/var/lib/mysql/mysql.sock', '/tmp/mysql.sock'):
        if os.path.exists(sock) and os.path.realpath(sock) not in [os.path.realpath(c[1]) for c in cands]:
            cands.append(('-u root --socket=' + shlex.quote(sock), sock))
    out = [c[0] for c in cands]
    out.append('-u root')
    if os.path.exists('/etc/mysql/debian.cnf'):
        out.append('--defaults-file=/etc/mysql/debian.cnf')
    if _MYSQL_AUTH['args'] in out:
        out.remove(_MYSQL_AUTH['args'])
        out.insert(0, _MYSQL_AUTH['args'])
    return out

def _mysql_run(binary, rest, timeout):
    """Run `<binary> <auth> <rest>` with each auth candidate until one connects.
    Only connection/auth failures fall through to the next candidate: a SQL
    error means we did connect, and re-running the batch would replay the
    statements that already succeeded."""
    last_err = ''
    for auth in _mysql_auth_candidates():
        out, err, rc = sh(f'{binary} {auth} {rest}', timeout)
        if rc == 0:
            _MYSQL_AUTH['args'] = auth
            return out, None
        last_err = err or out or 'MySQL/MariaDB command failed'
        if not _MYSQL_CONN_ERR.search(last_err):
            _MYSQL_AUTH['args'] = auth
            return out, last_err.strip()[:500]
    return '', 'MySQL/MariaDB connection failed: ' + last_err.strip()[:400]

def mysql_cmd(query, db=None, timeout=15):
    # Write query to temp file to avoid shell escaping issues
    path = _mk_tmp('.sql')
    with open(path, 'w') as tf:
        if db:
            tf.write('USE `%s`;\n' % db.replace('`', '``'))
        tf.write(query + '\n')
    try:
        return _mysql_run(_mysql_bin(), '< ' + shlex.quote(path), timeout)
    finally:
        _unlink(path)

def mysql_dbs():
    raw, err = mysql_cmd(
        "SELECT s.schema_name, ROUND(COALESCE(SUM(t.data_length+t.index_length),0)/1024/1024,2), COUNT(t.table_name) "
        "FROM information_schema.schemata s LEFT JOIN information_schema.tables t ON t.table_schema=s.schema_name "
        "GROUP BY s.schema_name ORDER BY s.schema_name;")
    if err: return [], err
    skip = _SYSTEM_DBS['mysql']
    dbs = []
    for line in raw.split('\n')[1:]:
        parts = line.split('\t')
        name = parts[0].strip()
        if not name or name in skip: continue
        try: size_mb = float(parts[1])
        except (IndexError, ValueError): size_mb = 0.0
        try: tcount = int(parts[2])
        except (IndexError, ValueError): tcount = 0
        dbs.append({'name':name,'size_mb':size_mb,'tables':tcount,'engine':'mysql'})
    return dbs, None

# --- PostgreSQL helpers ---------------------------------------------------------
# runuser is part of util-linux on every supported distro; sudo is often not
# installed on minimal Debian/Ubuntu images. `cd /` avoids psql's "could not
# change directory to /opt/vortexpanel" noise.
def _pg_prefix():
    return 'cd / && runuser -u postgres -- '

def pg_cmd(query, db='postgres', timeout=30):
    """Query goes through a temp file so its content never passes through the
    shell. ON_ERROR_STOP makes psql exit non-zero on SQL errors (without it,
    psql -f returns 0 even when every statement failed)."""
    path = _mk_tmp('.sql', 0o644)  # psql runs as 'postgres' - needs read access
    with open(path, 'w') as tf:
        tf.write(query + '\n')
    out, err, rc = sh(f'{_pg_prefix()}psql -X -q -v ON_ERROR_STOP=1 -d {shlex.quote(db)} -t -f {shlex.quote(path)}', timeout)
    _unlink(path)
    if rc == 0: return out, None
    return '', 'PostgreSQL error: ' + ((err or out or 'psql failed').strip()[:400])

def pg_dbs():
    rows, err = _pg_rows("SELECT datname, pg_database_size(datname) FROM pg_database "
                         "WHERE datistemplate=false ORDER BY datname;", 'postgres')
    if err: return [], err
    dbs = []
    for r in rows:
        name = r[0].strip()
        if not name: continue
        try: size_mb = round(int(r[1]) / 1024 / 1024, 2)
        except (IndexError, ValueError): size_mb = 0.0
        dbs.append({'name':name,'size_mb':size_mb,'tables':0,'engine':'postgresql'})
    return dbs, None

def _pg_rows(query, db):
    """Run a query with unaligned, tuples-only output and split rows on '|'."""
    path = _mk_tmp('.sql', 0o644)
    with open(path, 'w') as tf:
        tf.write(query + '\n')
    out, err, rc = sh(f'{_pg_prefix()}psql -X -d {shlex.quote(db)} -t -A -v ON_ERROR_STOP=1 -f {shlex.quote(path)}', timeout=120)
    _unlink(path)
    if rc != 0:
        return None, (err or 'PostgreSQL error').strip()[:400]
    return [l.split('|') for l in out.split('\n') if l.strip()], None

# --- MongoDB helpers ------------------------------------------------------------
def _mongo_bin():
    return 'mongosh' if shutil.which('mongosh') else 'mongo'

def _mongo_js(js, timeout=120):
    """Run a mongosh (or legacy mongo) script from a temp file - names and
    passwords are embedded with json.dumps, never through shell quoting."""
    path = _mk_tmp('.js')
    with open(path, 'w') as tf:
        tf.write(js)
    out, err, rc = sh(f'{_mongo_bin()} --quiet {shlex.quote(path)}', timeout)
    _unlink(path)
    if rc != 0:
        return None, (err or out or 'MongoDB error').strip()[:400]
    return out, None

def _json_lines(out):
    res = []
    for line in (out or '').split('\n'):
        line = line.strip()
        if not line.startswith('{'): continue
        try: res.append(json.loads(line))
        except ValueError: pass
    return res

def mongo_dbs():
    out, err = _mongo_js(
        "db.adminCommand({listDatabases:1}).databases.forEach(d => "
        "print(JSON.stringify({name: d.name, size: Number(d.sizeOnDisk) || 0})));\n", timeout=30)
    if err: return [], 'MongoDB connection failed: ' + err
    dbs = []
    for d in _json_lines(out):
        if not d.get('name') or d['name'] in _SYSTEM_DBS['mongodb']: continue
        try: size_mb = round(float(d.get('size') or 0) / 1024 / 1024, 2)
        except (TypeError, ValueError): size_mb = 0.0
        dbs.append({'name':d['name'],'size_mb':size_mb,'tables':0,'engine':'mongodb'})
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
        total = round(sum(float(d.get('size_mb') or 0) for d in dbs), 2)
        return jsonify({'ok':True,'databases':dbs,'engines':engines,'active_engine':engine,
            'info':{'version':ver,'connections':conns,'total_size_mb':total}})

    elif engine == 'postgresql':
        dbs, err = pg_dbs()
        if err:
            return jsonify({'ok':False,'error':err,'databases':[],'engines':engines,'active_engine':engine})
        ver_raw, _ = pg_cmd('SHOW server_version;')
        ver = ver_raw.strip().split(' ')[0] if ver_raw else ''
        conns_raw, _ = pg_cmd('SELECT count(*) FROM pg_stat_activity;')
        total = round(sum(float(d.get('size_mb') or 0) for d in dbs), 2)
        return jsonify({'ok':True,'databases':dbs,'engines':engines,'active_engine':engine,
            'info':{'version':ver,'connections':(conns_raw or '').strip() or 'N/A','total_size_mb':total}})

    elif engine == 'mongodb':
        dbs, err = mongo_dbs()
        if err:
            return jsonify({'ok':False,'error':err,'databases':[],'engines':engines,'active_engine':engine})
        ver, _, _ = sh('mongod --version 2>/dev/null | grep -oP "[0-9]+[.][0-9]+[.][0-9]+" | head -1')
        total = round(sum(float(d.get('size_mb') or 0) for d in dbs), 2)
        return jsonify({'ok':True,'databases':dbs,'engines':engines,'active_engine':engine,
            'info':{'version':ver or '','connections':'N/A','total_size_mb':total}})

    return jsonify({'ok':True,'databases':[],'engines':engines,'active_engine':engine})

def _pg_ensure_role(user, pwd):
    u = user.replace('"', '""')
    lit = user.replace("'", "''")
    return pg_cmd(
        "DO $vp$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='%s') THEN "
        "CREATE ROLE \"%s\" LOGIN PASSWORD '%s'; END IF; END$vp$;" % (lit, u, _pg_escape(pwd)))

def _pg_grant(db, user):
    """GRANT ALL ON DATABASE alone does not allow creating tables in the public
    schema on PostgreSQL 15+, so also grant on the schema inside that database."""
    _, err = pg_cmd('GRANT ALL PRIVILEGES ON DATABASE "%s" TO "%s";' % (db, user))
    if err: return err
    _, err = pg_cmd('GRANT ALL ON SCHEMA public TO "%s";' % user, db=db)
    return err

def _mongo_create_user(user, pwd, db):
    roles = [{'role': 'readWrite', 'db': db}] if db else [{'role': 'read', 'db': 'admin'}]
    _, err = _mongo_js('db.getSiblingDB("admin").createUser({user: %s, pwd: %s, roles: %s});\n'
                       % (json.dumps(user), json.dumps(pwd), json.dumps(roles)), timeout=30)
    return err

@databases_bp.route('/api/databases', methods=['POST'])
def create_db():
    if not req(): return jsonify({'ok':False}), 401
    d      = request.get_json() or {}
    name   = re.sub(r'[^a-zA-Z0-9_]','', d.get('name','') or '')[:64]
    user   = re.sub(r'[^a-zA-Z0-9_]','', d.get('user', '') or '')[:32]
    pwd    = d.get('password','') or d.get('pass','')
    engine = d.get('engine','mysql')
    if not name: return jsonify({'ok':False,'error':'Database name required'})
    if name.lower() in _SYSTEM_DBS.get(_engine_family(engine), set()):
        return jsonify({'ok':False,'error':'That name is reserved by the database engine'})

    if engine in ('mysql','mariadb'):
        _, err = mysql_cmd(f'CREATE DATABASE IF NOT EXISTS `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;')
        if err: return jsonify({'ok':False,'error':err})
        if user and pwd:
            _, err = mysql_cmd(f"CREATE USER IF NOT EXISTS '{user}'@'localhost' IDENTIFIED BY '{_sql_escape(pwd)}';\n"
                               f"GRANT ALL PRIVILEGES ON `{name}`.* TO '{user}'@'localhost'; FLUSH PRIVILEGES;")
            if err: return jsonify({'ok':False,'error':'Database created, but the user could not be set up: '+err})
        return jsonify({'ok':True,'name':name})

    elif engine == 'postgresql':
        _, err, rc = sh(f"{_pg_prefix()}createdb {shlex.quote(name)}", 60)
        if rc != 0: return jsonify({'ok':False,'error':err or 'Failed to create PostgreSQL database'})
        if user and pwd:
            _, err = _pg_ensure_role(user, pwd)
            if not err:
                _, err = pg_cmd('ALTER DATABASE "%s" OWNER TO "%s";' % (name, user))
            if not err:
                err = _pg_grant(name, user)
            if err: return jsonify({'ok':False,'error':'Database created, but the user could not be set up: '+err})
        return jsonify({'ok':True,'name':name})

    elif engine == 'mongodb':
        _, err = _mongo_js('const d = db.getSiblingDB(%s); d.createCollection("_init"); d.getCollection("_init").drop();\n'
                           % json.dumps(name), timeout=30)
        if err: return jsonify({'ok':False,'error':err or 'Failed to create MongoDB database'})
        if user and pwd:
            err = _mongo_create_user(user, pwd, name)
            if err: return jsonify({'ok':False,'error':'Database created, but the user could not be set up: '+err})
        return jsonify({'ok':True,'name':name})

    return jsonify({'ok':False,'error':'Unknown engine'})


def _pg_tables(name):
    rows, err = _pg_rows(
        "SELECT schemaname, relname, n_live_tup, pg_total_relation_size(relid) "
        "FROM pg_stat_user_tables ORDER BY schemaname, relname;", name)
    if err: return None, err
    tables = []
    for r in rows:
        if len(r) < 4: continue
        try: rows_n = int(r[2] or 0)
        except ValueError: rows_n = 0
        try: size = int(r[3] or 0)
        except ValueError: size = 0
        full = r[1] if r[0] == 'public' else f'{r[0]}.{r[1]}'
        tables.append({'name': full, 'engine': 'PostgreSQL', 'collation': r[0],
                       'rows': rows_n, 'size_bytes': size})
    return tables, None


def _mongo_tables(name):
    js = (
        "const d = db.getSiblingDB(%s);\n"
        "d.getCollectionInfos({type:'collection'}).forEach(ci => {\n"
        "  const c = ci.name; if (c.startsWith('system.')) return;\n"
        "  let n = 0, sz = 0;\n"
        "  try { const s = d.getCollection(c).aggregate([{$collStats:{storageStats:{}}}]).next().storageStats;\n"
        "        n = s.count || 0; sz = (s.storageSize || 0) + (s.totalIndexSize || 0); } catch (e) {}\n"
        "  print(JSON.stringify({name:c, rows:Number(n), size_bytes:Number(sz)}));\n"
        "});\n") % json.dumps(name)
    out, err = _mongo_js(js)
    if err: return None, err
    tables = []
    for t in _json_lines(out):
        if 'name' not in t: continue
        tables.append({'name': t['name'], 'engine': 'WiredTiger', 'collation': 'collection',
                       'rows': int(t.get('rows') or 0), 'size_bytes': int(t.get('size_bytes') or 0)})
    return tables, None


@databases_bp.route('/api/databases/<name>/tables')
def list_tables(name):
    if not req(): return jsonify({'ok':False}), 401
    engine = request.args.get('engine', 'mysql')
    if engine == 'postgresql':
        if not _valid_dbname(name):
            return jsonify({'ok':False,'error':'Invalid database name'}), 400
        tables, err = _pg_tables(name)
        return jsonify({'ok':False,'error':err}) if err else jsonify({'ok':True,'tables':tables})
    if engine == 'mongodb':
        if not _valid_mongo_name(name):
            return jsonify({'ok':False,'error':'Invalid database name'}), 400
        tables, err = _mongo_tables(name)
        return jsonify({'ok':False,'error':err}) if err else jsonify({'ok':True,'tables':tables})
    if not _valid_dbname(name):
        return jsonify({'ok':False,'error':'Invalid database name'}), 400
    raw, err = mysql_cmd(f'SHOW TABLE STATUS FROM `{name}`;', timeout=60)
    if err:
        return jsonify({'ok':False,'error':err})
    lines = [l for l in raw.split('\n') if l.strip()]
    if not lines:
        return jsonify({'ok':True,'tables':[]})
    header = lines[0].split('\t')
    idx = {h:i for i,h in enumerate(header)}
    def col(parts, key, default=''):
        i = idx.get(key)
        if i is None or i >= len(parts): return default
        v = parts[i]
        return default if v in ('NULL', '') else v
    tables = []
    for line in lines[1:]:
        parts = line.split('\t')
        if not parts or not parts[0]: continue
        try:
            data_len = int(col(parts, 'Data_length', '0') or 0)
            index_len = int(col(parts, 'Index_length', '0') or 0)
        except ValueError:
            data_len = index_len = 0
        try:
            rows = int(col(parts, 'Rows', '0') or 0)
        except ValueError:
            rows = 0
        tables.append({
            'name': col(parts, 'Name'),
            'engine': col(parts, 'Engine', '-'),
            'collation': col(parts, 'Collation', '-'),
            'rows': rows,
            'size_bytes': data_len + index_len,
        })
    return jsonify({'ok':True,'tables':tables})


@databases_bp.route('/api/databases/<name>/tables/<table>/action', methods=['POST'])
def table_action(name, table):
    if not req(): return jsonify({'ok':False}), 401
    engine = request.args.get('engine', 'mysql')
    action = (request.get_json() or {}).get('action', '')
    if engine == 'postgresql':
        parts = table.split('.')
        if not _valid_dbname(name) or len(parts) > 2 or not all(_valid_ident(p) for p in parts):
            return jsonify({'ok':False,'error':'Invalid database or table name'}), 400
        qualified = '.'.join(f'"{p}"' for p in parts)
        if action == 'vacuum':
            q = f'VACUUM (ANALYZE) {qualified};'
        elif action == 'reindex':
            q = f'REINDEX TABLE {qualified};'
        elif action == 'analyze':
            q = f'ANALYZE {qualified};'
        else:
            return jsonify({'ok':False,'error':'Unknown action'}), 400
        rows, err = _pg_rows(q, name)
        return jsonify({'ok':False,'error':err}) if err else jsonify({'ok':True,'output':'done'})
    if engine == 'mongodb':
        if not _valid_mongo_name(name) or not _valid_mongo_name(table):
            return jsonify({'ok':False,'error':'Invalid database or collection name'}), 400
        if action == 'compact':
            cmd = '{compact: %s}' % json.dumps(table)
        elif action == 'validate':
            cmd = '{validate: %s, full: true}' % json.dumps(table)
        else:
            return jsonify({'ok':False,'error':'Unknown action'}), 400
        out, err = _mongo_js('const r = db.getSiblingDB(%s).runCommand(%s);\n'
                             'print(JSON.stringify({ok: r.ok, valid: r.valid, errmsg: r.errmsg || ""}));\n'
                             % (json.dumps(name), cmd), timeout=600)
        if err: return jsonify({'ok':False,'error':err})
        res_l = _json_lines(out)
        if not res_l:
            return jsonify({'ok':False,'error':'Unexpected MongoDB response'})
        res = res_l[-1]
        if not res.get('ok'):
            return jsonify({'ok':False,'error':res.get('errmsg') or 'Command failed'})
        if action == 'validate' and res.get('valid') is False:
            return jsonify({'ok':False,'error':'Validation found problems in this collection - check the mongod log'})
        return jsonify({'ok':True,'output':'done'})
    if not _valid_dbname(name) or not _valid_ident(table):
        return jsonify({'ok':False,'error':'Invalid database or table name'}), 400
    if action == 'repair':
        out, err = mysql_cmd(f'REPAIR TABLE `{table}`;', db=name, timeout=1800)
    elif action == 'optimize':
        out, err = mysql_cmd(f'OPTIMIZE TABLE `{table}`;', db=name, timeout=1800)
    elif action in ('innodb', 'myisam'):
        engine = 'InnoDB' if action == 'innodb' else 'MyISAM'
        out, err = mysql_cmd(f'ALTER TABLE `{table}` ENGINE={engine};', db=name, timeout=1800)
    else:
        return jsonify({'ok':False,'error':'Unknown action'}), 400
    if err:
        return jsonify({'ok':False,'error':err})
    # REPAIR/OPTIMIZE report problems as result rows, not as errors
    for line in out.split('\n')[1:]:
        cols = line.split('\t')
        if len(cols) >= 4 and cols[2].strip().lower() == 'error':
            return jsonify({'ok':False,'error':cols[3].strip(),'output':out})
    return jsonify({'ok':True,'output':out})


def _check_db_name(engine, name):
    fam = _engine_family(engine)
    if fam == 'mongodb':
        ok = _valid_mongo_name(name)
    elif fam in ('mysql', 'postgresql'):
        ok = _valid_dbname(name)
    else:
        return 'Unknown engine'
    if not ok:
        return 'Invalid database name'
    return None


@databases_bp.route('/api/databases/<name>', methods=['DELETE'])
def drop_db(name):
    if not req(): return jsonify({'ok':False}), 401
    engine = request.args.get('engine','mysql')
    bad = _check_db_name(engine, name)
    if bad: return jsonify({'ok':False,'error':bad}), 400
    if name.lower() in _SYSTEM_DBS.get(_engine_family(engine), set()):
        return jsonify({'ok':False,'error':'Refusing to drop a system database'}), 400
    if engine in ('mysql','mariadb'):
        _, err = mysql_cmd(f'DROP DATABASE IF EXISTS `{name}`;', timeout=300)
    elif engine == 'postgresql':
        _, err, rc = sh(f"{_pg_prefix()}dropdb {shlex.quote(name)}", 300)
        err = (err or 'dropdb failed') if rc != 0 else None
    else:
        _, err = _mongo_js('db.getSiblingDB(%s).dropDatabase();\n' % json.dumps(name), timeout=300)
    if err: return jsonify({'ok':False,'error':err})
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/<name>/export')
def export_db(name):
    if not req(): return jsonify({'ok':False}), 401
    engine = request.args.get('engine','mysql')
    bad = _check_db_name(engine, name)
    if bad: return jsonify({'ok':False,'error':bad}), 400
    # Large databases take a while; gthread workers keep heartbeating while a
    # request thread runs, so a long subprocess timeout is safe here.
    if engine in ('mysql','mariadb'):
        tmp = _mk_tmp('.sql')
        _, err = _mysql_run(_mysql_bin('dump'),
                            f'--single-transaction --routines --triggers {shlex.quote(name)} > {shlex.quote(tmp)}', 3600)
        rc = 1 if err else 0
    elif engine == 'postgresql':
        tmp = _mk_tmp('.sql')
        _, err, rc = sh(f"{_pg_prefix()}pg_dump {shlex.quote(name)} > {shlex.quote(tmp)}", 3600)
    elif engine == 'mongodb':
        if not shutil.which('mongodump'):
            return jsonify({'ok':False,'error':'mongodump is not installed (package mongodb-database-tools)'}), 500
        tmp = _mk_tmp('.archive.gz')
        _, err, rc = sh(f"mongodump --db={shlex.quote(name)} --archive={shlex.quote(tmp)} --gzip", 3600)
        if rc == 0 and os.path.getsize(tmp) > 0:
            return _send_and_delete(tmp, f'{name}.archive.gz', 'application/gzip')
        _unlink(tmp)
        return jsonify({'ok':False,'error':'Export failed: ' + (err or '')[:400]}), 500
    else:
        return jsonify({'ok':False,'error':'Unknown engine'})
    if rc == 0 and os.path.exists(tmp) and os.path.getsize(tmp) > 0:
        return _send_and_delete(tmp, f'{name}.sql', 'application/sql')
    _unlink(tmp)
    return jsonify({'ok':False,'error':'Export failed: ' + (err or '')[:400]}), 500

@databases_bp.route('/api/databases/<name>/import', methods=['POST'])
def import_db(name):
    if not req(): return jsonify({'ok':False}), 401
    engine = request.args.get('engine','mysql')
    bad = _check_db_name(engine, name)
    if bad: return jsonify({'ok':False,'error':bad}), 400
    if engine not in ('mysql', 'mariadb', 'postgresql'):
        return jsonify({'ok':False,'error':'Import is supported for MySQL/MariaDB and PostgreSQL (.sql or .sql.gz)'})
    f = request.files.get('file')
    if not f: return jsonify({'ok':False,'error':'No file uploaded'})
    tmp = _mk_tmp('.sql', 0o644)
    raw = None
    try:
        f.save(tmp)
        with open(tmp, 'rb') as fh:
            magic = fh.read(4)
        if magic[:2] == b'\x1f\x8b':
            import gzip
            raw, tmp = tmp, _mk_tmp('.sql', 0o644)
            try:
                with gzip.open(raw, 'rb') as src, open(tmp, 'wb') as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
            except (OSError, EOFError) as e:
                return jsonify({'ok':False,'error':f'Could not decompress the uploaded file: {e}'})
        elif magic[:4] == b'PK\x03\x04':
            return jsonify({'ok':False,'error':'ZIP archives are not supported - upload a .sql or .sql.gz file'})
        if engine in ('mysql','mariadb'):
            _, err = _mysql_run(_mysql_bin(), f'{shlex.quote(name)} < {shlex.quote(tmp)}', 3600)
        else:
            _, err, rc = sh(f"{_pg_prefix()}psql -X -q -v ON_ERROR_STOP=1 -d {shlex.quote(name)} -f {shlex.quote(tmp)}", 3600)
            err = (err or 'psql failed') if rc != 0 else None
    finally:
        _unlink(tmp)
        if raw: _unlink(raw)
    if err:
        return jsonify({'ok':False,'error':'Import failed: ' + err[:400]})
    return jsonify({'ok':True,'error':None})

@databases_bp.route('/api/databases/users')
def list_users():
    if not req(): return jsonify({'ok':False}), 401
    engine = request.args.get('engine','auto')
    if engine == 'auto':
        engines = detect_engines()
        if not engines: return jsonify({'ok':True,'users':[]})
        engine = engines[0]['id']
    if engine in ('mysql','mariadb'):
        raw, err = mysql_cmd("SELECT user,host FROM mysql.user WHERE user NOT IN "
                             "('root','mysql.sys','mysql.infoschema','mysql.session','mariadb.sys','debian-sys-maint','') ORDER BY user;")
        if err: return jsonify({'ok':False,'error':err,'users':[]})
        users = []
        for line in raw.split('\n')[1:]:
            parts = line.strip().split('\t')
            if len(parts)>=2 and parts[0]:
                u, h = parts[0], parts[1]
                grants_raw, _ = mysql_cmd(f"SHOW GRANTS FOR '{_sql_escape(u)}'@'{_sql_escape(h)}';")
                dbs = []
                for gline in grants_raw.split('\n'):
                    m = re.search(r'ON `?([A-Za-z0-9_$\\*-]+)`?\.\*', gline)
                    if m and m.group(1) != '*':
                        dbs.append(m.group(1).replace('\\_', '_'))
                users.append({'user':u,'host':h,'databases':dbs})
        return jsonify({'ok':True,'users':users})
    elif engine == 'postgresql':
        raw, err = pg_cmd("SELECT usename FROM pg_user WHERE usename != 'postgres' ORDER BY usename;")
        if err: return jsonify({'ok':False,'error':err,'users':[]})
        users = [{'user':l.strip(),'host':'localhost'} for l in raw.split('\n') if l.strip()]
        return jsonify({'ok':True,'users':users})
    elif engine == 'mongodb':
        out, err = _mongo_js('db.getSiblingDB("admin").getCollection("system.users").find({}, {user:1, db:1})'
                             '.forEach(u => print(JSON.stringify({user: u.user, db: u.db})));\n', timeout=30)
        if err: return jsonify({'ok':False,'error':err,'users':[]})
        users = [{'user':u['user'],'host':u.get('db') or 'admin'} for u in _json_lines(out) if u.get('user')]
        return jsonify({'ok':True,'users':users})
    return jsonify({'ok':True,'users':[]})

@databases_bp.route('/api/databases/users', methods=['POST'])
def create_user():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    user   = re.sub(r'[^a-zA-Z0-9_]','', d.get('user','') or '')[:32]
    pwd    = d.get('password','')
    db     = (d.get('database','') or '').strip()
    host   = (d.get('host','') or 'localhost').strip()
    engine = d.get('engine','mysql')
    if not user or not pwd: return jsonify({'ok':False,'error':'Username and password required'})
    if user.lower() in ('root', 'postgres', 'mysql', 'debian-sys-maint'):
        return jsonify({'ok':False,'error':'That username is reserved'})
    if db:
        bad = _check_db_name(engine, db)
        if bad: return jsonify({'ok':False,'error':bad})
    if engine in ('mysql','mariadb'):
        if not _valid_host(host): return jsonify({'ok':False,'error':'Invalid host'})
        q = f"CREATE USER '{user}'@'{_sql_escape(host)}' IDENTIFIED BY '{_sql_escape(pwd)}';\n"
        if db: q += f"GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'{_sql_escape(host)}';\n"
        _, err = mysql_cmd(q + "FLUSH PRIVILEGES;")
    elif engine == 'postgresql':
        _, err = pg_cmd("CREATE ROLE \"%s\" LOGIN PASSWORD '%s';" % (user, _pg_escape(pwd)))
        if not err and db: err = _pg_grant(db, user)
    elif engine == 'mongodb':
        err = _mongo_create_user(user, pwd, db)
    else:
        err = 'Unknown engine'
    if err: return jsonify({'ok':False,'error':err})
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/users/<user>', methods=['DELETE'])
def drop_user(user):
    if not req(): return jsonify({'ok':False}), 401
    user = re.sub(r'[^a-zA-Z0-9_]','', user)
    engine = request.args.get('engine','mysql')
    host   = request.args.get('host','localhost')
    if not user or user.lower() in ('root', 'postgres'):
        return jsonify({'ok':False,'error':'Invalid or protected user'}), 400
    if engine in ('mysql','mariadb'):
        if not _valid_host(host): return jsonify({'ok':False,'error':'Invalid host'}), 400
        _, err = mysql_cmd(f"DROP USER IF EXISTS '{user}'@'{_sql_escape(host)}'; FLUSH PRIVILEGES;")
    elif engine == 'postgresql':
        _, err = pg_cmd('DROP ROLE IF EXISTS "%s";' % user)
    elif engine == 'mongodb':
        _, err = _mongo_js('db.getSiblingDB("admin").dropUser(%s);\n' % json.dumps(user), timeout=30)
    else:
        err = 'Unknown engine'
    if err: return jsonify({'ok':False,'error':err})
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/users/<user>/password', methods=['PUT'])
def change_password(user):
    if not req(): return jsonify({'ok':False}), 401
    user = re.sub(r'[^a-zA-Z0-9_]','', user)
    d = request.get_json() or {}
    pwd    = d.get('password','')
    engine = d.get('engine','mysql')
    host   = (d.get('host','') or 'localhost').strip()
    if not user: return jsonify({'ok':False,'error':'Invalid user'})
    if not pwd: return jsonify({'ok':False,'error':'Password required'})
    if engine in ('mysql','mariadb'):
        if not _valid_host(host): return jsonify({'ok':False,'error':'Invalid host'})
        _, err = mysql_cmd(f"ALTER USER '{user}'@'{_sql_escape(host)}' IDENTIFIED BY '{_sql_escape(pwd)}'; FLUSH PRIVILEGES;")
    elif engine == 'postgresql':
        _, err = pg_cmd("ALTER ROLE \"%s\" WITH PASSWORD '%s';" % (user, _pg_escape(pwd)))
    elif engine == 'mongodb':
        _, err = _mongo_js('db.getSiblingDB("admin").updateUser(%s, {pwd: %s});\n'
                           % (json.dumps(user), json.dumps(pwd)), timeout=30)
    else:
        err = 'Unknown engine'
    if err: return jsonify({'ok':False,'error':err})
    return jsonify({'ok':True})

@databases_bp.route('/api/databases/users/<user>/grant', methods=['POST'])
def grant_db(user):
    if not req(): return jsonify({'ok':False}), 401
    user = re.sub(r'[^a-zA-Z0-9_]','', user)
    d = request.get_json() or {}
    db     = (d.get('database','') or '').strip()
    host   = (d.get('host','') or 'localhost').strip()
    engine = d.get('engine','mysql')
    if not user: return jsonify({'ok':False,'error':'Invalid user'})
    if not db: return jsonify({'ok':False,'error':'Database required'})
    bad = _check_db_name(engine, db)
    if bad: return jsonify({'ok':False,'error':bad})
    if engine in ('mysql','mariadb'):
        if not _valid_host(host): return jsonify({'ok':False,'error':'Invalid host'})
        _, err = mysql_cmd(f"GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'{_sql_escape(host)}'; FLUSH PRIVILEGES;")
    elif engine == 'postgresql':
        err = _pg_grant(db, user)
    elif engine == 'mongodb':
        _, err = _mongo_js('db.getSiblingDB("admin").grantRolesToUser(%s, [{role: "readWrite", db: %s}]);\n'
                           % (json.dumps(user), json.dumps(db)), timeout=30)
    else:
        err = 'Unknown engine'
    if err: return jsonify({'ok':False,'error':err})
    return jsonify({'ok':True})
