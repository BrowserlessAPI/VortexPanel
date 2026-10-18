"""Server-to-server migration.

The new server ("target") turns on Receive and shows a migration key. The old
server ("source") pastes the key, picks websites and databases and sends them.

Nothing on the source is changed or stopped: files are read with tar at the
lowest CPU/disk priority, MySQL/MariaDB databases are dumped with
--single-transaction (no table locks for InnoDB) and PostgreSQL with pg_dump
(a consistent snapshot without locking writers). The sites keep serving
during and after the transfer; the switch happens when DNS is pointed at the
new server. "Sync again" repeats the transfer for sites this migration
created, so the copy can be refreshed right before the DNS change.

On the target a site is built in a staging folder and only moved into place
when it is complete; a failed site is removed again, existing sites and
databases that were not created by a migration are never overwritten.

Transport: every request and answer is encrypted (AES-256-CTR) and
authenticated (HMAC-SHA256, with the time and the operation name) with keys
derived from the secret in the migration key, so a panel served over plain
HTTP or a self-signed certificate does not expose data, and the secret itself
never travels. Receive endpoints live under /api/hooks/ (no session, no
entrance path) and answer 404 while Receive is off.
"""
import os, re, json, time, uuid, hmac, hashlib, base64, secrets, shutil, shlex, subprocess, threading
from flask import Blueprint, jsonify, request, current_app, Response
from panel.utils.authctx import authed as _vp_authed
from panel.routes.job_state import save_job, load_job

migration_bp = Blueprint('migration', __name__)

DATA = '/opt/vortexpanel/data'
RECV_FILE = DATA + '/migrate_recv.json'
LEDGER = DATA + '/migrate_ledger.json'
INBOX = '/opt/vortexpanel/migrate_in'
CANCEL_DIR = DATA + '/migrate_cancel'
CHUNK = 8 * 1024 * 1024
PROTO = 1
KEY_HOURS = 24
_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$')
_TID_RE = re.compile(r'^[0-9a-f]{16}$')


def req():
    return _vp_authed()


def _sh(cmd, t=60, inp=None):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t, input=inp)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, '', f'timed out after {t}s'


def _version():
    for p in ('/opt/vortexpanel/VERSION',):
        try:
            return open(p).read().strip()
        except OSError:
            pass
    return ''


# --- crypto -----------------------------------------------------------------------
def _keys(secret):
    return (hmac.new(secret, b'vp-migrate-enc', hashlib.sha256).digest(),
            hmac.new(secret, b'vp-migrate-mac', hashlib.sha256).digest())


def _ctr(key, iv, data):
    r = subprocess.run(['openssl', 'enc', '-aes-256-ctr', '-K', key.hex(), '-iv', iv.hex()],
                       input=data, capture_output=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError('openssl: ' + r.stderr.decode(errors='replace')[:200])
    return r.stdout


def seal(secret, label, data):
    ek, mk = _keys(secret)
    iv = os.urandom(16)
    ct = _ctr(ek, iv, data)
    ts = b'%010d' % int(time.time())
    mac = hmac.new(mk, label.encode() + b'|' + ts + b'|' + iv + ct, hashlib.sha256).digest()
    return ts + iv + mac + ct


def unseal(secret, label, blob, max_age=900):
    if len(blob) < 58:
        raise ValueError('short message')
    ts, iv, mac, ct = blob[:10], blob[10:26], blob[26:58], blob[58:]
    if not ts.isdigit() or abs(time.time() - int(ts)) > max_age:
        raise ValueError('message too old - check that both servers have the correct time')
    ek, mk = _keys(secret)
    want = hmac.new(mk, label.encode() + b'|' + ts + b'|' + iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, want):
        raise ValueError('authentication failed')
    return _ctr(ek, iv, ct)


def _b64e(b):
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


def _b64d(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def make_token(url, secret):
    return 'VPM1-' + _b64e(json.dumps({'u': url, 'k': _b64e(secret)}).encode())


def parse_token(token):
    token = (token or '').strip()
    if not token.startswith('VPM1-'):
        raise ValueError('This is not a VortexPanel migration key')
    try:
        d = json.loads(_b64d(token[5:]))
        url, secret = d['u'].rstrip('/'), _b64d(d['k'])
    except Exception:
        raise ValueError('The migration key is incomplete - copy it again')
    if not re.match(r'^https?://[^\s/]+$', url) or len(secret) != 32:
        raise ValueError('The migration key is not valid')
    return url, secret


# --- receiving side: state -----------------------------------------------------------
def _recv_state():
    try:
        st = json.load(open(RECV_FILE))
    except Exception:
        return None
    if st.get('expires', 0) < time.time():
        return None
    return st


def _write_private(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(data)


def _ledger():
    try:
        return json.load(open(LEDGER))
    except Exception:
        return {'sites': {}, 'databases': {}}


def _ledger_add(kind, name, info):
    lg = _ledger()
    lg.setdefault(kind, {})[name] = info
    _write_private(LEDGER, json.dumps(lg, indent=1))


@migration_bp.route('/api/migration/receive', methods=['GET', 'POST'])
def receive_settings():
    if not req(): return jsonify({'ok': False}), 401
    if request.method == 'POST':
        d = request.get_json() or {}
        if not d.get('enable'):
            try: os.remove(RECV_FILE)
            except OSError: pass
            return jsonify({'ok': True, 'enabled': False})
        url = (d.get('url') or request.host_url).strip().rstrip('/')
        if not re.match(r'^https?://[^\s/]+$', url):
            return jsonify({'ok': False, 'error': 'Enter the address as http(s)://host:port'}), 400
        secret = secrets.token_bytes(32)
        st = {'secret': _b64e(secret), 'url': url, 'created': int(time.time()),
              'expires': int(time.time()) + KEY_HOURS * 3600}
        _write_private(RECV_FILE, json.dumps(st))
    st = _recv_state()
    if not st:
        return jsonify({'ok': True, 'enabled': False, 'suggested_url': request.host_url.rstrip('/'),
                        'migrated': _ledger()})
    return jsonify({'ok': True, 'enabled': True, 'url': st['url'], 'expires': st['expires'],
                    'token': make_token(st['url'], _b64d(st['secret'])), 'migrated': _ledger()})


# --- receiving side: endpoints (authenticated by the migration key) -----------------
def _hook_reply(secret, op, obj, code=200):
    return Response(seal(secret, 'resp:' + op, json.dumps(obj).encode()), code,
                    mimetype='application/octet-stream')


@migration_bp.route('/api/hooks/migrate/<op>', methods=['POST'])
def hook(op):
    st = _recv_state()
    if not st or op not in ('hello', 'chunk', 'site', 'database', 'cron', 'job', 'finish'):
        return jsonify({'ok': False, 'error': 'Not found'}), 404
    secret = _b64d(st['secret'])
    try:
        payload = unseal(secret, 'req:' + op, request.get_data())
    except ValueError as e:
        return jsonify({'ok': False, 'error': f'Migration key rejected: {e}'}), 403
    if op == 'chunk':
        n = int.from_bytes(payload[:4], 'big')
        meta, data = json.loads(payload[4:4 + n]), payload[4 + n:]
        return _hook_reply(secret, op, _recv_chunk(meta, data))
    d = json.loads(payload or b'{}')
    if op == 'hello':
        return _hook_reply(secret, op, _target_info())
    if op == 'job':
        jid = str(d.get('job') or '')
        if not re.fullmatch(r'mig-[0-9a-f]{12}', jid):
            return _hook_reply(secret, op, {'ok': False, 'error': 'Invalid job'})
        return _hook_reply(secret, op, {'ok': True, **(load_job(jid) or {'done': True, 'ok': False, 'log': ['job lost']})})
    if op == 'finish':
        tid = str(d.get('tid') or '')
        if _TID_RE.match(tid):
            shutil.rmtree(f'{INBOX}/{tid}', ignore_errors=True)
        return _hook_reply(secret, op, {'ok': True})
    if op == 'cron':
        return _hook_reply(secret, op, _recv_cron(d))
    jid = 'mig-' + uuid.uuid4().hex[:12]
    save_job(jid, {'done': False, 'ok': False, 'log': []})
    fn = _recv_site if op == 'site' else _recv_database
    threading.Thread(target=fn, args=(current_app._get_current_object(), jid, d), daemon=True).start()
    return _hook_reply(secret, op, {'ok': True, 'job': jid})


def _db_names(res):
    rows = res[0] if isinstance(res, tuple) else res
    return [x['name'] if isinstance(x, dict) else x for x in (rows or [])]


def _php_installed():
    try:
        from panel.routes.php import installed_php_layouts
        return sorted({l['ver'] for l in installed_php_layouts() if l.get('ver')},
                      key=lambda v: [int(x) for x in v.split('.')])
    except Exception:
        return []


def _target_info():
    from panel.routes.websites_core import list_sites, get_webroot
    from panel.routes.wp_toolkit import _detect_webserver
    from panel.routes import databases as dbm
    engines = [e['id'] for e in dbm.detect_engines()]
    dbs = {}
    if 'mysql' in engines or 'mariadb' in engines:
        try: dbs['mysql'] = _db_names(dbm.mysql_dbs())
        except Exception: dbs['mysql'] = []
    if 'postgresql' in engines:
        try: dbs['postgresql'] = _db_names(dbm.pg_dbs())
        except Exception: dbs['postgresql'] = []
    root = get_webroot()
    try:
        free = shutil.disk_usage(root if os.path.isdir(root) else '/').free
    except OSError:
        free = 0
    return {'ok': True, 'proto': PROTO, 'version': _version(), 'hostname': os.uname().nodename,
            'webserver': _detect_webserver(), 'php': _php_installed(), 'engines': engines,
            'sites': [s['domain'] for s in list_sites()], 'databases': dbs, 'webroot': root,
            'free_bytes': free, 'migrated': _ledger()}


def _recv_chunk(meta, data):
    tid, name = str(meta.get('tid', '')), str(meta.get('name', ''))
    try:
        idx = int(meta.get('idx', -1))
    except (TypeError, ValueError):
        idx = -1
    if not _TID_RE.match(tid) or not _NAME_RE.match(name) or not 0 <= idx < 200000:
        return {'ok': False, 'error': 'invalid chunk'}
    if hashlib.sha256(data).hexdigest() != meta.get('sha'):
        return {'ok': False, 'error': 'chunk damaged in transit'}
    os.makedirs(f'{INBOX}/{tid}', mode=0o700, exist_ok=True)
    if shutil.disk_usage(INBOX).free < len(data) + 512 * 1024 * 1024:
        return {'ok': False, 'error': 'The new server is running out of disk space'}
    with open(f'{INBOX}/{tid}/{name}.p{idx:06d}', 'wb') as f:
        f.write(data)
    return {'ok': True}


def _assemble(tid, name, parts, sha):
    if not _TID_RE.match(tid or '') or not _NAME_RE.match(name or ''):
        raise ValueError('invalid transfer')
    base = f'{INBOX}/{tid}'
    out = f'{base}/{name}'
    h = hashlib.sha256()
    with open(out, 'wb') as w:
        for i in range(int(parts)):
            p = f'{base}/{name}.p{i:06d}'
            if not os.path.exists(p):
                raise ValueError(f'part {i} of {name} is missing')
            with open(p, 'rb') as r:
                while True:
                    b = r.read(1 << 20)
                    if not b: break
                    h.update(b); w.write(b)
            os.remove(p)
    if h.hexdigest() != sha:
        os.remove(out)
        raise ValueError(f'{name} does not match its checksum after the transfer')
    return out


class _Log:
    def __init__(self, jid):
        self.jid, self.lines, self.extra = jid, [], {}

    def __call__(self, line):
        self.lines.append(str(line))
        save_job(self.jid, {'done': False, 'ok': False, 'log': self.lines[-300:]})

    def finish(self, ok, **extra):
        st = {'done': True, 'ok': ok, 'log': self.lines[-300:]}
        st.update(extra)
        save_job(self.jid, st)


def _nearest_php(want):
    have = _php_installed()
    if not want or want == 'static' or want in have or not have:
        return want or 'static'
    return have[-1]


def _strip_maint(conf):
    return re.sub(r'[ \t]*#VP_MAINT_ALL\n.*?#VP_MAINT_ALL_END[^\n]*\n', '', conf, flags=re.S)


def _transplant_vhost(domain, src_conf, src_path, dst_path, extra_files, log):
    """nginx -> nginx: use the source vhost (custom rules, proxies, redirects,
    limits) adapted to this server. Returns True when applied."""
    from panel.routes.websites_core import _find_site_config
    fp, ws = _find_site_config(domain)
    if ws != 'nginx' or not fp:
        return False
    cur = open(fp).read()
    conf = _strip_maint(src_conf)
    if '#VP_ANUBIS' in conf:
        conf = re.sub(r'^[^\n]*#VP_ANUBIS[ \t]*\n', '', conf, flags=re.M)
        log('Bot protection was on for this website on the old server: turn it on here in the website window '
            '(Bot Protection) once it is installed from the App Store.')
    if src_path and src_path != dst_path:
        conf = re.sub(re.escape(src_path) + r'(?=[/;\s"\']|$)', dst_path, conf)
    sock = re.search(r'fastcgi_pass\s+([^;]+);', cur)
    if sock:
        conf = re.sub(r'(fastcgi_pass\s+)unix:[^;]+;', lambda m: m.group(1) + sock.group(1) + ';', conf)
    for k in ('ssl_certificate', 'ssl_certificate_key'):
        m = re.search(rf'^[ \t]*{k}\s+([^;]+);', cur, re.M)
        if m:
            conf = re.sub(rf'(^[ \t]*{k}\s+)[^;]+;', lambda x: x.group(1) + m.group(1) + ';', conf, flags=re.M)
    written = []
    for p, content in (extra_files or {}).items():
        rp = os.path.normpath(p)
        if not rp.startswith('/etc/nginx/') or '..' in p or os.path.exists(rp):
            continue
        os.makedirs(os.path.dirname(rp), exist_ok=True)
        _write_private(rp, content)
        os.chmod(rp, 0o640 if 'htpasswd' in rp else 0o644)
        written.append(rp)
    try:
        from panel.routes.websites_security import maint_wrap, MAINT_HTTP_CONF
        if os.path.exists(MAINT_HTTP_CONF):
            conf = maint_wrap(conf)
    except Exception:
        pass
    with open(fp, 'w') as f:
        f.write(conf)
    rc, out, err = _sh('nginx -t 2>&1')
    if rc != 0:
        with open(fp, 'w') as f:
            f.write(cur)
        for p in written:
            try: os.remove(p)
            except OSError: pass
        msg = (out + err).strip().splitlines()
        log('The source server\'s own vhost settings could not be used here (' + (msg[-2] if len(msg) > 1 else 'nginx -t failed')
            + ') - the site runs with this server\'s standard settings; check custom rules in the website\'s Config.')
        return False
    _sh('systemctl reload nginx')
    log('Applied the vhost settings of the old server (rewrite rules, proxies, redirects, limits).')
    return True


def _recv_site(app, jid, d):
    log = _Log(jid)
    created = False
    domain = str(d.get('domain') or '').lower()
    path = staging = None
    try:
        from panel.routes.websites_core import (is_valid_domain, _find_site_config, create_site_core,
                                                get_webroot, ensure_web_ownership)
        from panel.routes.wp_toolkit import _delete_vhost
        if not is_valid_domain(domain):
            raise ValueError('invalid domain')
        tid = str(d.get('tid') or '')
        resync = bool(d.get('resync'))
        lg = _ledger()['sites']
        fp, ws = _find_site_config(domain)
        if fp and not (resync and domain in lg):
            raise ValueError(f'{domain} already exists on this server' +
                             ('' if domain not in lg else ' (turn on "Sync again" to refresh it)'))
        archive = _assemble(tid, str(d.get('archive')), d.get('parts', 0), d.get('sha', ''))
        log(f'Received {domain} ({int(os.path.getsize(archive) / 1048576)} MB compressed).')
        php = _nearest_php(str(d.get('php') or 'static'))
        if php != (d.get('php') or 'static'):
            log(f'PHP {d.get("php")} is not installed here - the site uses PHP {php}. Install PHP {d.get("php")} '
                'in the App Store and switch the version if the site needs it.')
        if fp:
            path = lg[domain].get('path') or f'{get_webroot()}/{domain}'
        else:
            path = f'{get_webroot()}/{domain}'
            if os.path.exists(path) and os.listdir(path):
                raise ValueError(f'{path} already exists and is not empty')
            ok, res = create_site_core(domain, path, php)
            if not ok:
                raise ValueError(res.get('error') or 'site could not be created')
            created = True
            path = res.get('path') or path
            log(f'Created the website on {res.get("webserver", "")} with PHP {php}.')
        staging = f'{path}.vp-migrate-{tid}'
        shutil.rmtree(staging, ignore_errors=True)
        os.makedirs(staging, mode=0o755)
        rc, out, err = _sh(f'tar -xzf {shlex.quote(archive)} -C {shlex.quote(staging)} --no-same-owner '
                           '--no-overwrite-dir 2>&1', 3600)
        if rc != 0:
            raise ValueError('The files could not be unpacked: ' + (out + err)[-300:])
        os.remove(archive)
        ui = os.path.join(staging, '.user.ini')
        src_path = str(d.get('src_path') or '')
        if src_path and src_path != path and os.path.isfile(ui) and not os.path.islink(ui):
            # open_basedir of the old location would lock PHP out of the new one
            _sh(f'chattr -i {shlex.quote(ui)} 2>/dev/null')
            txt = open(ui, errors='replace').read()
            with open(ui, 'w') as f:
                f.write(txt.replace(src_path, path))
        ensure_web_ownership(staging, php if php != 'static' else None, _find_site_config(domain)[1])
        # swap in the complete copy: the site is never served half-copied
        old = f'{path}.vp-old-{int(time.time())}'
        if os.path.isdir(path):
            os.rename(path, old)
        os.rename(staging, path)
        staging = None
        shutil.rmtree(old, ignore_errors=True)
        log(f'Files are in place in {path}.')
        ssl = d.get('ssl') or {}
        if ssl.get('cert') and ssl.get('key'):
            from panel.routes.websites_ssl import install_manual_cert
            with app.app_context():
                r = install_manual_cert(domain, ssl['cert'], ssl['key'])
                r = (r[0] if isinstance(r, tuple) else r).get_json() or {}
            log('SSL certificate installed.' if r.get('ok') else f'SSL certificate not installed: {r.get("error")}')
            if r.get('ok') and ssl.get('letsencrypt'):
                log('Issue a new Let\'s Encrypt certificate here once DNS points to this server, '
                    'so it renews on this server.')
        if d.get('vhost') and d.get('src_webserver') == 'nginx':
            _transplant_vhost(domain, d['vhost'], d.get('src_path'), path, d.get('vhost_files'), log)
        _ledger_add('sites', domain, {'path': path, 'from': d.get('from', ''), 'time': int(time.time())})
        log(f'{domain} is ready on this server.')
        log.finish(True, path=path)
    except Exception as e:
        log(f'Failed: {e}')
        if staging:
            shutil.rmtree(staging, ignore_errors=True)
        if created:
            try:
                from panel.routes.wp_toolkit import _delete_vhost
                from panel.routes.websites_core import _find_site_config
                _delete_vhost(domain, _find_site_config(domain)[1])
                if path and os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                log('Removed the incomplete website again.')
            except Exception:
                pass
        log.finish(False)


# --- databases (receive) -----------------------------------------------------------
_PRIVS = {'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'REFERENCES', 'INDEX', 'ALTER',
          'CREATE TEMPORARY TABLES', 'LOCK TABLES', 'EXECUTE', 'CREATE VIEW', 'SHOW VIEW',
          'CREATE ROUTINE', 'ALTER ROUTINE', 'EVENT', 'TRIGGER', 'ALL PRIVILEGES', 'ALL', 'DELETE HISTORY'}


def _q(s):
    return "'" + str(s).replace('\\', '\\\\').replace("'", "\\'") + "'"


def _mysql_user(u, db, log, is_mariadb):
    from panel.routes import databases as dbm
    user, host = str(u.get('user', '')), str(u.get('host', 'localhost'))
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', user) or not re.fullmatch(r'[A-Za-z0-9_.%:-]{1,255}', host):
        log(f'Skipped database user {user!r}: unusual name')
        return
    who = f'{_q(user)}@{_q(host)}'
    out, err = dbm.mysql_cmd(f"SELECT COUNT(*) FROM mysql.user WHERE User={_q(user)} AND Host={_q(host)};")
    exists = (out or '').strip().splitlines()[-1:] == ['1']
    if not exists:
        done = False
        plugin, hsh = u.get('plugin', ''), u.get('hash', '')
        if plugin and hsh and re.fullmatch(r'[a-z0-9_]{3,40}', plugin):
            if re.fullmatch(r'0x[0-9A-Fa-f]{2,400}', hsh):
                ident = f'IDENTIFIED WITH {plugin} AS {hsh}'
            elif re.fullmatch(r'\*[0-9A-F]{40}', hsh):
                ident = (f'IDENTIFIED BY PASSWORD {_q(hsh)}' if is_mariadb
                         else f'IDENTIFIED WITH mysql_native_password AS {_q(hsh)}')
            else:
                ident = ''
            if ident and not (is_mariadb and plugin == 'caching_sha2_password'):
                _, e = dbm.mysql_cmd(f'CREATE USER {who} {ident};')
                done = not e
        if not done and u.get('password'):
            _, e = dbm.mysql_cmd(f'CREATE USER {who} IDENTIFIED BY {_q(u["password"])};')
            done = not e
            if done:
                log(f'Database user {user}@{host} created with the password from the site\'s configuration.')
        elif done:
            log(f'Database user {user}@{host} created (same password as before).')
        if not done:
            log(f'Database user {user}@{host} could not be created with its old password '
                f'(different database server type). Set a password in Databases > Users and update the site\'s configuration.')
            return
    else:
        log(f'Database user {user}@{host} already exists here - its password was not changed.')
    privs = [p.strip().upper() for p in str(u.get('privs') or 'ALL PRIVILEGES').split(',')]
    if not privs or any(p not in _PRIVS for p in privs):
        privs = ['ALL PRIVILEGES']
    _, e = dbm.mysql_cmd(f"GRANT {', '.join(privs)} ON `{db}`.* TO {who}; FLUSH PRIVILEGES;")
    if e:
        log(f'Could not grant {user} access to {db}: {e}')


def _recv_database(app, jid, d):
    log = _Log(jid)
    from panel.routes import databases as dbm
    engine = d.get('engine')
    name = str(d.get('name') or '')
    created = False
    try:
        if not re.fullmatch(r'[A-Za-z0-9_]{1,64}', name):
            raise ValueError('invalid database name')
        resync = bool(d.get('resync'))
        lg = _ledger()['databases']
        key = f'{engine}:{name}'
        archive = None
        engines = [e['id'] for e in dbm.detect_engines()]
        if engine == 'mysql':
            if not ({'mysql', 'mariadb'} & set(engines)):
                raise ValueError('MySQL/MariaDB is not installed on this server (App Store)')
            is_mariadb = 'mariadb' in engines or 'MariaDB' in (dbm.mysql_cmd('SELECT VERSION();')[0] or '')
            exists = name in _db_names(dbm.mysql_dbs())
            if exists and not (resync and key in lg):
                raise ValueError(f'A database named {name} already exists on this server')
            archive = _assemble(str(d.get('tid')), str(d.get('archive')), d.get('parts', 0), d.get('sha', ''))
            cs = d.get('charset') if re.fullmatch(r'[a-z0-9_]{2,40}', str(d.get('charset') or '')) else 'utf8mb4'
            co = str(d.get('collation') or '')
            if is_mariadb and '_0900_' in co:
                co = 'utf8mb4_unicode_ci'
            co_sql = f' COLLATE {co}' if re.fullmatch(r'[a-z0-9_]{2,60}', co) else ''
            if not exists:
                _, e = dbm.mysql_cmd(f'CREATE DATABASE `{name}` CHARACTER SET {cs}{co_sql};')
                if e: raise ValueError(e)
                created = True
            log(f'Importing {name} ({int(os.path.getsize(archive) / 1048576)} MB compressed)...')
            sql = archive + '.sql'
            # MySQL 8 collations (utf8mb4_0900_*) do not exist in MariaDB
            fix = "sed -E 's/utf8mb4_0900_[a-z_]+/utf8mb4_unicode_ci/g'" if is_mariadb else 'cat'
            rc, out, err = _sh(f'gzip -dc {shlex.quote(archive)} | {fix} > {shlex.quote(sql)}', 3600)
            if rc: raise ValueError('could not unpack the dump: ' + err[-200:])
            out, e = dbm._mysql_run(dbm._mysql_bin(), f'{shlex.quote(name)} < {shlex.quote(sql)}', 7200)
            os.remove(sql); os.remove(archive)
            if e: raise ValueError('import failed: ' + e[-400:])
            for u in d.get('users') or []:
                _mysql_user(u, name, log, is_mariadb)
        elif engine == 'postgresql':
            if 'postgresql' not in engines:
                raise ValueError('PostgreSQL is not installed on this server (App Store)')
            exists = name in _db_names(dbm.pg_dbs())
            if exists and not (resync and key in lg):
                raise ValueError(f'A database named {name} already exists on this server')
            archive = _assemble(str(d.get('tid')), str(d.get('archive')), d.get('parts', 0), d.get('sha', ''))
            owner = str(d.get('owner') or 'postgres')
            for r in d.get('roles') or []:
                rn, ph = str(r.get('name', '')), str(r.get('hash') or '')
                if not re.fullmatch(r'[a-z_][a-z0-9_]{0,62}', rn) or rn == 'postgres':
                    continue
                rc, out, _ = _sh(f"runuser -u postgres -- psql -tAc {shlex.quote(f'SELECT 1 FROM pg_roles WHERE rolname={_q(rn)}')}")
                if out.strip() == '1':
                    log(f'Role {rn} already exists here - its password was not changed.')
                    continue
                pw = f" PASSWORD {_q(ph)}" if re.fullmatch(r'(SCRAM-SHA-256\$[A-Za-z0-9+/=:$]{20,400}|md5[0-9a-f]{32})', ph) else ''
                rc, out, err = _sh(f"runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c {shlex.quote(f'CREATE ROLE {rn} LOGIN{pw}')}")
                if rc:
                    log(f'Role {rn} could not be created: {err[-200:]}')
                else:
                    log(f'Role {rn} created' + (' (same password as before).' if pw else ' without a password - set one in Databases.'))
            if not re.fullmatch(r'[a-z_][a-z0-9_]{0,62}', owner):
                owner = 'postgres'
            if not exists:
                rc, out, err = _sh(f'runuser -u postgres -- createdb -O {owner} {shlex.quote(name)}')
                if rc: raise ValueError(err[-300:])
                created = True
            log(f'Importing {name}...')
            clean = '--clean --if-exists ' if exists else ''
            # through stdin: the dump never becomes readable for the postgres user on disk
            rc, out, err = _sh(f'cd /tmp && runuser -u postgres -- pg_restore {clean}-d {shlex.quote(name)} < {shlex.quote(archive)} 2>&1', 7200)
            os.remove(archive)
            if rc and 'error' in (out + err).lower():
                errs = [l for l in (out + err).splitlines() if 'error' in l.lower()]
                log(f'pg_restore reported {len(errs)} problem(s): ' + (errs[0][-200:] if errs else ''))
        else:
            raise ValueError('unsupported database type')
        _ledger_add('databases', key, {'from': d.get('from', ''), 'time': int(time.time())})
        log(f'Database {name} is ready on this server.')
        log.finish(True)
    except Exception as e:
        log(f'Failed: {e}')
        if created:
            if engine == 'mysql':
                dbm.mysql_cmd(f'DROP DATABASE IF EXISTS `{name}`;')
            elif engine == 'postgresql':
                _sh(f'runuser -u postgres -- dropdb --if-exists {shlex.quote(name)}')
            log('Removed the incomplete database again.')
        log.finish(False)


def _recv_cron(d):
    from panel.routes.cron import add_cron_job, get_crontab
    try:
        current = get_crontab()
    except Exception:
        current = ''
    added, skipped = 0, 0
    for j in (d.get('jobs') or [])[:200]:
        sched, cmd = str(j.get('schedule', '')), str(j.get('command', ''))
        for src, dst in (d.get('paths') or {}).items():
            if src and dst:
                cmd = cmd.replace(src, dst)
        if cmd in current:
            skipped += 1
            continue
        ok, _ = add_cron_job(sched, cmd, str(j.get('name') or 'Migrated job')[:80])
        added += 1 if ok else 0
    return {'ok': True, 'added': added, 'skipped': skipped}


# --- sending side ---------------------------------------------------------------------
class Remote:
    def __init__(self, token):
        self.url, self.secret = parse_token(token)
        import requests, ipaddress, warnings
        warnings.filterwarnings('ignore', message='Unverified HTTPS request')
        self.s = requests.Session()
        host = self.url.split('//')[1].rsplit(':', 1)[0].strip('[]')
        try:
            private = not ipaddress.ip_address(host).is_global
        except ValueError:
            private = host == 'localhost'
        # a proxy configured for the internet cannot reach a server on the LAN
        self.s.trust_env = not private

    def call(self, op, obj=None, raw=None, timeout=120):
        body = raw if raw is not None else json.dumps(obj or {}).encode()
        sealed = seal(self.secret, 'req:' + op, body)
        last = None
        for attempt in range(4):
            try:
                r = self.s.post(f'{self.url}/api/hooks/migrate/{op}', data=sealed, timeout=timeout, verify=False,
                                headers={'Content-Type': 'application/octet-stream'})
            except Exception as e:
                last = f'The new server could not be reached ({type(e).__name__}).'
                time.sleep(2 + attempt * 3)
                sealed = seal(self.secret, 'req:' + op, body)
                continue
            if r.status_code == 404:
                raise RuntimeError('The new server does not accept migrations right now - turn on Receive there '
                                   '(the key is valid for 24 hours) and copy the new key.')
            if r.status_code == 403:
                try: msg = r.json().get('error')
                except Exception: msg = 'rejected'
                raise RuntimeError(msg)
            if r.status_code >= 500:
                last = f'The new server answered with an error ({r.status_code}).'
                time.sleep(2 + attempt * 3)
                sealed = seal(self.secret, 'req:' + op, body)
                continue
            try:
                return json.loads(unseal(self.secret, 'resp:' + op, r.content))
            except ValueError as e:
                raise RuntimeError(f'The answer of the new server could not be verified ({e}).')
        raise RuntimeError(last or 'transfer failed')


def _wp_creds(path):
    """{db_user: password} from the site's configuration (wp-config.php, .env)."""
    out = {}
    try:
        txt = open(os.path.join(path, 'wp-config.php'), errors='replace').read()
        u = re.search(r"define\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]", txt)
        p = re.search(r"define\(\s*['\"]DB_PASSWORD['\"]\s*,\s*'((?:[^'\\]|\\.)*)'", txt) or \
            re.search(r'define\(\s*[\'"]DB_PASSWORD[\'"]\s*,\s*"((?:[^"\\]|\\.)*)"', txt)
        n = re.search(r"define\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]", txt)
        if u and p:
            out[u.group(1)] = p.group(1).replace("\\'", "'")
        if n:
            out.setdefault('__dbs__', []).append(n.group(1))
    except OSError:
        pass
    try:
        env = dict(re.findall(r'^\s*([A-Z_]+)\s*=\s*"?([^"\n]*)"?\s*$', open(os.path.join(path, '.env'), errors='replace').read(), re.M))
        if env.get('DB_USERNAME') and env.get('DB_PASSWORD'):
            out[env['DB_USERNAME']] = env['DB_PASSWORD']
        if env.get('DB_DATABASE'):
            out.setdefault('__dbs__', []).append(env['DB_DATABASE'])
    except OSError:
        pass
    return out


def _site_conf(domain):
    from panel.routes.websites_core import _find_site_config
    fp, ws = _find_site_config(domain)
    try:
        return fp, ws, open(fp).read() if fp else ''
    except OSError:
        return fp, ws, ''


@migration_bp.route('/api/migration/local')
def local_inventory():
    if not req(): return jsonify({'ok': False}), 401
    from panel.routes.websites_core import list_sites
    from panel.routes import databases as dbm
    sites = []
    for s in list_sites():
        path = s.get('path') or ''
        reason = ''
        m = re.match(r'^/home/([^/]+)/', path)
        if m:
            reason = f'belongs to the hosting account {m.group(1)} - move hosting accounts with the Hosting Module'
        elif not os.path.isdir(path):
            reason = 'website folder not found'
        if s.get('webserver') not in ('nginx', 'apache', 'openlitespeed', 'caddy'):
            reason = reason or 'unsupported web server'
        rc, out, _ = _sh(f'du -sb {shlex.quote(path)} 2>/dev/null', 20) if not reason else (1, '', '')
        size = int(out.split()[0]) if rc == 0 and out else 0
        sites.append({'domain': s['domain'], 'path': path, 'php': s.get('php'), 'webserver': s.get('webserver'),
                      'ssl': bool(s.get('ssl')), 'size': size, 'dbs': (_wp_creds(path).get('__dbs__') or []) if not reason else [],
                      'movable': not reason, 'reason': reason})
    engines = [e['id'] for e in dbm.detect_engines()]
    dbs = []
    if {'mysql', 'mariadb'} & set(engines):
        for n in _db_names(dbm.mysql_dbs()):
            dbs.append({'engine': 'mysql', 'name': n})
    if 'postgresql' in engines:
        for n in _db_names(dbm.pg_dbs()):
            if n == 'postgres':
                continue
            dbs.append({'engine': 'postgresql', 'name': n})
    return jsonify({'ok': True, 'sites': sites, 'databases': dbs})


@migration_bp.route('/api/migration/connect', methods=['POST'])
def connect():
    if not req(): return jsonify({'ok': False}), 401
    try:
        info = Remote((request.get_json() or {}).get('token')).call('hello', timeout=30)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 400
    if info.get('proto') != PROTO:
        return jsonify({'ok': False, 'error': 'The new server runs a different VortexPanel version - update both servers first.'}), 400
    return jsonify({'ok': True, 'target': info})


def _cancelled(jid):
    return os.path.exists(f'{CANCEL_DIR}/{jid}')


class _SendJob:
    def __init__(self, jid, items):
        self.jid = jid
        self.st = {'done': False, 'ok': False, 'items': items, 'log': [], 'sent': 0, 'started': int(time.time())}
        self._t = 0

    def save(self, force=True):
        if force or time.time() - self._t > 1:
            self._t = time.time()
            save_job(self.jid, self.st)

    def log(self, line):
        self.st['log'].append(time.strftime('%H:%M:%S ') + line)
        self.st['log'] = self.st['log'][-400:]
        self.save()

    def item(self, idx, **kw):
        self.st['items'][idx].update(kw)
        self.save()


def _stream_upload(remote, job, tid, name, cmd, limit_kbps, tar=False):
    """Run cmd, upload its stdout in encrypted chunks. Returns (parts, sha, bytes)."""
    p = subprocess.Popen(['bash', '-o', 'pipefail', '-c', cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    h, idx, total = hashlib.sha256(), 0, 0
    t0 = time.time()
    try:
        while True:
            if _cancelled(job.jid):
                p.kill()
                raise RuntimeError('Cancelled')
            buf = b''
            while len(buf) < CHUNK:
                b = p.stdout.read(CHUNK - len(buf))
                if not b: break
                buf += b
            if not buf:
                break
            h.update(buf)
            meta = json.dumps({'tid': tid, 'name': name, 'idx': idx, 'sha': hashlib.sha256(buf).hexdigest()}).encode()
            r = remote.call('chunk', raw=len(meta).to_bytes(4, 'big') + meta + buf, timeout=300)
            if not r.get('ok'):
                p.kill()
                raise RuntimeError(r.get('error') or 'upload rejected')
            idx += 1
            total += len(buf)
            job.st['sent'] += len(buf)
            job.save(force=False)
            if limit_kbps:
                want = total / (limit_kbps * 1024.0)
                spent = time.time() - t0
                if want > spent:
                    time.sleep(min(want - spent, 30))
        err = p.stderr.read().decode(errors='replace')
        rc = p.wait()
    finally:
        if p.poll() is None:
            p.kill()
    # tar exits 1 when a file changed while it was read (a live site): not an error
    if rc != 0 and not (tar and rc == 1):
        raise RuntimeError(f'reading the data failed: {err.strip()[-300:]}')
    return idx, h.hexdigest(), total


def _wait_remote(remote, job, rjid, label):
    seen, t0 = 0, time.time()
    while time.time() - t0 < 6 * 3600:
        time.sleep(2)
        r = remote.call('job', {'job': rjid}, timeout=60)
        lines = r.get('log') or []
        for l in lines[seen:]:
            job.log(f'{label}: {l}')
        seen = len(lines)
        if r.get('done'):
            return bool(r.get('ok'))
    return False


def _ssl_files(conf, ws):
    if ws == 'apache':
        c = re.search(r'^\s*SSLCertificateFile\s+"?([^"\s]+)', conf, re.M)
        k = re.search(r'^\s*SSLCertificateKeyFile\s+"?([^"\s]+)', conf, re.M)
    else:
        c = re.search(r'^[ \t]*ssl_certificate\s+([^;\s]+)\s*;', conf, re.M)
        k = re.search(r'^[ \t]*ssl_certificate_key\s+([^;\s]+)\s*;', conf, re.M)
    if c and k and os.path.exists(c.group(1)) and os.path.exists(k.group(1)):
        return c.group(1), k.group(1)
    return None, None


def _vhost_files(conf):
    """Small files a vhost includes from /etc/nginx (htpasswd, rewrite includes)."""
    out = {}
    std = ('fastcgi_params', 'fastcgi.conf', 'mime.types', 'snippets/fastcgi-php.conf', 'proxy_params', 'uwsgi_params')
    for m in re.finditer(r'^[ \t]*(?:include|auth_basic_user_file)\s+([^;\s]+)\s*;', conf, re.M):
        p = m.group(1)
        if not p.startswith('/'):
            p = '/etc/nginx/' + p
        p = os.path.normpath(p)
        if any(p.endswith(s) for s in std) or '*' in p or not p.startswith('/etc/nginx/'):
            continue
        try:
            if os.path.getsize(p) < 256 * 1024:
                out[p] = open(p, errors='replace').read()
        except OSError:
            pass
    return out


def _mysql_meta(name, site_creds):
    from panel.routes import databases as dbm
    users = []
    out, e = dbm.mysql_cmd(f"SELECT User, Host FROM mysql.db WHERE Db={_q(name)} OR Db={_q(name.replace('_', chr(92) + '_'))};")
    rows = [l.split('\t') for l in (out or '').splitlines()[1:] if '\t' in l]
    ver, _ = dbm.mysql_cmd('SELECT VERSION();')
    is_mariadb = 'mariadb' in (ver or '').lower()
    for user, host in rows:
        if user in ('root', 'mysql.sys', 'debian-sys-maint'):
            continue
        u = {'user': user, 'host': host, 'password': site_creds.get(user, '')}
        if is_mariadb:
            o, _ = dbm.mysql_cmd(f"SELECT plugin, authentication_string FROM mysql.user "
                                 f"WHERE User={_q(user)} AND Host={_q(host)};")
        else:
            o, _ = dbm.mysql_cmd(f"SELECT plugin, CONCAT('0x', HEX(authentication_string)) FROM mysql.user "
                                 f"WHERE User={_q(user)} AND Host={_q(host)};")
        line = [l for l in (o or '').splitlines() if '\t' in l and not l.startswith('plugin')]
        if line:
            plugin, hsh = line[-1].split('\t')[:2]
            u['plugin'], u['hash'] = plugin, hsh
        g, _ = dbm.mysql_cmd(f'SHOW GRANTS FOR {_q(user)}@{_q(host)};')
        for l in (g or '').splitlines():
            m = re.match(r'GRANT (.+?) ON [`"]?' + re.escape(name).replace('_', r'\\?_') + r'[`"]?\.\*', l)
            if m:
                u['privs'] = m.group(1)
        users.append(u)
    cs, _ = dbm.mysql_cmd(f"SELECT DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA "
                          f"WHERE SCHEMA_NAME={_q(name)};")
    row = [l.split('\t') for l in (cs or '').splitlines()[1:] if '\t' in l]
    charset, collation = (row[0] + ['', ''])[:2] if row else ('utf8mb4', '')
    return users, charset, collation


def _send(jid, token, sites, dbs, opts):
    items = [{'type': 'site', 'name': s, 'status': 'waiting'} for s in sites] + \
            [{'type': 'database', 'engine': e, 'name': n, 'status': 'waiting'} for e, n in dbs]
    if opts.get('cron'):
        items.append({'type': 'cron', 'name': 'Cron jobs', 'status': 'waiting'})
    job = _SendJob(jid, items)
    job.save()
    tid = secrets.token_hex(8)
    ok_all = True
    try:
        remote = Remote(token)
        info = remote.call('hello', timeout=30)
        me = os.uname().nodename
        job.log(f'Connected to {info.get("hostname")} (VortexPanel {info.get("version")}, {info.get("webserver") or "no web server"}).')
        from panel.routes.websites_core import list_sites
        local = {s['domain']: s for s in list_sites()}
        site_creds, path_map = {}, {}
        lim = int(opts.get('limit_kbps') or 0)
        for i, it in enumerate(job.st['items']):
            if _cancelled(jid):
                raise RuntimeError('Cancelled')
            if it['type'] == 'site':
                s = local.get(it['name'])
                if not s:
                    job.item(i, status='failed', detail='not found'); ok_all = False; continue
                if s['domain'] in (info.get('sites') or []) and not (
                        opts.get('resync') and s['domain'] in ((info.get('migrated') or {}).get('sites') or {})):
                    why = ('already exists on the new server' if s['domain'] not in ((info.get('migrated') or {}).get('sites') or {})
                           else 'already copied - turn on "Sync again" to refresh it')
                    job.log(f'{s["domain"]}: skipped, {why}.')
                    job.item(i, status='skipped', detail=why); continue
                job.item(i, status='sending')
                path = s['path']
                site_creds.update({k: v for k, v in _wp_creds(path).items() if k != '__dbs__'})
                job.log(f'{s["domain"]}: packing and sending the files (the site keeps running)...')
                cmd = (f'nice -n 19 ionice -c3 tar -C {shlex.quote(path)} --warning=no-file-changed '
                       f'--ignore-failed-read -czf - .')
                try:
                    parts, sha, size = _stream_upload(remote, job, tid, f'site-{i}.tgz', cmd, lim, tar=True)
                    fp, ws, conf = _site_conf(s['domain'])
                    payload = {'tid': tid, 'domain': s['domain'], 'archive': f'site-{i}.tgz', 'parts': parts,
                               'sha': sha, 'php': s.get('php') or 'static', 'src_webserver': ws, 'src_path': path,
                               'resync': bool(opts.get('resync')), 'from': me}
                    if ws == 'nginx' and opts.get('vhost') is not False:
                        payload['vhost'] = conf
                        payload['vhost_files'] = _vhost_files(conf)
                    if opts.get('ssl') is not False:
                        c, k = _ssl_files(conf, ws)
                        if c:
                            payload['ssl'] = {'cert': open(c).read(), 'key': open(k).read(),
                                              'letsencrypt': '/letsencrypt/' in c or '/vortexpanel/acme' in c}
                    job.item(i, status='installing', detail=f'{size // 1048576} MB sent')
                    r = remote.call('site', payload, timeout=60)
                    if not r.get('ok'):
                        raise RuntimeError(r.get('error'))
                    ok = _wait_remote(remote, job, r['job'], s['domain'])
                    job.item(i, status='done' if ok else 'failed')
                    ok_all &= ok
                    if ok:
                        path_map[path] = f'{info.get("webroot", "/www/wwwroot")}/{s["domain"]}'
                except Exception as e:
                    job.log(f'{s["domain"]}: {e}')
                    job.item(i, status='failed', detail=str(e)[:200]); ok_all = False
                    if str(e) == 'Cancelled':
                        raise
            elif it['type'] == 'database':
                name, engine = it['name'], it['engine']
                teng = info.get('engines') or []
                if (engine == 'mysql' and not ({'mysql', 'mariadb'} & set(teng))) or (engine == 'postgresql' and 'postgresql' not in teng):
                    why = ('MySQL/MariaDB' if engine == 'mysql' else 'PostgreSQL') + ' is not installed on the new server (App Store)'
                    job.log(f'Database {name}: skipped, {why}.')
                    job.item(i, status='skipped', detail=why); ok_all = False; continue
                tdbs = (info.get('databases') or {}).get(engine) or []
                migrated = (info.get('migrated') or {}).get('databases') or {}
                if name in tdbs and not (opts.get('resync') and f'{engine}:{name}' in migrated):
                    why = ('already exists on the new server' if f'{engine}:{name}' not in migrated
                           else 'already copied - turn on "Sync again" to refresh it')
                    job.log(f'Database {name}: skipped, {why}.')
                    job.item(i, status='skipped', detail=why); continue
                job.item(i, status='sending')
                job.log(f'Database {name}: exporting and sending (no table locks, the site keeps running)...')
                try:
                    if engine == 'mysql':
                        from panel.routes import databases as dbm
                        dbm.mysql_cmd('SELECT 1;')
                        auth = dbm._mysql_auth_candidates()[0]
                        dump = dbm._mysql_bin('dump')
                        extra = ''
                        if dump == 'mysqldump' and '--set-gtid-purged' in _sh('mysqldump --help 2>/dev/null', 20)[1]:
                            extra = ' --set-gtid-purged=OFF'
                        cmd = (f'nice -n 10 {dump} {auth} --single-transaction --quick --routines --triggers --events '
                               f'--hex-blob --no-tablespaces --default-character-set=utf8mb4{extra} {shlex.quote(name)} | gzip -c')
                        users, cs, co = _mysql_meta(name, site_creds)
                        parts, sha, size = _stream_upload(remote, job, tid, f'db-{i}.sql.gz', cmd, lim)
                        payload = {'tid': tid, 'engine': 'mysql', 'name': name, 'archive': f'db-{i}.sql.gz',
                                   'parts': parts, 'sha': sha, 'users': users, 'charset': cs, 'collation': co,
                                   'resync': bool(opts.get('resync')), 'from': me}
                    else:
                        rc, owner, _ = _sh(f"runuser -u postgres -- psql -tAc {shlex.quote(f'SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname={_q(name)}')}")
                        roles = []
                        if owner and owner != 'postgres':
                            rc, ph, _ = _sh(f"runuser -u postgres -- psql -tAc {shlex.quote(f'SELECT rolpassword FROM pg_authid WHERE rolname={_q(owner)}')}")
                            roles.append({'name': owner, 'hash': ph})
                        cmd = f'cd /tmp && nice -n 10 runuser -u postgres -- pg_dump -Fc {shlex.quote(name)}'
                        parts, sha, size = _stream_upload(remote, job, tid, f'db-{i}.dump', cmd, lim)
                        payload = {'tid': tid, 'engine': 'postgresql', 'name': name, 'archive': f'db-{i}.dump',
                                   'parts': parts, 'sha': sha, 'owner': owner or 'postgres', 'roles': roles,
                                   'resync': bool(opts.get('resync')), 'from': me}
                    job.item(i, status='installing', detail=f'{max(size // 1048576, 1)} MB sent')
                    r = remote.call('database', payload, timeout=60)
                    if not r.get('ok'):
                        raise RuntimeError(r.get('error'))
                    ok = _wait_remote(remote, job, r['job'], f'Database {name}')
                    job.item(i, status='done' if ok else 'failed')
                    ok_all &= ok
                except Exception as e:
                    job.log(f'Database {name}: {e}')
                    job.item(i, status='failed', detail=str(e)[:200]); ok_all = False
                    if str(e) == 'Cancelled':
                        raise
            elif it['type'] == 'cron':
                from panel.routes.cron import get_crontab, load_meta
                meta = load_meta()
                jobs = []
                for line in (get_crontab() or '').splitlines():
                    m = re.match(r'^((?:@\w+)|(?:\S+\s+\S+\s+\S+\s+\S+\s+\S+))\s+(.*?)\s+# vp:(\w+)\s*$', line)
                    if m and any(p in m.group(2) for p in path_map):
                        jobs.append({'schedule': m.group(1), 'command': m.group(2).replace('\\%', '%'),
                                     'name': (meta.get(m.group(3)) or {}).get('name', '')})
                r = remote.call('cron', {'jobs': jobs, 'paths': path_map})
                job.item(i, status='done', detail=f'{r.get("added", 0)} added, {r.get("skipped", 0)} already there')
        remote.call('finish', {'tid': tid})
        job.log('Finished.' if ok_all else 'Finished with problems - see the items marked failed.')
        job.st.update(done=True, ok=ok_all)
        job.save()
    except Exception as e:
        job.log(str(e))
        for it in job.st['items']:
            if it['status'] in ('waiting', 'sending', 'installing'):
                it['status'] = 'cancelled' if str(e) == 'Cancelled' else 'failed'
        job.st.update(done=True, ok=False)
        job.save()
        try:
            Remote(token).call('finish', {'tid': tid}, timeout=20)
        except Exception:
            pass
    finally:
        try: os.remove(f'{CANCEL_DIR}/{jid}')
        except OSError: pass


@migration_bp.route('/api/migration/start', methods=['POST'])
def start():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    try:
        parse_token(d.get('token'))
    except ValueError as e:
        return jsonify({'ok': False, 'error': str(e)}), 400
    from panel.routes.websites_core import is_valid_domain
    sites = [s for s in (d.get('sites') or []) if isinstance(s, str) and is_valid_domain(s)]
    dbs = []
    for x in d.get('databases') or []:
        e, n = str((x or {}).get('engine')), str((x or {}).get('name'))
        if e in ('mysql', 'postgresql') and re.fullmatch(r'[A-Za-z0-9_]{1,64}', n):
            dbs.append((e, n))
    if not sites and not dbs:
        return jsonify({'ok': False, 'error': 'Choose at least one website or database'}), 400
    jid = 'mig-' + uuid.uuid4().hex[:12]
    opts = {k: d.get(k) for k in ('ssl', 'cron', 'vhost', 'resync', 'limit_kbps')}
    threading.Thread(target=_send, args=(jid, d['token'], sites, dbs, opts), daemon=True).start()
    try:
        _write_private(DATA + '/migrate_last_job', jid)
    except OSError:
        pass
    return jsonify({'ok': True, 'job_id': jid})


@migration_bp.route('/api/migration/job/<jid>', methods=['GET', 'DELETE'])
def job_status(jid):
    if not req(): return jsonify({'ok': False}), 401
    if not re.fullmatch(r'mig-[0-9a-f]{12}', jid):
        return jsonify({'ok': False, 'error': 'Invalid job'}), 400
    if request.method == 'DELETE':
        os.makedirs(CANCEL_DIR, exist_ok=True)
        open(f'{CANCEL_DIR}/{jid}', 'w').close()
        return jsonify({'ok': True})
    st = load_job(jid)
    if not st:
        return jsonify({'ok': False, 'error': 'Job not found'}), 404
    return jsonify({'ok': True, **st})


@migration_bp.route('/api/migration/last')
def last_job():
    if not req(): return jsonify({'ok': False}), 401
    try:
        jid = open(DATA + '/migrate_last_job').read().strip()
    except OSError:
        return jsonify({'ok': True, 'job_id': ''})
    return jsonify({'ok': True, 'job_id': jid if load_job(jid) else ''})
