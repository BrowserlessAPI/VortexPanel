from flask import Blueprint, jsonify, request, session
import subprocess, os, re, pwd, shutil
try:
    from panel.routes import os_utils as _ou
except ImportError:
    import os_utils as _ou

ftp_bp = Blueprint('ftp', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.check_output(c, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=30).strip()
    except Exception: return ''

def run(args, input=None, timeout=30):
    try:
        r = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stderr or r.stdout or '').strip()
    except FileNotFoundError:
        return 127, f'{args[0]} not found'
    except subprocess.TimeoutExpired:
        return 124, f'{args[0]} timed out'

PURE_PASSWD = '/etc/pure-ftpd/pureftpd.passwd'
PURE_PDB    = '/etc/pure-ftpd/pureftpd.pdb'
_USER_RE    = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
_PROTECTED_HOMES = {'/', '/bin', '/boot', '/dev', '/etc', '/lib', '/lib64', '/proc', '/root', '/run',
                    '/sbin', '/sys', '/usr', '/var', '/opt', '/opt/vortexpanel', '/tmp', '/home'}

def get_ftp_daemon():
    """Detect which FTP daemon is installed, preferring the one that is running."""
    found = []
    for daemon in ['pure-ftpd', 'proftpd', 'vsftpd']:
        if sh(f'command -v {daemon} 2>/dev/null') or os.path.exists(f'/usr/sbin/{daemon}'):
            status = sh(f'systemctl is-active {daemon} 2>/dev/null') or 'inactive'
            found.append((daemon, status))
    for daemon, status in found:
        if status == 'active':
            return daemon, status
    if found:
        return found[0]
    return None, 'none'

def is_ftp_installed():
    daemon, _ = get_ftp_daemon()
    return daemon is not None

def _nologin_shell():
    for p in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false'):
        if os.path.exists(p): return p
    return '/bin/false'

def _ensure_shell_listed(shell):
    """ProFTPD (RequireValidShell on) and vsftpd (pam_shells) refuse users whose
    shell is not in /etc/shells, so a nologin FTP user could never log in."""
    try:
        with open('/etc/shells') as f:
            if shell in [l.strip() for l in f]: return
        with open('/etc/shells', 'a') as f:
            f.write(shell + '\n')
    except OSError:
        pass

PASV_RANGE = (39000, 40000)


def _pasv_range_conf():
    """(changed, (lo, hi)) -- make sure Pure-FTPd has a fixed passive port
    range (Debian: conf/PassivePortRange, RHEL: PassivePortRange in
    pure-ftpd.conf). Without one it picks any high port, which no firewall
    rule can allow: logins worked but every directory listing / transfer hung."""
    lo, hi = PASV_RANGE
    if os.path.isdir('/etc/pure-ftpd/conf'):
        conf = '/etc/pure-ftpd/conf/PassivePortRange'
        try:
            cur = open(conf).read().split() if os.path.exists(conf) else []
        except OSError:
            cur = []
        if len(cur) == 2 and cur[0].isdigit() and cur[1].isdigit():
            return False, (int(cur[0]), int(cur[1]))
        with open(conf, 'w') as f: f.write(f'{lo} {hi}\n')
        return True, (lo, hi)
    for conf in ('/etc/pure-ftpd/pure-ftpd.conf', '/etc/pure-ftpd.conf'):
        if not os.path.isfile(conf): continue
        with open(conf) as f: txt = f.read()
        m = re.search(r'^\s*PassivePortRange\s+(\d+)\s+(\d+)', txt, re.M)
        if m:
            return False, (int(m.group(1)), int(m.group(2)))
        line = f'PassivePortRange             {lo} {hi}'
        if re.search(r'^\s*#\s*PassivePortRange\b', txt, re.M):
            txt = re.sub(r'^\s*#\s*PassivePortRange\b.*$', line, txt, count=1, flags=re.M)
        else:
            txt = txt.rstrip('\n') + '\n' + line + '\n'
        with open(conf, 'w') as f: f.write(txt)
        return True, (lo, hi)
    return False, (lo, hi)


def _open_ftp_firewall(lo, hi):
    """Allow 21/tcp and the passive range in whichever firewall is active."""
    if shutil.which('ufw'):
        st = sh('ufw status 2>/dev/null')
        if st.startswith('Status: active'):
            run(['ufw', 'allow', '21/tcp'])
            run(['ufw', 'allow', f'{lo}:{hi}/tcp'])
    if shutil.which('firewall-cmd') and sh('firewall-cmd --state 2>/dev/null') == 'running':
        changed = False
        if run(['firewall-cmd', '--permanent', '--query-service=ftp'])[0] != 0:
            run(['firewall-cmd', '--permanent', '--add-service=ftp']); changed = True
        if run(['firewall-cmd', '--permanent', f'--query-port={lo}-{hi}/tcp'])[0] != 0:
            run(['firewall-cmd', '--permanent', f'--add-port={lo}-{hi}/tcp']); changed = True
        if changed:
            run(['firewall-cmd', '--reload'], timeout=60)


def _ensure_puredb_enabled():
    """Make Pure-FTPd usable for panel-created accounts: PureDB auth on
    (Debian ships it disabled -- auth/ has only 65unix + 70pam; the RHEL/EPEL
    pure-ftpd.conf has the PureDB line commented out), a fixed passive port
    range opened in ufw/firewalld together with 21/tcp, and on SELinux the
    ftpd_full_access boolean (otherwise uploads into site directories are
    denied). Returns True if the config was changed (pure-ftpd needs a
    restart to pick it up)."""
    changed = False
    # pure-ftpd refuses to start with PureDB enabled while the .pdb file does
    # not exist yet (fresh install, no account created so far).
    try:
        if not os.path.exists(PURE_PDB) and shutil.which('pure-pw'):
            os.makedirs(os.path.dirname(PURE_PDB), exist_ok=True)
            if not os.path.exists(PURE_PASSWD):
                fd = os.open(PURE_PASSWD, os.O_WRONLY | os.O_CREAT, 0o600); os.close(fd)
            subprocess.run(['pure-pw', 'mkdb', PURE_PDB, '-f', PURE_PASSWD], capture_output=True, timeout=60)
    except Exception:
        pass
    try:
        pchanged, (lo, hi) = _pasv_range_conf()
        changed = changed or pchanged
        _open_ftp_firewall(lo, hi)
    except OSError:
        pass
    try:
        _ou.selinux_web_booleans(proxy=False, db=False, ftp=True)
    except Exception:
        pass
    if os.path.isdir('/etc/pure-ftpd/conf') and os.path.isdir('/etc/pure-ftpd/auth'):
        conf = '/etc/pure-ftpd/conf/PureDB'
        try:
            cur = open(conf).read().strip() if os.path.exists(conf) else ''
        except OSError:
            cur = ''
        if not cur:
            with open(conf, 'w') as f: f.write(PURE_PDB + '\n')
            changed = True
        auth = '/etc/pure-ftpd/auth'
        linked = any(os.path.islink(os.path.join(auth, n)) and
                     os.path.basename(os.readlink(os.path.join(auth, n))) == 'PureDB'
                     for n in os.listdir(auth))
        if not linked:
            os.symlink('../conf/PureDB', os.path.join(auth, '50pure'))
            changed = True
    else:
        for conf in ('/etc/pure-ftpd/pure-ftpd.conf', '/etc/pure-ftpd.conf'):
            if not os.path.isfile(conf): continue
            with open(conf) as f: txt = f.read()
            if re.search(r'^\s*PureDB\s+\S+', txt, re.M):
                break
            if re.search(r'^\s*#\s*PureDB\s+', txt, re.M):
                txt = re.sub(r'^\s*#\s*PureDB\s+.*$', 'PureDB                       ' + PURE_PDB, txt, count=1, flags=re.M)
            else:
                txt = txt.rstrip('\n') + '\nPureDB                       ' + PURE_PDB + '\n'
            with open(conf, 'w') as f: f.write(txt)
            changed = True
            break
    return changed

def _pure_users():
    users = {}
    for f in [PURE_PASSWD, '/etc/pureftpd.passwd']:
        if os.path.exists(f):
            with open(f) as fh:
                for line in fh:
                    parts = line.strip().split(':')
                    if len(parts) >= 7 and parts[0] not in users:
                        # pure-pw stores chrooted homes as "/path/./"; show the real path
                        home = parts[5].replace('/./', '/')
                        users[parts[0]] = os.path.normpath('/' + home.lstrip('/')) if home else home
    return users

def _ftp_system_user(user):
    """A system account this panel may manage as an FTP user: a regular uid
    (>= 1000) with a non-login shell. Prevents the FTP page from deleting
    'mysql' / 'www-data' or resetting the password of a real login account."""
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return None
    if pw.pw_uid < 1000 or pw.pw_uid == 65534:
        return None
    if not any(s in pw.pw_shell for s in ('nologin', 'false')):
        return None
    return pw


@ftp_bp.route('/api/ftp/users')
def list_users_alias():
    return list_accounts()

@ftp_bp.route('/api/ftp/status')
def ftp_status():
    if not req(): return jsonify({'ok':False}), 401
    daemon, status = get_ftp_daemon()
    installed = daemon is not None

    # Get accounts count
    accounts = _list_ftp_accounts()

    return jsonify({
        'ok': True,
        'installed': installed,
        'daemon': daemon or 'none',
        'status': status,
        'accounts_count': len(accounts),
    })

def _list_ftp_accounts():
    """List FTP virtual users from all possible sources"""
    accounts = []
    seen = set()

    # Pure-FTPd virtual users
    for user, home in _pure_users().items():
        seen.add(user)
        accounts.append({'user': user, 'home': home})

    # ProFTPD virtual users
    for f in ['/etc/proftpd/ftpd.passwd']:
        if os.path.exists(f):
            with open(f) as fh:
                for line in fh:
                    parts = line.strip().split(':')
                    if len(parts) >= 6 and parts[0] not in seen:
                        seen.add(parts[0])
                        accounts.append({'user': parts[0], 'home': parts[5]})

    # System users with FTP shell or home in webroot
    if not accounts:
        out = sh("getent passwd | awk -F: '$3 >= 1000 && $7 ~ /nologin|false/ && $6 ~ /www/ {print $1\":\"$6}'")
        for line in out.split('\n'):
            if ':' in line:
                user, home = line.split(':', 1)
                if user not in seen:
                    seen.add(user)
                    accounts.append({'user': user, 'home': home})

    return accounts

@ftp_bp.route('/api/ftp/accounts')
def list_accounts():
    if not req(): return jsonify({'ok':False}), 401
    if not is_ftp_installed():
        return jsonify({'ok':False, 'installed':False, 'error':'FTP daemon not installed'}), 200
    return jsonify({'ok':True, 'installed':True, 'accounts': _list_ftp_accounts()})

@ftp_bp.route('/api/ftp/accounts', methods=['POST'])
def create_account():
    if not req(): return jsonify({'ok':False}), 401
    if not is_ftp_installed():
        return jsonify({'ok':False, 'error':'Install Pure-FTPd or ProFTPD via Modules first'}), 400

    d    = request.get_json() or {}
    user = re.sub(r'[^a-zA-Z0-9_-]', '', d.get('user', '') or '').lower()
    code, res = create_ftp_account(user, d.get('password', '') or '', d.get('home') or '')
    return jsonify(res), code


def create_ftp_account(user, pwd_, home=''):
    """Create an FTP account (Pure-FTPd virtual user backed by a nologin
    system account, or a nologin system account for ProFTPD / vsftpd).
    Shared by the FTP page and Websites -> New site -> Create FTP.
    Returns (http_status, json_dict)."""
    if not user: return 400, {'ok':False, 'error':'Username required'}
    if not _USER_RE.match(user):
        return 400, {'ok':False, 'error':'Username must start with a letter or underscore (max 32 chars)'}
    if not pwd_: return 400, {'ok':False, 'error':'Password required'}
    if len(pwd_) < 6: return 400, {'ok':False, 'error':'Password must be at least 6 characters'}
    if '\n' in pwd_ or '\r' in pwd_ or ':' in pwd_:
        return 400, {'ok':False, 'error':'Password cannot contain line breaks or ":"'}
    if not home:
        home = os.path.join(_ou.get_webroot(), user)
    home = os.path.normpath('/' + home.strip())
    if home in _PROTECTED_HOMES or os.path.realpath(home) in _PROTECTED_HOMES:
        return 400, {'ok':False, 'error':f'{home} cannot be used as an FTP home directory'}

    daemon, _ = get_ftp_daemon()
    if not daemon:
        return 400, {'ok':False, 'error':'Install Pure-FTPd or ProFTPD via Modules first'}
    created_home = not os.path.isdir(home)
    try:
        os.makedirs(home, exist_ok=True)
    except OSError as e:
        return 500, {'ok':False, 'error':f'Cannot create {home}: {e}'}

    try:
        pwd.getpwnam(user)
        sys_exists = True
    except KeyError:
        sys_exists = False

    warning = ''
    if daemon == 'pure-ftpd':
        if user in _pure_users():
            return 400, {'ok':False, 'error':f'FTP user {user} already exists'}
        if sys_exists and not _ftp_system_user(user):
            return 400, {'ok':False, 'error':f'{user} is an existing system account - choose another name'}
        if not sys_exists:
            rc, err = run(['useradd', '-M', '-s', _nologin_shell(), '-d', home, user])
            if rc != 0: return 500, {'ok':False, 'error':f'useradd failed: {err}'}
        rc, err = run(['pure-pw', 'useradd', user, '-u', user, '-d', home, '-f', PURE_PASSWD, '-F', PURE_PDB, '-m'],
                      input=f'{pwd_}\n{pwd_}\n')
        if rc != 0:
            if not sys_exists:
                run(['userdel', user])
            return 500, {'ok':False, 'error':f'pure-pw failed: {err}'}
        try:
            if _ensure_puredb_enabled():
                rc, err = run(['systemctl', 'restart', 'pure-ftpd'], timeout=60)
                if rc != 0:
                    warning = f'Account created, but pure-ftpd did not restart: {err[:300]}'
        except OSError as e:
            warning = f'Account created, but PureDB authentication could not be enabled: {e}'
    else:
        # Generic system user (ProFTPD / vsftpd authenticate system accounts).
        # Never reset the password of an existing account that is not an FTP
        # user (the old `useradd || true; chpasswd` did exactly that).
        if sys_exists:
            return 400, {'ok':False, 'error':f'{user} already exists - choose another name'}
        shell = _nologin_shell()
        rc, err = run(['useradd', '-M', '-d', home, '-s', shell, user])
        if rc != 0: return 500, {'ok':False, 'error':f'useradd failed: {err}'}
        rc, err = run(['chpasswd'], input=f'{user}:{pwd_}\n')
        if rc != 0:
            run(['userdel', user])
            return 500, {'ok':False, 'error':f'chpasswd failed: {err}'}
        _ensure_shell_listed(shell)
        try:
            _ou.selinux_web_booleans(proxy=False, db=False, ftp=True)
        except Exception:
            pass

    # A directory we just created is owned by root - give it to the FTP user
    # so uploads work. Existing site directories keep their owner.
    if created_home:
        try:
            pw = pwd.getpwnam(user)
            os.chown(home, pw.pw_uid, pw.pw_gid)
        except (KeyError, OSError):
            pass

    res = {'ok':True, 'user':user, 'home':home}
    if warning:
        res['warning'] = warning
    return 200, res

@ftp_bp.route('/api/ftp/accounts/<user>', methods=['DELETE'])
def delete_account(user):
    if not req(): return jsonify({'ok':False}), 401
    user = re.sub(r'[^a-zA-Z0-9_-]', '', user)
    if not user: return jsonify({'ok':False,'error':'Invalid user'}), 400
    daemon, _ = get_ftp_daemon()
    if user in _pure_users():
        rc, err = run(['pure-pw', 'userdel', user, '-f', PURE_PASSWD, '-F', PURE_PDB, '-m'])
        if rc != 0: return jsonify({'ok':False,'error':f'pure-pw failed: {err}'}), 500
    # Only remove the backing system account if it looks like an FTP-only user
    if _ftp_system_user(user):
        rc, err = run(['userdel', user])
        if rc != 0 and daemon != 'pure-ftpd':
            return jsonify({'ok':False,'error':f'userdel failed: {err}'}), 500
    elif daemon != 'pure-ftpd':
        return jsonify({'ok':False,'error':f'{user} is not an FTP account'}), 400
    return jsonify({'ok':True})

@ftp_bp.route('/api/ftp/accounts/<user>/password', methods=['PUT'])
def change_password(user):
    if not req(): return jsonify({'ok':False}), 401
    user = re.sub(r'[^a-zA-Z0-9_-]', '', user)
    pwd_ = (request.get_json() or {}).get('password','') or ''
    if len(pwd_) < 6: return jsonify({'ok':False,'error':'Min 6 characters'}), 400
    if '\n' in pwd_ or '\r' in pwd_ or ':' in pwd_:
        return jsonify({'ok':False, 'error':'Password cannot contain line breaks or ":"'}), 400
    if user in _pure_users():
        rc, err = run(['pure-pw', 'passwd', user, '-f', PURE_PASSWD, '-F', PURE_PDB, '-m'], input=f'{pwd_}\n{pwd_}\n')
        if rc != 0: return jsonify({'ok':False,'error':f'pure-pw failed: {err}'}), 500
    elif _ftp_system_user(user):
        rc, err = run(['chpasswd'], input=f'{user}:{pwd_}\n')
        if rc != 0: return jsonify({'ok':False,'error':f'chpasswd failed: {err}'}), 500
    else:
        return jsonify({'ok':False,'error':f'{user} is not an FTP account'}), 404
    return jsonify({'ok':True})
