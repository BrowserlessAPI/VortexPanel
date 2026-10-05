from flask import Blueprint, jsonify, request, session
import subprocess, re, os, json
from datetime import datetime, timedelta
from panel.routes.os_utils import get_os

security_bp = Blueprint('security', __name__)
def req(): return 'user' in session
def sh(c, t=10):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except: return '', 'timeout', 1

# --- SSH -----------------------------------------------------------------------

@security_bp.route('/api/security/status')
def security_status():
    from flask import jsonify, session
    if 'user' not in session: return jsonify({'ok':False}), 401
    import subprocess
    def check(cmd):
        try: r = subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=3); return r.returncode==0
        except: return False
    # "Status: inactive" also contains the substring "active", so the plain
    # grep reported UFW as on whenever it was merely installed. firewalld is
    # the firewall on RHEL-family boxes, so count it as well.
    return jsonify({'ok':True,
        'fail2ban': check('systemctl is-active fail2ban'),
        'modsecurity': os.path.exists(_modsec_conf()),
        'ufw': check('ufw status 2>/dev/null | grep -q "Status: active" || firewall-cmd --state 2>/dev/null | grep -q running'),
    })

SSHD_CONFIG     = '/etc/ssh/sshd_config'
SSHD_DROPIN_DIR = '/etc/ssh/sshd_config.d'
_SSH_KEYS = {
    'port':           'Port',
    'password_auth':  'PasswordAuthentication',
    'root_login':     'PermitRootLogin',
    'pubkey_auth':    'PubkeyAuthentication',
    'max_auth_tries': 'MaxAuthTries',
}
_SSH_ROOT_LOGIN_VALUES = ('yes', 'no', 'prohibit-password', 'without-password', 'forced-commands-only')


def _sshd_effective():
    """Effective sshd settings via `sshd -T` (lower-cased keys). This is the
    only reliable view: sshd uses the FIRST value it reads and Ubuntu/Debian
    cloud images ship drop-ins (sshd_config.d/50-cloud-init.conf ...) that are
    Included before anything in the main file. Returns {} if sshd -T fails."""
    out, _, rc = sh('sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null', t=15)
    if rc != 0 or not out:
        return {}
    eff = {}
    for line in out.splitlines():
        k, _, v = line.strip().partition(' ')
        if not k:
            continue
        if k == 'port':
            eff.setdefault('port_list', []).append(v.strip())
        eff.setdefault(k, v.strip())
    if eff.get('permitrootlogin') == 'without-password':
        eff['permitrootlogin'] = 'prohibit-password'
    return eff


def _sshd_head_tail(content):
    """Split sshd_config at the first Match block: directives appended after
    a Match line would silently become part of that Match block."""
    m = re.search(r'^[ \t]*Match[ \t]', content, re.MULTILINE | re.IGNORECASE)
    if not m:
        return content, ''
    return content[:m.start()], content[m.start():]


def _sshd_file_value(content, key, default=''):
    head, _ = _sshd_head_tail(content)
    m = re.search(rf'^[ \t]*{key}[ \t]+(\S+)', head, re.MULTILINE | re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(rf'^[ \t]*#[ \t]*{key}[ \t]+(\S+)', head, re.MULTILINE | re.IGNORECASE)
    return m.group(1) if m else default


def _sshd_set(content, key, val, append=True):
    """Set a global directive: rewrite the first active line (or the first
    commented example), drop any further active duplicates, and insert before
    the first Match block when absent. Returns (new_content, changed)."""
    head, tail = _sshd_head_tail(content)
    new_line = f'{key} {val}'
    active = re.compile(rf'^[ \t]*{key}[ \t]+.*$', re.MULTILINE | re.IGNORECASE)
    if active.search(head):
        first = [True]
        def _sub(m):
            if first[0]:
                first[0] = False
                return new_line
            return ''
        head = active.sub(_sub, head)
        return head + tail, True
    if not append:
        return content, False
    commented = re.compile(rf'^[ \t]*#[ \t]*{key}[ \t]+.*$', re.MULTILINE | re.IGNORECASE)
    if commented.search(head):
        head = commented.sub(new_line, head, count=1)
    else:
        if head and not head.endswith('\n'):
            head += '\n'
        head += new_line + '\n'
    return head + tail, True


def _authorized_keys_present(home):
    p = os.path.join(home, '.ssh', 'authorized_keys')
    try:
        return any(l.strip() and not l.strip().startswith('#') for l in open(p))
    except Exception:
        return False


def _sudo_users():
    out, _, _ = sh("getent group sudo wheel 2>/dev/null | cut -d: -f4 | tr ',' '\\n' | sort -u | grep -v '^$'")
    return [u for u in out.split('\n') if u and u != 'root']


def _user_home(user):
    out, _, rc = sh(f'getent passwd {user} 2>/dev/null | cut -d: -f6')
    return out.strip() if rc == 0 and out.strip() else f'/home/{user}'


def _port_listening(port):
    out, _, _ = sh(f"ss -Htln 'sport = :{int(port)}' 2>/dev/null")
    return bool(out.strip())


def _fw_open_tcp(port):
    """Open a TCP port in whichever firewall is present. firewalld gets the
    runtime AND permanent rule instead of --permanent + --reload, because a
    reload drops runtime-only rules (fail2ban bans among them)."""
    port = int(port)
    sh(f'command -v ufw >/dev/null 2>&1 && ufw allow {port}/tcp', t=30)
    sh(f'firewall-cmd --state 2>/dev/null | grep -q running && '
       f'firewall-cmd --add-port={port}/tcp && firewall-cmd --permanent --add-port={port}/tcp', t=30)


def _fw_close_tcp(port):
    port = int(port)
    sh(f'command -v ufw >/dev/null 2>&1 && ufw delete allow {port}/tcp', t=30)
    sh(f'firewall-cmd --state 2>/dev/null | grep -q running && '
       f'(firewall-cmd --remove-port={port}/tcp; firewall-cmd --permanent --remove-port={port}/tcp)', t=30)


def _sshd_apply():
    """Make sshd pick up the new config. Ubuntu 22.10+ runs sshd socket-
    activated (ssh.socket); the listen port then comes from the socket unit,
    which a generator derives from sshd_config, so it needs daemon-reload +
    socket restart (existing sessions are separate processes and survive).
    Otherwise reload the service: 'ssh' on Debian/Ubuntu, 'sshd' on RHEL."""
    sock, _, _ = sh('systemctl is-active ssh.socket 2>/dev/null')
    if sock.strip() == 'active':
        _, err, rc = sh('systemctl daemon-reload && systemctl restart ssh.socket', t=30)
        return rc == 0, err
    _, err, rc = sh('systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null '
                    '|| service ssh reload 2>/dev/null || service sshd reload', t=30)
    return rc == 0, err


@security_bp.route('/api/security/ssh')
def ssh_config():
    if not req(): return jsonify({'ok':False}), 401
    cfg = {}
    if os.path.exists(SSHD_CONFIG):
        try:
            with open(SSHD_CONFIG) as f: content = f.read()
        except Exception:
            content = ''
        eff = _sshd_effective()
        cfg = {
            'port':           eff.get('port') or _sshd_file_value(content, 'Port', '22'),
            'password_auth':  (eff.get('passwordauthentication') or _sshd_file_value(content, 'PasswordAuthentication', 'yes')).lower(),
            'root_login':     (eff.get('permitrootlogin') or _sshd_file_value(content, 'PermitRootLogin', 'yes')).lower(),
            'pubkey_auth':    (eff.get('pubkeyauthentication') or _sshd_file_value(content, 'PubkeyAuthentication', 'yes')).lower(),
            'max_auth_tries': eff.get('maxauthtries') or _sshd_file_value(content, 'MaxAuthTries', '6'),
        }
        if cfg['root_login'] == 'without-password':
            cfg['root_login'] = 'prohibit-password'
    port_out, _, _ = sh("ss -tlnp 2>/dev/null | grep -E '\"sshd\"|\"systemd\".*ssh' | awk '{print $4}' | grep -oE '[0-9]+$'")
    if port_out: cfg['active_port'] = port_out.split('\n')[0]
    elif cfg.get('port'): cfg['active_port'] = cfg['port']

    # Keys that actually allow a login: root's authorized_keys, or any sudo
    # user's (an id_rsa.pub in /root/.ssh is an outgoing key, not a login key).
    sudo_users = _sudo_users()
    cfg['keys_exist'] = _authorized_keys_present('/root') or any(
        _authorized_keys_present(_user_home(u)) for u in sudo_users)
    cfg['sudo_users'] = sudo_users

    return jsonify({'ok':True, 'config':cfg})


@security_bp.route('/api/security/ssh', methods=['PUT'])
def save_ssh():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    if not os.path.exists(SSHD_CONFIG):
        return jsonify({'ok':False,'error':'sshd_config not found'}), 404

    # --- validate every value: they are written into sshd_config and the
    # port is passed to ufw / firewall-cmd / semanage.
    want = {}
    if d.get('port') not in (None, ''):
        try:
            p = int(str(d['port']).strip())
            if not 1 <= p <= 65535: raise ValueError()
        except (ValueError, TypeError):
            return jsonify({'ok':False,'error':'Port must be a number between 1 and 65535'}), 400
        want['port'] = str(p)
    for k in ('password_auth', 'pubkey_auth'):
        if d.get(k) not in (None, ''):
            v = str(d[k]).strip().lower()
            if v not in ('yes', 'no'):
                return jsonify({'ok':False,'error':f'{k} must be yes or no'}), 400
            want[k] = v
    if d.get('root_login') not in (None, ''):
        v = str(d['root_login']).strip().lower()
        if v not in _SSH_ROOT_LOGIN_VALUES:
            return jsonify({'ok':False,'error':'Invalid PermitRootLogin value'}), 400
        want['root_login'] = 'prohibit-password' if v == 'without-password' else v
    if d.get('max_auth_tries') not in (None, ''):
        try:
            m = int(str(d['max_auth_tries']).strip())
            if not 1 <= m <= 100: raise ValueError()
        except (ValueError, TypeError):
            return jsonify({'ok':False,'error':'MaxAuthTries must be between 1 and 100'}), 400
        want['max_auth_tries'] = str(m)

    with open(SSHD_CONFIG) as f: content = f.read()
    eff = _sshd_effective()
    old_port = eff.get('port') or _sshd_file_value(content, 'Port', '22')
    old_ports = set(eff.get('port_list') or [old_port])
    new_port = want.get('port', old_port)

    # --- lockout guards (effective values after this change)
    final_pw   = want.get('password_auth', eff.get('passwordauthentication', 'yes'))
    final_pk   = want.get('pubkey_auth', eff.get('pubkeyauthentication', 'yes'))
    final_root = want.get('root_login', eff.get('permitrootlogin', 'prohibit-password'))
    sudo_users = _sudo_users()
    if final_pw == 'no' and final_pk == 'no':
        return jsonify({'ok':False,'error':'Disabling both password and public-key authentication would lock everyone out.'}), 400
    # Only guard transitions this request makes, so an already-hardened box
    # (keys kept somewhere this check cannot see) can still save other fields.
    if final_root == 'no' and eff.get('permitrootlogin') != 'no' and not sudo_users:
        return jsonify({'ok':False,'error':'Cannot disable root login: no sudo user exists. Create a sudo user first.'}), 400
    if final_pw == 'no' and (eff.get('passwordauthentication') != 'no' or final_root == 'no'):
        root_key = final_root != 'no' and _authorized_keys_present('/root')
        user_key = any(_authorized_keys_present(_user_home(u)) for u in sudo_users)
        if not root_key and not user_key:
            return jsonify({'ok':False,
                'error':'Cannot disable password auth: no usable SSH key found (root authorized_keys with root login allowed, or a sudo user with authorized_keys).'}), 400
    if new_port not in old_ports and _port_listening(new_port):
        return jsonify({'ok':False,'error':f'Port {new_port} is already in use by another service'}), 400

    # --- build new main file + rewrite overriding drop-ins
    files = {SSHD_CONFIG: content}
    if (SSHD_DROPIN_DIR in content or 'sshd_config.d' in content) and os.path.isdir(SSHD_DROPIN_DIR):
        for fn in sorted(os.listdir(SSHD_DROPIN_DIR)):
            fp = os.path.join(SSHD_DROPIN_DIR, fn)
            if fn.endswith('.conf') and os.path.isfile(fp):
                try: files[fp] = open(fp).read()
                except Exception: pass
    new_files = dict(files)
    for k, v in want.items():
        key = _SSH_KEYS[k]
        new_files[SSHD_CONFIG], _ = _sshd_set(new_files[SSHD_CONFIG], key, v)
        for fp in new_files:
            if fp != SSHD_CONFIG:
                new_files[fp], _ = _sshd_set(new_files[fp], key, v, append=False)

    def _restore():
        for fp, txt in files.items():
            if new_files.get(fp) != txt:
                with open(fp, 'w') as f: f.write(txt)

    for fp, txt in new_files.items():
        if txt != files[fp]:
            with open(fp, 'w') as f: f.write(txt)
    test_out, test_err, rc = sh('sshd -t 2>&1 || /usr/sbin/sshd -t 2>&1', t=15)
    if rc != 0:
        _restore()
        return jsonify({'ok':False, 'error':f'sshd config test failed, nothing changed: {test_out}{test_err}'}), 400

    port_changed = new_port not in old_ports
    if port_changed:
        # Open the new port BEFORE sshd moves to it. On SELinux-enforcing
        # systems sshd may only bind ports labelled ssh_port_t.
        _fw_open_tcp(new_port)
        _, _, se_rc = sh('command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled')
        if se_rc == 0:
            sh(f'semanage port -a -t ssh_port_t -p tcp {new_port} 2>&1 || '
               f'semanage port -m -t ssh_port_t -p tcp {new_port} 2>&1', t=90)

    applied, apply_err = _sshd_apply()

    if port_changed:
        import time as _time
        listening = False
        for _ in range(8):
            if _port_listening(new_port):
                listening = True
                break
            _time.sleep(1)
        if not listening:
            # Roll back so the admin keeps the port they are connected on.
            _restore()
            _sshd_apply()
            _fw_close_tcp(new_port)
            return jsonify({'ok':False,
                'error':f'sshd did not start listening on port {new_port} (SELinux label, socket unit or bind failure); '
                        f'the previous configuration (port {old_port}) was restored. {apply_err}'.strip()}), 500
        _fw_close_tcp(old_port)
    elif not applied:
        return jsonify({'ok':False, 'error':f'Config saved and validated, but reloading sshd failed: {apply_err}'}), 500

    return jsonify({'ok':True, 'port': new_port})


@security_bp.route('/api/security/ssh/create-user', methods=['POST'])
def create_sudo_user():
    """Create a new sudo user — must do this before disabling root login."""
    if not req(): return jsonify({'ok':False}), 401
    d        = request.get_json() or {}
    username = d.get('username','').strip().lower()
    password = d.get('password','')
    pubkey   = d.get('pubkey','').strip()

    if not username or not re.match(r'^[a-z_][a-z0-9_-]{1,30}$', username):
        return jsonify({'ok':False,'error':'Invalid username (2-31 chars, lowercase letters/numbers/-/_)'}), 400
    if not password and not pubkey:
        return jsonify({'ok':False,'error':'Password or SSH public key required'}), 400
    if len(password) < 8 and password:
        return jsonify({'ok':False,'error':'Password must be at least 8 characters'}), 400
    # chpasswd reads "user:password" lines: a newline in the password would
    # let the request set the password of any other account (root included).
    if '\n' in password or '\r' in password:
        return jsonify({'ok':False,'error':'Password must not contain line breaks'}), 400
    if pubkey and not _valid_pubkey_lines(pubkey):
        return jsonify({'ok':False,'error':'Invalid SSH public key'}), 400

    # Check user doesn't already exist
    out, _, rc = sh(f'id {username} 2>/dev/null')
    if rc == 0:
        return jsonify({'ok':False,'error':f'User {username} already exists'}), 409

    # Create user
    _, err, rc = sh(f'useradd -m -s /bin/bash {username} 2>&1')
    if rc != 0:
        return jsonify({'ok':False,'error':f'Failed to create user: {err}'}), 500

    # Set password
    if password:
        pw_proc = subprocess.run(['chpasswd'], input=f'{username}:{password}\n', text=True, capture_output=True, timeout=30)
        if pw_proc.returncode != 0:
            sh(f'userdel -r {username} 2>/dev/null')
            return jsonify({'ok':False,'error':f'Failed to set password: {pw_proc.stderr.strip()}'}), 500

    # Add to sudo/wheel group
    os_family, _, _ = sh('. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian')
    sudo_group = 'wheel' if any(x in os_family for x in ('rhel','fedora','centos','almalinux','rocky','ol','cloudlinux')) else 'sudo'
    sh(f'usermod -aG {sudo_group} {username} 2>/dev/null')

    # Add SSH public key
    if pubkey:
        ssh_dir = os.path.join(_user_home(username), '.ssh')
        sh(f'mkdir -p {ssh_dir} && chmod 700 {ssh_dir}')
        with open(f'{ssh_dir}/authorized_keys', 'w') as f:
            f.write(pubkey.replace('\r', '') + '\n')
        sh(f'chmod 600 {ssh_dir}/authorized_keys && chown -R {username}: {ssh_dir} && '
           f'(command -v restorecon >/dev/null 2>&1 && restorecon -R {ssh_dir} || true)')

    return jsonify({'ok':True,'username':username,'sudo_group':sudo_group})


@security_bp.route('/api/security/ssh/add-key', methods=['POST'])
def add_ssh_key():
    """Add an SSH public key to /root/.ssh/authorized_keys."""
    if not req(): return jsonify({'ok':False}), 401
    pubkey = ((request.get_json() or {}).get('pubkey') or '').strip()
    if not pubkey or '\n' in pubkey or '\r' in pubkey or not _valid_pubkey_lines(pubkey):
        return jsonify({'ok':False,'error':'Invalid public key format (one key, e.g. ssh-ed25519 AAAA... comment)'}), 400
    ssh_dir = '/root/.ssh'
    os.makedirs(ssh_dir, exist_ok=True)
    os.chmod(ssh_dir, 0o700)
    auth_file = f'{ssh_dir}/authorized_keys'
    # Check if key already exists
    existing = ''
    if os.path.exists(auth_file):
        existing = open(auth_file).read()
    if pubkey in existing:
        return jsonify({'ok':True,'message':'Key already exists'})
    with open(auth_file,'a') as f:
        f.write(('\n' if existing and not existing.endswith('\n') else '') + pubkey + '\n')
    os.chmod(auth_file, 0o600)
    sh('command -v restorecon >/dev/null 2>&1 && restorecon -R /root/.ssh')
    return jsonify({'ok':True})


_PUBKEY_RE = re.compile(r'^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|'
                        r'sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+[A-Za-z0-9+/=]{20,}(\s+\S.*)?$')

def _valid_pubkey_lines(text):
    """Every non-empty line must be a plain OpenSSH public key (no options
    prefix such as command=... and nothing that is not a key)."""
    lines = [l.strip() for l in text.replace('\r', '').split('\n') if l.strip()]
    return bool(lines) and all(_PUBKEY_RE.match(l) for l in lines)

# --- Fail2ban ------------------------------------------------------------------
@security_bp.route('/api/security/fail2ban')
def fail2ban_status():
    if not req(): return jsonify({'ok':False}), 401
    out, _, rc = sh('fail2ban-client status 2>/dev/null')
    if rc != 0: return jsonify({'ok':False,'error':'Fail2ban not running','jails':[]})

    jails_raw = re.search(r'Jail list:\s*(.+)', out)
    jail_names = [j.strip() for j in jails_raw.group(1).split(',')] if jails_raw else []

    jails = []
    for jail in jail_names:
        if not jail or not _F2B_JAIL_RE.match(jail): continue
        jout, _, _ = sh(f'fail2ban-client status {jail} 2>/dev/null')
        currently_banned = re.search(r'Currently banned:\s*(\d+)', jout)
        total_banned     = re.search(r'Total banned:\s*(\d+)', jout)
        banned_ips_m     = re.search(r'Banned IP list:\s*(.*)', jout)
        banned_ips = [ip.strip() for ip in (banned_ips_m.group(1).split() if banned_ips_m else [])]
        jails.append({
            'name':          jail,
            'currently':     int(currently_banned.group(1)) if currently_banned else 0,
            'total':         int(total_banned.group(1)) if total_banned else 0,
            'banned_ips':    banned_ips[:20],
        })
    return jsonify({'ok':True,'jails':jails})

@security_bp.route('/api/security/fail2ban/unban', methods=['POST'])
def unban_ip():
    if not req(): return jsonify({'ok':False}), 401
    d    = request.get_json() or {}
    ip   = d.get('ip','').strip()
    jail = d.get('jail','sshd')
    if not ip: return jsonify({'ok':False,'error':'IP required'}), 400
    # Both values reach a shell: only a real IP/CIDR and a plain jail name.
    if not _valid_ip_or_cidr(ip) or not _F2B_JAIL_RE.match(str(jail)):
        return jsonify({'ok':False,'error':'Invalid IP or jail name'}), 400
    out, err, rc = sh(f'fail2ban-client set {jail} unbanip {ip} 2>&1')
    if rc != 0:
        return jsonify({'ok':False,'error':(out or err or 'fail2ban-client failed')[-300:]}), 400
    return jsonify({'ok':True})

@security_bp.route('/api/security/fail2ban/ban', methods=['POST'])
def ban_ip():
    if not req(): return jsonify({'ok':False}), 401
    d    = request.get_json() or {}
    ip   = d.get('ip','').strip()
    jail = d.get('jail','sshd')
    if not ip: return jsonify({'ok':False,'error':'IP required'}), 400
    # Both values reach a shell: only a real IP/CIDR and a plain jail name.
    if not _valid_ip_or_cidr(ip) or not _F2B_JAIL_RE.match(str(jail)):
        return jsonify({'ok':False,'error':'Invalid IP or jail name'}), 400
    out, err, rc = sh(f'fail2ban-client set {jail} banip {ip} 2>&1')
    if rc != 0:
        return jsonify({'ok':False,'error':(out or err or 'fail2ban-client failed')[-300:]}), 400
    return jsonify({'ok':True})


# --- FAIL2BAN JAIL CREATION (Website Protection / Server Protection) -------------
# Previously VortexPanel could only view/ban/unban IPs on jails that already
# existed at the OS level (e.g. the default sshd jail) — there was no way to
# actually CREATE a jail from the panel, so "Website Protection" and "Server
# Protection" (matching aaPanel's Fail2ban Manager) only ever showed
# "No jails configured" with no path forward. This was a genuinely missing
# feature, not a bug in existing code.
_F2B_JAIL_RE   = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
F2B_JAIL_DIR   = '/etc/fail2ban/jail.d'
F2B_FILTER_DIR = '/etc/fail2ban/filter.d'
VORTEX_SITE_PREFIX   = 'vortex-site-'
VORTEX_SERVER_PREFIX = 'vortex-server-'

def _f2b_safe_name(name):
    return re.sub(r'[^a-zA-Z0-9_-]', '', (name or '').strip())[:60]

def _f2b_reload():
    out, err, rc = sh('fail2ban-client reload 2>&1', t=20)
    return rc == 0, (out or err)

def _parse_jail_conf(path):
    """Parse a simple INI-style jail.d config file into a dict."""
    if not os.path.exists(path): return {}
    cfg = {}
    section = None
    for line in open(path).read().splitlines():
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
            cfg[section] = {}
        elif '=' in line and section:
            k, _, v = line.partition('=')
            cfg[section][k.strip()] = v.strip()
    return cfg


@security_bp.route('/api/security/fail2ban/website-jails')
def list_website_jails():
    if not req(): return jsonify({'ok': False}), 401
    jails = []
    if os.path.isdir(F2B_JAIL_DIR):
        for fname in sorted(os.listdir(F2B_JAIL_DIR)):
            if not fname.startswith(VORTEX_SITE_PREFIX) or not fname.endswith('.conf'):
                continue
            cfg = _parse_jail_conf(os.path.join(F2B_JAIL_DIR, fname))
            for section, opts in cfg.items():
                status_out, _, _ = sh(f'fail2ban-client status {section} 2>/dev/null')
                currently = re.search(r'Currently banned:\s*(\d+)', status_out)
                jails.append({
                    'name': section,
                    'site': opts.get('_vortex_site', ''),
                    'port': opts.get('port', ''),
                    'mode': opts.get('_vortex_mode', 'anti-cc'),
                    'maxretry': opts.get('maxretry', ''),
                    'findtime': opts.get('findtime', ''),
                    'bantime': opts.get('bantime', ''),
                    'enabled': opts.get('enabled', 'true') == 'true',
                    'currently_banned': int(currently.group(1)) if currently else 0,
                })
    return jsonify({'ok': True, 'jails': jails})


_F2B_PORT_RE = re.compile(r'^[A-Za-z0-9:,-]{1,100}$')


def _f2b_numbers(d, defaults):
    """Parse maxretry/findtime/bantime. Returns (values_dict, error)."""
    limits = {'maxretry': (1, 100000), 'findtime': (1, 31536000), 'bantime': (-1, 315360000)}
    vals = {}
    for k, dflt in defaults.items():
        try:
            v = int(d.get(k, dflt) if d.get(k) not in (None, '') else dflt)
        except (ValueError, TypeError):
            return None, f'{k} must be a number'
        lo, hi = limits[k]
        if v < lo or v > hi or (k == 'bantime' and v == 0):
            return None, f'{k} out of range'
        vals[k] = v
    return vals, ''


def _f2b_action_line(key, port_val):
    """Ban action that follows the distro's configured banaction (iptables
    on Debian/Ubuntu, firewallcmd-* with fail2ban-firewalld on RHEL, nftables
    where configured). The name is a short hash: iptables chain names are
    limited to 28 chars ("f2b-" + name), which a domain-derived name broke
    for any domain longer than ~24 characters."""
    import hashlib
    short = 'vx' + hashlib.sha1(key.encode()).hexdigest()[:10]
    return f'action = %(banaction)s[name={short}, port="{port_val}", protocol=tcp]\n'


def _site_access_log(site):
    """(log path, log format) for a site, per web server -- the same paths
    the vhost templates in wp_toolkit write. Caddy writes JSON logs."""
    try:
        from panel.routes.websites_core import site_webserver, apache_log_dir
        ws = site_webserver(site) or 'nginx'
    except Exception:
        ws, apache_log_dir = 'nginx', None
    if ws == 'apache' and apache_log_dir:
        return f'{apache_log_dir()}/{site}.access.log', 'combined'
    if ws == 'openlitespeed':
        return f'/var/log/openlitespeed/{site}.access_log', 'combined'
    if ws == 'caddy':
        return f'/var/log/caddy/{site}.log', 'caddy-json'
    return f'/var/log/nginx/{site}.access.log', 'combined'


@security_bp.route('/api/security/fail2ban/website-jails', methods=['POST'])
def create_website_jail():
    """Anti-CC / scan protection for a specific site's access log.
    Uses fail2ban's own counting engine (maxretry within findtime) — the
    filter just needs to correctly extract the client IP from each request
    line; fail2ban handles the threshold/ban logic itself."""
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}

    site     = (d.get('site') or '').strip().lower()
    mode     = d.get('mode', 'anti-cc')  # 'anti-cc' | 'anti-scan'
    port_val = str(d.get('port') or '80,443').strip().replace(' ', '')

    if not site:
        return jsonify({'ok': False, 'error': 'Site is required'})
    # site and port are written into fail2ban config files and site into a
    # log path: plain hostname / port list only.
    if not _valid_hostname(site):
        return jsonify({'ok': False, 'error': 'Invalid site domain'}), 400
    if mode not in ('anti-cc', 'anti-scan'):
        return jsonify({'ok': False, 'error': 'mode must be anti-cc or anti-scan'}), 400
    if not _F2B_PORT_RE.match(port_val):
        return jsonify({'ok': False, 'error': 'Invalid port list (e.g. 80,443)'}), 400
    nums, nerr = _f2b_numbers(d, {'maxretry': 30, 'findtime': 300, 'bantime': 600})
    if nerr:
        return jsonify({'ok': False, 'error': nerr}), 400
    maxretry, findtime, bantime = nums['maxretry'], nums['findtime'], nums['bantime']

    safe_site = _f2b_safe_name(site.replace('.', '_'))
    jail_name = f'{VORTEX_SITE_PREFIX}{safe_site}'
    access_log, log_fmt = _site_access_log(site)

    if not os.path.exists(access_log):
        return jsonify({'ok': False, 'error': f'Access log not found: {access_log} — the site must exist and have received at least one request'})

    os.makedirs(F2B_FILTER_DIR, exist_ok=True)
    os.makedirs(F2B_JAIL_DIR, exist_ok=True)

    # Filter: matches every request line, extracting the client IP as <HOST>.
    # fail2ban's engine does the actual counting — this filter only needs to
    # reliably identify "a request happened, here's who made it".
    datepattern = ''
    if log_fmt == 'caddy-json':
        # Caddy access log: one JSON object per line, epoch "ts" field.
        status = '(?:404|403)' if mode == 'anti-scan' else r'\d+'
        failregex = rf'"remote_ip":"<HOST>".*"status":{status}\b'
        datepattern = 'datepattern = "ts":{EPOCH}\n'
    elif mode == 'anti-scan':
        # Anti-scan: only count 4xx/404-type responses (probing for files/paths)
        failregex = r'^<HOST> -.*"(GET|POST|HEAD|PUT|DELETE|OPTIONS) [^"]*" (404|403) '
    else:
        # Anti-CC: count every request regardless of status (raw request-rate limiting)
        failregex = r'^<HOST> -.*"(GET|POST|HEAD|PUT|DELETE|OPTIONS) [^"]*" \d+ '

    filter_content = (
        f'[Definition]\n'
        f'failregex = {failregex}\n'
        f'ignoreregex =\n'
        f'{datepattern}'
    )
    filter_path = os.path.join(F2B_FILTER_DIR, f'{jail_name}.conf')

    jail_content = (
        f'[{jail_name}]\n'
        f'enabled = true\n'
        f'port = {port_val}\n'
        f'filter = {jail_name}\n'
        f'logpath = {access_log}\n'
        f'maxretry = {maxretry}\n'
        f'findtime = {findtime}\n'
        f'bantime = {bantime}\n'
        f'backend = polling\n'
        + _f2b_action_line(jail_name, port_val) +
        f'_vortex_site = {site}\n'
        f'_vortex_mode = {mode}\n'
    )
    jail_path = os.path.join(F2B_JAIL_DIR, f'{jail_name}.conf')

    prev_filter = open(filter_path).read() if os.path.exists(filter_path) else None
    prev_jail   = open(jail_path).read() if os.path.exists(jail_path) else None
    with open(filter_path, 'w') as f: f.write(filter_content)
    with open(jail_path, 'w') as f: f.write(jail_content)

    ok, output = _f2b_reload()
    if not ok:
        # Restore the previous state so we don't leave a broken jail definition behind
        for path, prev in ((jail_path, prev_jail), (filter_path, prev_filter)):
            try:
                if prev is None: os.remove(path)
                else: open(path, 'w').write(prev)
            except Exception: pass
        _f2b_reload()
        return jsonify({'ok': False, 'error': f'fail2ban reload failed: {output[-400:]}'})

    return jsonify({'ok': True, 'jail': jail_name})


@security_bp.route('/api/security/fail2ban/website-jails/<name>', methods=['DELETE'])
def delete_website_jail(name):
    if not req(): return jsonify({'ok': False}), 401
    name = _f2b_safe_name(name)
    if not name.startswith(VORTEX_SITE_PREFIX):
        return jsonify({'ok': False, 'error': 'Invalid jail name'})
    jail_path   = os.path.join(F2B_JAIL_DIR, f'{name}.conf')
    filter_path = os.path.join(F2B_FILTER_DIR, f'{name}.conf')
    for p in (jail_path, filter_path):
        if os.path.exists(p):
            try: os.remove(p)
            except Exception: pass
    ok, output = _f2b_reload()
    return jsonify({'ok': ok, 'error': output[-400:] if not ok else ''})


@security_bp.route('/api/security/fail2ban/server-jails')
def list_server_jails():
    if not req(): return jsonify({'ok': False}), 401
    jails = []
    if os.path.isdir(F2B_JAIL_DIR):
        for fname in sorted(os.listdir(F2B_JAIL_DIR)):
            if not fname.startswith(VORTEX_SERVER_PREFIX) or not fname.endswith('.conf'):
                continue
            cfg = _parse_jail_conf(os.path.join(F2B_JAIL_DIR, fname))
            for section, opts in cfg.items():
                status_out, _, _ = sh(f'fail2ban-client status {section} 2>/dev/null')
                currently = re.search(r'Currently banned:\s*(\d+)', status_out)
                jails.append({
                    'name': section,
                    'server': opts.get('filter', ''),
                    'port': opts.get('port', ''),
                    'maxretry': opts.get('maxretry', ''),
                    'findtime': opts.get('findtime', ''),
                    'bantime': opts.get('bantime', ''),
                    'enabled': opts.get('enabled', 'true') == 'true',
                    'currently_banned': int(currently.group(1)) if currently else 0,
                })
    return jsonify({'ok': True, 'jails': jails})


# Common services and their built-in fail2ban filter name + log locations.
# These reuse fail2ban's OWN shipped filters (no custom regex needed) — only
# the well-known, standard services are offered here to avoid generating a
# jail against a filter/log combination that doesn't actually exist.
# Log paths differ per distro (Debian: auth.log / mail.log, RHEL: secure /
# maillog) and Debian 12+ ships without rsyslog, so there may be no file at
# all: filters that define a journalmatch then use backend = systemd.
SERVER_PROTECTION_PRESETS = {
    'sshd':     {'filter': 'sshd',    'logpaths': ['/var/log/auth.log', '/var/log/secure'],
                 'journal': True,  'default_port': '22'},
    'vsftpd':   {'filter': 'vsftpd',  'logpaths': ['/var/log/vsftpd.log', '/var/log/secure', '/var/log/auth.log'],
                 'journal': False, 'default_port': '21'},
    'proftpd':  {'filter': 'proftpd', 'logpaths': ['/var/log/proftpd/proftpd.log', '/var/log/secure', '/var/log/auth.log'],
                 'journal': False, 'default_port': '21'},
    'postfix':  {'filter': 'postfix', 'logpaths': ['/var/log/mail.log', '/var/log/maillog'],
                 'journal': True,  'default_port': '25,465,587'},
    'dovecot':  {'filter': 'dovecot', 'logpaths': ['/var/log/mail.log', '/var/log/maillog'],
                 'journal': True,  'default_port': '110,143,993,995'},
}


def _preset_default_port(key):
    if key == 'sshd':
        ports = _sshd_effective().get('port_list')
        if ports:
            return ','.join(ports)
    return SERVER_PROTECTION_PRESETS[key]['default_port']


@security_bp.route('/api/security/fail2ban/server-presets')
def server_presets():
    if not req(): return jsonify({'ok': False}), 401
    return jsonify({'ok': True, 'presets': [
        {'id': k, 'label': k, 'default_port': _preset_default_port(k)} for k in SERVER_PROTECTION_PRESETS
    ]})


@security_bp.route('/api/security/fail2ban/server-jails', methods=['POST'])
def create_server_jail():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}

    server = (d.get('server') or 'sshd').strip()
    if server not in SERVER_PROTECTION_PRESETS:
        return jsonify({'ok': False, 'error': f'Unknown service "{server}" — supported: {", ".join(SERVER_PROTECTION_PRESETS)}'})

    preset   = SERVER_PROTECTION_PRESETS[server]
    port_val = str(d.get('port') or _preset_default_port(server)).strip().replace(' ', '')
    if not _F2B_PORT_RE.match(port_val):
        return jsonify({'ok': False, 'error': 'Invalid port list (e.g. 22 or 25,465,587)'}), 400
    nums, nerr = _f2b_numbers(d, {'maxretry': 30, 'findtime': 300, 'bantime': 600})
    if nerr:
        return jsonify({'ok': False, 'error': nerr}), 400

    jail_name = f'{VORTEX_SERVER_PREFIX}{server}'
    os.makedirs(F2B_JAIL_DIR, exist_ok=True)

    logpath = next((p for p in preset['logpaths'] if os.path.exists(p)), None)
    if logpath:
        source = f'logpath = {logpath}\nbackend = auto\n'
    elif preset['journal']:
        _, _, jrc = sh('python3 -c "import systemd.journal" 2>/dev/null')
        if jrc != 0:
            return jsonify({'ok': False, 'error': f'No {server} log file ({", ".join(preset["logpaths"])}) and the systemd journal backend '
                                                  f'is unavailable — install python3-systemd (or rsyslog) and retry.'})
        source = 'backend = systemd\n'
    else:
        return jsonify({'ok': False, 'error': f'Log file not found ({", ".join(preset["logpaths"])}) — is {server} installed and has it logged anything yet?'})

    jail_content = (
        f'[{jail_name}]\n'
        f'enabled = true\n'
        f'port = {port_val}\n'
        f'filter = {preset["filter"]}\n'
        f'{source}'
        f'maxretry = {nums["maxretry"]}\n'
        f'findtime = {nums["findtime"]}\n'
        f'bantime = {nums["bantime"]}\n'
        + _f2b_action_line(jail_name, port_val)
    )
    jail_path = os.path.join(F2B_JAIL_DIR, f'{jail_name}.conf')
    prev = open(jail_path).read() if os.path.exists(jail_path) else None
    with open(jail_path, 'w') as f: f.write(jail_content)

    ok, output = _f2b_reload()
    if not ok:
        try:
            if prev is None: os.remove(jail_path)
            else: open(jail_path, 'w').write(prev)
        except Exception: pass
        _f2b_reload()
        return jsonify({'ok': False, 'error': f'fail2ban reload failed: {output[-400:]}'})

    return jsonify({'ok': True, 'jail': jail_name})


@security_bp.route('/api/security/fail2ban/server-jails/<name>', methods=['DELETE'])
def delete_server_jail(name):
    if not req(): return jsonify({'ok': False}), 401
    name = _f2b_safe_name(name)
    if not name.startswith(VORTEX_SERVER_PREFIX):
        return jsonify({'ok': False, 'error': 'Invalid jail name'})
    jail_path = os.path.join(F2B_JAIL_DIR, f'{name}.conf')
    if os.path.exists(jail_path):
        try: os.remove(jail_path)
        except Exception: pass
    ok, output = _f2b_reload()
    return jsonify({'ok': ok, 'error': output[-400:] if not ok else ''})


# --- Login attempts -------------------------------------------------------------
@security_bp.route('/api/security/login-attempts')
def login_attempts():
    if not req(): return jsonify({'ok':False}), 401
    attempts = []
    # Try different auth log locations
    for log in ['/var/log/auth.log', '/var/log/secure', '/var/log/btmp']:
        if not os.path.exists(log): continue
        if log == '/var/log/btmp':
            out, _, _ = sh('last -F -f /var/log/btmp 2>/dev/null | head -30')
        else:
            out, _, _ = sh(f'grep -i "failed\\|invalid\\|illegal" {log} 2>/dev/null | tail -50')
        if out: attempts.append({'log':log, 'content':out})
        break
    if not attempts:
        # Debian 12+ / minimal images have no rsyslog: auth events only
        # live in the journal.
        out, _, _ = sh('journalctl -q --no-pager -n 2000 _COMM=sshd 2>/dev/null '
                       '| grep -iE "failed|invalid|illegal" | tail -50', t=20)
        if out: attempts.append({'log':'journal (sshd)', 'content':out})
    return jsonify({'ok':True,'attempts':attempts})

# --- Port scan / open ports -----------------------------------------------------
@security_bp.route('/api/security/ports')
def open_ports():
    if not req(): return jsonify({'ok':False}), 401
    out, _, _ = sh('ss -tlnp 2>/dev/null')
    return jsonify({'ok':True,'output':out})

# --- Security Score -------------------------------------------------------------
@security_bp.route('/api/security/score')
def security_score():
    if not req(): return jsonify({'ok':False}), 401
    checks = []

    # --- SSH --------------------------------------------------------------------
    sshd = '/etc/ssh/sshd_config'
    if os.path.exists(sshd):
        # Effective values (drop-ins included) rather than a grep of the main file.
        with open(sshd) as f: content = f.read()
        eff = _sshd_effective()
        val  = (eff.get('permitrootlogin') or _sshd_file_value(content, 'PermitRootLogin', 'yes')).lower()
        checks.append({'label':'SSH Root Login Disabled',
                        'pass': val in ('no','prohibit-password','without-password','forced-commands-only'),
                        'severity':'high'})
        pval = (eff.get('passwordauthentication') or _sshd_file_value(content, 'PasswordAuthentication', 'yes')).lower()
        checks.append({'label':'SSH Password Auth Disabled',
                        'pass': pval == 'no', 'severity':'medium'})
        ports = eff.get('port_list') or [_sshd_file_value(content, 'Port', '22')]
        checks.append({'label':'SSH on Non-default Port',
                        'pass': '22' not in ports, 'severity':'low'})

    # --- Fail2ban ---------------------------------------------------------------
    f2b, _, _ = sh('systemctl is-active fail2ban 2>/dev/null')
    checks.append({'label':'Fail2ban Running',
                   'pass': f2b.strip() == 'active', 'severity':'high'})

    # --- Firewall — check both UFW and firewalld --------------------------------
    ufw, _, _  = sh('ufw status 2>/dev/null | head -1')
    fwd, _, _  = sh('firewall-cmd --state 2>/dev/null')
    # "Status: inactive" contains "active" -- compare the exact status line.
    fw_active  = ufw.strip().lower() == 'status: active' or fwd.strip() == 'running'
    checks.append({'label':'Firewall Active (UFW or firewalld)',
                   'pass': fw_active, 'severity':'high'})

    # --- Auto security updates --------------------------------------------------
    apt_out, _, _ = sh('dpkg -l unattended-upgrades 2>/dev/null | grep -c "^ii"')
    # rpm -q works with dnf4 and dnf5 alike (dnf5 changed `list installed`).
    _, _, dnf_rc  = sh('rpm -q dnf-automatic >/dev/null 2>&1 || rpm -q dnf5-plugin-automatic >/dev/null 2>&1')
    auto_updates  = apt_out.strip() == '1' or dnf_rc == 0
    checks.append({'label':'Auto Security Updates Enabled',
                   'pass': auto_updates, 'severity':'medium'})

    # --- Panel security ---------------------------------------------------------
    try:
        import json as _json, hashlib as _hashlib
        creds_file = '/opt/vortexpanel/credentials.json'
        if os.path.exists(creds_file):
            creds = _json.load(open(creds_file))
            h = creds.get('password_hash','')
            # bcrypt hash starts with $2b$
            checks.append({'label':'Panel Password Uses bcrypt or Argon2id (not SHA-256)',
                           'pass': h.startswith('$2b$') or h.startswith('$2a$') or h.startswith('$argon2'),
                           'severity':'high'})
            # Default password check (admin123)
            default_sha = _hashlib.sha256(b'admin123').hexdigest()
            not_default = h != default_sha and h != _hashlib.sha256(b'admin').hexdigest()
            checks.append({'label':'Panel Default Password Changed',
                           'pass': not_default, 'severity':'critical'})
            # 2FA
            checks.append({'label':'Panel Two-Factor Authentication Enabled',
                           'pass': bool(creds.get('totp_enabled') and creds.get('totp_secret')),
                           'severity':'medium'})
    except Exception:
        pass

    # --- Secret key not default -------------------------------------------------
    checks.append({'label':'Panel Secret Key Auto-Generated (not default)',
                   'pass': os.path.exists('/opt/vortexpanel/secret.key'),
                   'severity':'high'})

    passed = sum(1 for c in checks if c['pass'])
    score  = round(passed / len(checks) * 100) if checks else 0
    return jsonify({'ok':True, 'checks':checks, 'score':score})

# --- ModSecurity ----------------------------------------------------------------

def _modsec_target():
    """Which webserver's ModSecurity is actually installed on this box,
    checked directly against disk rather than assumed. Returns 'nginx',
    'apache', or None if neither config exists yet. Every path helper and
    every endpoint below goes through this instead of a hardcoded nginx
    path, which is the root cause behind four separate broken surfaces
    found by a real user: the WAF Settings modal ('nginx service:
    inactive' on an Apache box), WAF Analytics ('not installed' despite
    a working install), the Security page WAF tab ('supports Nginx'
    only), and the App Store status badge -- all of them ultimately call
    into this same backend, and it only ever checked nginx paths."""
    if os.path.exists('/etc/nginx/modsec/modsecurity.conf'):
        return 'nginx'
    if os.path.exists('/etc/modsecurity/modsecurity.conf'):
        return 'apache'
    return None

def _modsec_conf():
    return '/etc/modsecurity/modsecurity.conf' if _modsec_target() == 'apache' else '/etc/nginx/modsec/modsecurity.conf'

def _modsec_main():
    return '/etc/modsecurity/main.conf' if _modsec_target() == 'apache' else '/etc/nginx/modsec/main.conf'

def _modsec_crs_dir():
    return '/etc/modsecurity/crs' if _modsec_target() == 'apache' else '/etc/nginx/modsec/crs'

def _modsec_custom():
    return '/etc/modsecurity/custom-rules.conf' if _modsec_target() == 'apache' else '/etc/nginx/modsec/custom-rules.conf'

def _modsec_dir():
    return '/etc/modsecurity' if _modsec_target() == 'apache' else '/etc/nginx/modsec'

def _modsec_lists_conf():
    return os.path.join(_modsec_dir(), 'vortex-lists.conf')

def _modsec_lists_json():
    return _waf_state_path('vortex-lists.json')


WAF_STATE_DIR = '/opt/vortexpanel/data/waf'

def _waf_state_path(name):
    """Where a WAF model JSON lives. Older installs kept it next to the
    ModSecurity config (/etc/nginx/modsec or /etc/modsecurity) -- keep using
    that file when it exists. Otherwise use the panel's data dir: the model
    is shared by nginx, Apache AND Caddy/Coraza, and creating /etc/nginx/...
    on a Caddy-only server made other pages believe nginx was installed."""
    legacy = os.path.join(_modsec_dir(), name)
    if os.path.exists(legacy):
        return legacy
    return os.path.join(WAF_STATE_DIR, name)


def _write_json_state(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def _modsec_audit():
    """Read the actual SecAuditLog path from whichever modsecurity.conf
    is active, rather than assume a shared constant -- the downloaded
    recommended conf and VortexPanel's own fallback conf could specify
    different paths, and nginx vs Apache builds may too."""
    conf = _modsec_conf()
    if os.path.exists(conf):
        try:
            m = re.search(r'SecAuditLog\s+(\S+)', open(conf).read())
            if m: return m.group(1)
        except Exception:
            pass
    return '/var/log/modsec_audit.log'

def _modsec_configtest():
    """Validate config for whichever webserver is active. Returns
    (ok, output)."""
    if _modsec_target() == 'apache':
        out, err, rc = sh('apache2ctl configtest 2>&1 || apachectl configtest 2>&1 || httpd -t 2>&1')
        return rc == 0, (out or err)
    out, err, rc = sh('nginx -t 2>&1')
    return rc == 0, (out or err)

def _modsec_reload():
    """Reload whichever webserver is active."""
    if _modsec_target() == 'apache':
        sh('systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null || service apache2 reload 2>/dev/null || apachectl graceful 2>/dev/null')
    else:
        sh('systemctl reload nginx 2>/dev/null')

MODSEC_AUDIT    = '/var/log/modsec_audit.log'  # fallback default; _modsec_audit() reads the real value at runtime

# --- WAF Blacklist / Whitelist ----------------------------------------------------
# ID ranges reserved outside OWASP CRS's 900000-999999 space so this can never
# collide with CRS or the free-text custom-rules.conf. Whitelist rules use
# ctl:ruleEngine=Off so a whitelisted request skips CRS entirely (real
# performance win, not just a "don't block" flag) — this is why the lists file
# must be Included BEFORE crs-setup.conf, not after.
_LIST_ID_BASE = {'ip_whitelist': 1050000, 'ip_blacklist': 1051000,
                  'ua_blacklist': 1052000, 'url_blacklist': 1053000}

_IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
_IPV6_RE = re.compile(r'^[0-9a-fA-F:]+(/\d{1,3})?$')

def _valid_ip(v):
    v = v.strip()
    if not v: return False
    if _IPV4_RE.match(v):
        parts = v.split('/')[0].split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    return bool(_IPV6_RE.match(v)) and ':' in v

def _modsec_str_escape(v):
    """Escape a value going inside a ModSecurity double-quoted operator
    string. Only the string delimiter is escaped (\\"): the config parsers
    (Apache's for v2, libmodsecurity's for v3, Coraza's) do NOT turn "\\\\"
    back into one backslash, so the old doubling of backslashes changed
    every user regex -- "\\.php$" became "\\\\.php$" (a literal backslash
    followed by any character). Pattern metacharacters are intentionally
    left alone since users are entering real regex. Newlines are stripped so
    a value can't break out onto a new config line, and a trailing backslash
    is dropped so it cannot escape the closing quote. The config test is
    still the final gate before anything is ever reloaded."""
    v = v.replace('\r', '').replace('\n', '').rstrip('\\')
    return re.sub(r'(?<!\\)"', '\\\\"', v)

def _load_lists():
    import json
    default = {'ip_whitelist': [], 'ip_blacklist': [], 'ua_blacklist': [], 'url_blacklist': []}
    if not os.path.exists(_modsec_lists_json()):
        return default
    try:
        data = json.load(open(_modsec_lists_json()))
        for k in default:
            data.setdefault(k, [])
        return data
    except Exception:
        return default

def _save_lists_json(data):
    _write_json_state(_modsec_lists_json(), data)

def _render_lists_conf(data):
    """Build the ModSecurity rules file from the stored lists. Rebuilt
    fully from scratch every save (not appended-to) so a removed entry
    actually disappears instead of lingering as a stale rule."""
    lines = ['# Auto-generated by VortexPanel — do not edit by hand, use the WAF Blacklist/Whitelist page',
             '# Regenerated in full on every save']

    wl = [ip.strip() for ip in data.get('ip_whitelist', []) if ip.strip()]
    if wl:
        rid = _LIST_ID_BASE['ip_whitelist'] + 1
        ip_list = ','.join(_modsec_str_escape(ip) for ip in wl)
        lines.append(
            f'SecRule REMOTE_ADDR "@ipMatch {ip_list}" '
            f'"id:{rid},phase:1,pass,nolog,ctl:ruleEngine=Off"'
        )

    for i, ip in enumerate([x.strip() for x in data.get('ip_blacklist', []) if x.strip()]):
        rid = _LIST_ID_BASE['ip_blacklist'] + i + 1
        lines.append(
            f'SecRule REMOTE_ADDR "@ipMatch {_modsec_str_escape(ip)}" '
            f'"id:{rid},phase:1,deny,status:403,log,msg:\'VortexPanel IP Blacklist\'"'
        )

    for i, ua in enumerate([x.strip() for x in data.get('ua_blacklist', []) if x.strip()]):
        rid = _LIST_ID_BASE['ua_blacklist'] + i + 1
        lines.append(
            f'SecRule REQUEST_HEADERS:User-Agent "@rx {_modsec_str_escape(ua)}" '
            f'"id:{rid},phase:1,deny,status:403,log,msg:\'VortexPanel UA Blacklist\'"'
        )

    for i, url in enumerate([x.strip() for x in data.get('url_blacklist', []) if x.strip()]):
        rid = _LIST_ID_BASE['url_blacklist'] + i + 1
        lines.append(
            f'SecRule REQUEST_URI "@rx {_modsec_str_escape(url)}" '
            f'"id:{rid},phase:1,deny,status:403,log,msg:\'VortexPanel URL Blacklist\'"'
        )

    return '\n'.join(lines) + '\n'

def _ensure_lists_included():
    """Insert the Include for vortex-lists.conf right after modsecurity.conf
    and BEFORE crs-setup.conf in main.conf, so whitelist's ruleEngine=Off can
    actually skip CRS. Idempotent — safe to call on every save.

    Apache-only exception: Apache's security2.conf already does
    IncludeOptional /etc/modsecurity/*.conf, which auto-includes
    vortex-lists.conf (and modsecurity.conf, and custom-rules.conf) on
    its own since they sit directly in that directory. Adding an
    explicit Include for it here too causes double-inclusion — the same
    rule ID gets loaded twice and Apache refuses to start. Confirmed via
    a real reproduced failure. nginx has no equivalent auto-include, so
    it genuinely needs this explicit wiring; Apache does not."""
    if _modsec_target() == 'apache':
        return
    if not os.path.exists(_modsec_main()):
        return
    main = open(_modsec_main()).read()
    include_line = f'Include {_modsec_lists_conf()}'
    if include_line in main:
        return
    base_include = f'Include {_modsec_conf()}'
    if base_include in main:
        main = main.replace(base_include, f'{base_include}\n{include_line}', 1)
    else:
        main = f'{include_line}\n{main}'
    with open(_modsec_main(), 'w') as f:
        f.write(main)

def _connector_present():
    """Whether the actual connector/module is present AND wired in for
    whichever webserver this is. nginx's connector is compiled from
    source (see the App Store install_tpl) so this checks for the real
    .so plus the nginx.conf wiring, not just a package. Apache's
    security2 module is a distro package that self-registers via
    a2enmod, so this checks it's actually enabled."""
    if _modsec_target() == 'apache':
        enabled, _, _ = sh('a2query -m security2 2>&1')
        if 'enabled' in (enabled or '').lower():
            return True
        return os.path.exists('/etc/apache2/mods-enabled/security2.load')

    so_present = any(
        os.path.exists(os.path.join(d, 'ngx_http_modsecurity_module.so'))
        for d in ['/usr/lib/nginx/modules', '/usr/lib64/nginx/modules']
    )
    wired = False
    if os.path.exists('/etc/nginx/nginx.conf'):
        try:
            wired = 'modsecurity_rules_file' in open('/etc/nginx/nginx.conf').read()
        except Exception:
            pass
    return so_present and wired

def _modsec_installed():
    """'Installed' = the core engine is actually usable, which requires
    the engine library, modsecurity.conf, AND the connector/module
    actually being loadable — checking only the first two was exactly
    the false-green pattern already fixed once for the CRS chain.
    The engine library check differs by target: nginx's connector links
    against libmodsecurity.so.3 (the v3 library), but Apache's
    libapache2-mod-security2 is a self-contained v2 module that never
    installs that library at all — confirmed via the actual install log
    (only libapache2-mod-security2 + modsecurity-crs as new packages,
    no v3 library pulled in). Checking for libmodsecurity.so.3
    unconditionally would make this always return False on a genuinely
    working Apache install."""
    if _modsec_target() == 'apache':
        engine_present = os.path.exists('/usr/lib/apache2/modules/mod_security2.so')
    else:
        engine_present = any(os.path.exists(p) for p in [
            '/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3',
            '/usr/lib64/libmodsecurity.so.3',
            '/usr/lib/aarch64-linux-gnu/libmodsecurity.so.3',
        ])
    return engine_present and os.path.exists(_modsec_conf()) and _connector_present()

def _crs_version():
    """Read CRS version from the CHANGES file or setup.conf."""
    for path in [f'{_modsec_crs_dir()}/CHANGES.md',
                 f'{_modsec_crs_dir()}/CHANGES',
                 f'{_modsec_crs_dir()}/crs-setup.conf.example']:
        if not os.path.exists(path): continue
        try:
            for line in open(path):
                m = re.search(r'(\d+\.\d+\.\d+)', line)
                if m: return m.group(1)
        except: pass
    return 'unknown'

def _active_conf_text(content):
    """Config text with comment lines removed -- crs-setup.conf.example ships
    every option as a commented-out example, which must not be read as set."""
    return '\n'.join(l for l in content.split('\n') if not l.lstrip().startswith('#'))


_PL_MARK = '# VortexPanel: paranoia level (managed, do not edit)'


def _crs_is_v4(setup_content):
    """CRS 4 renamed tx.paranoia_level to tx.blocking_paranoia_level."""
    if 'blocking_paranoia_level' in setup_content:
        return True
    init = f'{_modsec_crs_dir()}/rules/REQUEST-901-INITIALIZATION.conf'
    try:
        return 'blocking_paranoia_level' in open(init).read()
    except Exception:
        return False


def _apply_paranoia_text(original, level, v4):
    """PURE: set the paranoia level in crs-setup.conf text. The shipped file
    only has the paranoia SecAction (id 900000) as a COMMENTED example, so
    rewriting the commented text changed nothing. Drop our previous managed
    line, then either update an id:900000 the admin un-commented themselves,
    or append a managed one. CRS 4 uses tx.blocking_paranoia_level, CRS 3
    tx.paranoia_level."""
    kept, skip = [], False
    for line in original.split('\n'):
        if line.strip() == _PL_MARK:
            skip = True
            continue
        if skip:
            skip = False
            continue
        kept.append(line)
    content = '\n'.join(kept)
    if re.search(r'id:900000\b', _active_conf_text(content)):
        # (an older panel version appended an unmarked CRS-3 style
        # tx.paranoia_level SecAction, which CRS 4 ignores: rename it)
        repl = 'tx.blocking_paranoia_level=' if v4 else r'\g<1>'
        return '\n'.join(
            l if l.lstrip().startswith('#')
            else re.sub(r'(tx\.(?:blocking_)?paranoia_level=)\d', rf'{repl}{level}', l)
            for l in content.split('\n'))
    var = 'tx.blocking_paranoia_level' if v4 else 'tx.paranoia_level'
    return (content.rstrip('\n') + f'\n{_PL_MARK}\n'
            f'SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:{var}={level}"\n')


def _paranoia_level():
    """Read current paranoia level from crs-setup.conf (active lines only)."""
    setup = f'{_modsec_crs_dir()}/crs-setup.conf'
    if not os.path.exists(setup): return 1
    try:
        content = _active_conf_text(open(setup).read())
        m = re.search(r'tx\.(?:blocking_)?paranoia_level=(\d)', content)
        return int(m.group(1)) if m else 1
    except Exception: return 1

def _engine_state():
    """Return engine state: On / DetectionOnly / Off."""
    if not os.path.exists(_modsec_conf()): return 'Off'
    content = open(_modsec_conf()).read()
    if 'SecRuleEngine On' in content:             return 'On'
    if 'SecRuleEngine DetectionOnly' in content:  return 'DetectionOnly'
    return 'Off'

def _caddy_site_files():
    """(filename, path) for every per-site Caddy file. _write_vhost() and the
    other project types write *.caddy; very old installs used *.conf."""
    out = []
    if os.path.isdir(CADDY_SITES):
        for fn in sorted(os.listdir(CADDY_SITES)):
            if fn.endswith('.caddy') or fn.endswith('.conf'):
                out.append((fn, os.path.join(CADDY_SITES, fn)))
    return out


def _caddy_site_file(domain):
    for ext in ('.caddy', '.conf'):
        fp = os.path.join(CADDY_SITES, f'{domain}{ext}')
        if os.path.exists(fp):
            return fp
    return None


@security_bp.route('/api/security/caddywaf')
def caddywaf_status():
    if not req(): return jsonify({'ok': False}), 401
    modules_out, _, _ = sh('caddy list-modules 2>/dev/null')
    installed = 'http.handlers.waf' in modules_out

    settings_path = '/etc/caddy/waf/panel_settings.json'
    settings = {'anomaly_threshold': 20, 'rate_limit_requests': 100, 'rate_limit_window': 10, 'rate_limit_paths': ''}
    if os.path.exists(settings_path):
        try:
            with open(settings_path) as f:
                settings.update(json.load(f))
        except Exception:
            pass

    def _count_lines(path):
        if not os.path.exists(path):
            return 0
        try:
            with open(path) as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0

    ip_count = _count_lines('/etc/caddy/waf/ip_blacklist.txt')
    dns_count = _count_lines('/etc/caddy/waf/dns_blacklist.txt')

    # Sites currently running the WAF - scan Caddy's per-site config dir
    # for the waf{} block, the same directory _find_site_config already
    # uses for Caddy sites.
    enabled_sites = []
    for fn, fp in _caddy_site_files():
        try:
            with open(fp) as f:
                content = f.read()
            if re.search(r'(?<![\w-])waf\s*\{', content):
                enabled_sites.append(fn.rsplit('.', 1)[0])
        except Exception:
            pass

    return jsonify({
        'ok': True, 'installed': installed, 'settings': settings,
        'ip_blacklist_count': ip_count, 'dns_blacklist_count': dns_count,
        'enabled_sites': enabled_sites,
    })


@security_bp.route('/api/security/caddywaf/settings', methods=['POST'])
def caddywaf_save_settings():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}

    try:
        settings = {
            'anomaly_threshold': int(d.get('anomaly_threshold', 20)),
            'rate_limit_requests': int(d.get('rate_limit_requests', 100)),
            'rate_limit_window': int(d.get('rate_limit_window', 10)),
            'rate_limit_paths': (d.get('rate_limit_paths') or '').strip(),
        }
    except (ValueError, TypeError):
        return jsonify({'ok': False, 'error': 'Numeric settings must be numbers'}), 400
    if not (1 <= settings['anomaly_threshold'] <= 10000 and 0 <= settings['rate_limit_requests'] <= 1000000
            and 1 <= settings['rate_limit_window'] <= 86400):
        return jsonify({'ok': False, 'error': 'Setting out of range'}), 400
    # Written verbatim into every WAF-enabled Caddy site block.
    if re.search(r'[\r\n{}`"#]', settings['rate_limit_paths']):
        return jsonify({'ok': False, 'error': 'rate_limit_paths: space-separated paths only'}), 400
    os.makedirs('/etc/caddy/waf', exist_ok=True)
    with open('/etc/caddy/waf/panel_settings.json', 'w') as f:
        json.dump(settings, f)

    # Re-apply to every site currently running the WAF, so a settings
    # change actually takes effect everywhere rather than only on the
    # next fresh enable. Reuses the same real brace-matching already
    # proven for the enable/disable toggle in websites_core.py.
    from panel.routes.websites_core import _split_site_block
    updated, failed = [], []
    for fn, fp in _caddy_site_files():
        domain = fn.rsplit('.', 1)[0]
        try:
            with open(fp) as f:
                content = f.read()
            # 'waf {' must not match the Coraza 'coraza_waf {' block
            if not re.search(r'(?<![\w-])waf\s*\{', content):
                continue
            header, inner, trailing = _split_site_block(content)
            if header is None:
                failed.append(domain); continue
            route_start = inner.find('route {')
            if route_start == -1:
                failed.append(domain); continue
            _, route_inner, route_trailing = _split_site_block(inner[route_start:])
            wm = re.search(r'(?<![\w-])waf\s*\{', route_inner)
            waf_start = wm.start() if wm else -1
            if waf_start == -1:
                failed.append(domain); continue
            _, _, after_waf = _split_site_block(route_inner[waf_start:])

            rate_limit_block = ''
            if settings['rate_limit_requests'] > 0:
                paths_line = f'\n                paths            {settings["rate_limit_paths"]}' if settings['rate_limit_paths'] else ''
                rate_limit_block = (
                    f'\n            rate_limit {{\n'
                    f'                requests         {settings["rate_limit_requests"]}\n'
                    f'                window           {settings["rate_limit_window"]}s{paths_line}\n'
                    f'            }}'
                )
            new_waf_block = (
                '\n    route {\n'
                '        waf {\n'
                '            metrics_endpoint   /waf_metrics\n'
                '            rule_file          /etc/caddy/waf/rules.json\n'
                '            ip_blacklist_file  /etc/caddy/waf/ip_blacklist.txt\n'
                '            dns_blacklist_file /etc/caddy/waf/dns_blacklist.txt\n'
                f'            anomaly_threshold  {settings["anomaly_threshold"]}'
                f'{rate_limit_block}\n'
                '        }\n'
                f'    {after_waf.lstrip("}").strip()}\n'
                '    }\n'
            )
            new_content = header + new_waf_block + trailing

            tmp_path = fp + '.waf-test'
            with open(tmp_path, 'w') as f:
                f.write(new_content)
            _, _, vrc = sh(f'caddy validate --config {tmp_path} --adapter caddyfile 2>&1', t=60)
            if vrc != 0:
                os.remove(tmp_path)
                failed.append(domain)
                continue
            os.replace(tmp_path, fp)
            updated.append(domain)
        except Exception:
            failed.append(domain)

    if updated:
        sh('systemctl reload caddy 2>/dev/null')

    return jsonify({'ok': True, 'settings': settings, 'updated_sites': updated, 'failed_sites': failed})


@security_bp.route('/api/security/caddywaf/blacklist', methods=['POST'])
def caddywaf_add_blacklist():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    kind = d.get('type')  # 'ip' or 'dns'
    entry = (d.get('entry') or '').strip()
    if kind not in ('ip', 'dns') or not entry:
        return jsonify({'ok': False, 'error': 'type (ip/dns) and entry are required'}), 400
    # One entry per line in the list file: no line breaks, real IP/hostname.
    if (kind == 'ip' and not _valid_ip_or_cidr(entry)) or \
       (kind == 'dns' and not _valid_hostname(entry.lstrip('*.'))):
        return jsonify({'ok': False, 'error': f'Invalid {kind} entry'}), 400

    path = f'/etc/caddy/waf/{"ip_blacklist" if kind == "ip" else "dns_blacklist"}.txt'
    os.makedirs('/etc/caddy/waf', exist_ok=True)
    existing = set()
    if os.path.exists(path):
        with open(path) as f:
            existing = {line.strip() for line in f if line.strip()}
    if entry in existing:
        return jsonify({'ok': True, 'message': 'Entry already present'})
    with open(path, 'a') as f:
        f.write(entry + '\n')
    return jsonify({'ok': True})


@security_bp.route('/api/security/caddywaf/blacklist', methods=['DELETE'])
def caddywaf_remove_blacklist():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    kind = d.get('type')
    entry = (d.get('entry') or '').strip()
    if kind not in ('ip', 'dns') or not entry:
        return jsonify({'ok': False, 'error': 'type (ip/dns) and entry are required'}), 400

    path = f'/etc/caddy/waf/{"ip_blacklist" if kind == "ip" else "dns_blacklist"}.txt'
    if not os.path.exists(path):
        return jsonify({'ok': True, 'message': 'Nothing to remove'})
    with open(path) as f:
        lines = [l for l in f if l.strip() != entry]
    with open(path, 'w') as f:
        f.writelines(lines)
    return jsonify({'ok': True})


@security_bp.route('/api/security/modsecurity')
def modsec_status():
    if not req(): return jsonify({'ok':False}), 401
    installed = _modsec_installed()
    state     = _engine_state()
    rules_out, _, _ = sh(f'find {_modsec_crs_dir()}/rules/ -name "*.conf" 2>/dev/null | wc -l')
    try:    rules_count = int(rules_out.strip() or 0)
    except: rules_count = 0

    # Custom rules
    custom_rules = ''
    if os.path.exists(_modsec_custom()):
        try: custom_rules = open(_modsec_custom()).read()
        except: pass

    # Sites with per-site overrides
    site_overrides = {}
    for conf_dir in ['/etc/nginx/vortex', '/etc/nginx/conf.d']:
        if not os.path.isdir(conf_dir): continue
        for fn in os.listdir(conf_dir):
            fp = os.path.join(conf_dir, fn)
            try:
                c = open(fp).read()
                domain = re.search(r'server_name\s+([^;]+);', c)
                if domain:
                    d = domain.group(1).strip().split()[0]
                    if 'modsecurity off' in c.lower():
                        site_overrides[d] = 'off'
                    elif 'modsecurity on' in c.lower():
                        site_overrides[d] = 'on'
            except: pass

    return jsonify({
        'ok':            True,
        'installed':     installed,
        'enabled':       state == 'On',
        'state':         state,
        'rules':         rules_count,
        'crs_version':   _crs_version() if installed else '',
        'paranoia_level':_paranoia_level() if installed else 1,
        'custom_rules':  custom_rules,
        'site_overrides':site_overrides,
        'audit_log':     os.path.exists(_modsec_audit()),
        'webserver_name': 'apache2' if _modsec_target() == 'apache' else 'nginx',
        'custom_rules_path': _modsec_custom(),
    })


@security_bp.route('/api/security/modsecurity/toggle', methods=['POST'])
def modsec_toggle():
    if not req(): return jsonify({'ok':False}), 401
    d      = request.get_json() or {}
    state  = d.get('state', 'On')     # 'On' | 'DetectionOnly' | 'Off'
    if state not in ('On', 'DetectionOnly', 'Off'):
        return jsonify({'ok':False,'error':'state must be On, DetectionOnly or Off'}), 400
    conf   = _modsec_conf()
    if not os.path.exists(conf):
        return jsonify({'ok':False,'error':'ModSecurity not installed'}), 404
    original = open(conf).read()
    # Replace any existing state (or add one if the conf has none)
    content, n = re.subn(r'(?m)^(\s*)SecRuleEngine\s+(On|DetectionOnly|Off)\b',
                         rf'\g<1>SecRuleEngine {state}', original)
    if n == 0:
        content = f'SecRuleEngine {state}\n' + original
    with open(conf,'w') as f: f.write(content)
    ok, out = _modsec_configtest()
    if not ok:
        with open(conf,'w') as f: f.write(original)
        return jsonify({'ok':False,'error':f'Config error, change reverted: {out}'}), 400
    _modsec_reload()
    return jsonify({'ok':True,'state':state})


@security_bp.route('/api/security/modsecurity/paranoia', methods=['POST'])
def modsec_paranoia():
    """Set OWASP CRS paranoia level (1–4)."""
    if not req(): return jsonify({'ok':False}), 401
    try:
        level = int((request.get_json() or {}).get('level', 1))
    except (ValueError, TypeError):
        return jsonify({'ok':False,'error':'level must be 1-4'}), 400
    level = max(1, min(4, level))
    setup = f'{_modsec_crs_dir()}/crs-setup.conf'
    if not os.path.exists(setup):
        return jsonify({'ok':False,'error':'CRS setup.conf not found'}), 404
    original = open(setup).read()
    content = _apply_paranoia_text(original, level, _crs_is_v4(original))
    with open(setup,'w') as f: f.write(content)
    ok, out = _modsec_configtest()
    if not ok:
        with open(setup,'w') as f: f.write(original)
        return jsonify({'ok':False,'error':f'Config test failed, change reverted: {out}'}), 400
    _modsec_reload()
    return jsonify({'ok':True,'level':level})


@security_bp.route('/api/security/modsecurity/custom-rules', methods=['GET'])
def modsec_get_custom():
    if not req(): return jsonify({'ok':False}), 401
    content = ''
    if os.path.exists(_modsec_custom()):
        try: content = open(_modsec_custom()).read()
        except: pass
    return jsonify({'ok':True,'rules':content})


@security_bp.route('/api/security/modsecurity/custom-rules', methods=['POST'])
def modsec_save_custom():
    """Save custom SecRule directives."""
    if not req(): return jsonify({'ok':False}), 401
    rules = (request.get_json() or {}).get('rules', '')
    if not isinstance(rules, str):
        return jsonify({'ok':False,'error':'rules must be text'}), 400
    if _modsec_target() is None:
        return jsonify({'ok':False,'error':'ModSecurity is not installed'}), 400
    os.makedirs(_modsec_dir(), exist_ok=True)
    prev_custom = open(_modsec_custom()).read() if os.path.exists(_modsec_custom()) else None
    prev_main   = open(_modsec_main()).read() if os.path.exists(_modsec_main()) else None
    with open(_modsec_custom(),'w') as f: f.write(rules)
    # Ensure it's included in main.conf -- nginx only. Apache's
    # security2.conf already glob-includes every top-level .conf file in
    # /etc/modsecurity/ (confirmed: IncludeOptional /etc/modsecurity/*.conf),
    # so custom-rules.conf is already loaded without this; adding an
    # explicit Include here too caused a real, reproduced double-inclusion
    # failure ("Found another rule with the same id").
    if _modsec_target() != 'apache' and os.path.exists(_modsec_main()):
        main = open(_modsec_main()).read()
        include_line = f'Include {_modsec_custom()}'
        if include_line not in main:
            with open(_modsec_main(),'a') as f: f.write(f'\n{include_line}\n')
    ok, out = _modsec_configtest()
    if not ok:
        # Never leave a rejected rules file live: the next unrelated reload
        # (any site edit) would otherwise fail on it.
        if prev_custom is not None:
            with open(_modsec_custom(),'w') as f: f.write(prev_custom)
        else:
            try: os.unlink(_modsec_custom())
            except Exception: pass
        if prev_main is not None:
            with open(_modsec_main(),'w') as f: f.write(prev_main)
        return jsonify({'ok':False,'error':f'Syntax error in rules (not saved): {out}'}), 400
    _modsec_reload()
    return jsonify({'ok':True})


@security_bp.route('/api/security/modsecurity/lists')
def modsec_get_lists():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, 'lists': _load_lists()})


@security_bp.route('/api/security/modsecurity/lists', methods=['POST'])
def modsec_save_lists():
    """Save IP/UA/URL blacklist+whitelist. Unlike modsec_save_custom, this
    validates against nginx -t BEFORE committing the live .conf file and
    rolls back to the previous working version on failure — a broken
    custom-rules.conf left in place after a rejected save is exactly the
    kind of silent half-state that caused the ModSecurity bug fixed last
    round, not repeating that pattern here."""
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}

    incoming = {}
    for key in ('ip_whitelist', 'ip_blacklist', 'ua_blacklist', 'url_blacklist'):
        vals = d.get(key) or []
        if isinstance(vals, str):
            vals = vals.split('\n')
        if not isinstance(vals, list):
            return jsonify({'ok':False, 'error': f'{key} must be a list'}), 400
        incoming[key] = [str(v).strip() for v in vals if str(v).strip()]
    for key in ('ip_whitelist', 'ip_blacklist'):
        bad = [ip for ip in incoming[key] if ip.strip() and not _valid_ip(ip)]
        if bad:
            return jsonify({'ok':False, 'error': f'Invalid IP/CIDR in {key}: {", ".join(bad[:5])}'}), 400

    if _modsec_target() is None:
        # Caddy-only (or nothing yet): never create /etc/nginx/modsec here.
        if not _coraza_present():
            return jsonify({'ok':False, 'error': 'ModSecurity is not installed'}), 400
        ok, err = _commit_model(_modsec_lists_json(), incoming, _coraza_sync)
        if not ok:
            return jsonify({'ok':False, 'error': f'Caddy/Coraza config test failed, reverted: {err}'}), 400
        return jsonify({'ok':True, 'lists': incoming})

    os.makedirs(_modsec_dir(), exist_ok=True)

    backup = None
    if os.path.exists(_modsec_lists_conf()):
        backup = open(_modsec_lists_conf()).read()
    main_backup = open(_modsec_main()).read() if os.path.exists(_modsec_main()) else None

    with open(_modsec_lists_conf(), 'w') as f:
        f.write(_render_lists_conf(incoming))
    _ensure_lists_included()

    ok, out = _modsec_configtest()
    if not ok:
        # Roll back both files to their pre-save state — the webserver must
        # never be left in a broken state by a rejected save.
        if backup is not None:
            with open(_modsec_lists_conf(), 'w') as f: f.write(backup)
        elif os.path.exists(_modsec_lists_conf()):
            os.remove(_modsec_lists_conf())
        if main_backup is not None:
            with open(_modsec_main(), 'w') as f: f.write(main_backup)
        return jsonify({'ok':False, 'error': f'Syntax error in generated rules: {out}'}), 400

    _save_lists_json(incoming)
    _modsec_reload()
    # Mirror the same lists to Caddy/Coraza when it's installed, so black/white
    # list edits made here apply to Caddy sites too (no-op otherwise).
    c_ok, c_err = _coraza_sync()
    return jsonify({'ok':True, 'lists': incoming,
                    'warning': '' if c_ok else f'Saved for nginx/Apache, but Caddy/Coraza rejected the lists: {c_err[-300:]}'})


@security_bp.route('/api/security/modsecurity/audit-log')
def modsec_audit_log():
    """Return last N lines of ModSecurity audit log."""
    if not req(): return jsonify({'ok':False}), 401
    try: lines = max(1, int(request.args.get('lines', 100)))
    except (ValueError, TypeError): lines = 100
    if not os.path.exists(_modsec_audit()):
        return jsonify({'ok':True,'entries':[],'raw':'','exists':False})
    out, _, _ = sh(f'tail -n {min(lines, 500)} "{_modsec_audit()}" 2>/dev/null')
    entries = _parse_modsec_entries(out)
    entries.reverse()
    return jsonify({'ok':True,'entries':entries[-100:],'raw':out,'exists':True})


# --- WAF ANALYTICS ----------------------------------------------------------------
# OWASP CRS assigns rule IDs in stable, documented ranges per attack category.
# This mapping is based on that well-established convention (CRS 3.x/4.x) — I
# could not live-verify it against crs.owasp.org given this environment's
# network restrictions, so treat category labels as best-effort; the raw
# rule_id is always preserved alongside so nothing is hidden or guessed away.
CRS_CATEGORY_RANGES = [
    (911000, 911999, 'Method Enforcement'),
    (912000, 912999, 'DoS Protection'),
    (913000, 913999, 'Scanner Detection'),
    (920000, 920999, 'Protocol Enforcement'),
    (921000, 921999, 'Protocol Attack'),
    (930000, 930999, 'Path Traversal / LFI'),
    (931000, 931999, 'Remote File Inclusion'),
    (932000, 932999, 'Remote Code Execution'),
    (933000, 933999, 'PHP Injection'),
    (934000, 934999, 'Node.js Injection'),
    (941000, 941999, 'XSS'),
    (942000, 942999, 'SQL Injection'),
    (943000, 943999, 'Session Fixation'),
    (944000, 944999, 'Java Attack'),
    (949000, 949999, 'Anomaly Threshold'),
    (950000, 959999, 'Data Leakage'),
    (980000, 980999, 'Correlation'),
]

def _categorize_rule(rule_id):
    if not rule_id: return 'Other'
    try: rid = int(rule_id)
    except (ValueError, TypeError): return 'Other'
    for lo, hi, name in CRS_CATEGORY_RANGES:
        if lo <= rid <= hi: return name
    return 'Other'

_AUDIT_BOUNDARY_RE = re.compile(r'^-{2,3}[A-Za-z0-9@_]+-{1,3}([A-Z])--\s*$')


def _parse_modsec_entries(raw_text):
    """Shared parser for ModSecurity audit log entries.

    IMPORTANT: section markers (--uuid-X--) announce that the FOLLOWING
    lines belong to section X, until the next marker — the marker line
    itself never contains the actual request/message data. The original
    inline parser (before this refactor) tried to regex-match request/
    message content against the marker line itself, which never matched
    anything real; this version tracks "current section" as state and
    processes each subsequent line according to it, which is how
    ModSecurity's audit log format actually works.
    """
    entries, current, section = [], {}, None
    for line in raw_text.split('\n'):
        # v2 (Apache) boundary: --1a2b3c4d-A--   v3 (libmodsecurity/nginx
        # Native format): ---Xy12AbCd---A--  (alphanumeric, extra dashes).
        m = _AUDIT_BOUNDARY_RE.match(line)
        if m:
            new_section = m.group(1)
            if new_section == 'A':
                if current:
                    entries.append(current)
                current = {'raw': line}
            section = new_section
            continue

        if not current:
            continue

        if section == 'A':
            # Section A content line: [DD/Mon/YYYY:HH:MM:SS +ZZZZ] txid client-ip client-port server-ip server-port
            ts_m = re.search(r'\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})', line)
            if ts_m: current['timestamp'] = ts_m.group(1)
            # The transaction id is a base64-ish string on v2 and a dotted
            # number on v3; client address may be IPv4 or IPv6.
            ip_m = re.search(r'^\[[^\]]+\]\s+\S+\s+([0-9A-Fa-f:.]*[0-9A-Fa-f])\s', line)
            if ip_m and (':' in ip_m.group(1) or '.' in ip_m.group(1)): current['ip'] = ip_m.group(1)
        elif section == 'B':
            req_m = re.search(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)', line)
            if req_m:
                current['method'] = req_m.group(1)
                current['uri']    = req_m.group(2)
            host_m = re.search(r'^Host:\s*(\S+)', line, re.IGNORECASE)
            if host_m: current['domain'] = host_m.group(1)
        elif section == 'H':
            # v2 prefixes each match with "Message: ", v3 with "ModSecurity: ".
            msg_m = re.search(r'\[msg "([^"]+)"\]', line) or re.search(r'(?:Message|ModSecurity): (.+)', line)
            if msg_m and 'message' not in current:  # keep the first/primary message
                current['message'] = msg_m.group(1)[:200]
            id_m = re.search(r'\[id "(\d+)"\]', line)
            if id_m and 'rule_id' not in current:
                current['rule_id'] = id_m.group(1)
            sev_m = re.search(r'\[severity "(\w+)"\]', line)
            if sev_m and 'severity' not in current:
                current['severity'] = sev_m.group(1)
            if 'ip' not in current:
                ip_m2 = re.search(r'client:\s*(\d+\.\d+\.\d+\.\d+)|client (\d+\.\d+\.\d+\.\d+)', line)
                if ip_m2: current['ip'] = ip_m2.group(1) or ip_m2.group(2)

    if current:
        entries.append(current)
    entries = [e for e in entries if e.get('message') or e.get('uri')]
    return entries

def _entry_datetime(entry):
    """Parse ModSecurity's [DD/Mon/YYYY:HH:MM:SS timestamp into a datetime."""
    ts = entry.get('timestamp')
    if not ts: return None
    try:
        return datetime.strptime(ts, '%d/%b/%Y:%H:%M:%S')
    except (ValueError, TypeError):
        return None

@security_bp.route('/api/security/waf/stats')
def waf_stats():
    """Aggregated WAF analytics — attack categories, top IPs/URIs, and a
    timeline, built on top of the same parser as the raw audit-log view.
    Reads a capped tail of the log (not the whole file, which can be large
    on a busy server) then filters/aggregates in Python."""
    if not req(): return jsonify({'ok': False}), 401
    period = request.args.get('period', 'today')

    if not os.path.exists(_modsec_audit()):
        return jsonify({'ok': True, 'exists': False, 'total': 0,
                         'categories': [], 'top_ips': [], 'top_uris': [], 'timeline': []})

    # Cap the read — a very busy site's audit log can be huge; this covers a
    # generous window of recent activity without loading the whole file.
    out, _, _ = sh(f'tail -n 20000 "{_modsec_audit()}" 2>/dev/null', t=20)
    entries = _parse_modsec_entries(out)

    now = datetime.now()
    if period == 'today':
        cutoff = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == 'yesterday':
        cutoff = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        upper  = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == '7days':
        cutoff = now - timedelta(days=7)
    else:
        cutoff = now - timedelta(days=1)

    filtered = []
    for e in entries:
        dt = _entry_datetime(e)
        if dt is None:
            continue  # can't place it in time — exclude from period-bounded stats
        if period == 'yesterday':
            if cutoff <= dt < upper: filtered.append((dt, e))
        elif dt >= cutoff:
            filtered.append((dt, e))

    total = len(filtered)
    cat_counts, ip_counts, uri_counts = {}, {}, {}
    timeline_buckets = {}

    for dt, e in filtered:
        cat = _categorize_rule(e.get('rule_id'))
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
        if e.get('ip'):
            ip_counts[e['ip']] = ip_counts.get(e['ip'], 0) + 1
        if e.get('uri'):
            uri_counts[e['uri']] = uri_counts.get(e['uri'], 0) + 1
        # Bucket by hour for today/yesterday, by day for 7days
        bucket = dt.strftime('%H:00') if period in ('today', 'yesterday') else dt.strftime('%m/%d')
        timeline_buckets[bucket] = timeline_buckets.get(bucket, 0) + 1

    top_ips  = sorted(ip_counts.items(),  key=lambda x: -x[1])[:10]
    top_uris = sorted(uri_counts.items(), key=lambda x: -x[1])[:10]
    categories = sorted(cat_counts.items(), key=lambda x: -x[1])
    timeline = sorted(timeline_buckets.items(), key=lambda x: x[0])

    return jsonify({
        'ok': True, 'exists': True, 'period': period, 'total': total,
        'categories': [{'name': k, 'count': v} for k, v in categories],
        'top_ips':    [{'ip': k, 'count': v} for k, v in top_ips],
        'top_uris':   [{'uri': k, 'count': v} for k, v in top_uris],
        'timeline':   [{'label': k, 'count': v} for k, v in timeline],
    })


@security_bp.route('/api/security/waf/blockade-log')
def waf_blockade_log():
    """Filterable version of the raw audit log — supports search by IP,
    URI, or rule category, plus pagination for larger result sets."""
    if not req(): return jsonify({'ok': False}), 401
    if not os.path.exists(_modsec_audit()):
        return jsonify({'ok': True, 'entries': [], 'total': 0, 'exists': False})

    search   = (request.args.get('q') or '').strip().lower()
    try:
        page     = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(10, int(request.args.get('per_page', 20))))
    except (ValueError, TypeError):
        page, per_page = 1, 20

    out, _, _ = sh(f'tail -n 20000 "{_modsec_audit()}" 2>/dev/null', t=20)
    entries = _parse_modsec_entries(out)
    for e in entries:
        e['category'] = _categorize_rule(e.get('rule_id'))
    entries.reverse()  # most recent first

    if search:
        entries = [e for e in entries if
                   search in (e.get('ip') or '').lower() or
                   search in (e.get('uri') or '').lower() or
                   search in (e.get('domain') or '').lower() or
                   search in (e.get('category') or '').lower() or
                   search in (e.get('message') or '').lower()]

    total = len(entries)
    start = (page - 1) * per_page
    page_entries = entries[start:start + per_page]

    return jsonify({'ok': True, 'exists': True, 'entries': page_entries,
                     'total': total, 'page': page, 'per_page': per_page})

@security_bp.route('/api/security/modsecurity/repair', methods=['POST'])
def modsec_repair():
    """Fix an incomplete ModSecurity install — writes modsecurity.conf if
    missing, downloads OWASP CRS if missing, and regenerates main.conf to
    correctly reflect whichever pieces end up present. This exists because
    the install script has multiple independent download steps that can
    each fail on their own (network hiccups, GitHub rate limits); previously
    a partial failure left the install stuck with no in-panel way to finish
    it short of a full uninstall/reinstall."""
    if not req(): return jsonify({'ok': False}), 401
    log = []

    # Apache install whose modsecurity.conf went missing: _modsec_target()
    # cannot tell it is Apache any more, so restore the conf from the
    # package's recommended copy first.
    if _modsec_target() is None and os.path.exists('/usr/lib/apache2/modules/mod_security2.so') \
            and os.path.exists('/etc/modsecurity/modsecurity.conf-recommended'):
        content = open('/etc/modsecurity/modsecurity.conf-recommended').read()
        content = content.replace('SecRuleEngine DetectionOnly', 'SecRuleEngine On')
        content = content.replace('SecUnicodeMapFile unicode.mapping', 'SecUnicodeMapFile /etc/modsecurity/unicode.mapping')
        open('/etc/modsecurity/modsecurity.conf', 'w').write(content)
        log.append('modsecurity.conf restored from the package copy (Apache)')

    # The old check (_modsec_installed) itself requires modsecurity.conf, so
    # the "conf missing" repair below could never run. Check only the engine
    # library + webserver module here.
    if not _modsec_engine_present():
        return jsonify({'ok': False, 'error': 'ModSecurity engine (library + webserver module) is not installed at all — install it from the App Store first, this repair only fixes an incomplete config.'})

    os.makedirs(_modsec_dir(), exist_ok=True)
    is_apache = _modsec_target() == 'apache'

    # 1. Fix modsecurity.conf if missing
    conf_ok = os.path.exists(_modsec_conf())
    if not conf_ok:
        log.append('modsecurity.conf missing — downloading...')
        rc = _fetch('https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended',
                    _modsec_conf())
        if rc == 0 and os.path.exists(_modsec_conf()) and os.path.getsize(_modsec_conf()) > 0:
            content = open(_modsec_conf()).read()
            content = content.replace('SecRuleEngine DetectionOnly', 'SecRuleEngine On')
            content = content.replace('SecAuditLogParts ABIJDEFHZ', 'SecAuditLogParts ABCEFHJKZ')
            open(_modsec_conf(), 'w').write(content)
            conf_ok = True
            log.append('modsecurity.conf downloaded and configured')
        else:
            # Fallback minimal config so the engine is at least usable
            open(_modsec_conf(), 'w').write(
                'SecRuleEngine On\nSecRequestBodyAccess On\n'
                'SecAuditEngine RelevantOnly\nSecAuditLog /var/log/modsec_audit.log\n'
            )
            conf_ok = True
            log.append('Download failed — wrote minimal fallback config so the engine is still usable')
    else:
        log.append('modsecurity.conf already present')

    # 1b. The recommended conf references unicode.mapping; when that file is
    # missing nginx -t / apachectl fail ("Failed to locate the unicode map
    # file"). Download it, or comment the directive out (it is optional).
    content = open(_modsec_conf()).read()
    um = re.search(r'(?m)^\s*SecUnicodeMapFile\s+(\S+)', content)
    if um:
        um_path = um.group(1)
        if not um_path.startswith('/'):
            um_path = os.path.join(_modsec_dir(), um_path)
        if not os.path.exists(um_path):
            rc = _fetch('https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping', um_path)
            if rc == 0 and os.path.exists(um_path) and os.path.getsize(um_path) > 0:
                log.append('unicode.mapping downloaded')
            else:
                try: os.unlink(um_path)
                except Exception: pass
                content = re.sub(r'(?m)^(\s*)(SecUnicodeMapFile\s+)', r'\1# \2', content)
                log.append('unicode.mapping unavailable — SecUnicodeMapFile disabled so the config loads')
        content = re.sub(r'(?m)^(\s*SecUnicodeMapFile\s+)unicode\.mapping\b', rf'\g<1>{um_path}', content)
        open(_modsec_conf(), 'w').write(content)

    # 2. Fix CRS if missing
    crs_ok = os.path.exists(f'{_modsec_crs_dir()}/crs-setup.conf')
    if not crs_ok:
        log.append('OWASP CRS missing — downloading...')
        os.makedirs(_modsec_crs_dir(), exist_ok=True)
        tag = _crs_latest_tag() or 'v4.0.0'
        import tempfile
        _fd, tmp_tar = tempfile.mkstemp(prefix='crs_repair_', suffix='.tar.gz')
        os.close(_fd)
        rc = _fetch(f'https://github.com/coreruleset/coreruleset/archive/refs/tags/{tag}.tar.gz', tmp_tar, t=90)
        if rc == 0:
            _, _, rc = sh(f'tar -xzf {tmp_tar} -C {_modsec_crs_dir()} --strip-components=1', t=60)
        try: os.unlink(tmp_tar)
        except Exception: pass
        if rc == 0 and os.path.exists(f'{_modsec_crs_dir()}/crs-setup.conf.example'):
            sh(f'cp {_modsec_crs_dir()}/crs-setup.conf.example {_modsec_crs_dir()}/crs-setup.conf')
            crs_ok = True
            log.append(f'OWASP CRS {tag} downloaded')
        else:
            log.append('CRS download failed — engine will work but with no ruleset loaded. Try Repair again later.')
    else:
        log.append('OWASP CRS already present')

    # 3. Regenerate main.conf to match reality — never reference a CRS file
    # that doesn't actually exist, or the webserver will fail to reload
    # entirely. Apache-only nuance: modsecurity.conf (and every vortex-*.conf)
    # is already auto-included by security2.conf's own glob (IncludeOptional
    # /etc/modsecurity/*.conf), so re-including it here would double-load
    # it -- confirmed via a real reproduced failure. Only CRS (in a
    # subdirectory the glob doesn't reach) genuinely needs wiring there.
    # nginx: keep the panel's own generated files (lists, region, custom
    # rules builder, exceptions, free-text custom rules) wired in -- the old
    # regeneration silently dropped them, disabling those features.
    main_prev = open(_modsec_main()).read() if os.path.exists(_modsec_main()) else None
    lines = []
    if not is_apache:
        lines.append(f'Include {_modsec_conf()}')
        for extra in (_modsec_lists_conf(), _geo_conf(), _custom_conf(), _exc_conf()):
            if os.path.exists(extra):
                lines.append(f'Include {extra}')
    if crs_ok:
        lines.append(f'Include {_modsec_crs_dir()}/crs-setup.conf')
        lines.append(f'Include {_modsec_crs_dir()}/rules/*.conf')
    if not is_apache and os.path.exists(_modsec_custom()):
        lines.append(f'Include {_modsec_custom()}')
    open(_modsec_main(), 'w').write('\n'.join(lines) + ('\n' if lines else ''))
    log.append(f'main.conf regenerated ({"with" if crs_ok else "without"} CRS includes)')

    # 4. Ensure the webserver actually loads main.conf -- nginx-only step.
    # Apache's security2.conf already auto-includes /etc/modsecurity/*.conf
    # by default (confirmed by installing the package fresh and inspecting
    # it), so there is no equivalent wiring step needed there.
    nginx_prev = None
    if not is_apache and os.path.exists('/etc/nginx/nginx.conf'):
        nc = open('/etc/nginx/nginx.conf').read()
        if 'modsecurity_rules_file' not in nc:
            new_nc, n = re.subn(r'(?m)^(\s*http\s*\{[^\n]*\n)',
                                rf'\g<1>    modsecurity on;\n    modsecurity_rules_file {_modsec_main()};\n', nc, count=1)
            if n:
                nginx_prev = nc
                open('/etc/nginx/nginx.conf', 'w').write(new_nc)
                log.append('Enabled modsecurity directives in nginx.conf')
            else:
                log.append('Could not find the http { block in nginx.conf — add "modsecurity on;" manually')

    ok, out = _modsec_configtest()
    if not ok:
        # Put back what this repair changed outside its own files, so a
        # failed repair cannot take the web server down on its next reload.
        if nginx_prev is not None:
            open('/etc/nginx/nginx.conf', 'w').write(nginx_prev)
        if main_prev is not None:
            open(_modsec_main(), 'w').write(main_prev)
        return jsonify({'ok': False, 'error': f'Config test failed after repair (nginx.conf/main.conf changes reverted): {out}', 'log': log})
    _modsec_reload()
    log.append('webserver reloaded')

    return jsonify({'ok': True, 'conf_ok': conf_ok, 'crs_ok': crs_ok, 'log': log})


def _modsec_engine_present():
    """Engine library + webserver module present (modsecurity.conf NOT
    required -- that is what repair recreates)."""
    if _modsec_target() == 'apache':
        return os.path.exists('/usr/lib/apache2/modules/mod_security2.so')
    lib = any(os.path.exists(p) for p in [
        '/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3',
        '/usr/lib64/libmodsecurity.so.3',
        '/usr/lib/aarch64-linux-gnu/libmodsecurity.so.3',
        '/usr/local/modsecurity/lib/libmodsecurity.so.3',
    ])
    so = any(os.path.exists(os.path.join(d, 'ngx_http_modsecurity_module.so'))
             for d in ['/usr/lib/nginx/modules', '/usr/lib64/nginx/modules', '/usr/share/nginx/modules'])
    return lib and so


def _fetch(url, dest, t=30):
    """Download url to dest with curl, falling back to wget. Returns rc."""
    _, _, rc = sh(f'curl -fsSL --max-time {t} "{url}" -o "{dest}" 2>/dev/null || '
                  f'wget -q --timeout={t} "{url}" -O "{dest}"', t=t * 2 + 5)
    return rc


def _crs_latest_tag():
    out, _, rc = sh('curl -s --max-time 10 https://api.github.com/repos/coreruleset/coreruleset/releases/latest'
                    ' | python3 -c "import json,sys; print(json.load(sys.stdin)[\'tag_name\'])"', t=15)
    tag = out.strip()
    return tag if rc == 0 and re.fullmatch(r'v\d+\.\d+\.\d+', tag) else ''


@security_bp.route('/api/security/modsecurity/update-crs', methods=['POST'])
def modsec_update_crs():
    """Pull the latest OWASP CRS release and swap it in atomically.
    The old shell chain was `a && b || true && c ...`: because && and || have
    equal precedence, a failed download fell through the `|| true` and the
    route reported success; files from the previous release were also left
    behind in rules/ (CRS 4 removed/renamed several), and a failing config
    test left the half-updated tree live."""
    if not req(): return jsonify({'ok':False}), 401
    if not _modsec_installed():
        return jsonify({'ok':False, 'error':'ModSecurity is not installed'}), 400
    tag = _crs_latest_tag()
    if not tag:
        return jsonify({'ok':False, 'error':'Could not determine the latest CRS release (GitHub API unreachable or rate-limited). Nothing was changed.'}), 502
    ver = tag.lstrip('v')

    import tempfile, shutil
    crs = _modsec_crs_dir()
    work = tempfile.mkdtemp(prefix='vortex-crs-')
    try:
        tarball = os.path.join(work, 'crs.tar.gz')
        new_dir = os.path.join(work, 'crs')
        os.makedirs(new_dir)
        if _fetch(f'https://github.com/coreruleset/coreruleset/archive/refs/tags/{tag}.tar.gz', tarball, t=90) != 0:
            return jsonify({'ok':False, 'error':f'Download of CRS {tag} failed. Nothing was changed.'}), 502
        out, err, rc = sh(f'tar -xzf {tarball} -C {new_dir} --strip-components=1 2>&1', t=60)
        if rc != 0 or not os.path.exists(os.path.join(new_dir, 'crs-setup.conf.example')) \
                or not os.path.isdir(os.path.join(new_dir, 'rules')):
            return jsonify({'ok':False, 'error':f'CRS archive is incomplete: {(out or err)[-300:]}'}), 502

        old_setup = os.path.join(crs, 'crs-setup.conf')
        old_text = open(old_setup).read() if os.path.exists(old_setup) else ''
        example = open(os.path.join(new_dir, 'crs-setup.conf.example')).read()
        new_v4 = _crs_is_v4(example) or 'blocking_paranoia_level' in example
        if old_text and _crs_is_v4(old_text) == new_v4:
            setup_text = old_text      # same major: keep the admin's tuning
        else:
            level = _paranoia_level() if old_text else 1
            setup_text = _apply_paranoia_text(example, level, new_v4) if level != 1 else example
        open(os.path.join(new_dir, 'crs-setup.conf'), 'w').write(setup_text)
        # keep locally installed CRS 4 plugins
        old_plugins = os.path.join(crs, 'plugins')
        if os.path.isdir(old_plugins):
            os.makedirs(os.path.join(new_dir, 'plugins'), exist_ok=True)
            for fn in os.listdir(old_plugins):
                dst = os.path.join(new_dir, 'plugins', fn)
                if not os.path.exists(dst) and os.path.isfile(os.path.join(old_plugins, fn)):
                    shutil.copy2(os.path.join(old_plugins, fn), dst)

        prev = crs + '.vortex-prev'
        shutil.rmtree(prev, ignore_errors=True)
        if os.path.isdir(crs):
            os.rename(crs, prev)
        shutil.move(new_dir, crs)
        ok, test_out = _modsec_configtest()
        if not ok:
            shutil.rmtree(crs, ignore_errors=True)
            if os.path.isdir(prev):
                os.rename(prev, crs)
            return jsonify({'ok':False, 'version': ver,
                            'error':f'Config test failed with CRS {tag}; previous ruleset restored: {test_out[-400:]}',
                            'output': test_out[-500:]}), 400
        _modsec_reload()
        shutil.rmtree(prev, ignore_errors=True)
        return jsonify({'ok': True, 'version': ver, 'output': test_out[-500:]})
    finally:
        shutil.rmtree(work, ignore_errors=True)


@security_bp.route('/api/security/modsecurity/per-site', methods=['POST'])
def modsec_per_site():
    """Enable or disable ModSecurity for a specific site's nginx vhost.
    Apache uses a different per-vhost mechanism (IfModule blocks in a
    different config location) that hasn't been built and tested yet --
    explicitly say so rather than silently do nothing or risk an
    untested edit to an Apache vhost file."""
    if not req(): return jsonify({'ok':False}), 401
    if _modsec_target() == 'apache':
        return jsonify({'ok':False,'error':'Per-site ModSecurity override is not yet available for Apache installs (global toggle, paranoia level, custom rules, and IP/UA/URL lists all work correctly). Use the global Engine Mode toggle for now.'}), 501
    d      = request.get_json() or {}
    domain = (d.get('domain') or '').strip().lower()
    enable = d.get('enable', True)   # True = use global setting, False = disable for this site
    if not domain:
        return jsonify({'ok':False,'error':'domain required'}), 400
    if not _valid_hostname(domain):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400

    # Find this site's own vhost. The old substring scan ("domain in
    # content") picked the first file merely mentioning the name, e.g.
    # a.com matched the vhost of shop-a.com.
    fp = None
    try:
        from panel.routes.websites_core import _find_site_config
        cfp, ws = _find_site_config(domain)
        if cfp and ws == 'nginx':
            fp = cfp
    except Exception:
        pass
    if not fp:
        for conf_dir in ['/etc/nginx/vortex', '/etc/nginx/conf.d']:
            if not os.path.isdir(conf_dir): continue
            for fn in sorted(os.listdir(conf_dir)):
                cand = os.path.join(conf_dir, fn)
                if not os.path.isfile(cand): continue
                try: c = open(cand).read()
                except Exception: continue
                if any(domain in m.split() for m in re.findall(r'server_name\s+([^;]+);', c)):
                    fp = cand
                    break
            if fp: break
    if not fp:
        return jsonify({'ok':False,'error':f'No nginx config found for {domain}'}), 404

    try:
        original = open(fp).read()
        # Remove any existing modsecurity directives for this site
        content = re.sub(r'(?m)^[ \t]*modsecurity\s+(on|off)\s*;[ \t]*\n?', '', original, flags=re.IGNORECASE)
        content = re.sub(r'(?m)^[ \t]*modsecurity_rules_file[^\n]*\n?', '', content)
        if not enable:
            # Every server block: an HTTP->HTTPS redirect block usually comes
            # first, so patching only the first one left the real HTTPS
            # server protected.
            content = re.sub(r'(?m)^([ \t]*)server\s*\{[ \t]*$', r'\g<0>\n\1    modsecurity off;', content)
        with open(fp,'w') as f: f.write(content)
        out, err, rc = sh('nginx -t 2>&1')
        if rc != 0:
            with open(fp,'w') as f: f.write(original)
            return jsonify({'ok':False,'error':f'nginx config error, change reverted: {out}{err}'}), 400
        sh('systemctl reload nginx 2>/dev/null')
        return jsonify({'ok':True,'domain':domain,'enabled':enable})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)}), 500

# --- Nginx Load Balancer --------------------------------------------------------
LB_CONF = '/etc/nginx/conf.d/loadbalancer.conf'

_LB_ACTIVE_RE  = re.compile(r'^\s*server\s+([^\s;{}#]+)(?:\s+weight=(\d+))?\s*;')
_LB_MARKED_RE  = re.compile(r'^\s*#\s*server\s+([^\s;{}#]+)(?:\s+weight=(\d+))?\s*;\s*# VortexPanel: marked unhealthy')

def _lb_parse_servers(content):
    """Upstream backends, including ones the health checker commented out
    ("#server ...; # VortexPanel: marked unhealthy"): they are still part of
    the configuration, and dropping them made the next health-config save
    forget them, so they were never re-checked or restored."""
    out = []
    for line in content.split('\n'):
        m = _LB_ACTIVE_RE.match(line) or _LB_MARKED_RE.match(line)
        if m:
            out.append((m.group(1), m.group(2) or ''))
    return out


_LB_ADDR_RE = re.compile(r'^(unix:/[\w./-]+|\[[0-9A-Fa-f:.]+\](:\d{1,5})?|[A-Za-z0-9.-]+(:\d{1,5})?)$')

def _lb_valid_servers(servers):
    """Validate [{address, weight}] -- both are written into nginx config."""
    if not isinstance(servers, list):
        return None, 'servers must be a list'
    out = []
    for s in servers:
        if not isinstance(s, dict) or not s.get('address'):
            continue
        addr = str(s['address']).strip()
        if not _LB_ADDR_RE.match(addr):
            return None, f'Invalid server address: {addr}'
        try:
            w = int(s.get('weight', 1) or 1)
            if not 1 <= w <= 1000: raise ValueError()
        except (ValueError, TypeError):
            return None, f'Invalid weight for {addr}'
        out.append({'address': addr, 'weight': w})
    return out, ''


@security_bp.route('/api/security/loadbalancer')
def lb_status():
    if not req(): return jsonify({'ok':False}), 401
    if not os.path.exists(LB_CONF):
        return jsonify({'ok':True,'configured':False,'servers':[],'method':'roundrobin'})
    with open(LB_CONF) as f: content = f.read()
    # Parse only real "server <addr> [weight=N];" upstream directives.
    # Must end in ';' and exclude { } — this prevents the virtual host's
    # "server {" block declaration from being parsed as a phantom backend.
    servers = _lb_parse_servers(content)
    method = 'roundrobin'
    if 'least_conn' in content: method = 'leastconn'
    if 'ip_hash'    in content: method = 'iphash'
    if re.search(r'^\s*hash\s+\$cookie_', content, re.MULTILINE): method = 'cookie'
    server_list = [{'address':s[0],'weight':int(s[1]) if s[1] else 1} for s in servers]
    return jsonify({'ok':True,'configured':True,'servers':server_list,'method':method,'content':content})

@security_bp.route('/api/security/loadbalancer', methods=['PUT'])
def lb_save():
    if not req(): return jsonify({'ok':False}), 401
    d       = request.get_json() or {}
    servers = d.get('servers', [])  # [{address, weight}]
    method  = d.get('method', 'roundrobin')
    domain  = (d.get('domain') or '_').strip()
    port    = str(d.get('port') or '80').strip()
    cookie_name = d.get('cookie_name', 'VORTEX_LB')
    if not servers: return jsonify({'ok':False,'error':'At least one server required'}), 400
    servers, verr = _lb_valid_servers(servers)
    if verr: return jsonify({'ok':False,'error':verr}), 400
    if domain != '_' and not all(_valid_hostname(x.lstrip('*.')) for x in domain.split()):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400
    if not re.fullmatch(r'(\d{1,5})( ssl)?( http2)?', port) or not 1 <= int(port.split()[0]) <= 65535:
        return jsonify({'ok':False,'error':'Invalid port'}), 400

    # Build upstream block
    method_directive = ''
    if method == 'leastconn': method_directive = '    least_conn;\n'
    if method == 'iphash':    method_directive = '    ip_hash;\n'
    if method == 'cookie':
        # Open-source nginx has no nginx-plus "sticky cookie" directive, but
        # the standard `hash` directive with `consistent` minimizes
        # redistribution when servers are added/removed — using the
        # client's existing session cookie as the hash key gives the same
        # practical session-affinity result without needing nginx-plus.
        # The backend application must already be setting this cookie
        # (e.g. PHPSESSID, JSESSIONID, or a custom session cookie name).
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', cookie_name):
            return jsonify({'ok':False,'error':'Invalid cookie name'}), 400
        method_directive = f'    hash $cookie_{cookie_name} consistent;\n'

    server_lines = '\n'.join([
        f"    server {s['address']} weight={s.get('weight',1)};"
        for s in servers if s.get('address')
    ])
    if not server_lines:
        return jsonify({'ok':False,'error':'At least one valid server address required'}), 400

    method_comment = f'cookie ({cookie_name})' if method == 'cookie' else method
    conf = f"""# VortexPanel Load Balancer — managed by VortexPanel
# Method: {method_comment}
upstream vortex_backend {{
{method_directive}{server_lines}
    keepalive 32;
}}

server {{
    listen {port};
    server_name {domain};

    access_log /var/log/nginx/lb.access.log;
    error_log  /var/log/nginx/lb.error.log;

    location / {{
        proxy_pass http://vortex_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_send_timeout    60s;
        proxy_read_timeout    60s;
        proxy_next_upstream   error timeout invalid_header http_500 http_502 http_503;
    }}
}}
"""
    os.makedirs('/etc/nginx/conf.d', exist_ok=True)

    # Back up the existing config before overwriting. If 'nginx -t' fails
    # below, we restore this so a broken config is never left on disk
    # (which would otherwise break nginx on the next restart/reload and
    # take down every site on the server).
    existed = os.path.exists(LB_CONF)
    backup = None
    if existed:
        with open(LB_CONF) as f: backup = f.read()

    with open(LB_CONF,'w') as f: f.write(conf)
    test_out, test_err, test_rc = sh('nginx -t 2>&1')
    test = (test_out + test_err)
    if test_rc != 0 or 'failed' in test.lower():
        if existed:
            with open(LB_CONF,'w') as f: f.write(backup)
        else:
            try: os.unlink(LB_CONF)
            except: pass
        return jsonify({'ok':False,'error':test}), 400
    sh('systemctl reload nginx 2>/dev/null')

    # Keep health-check's server list in sync if health checking is active,
    # so newly added/removed servers are picked up without a separate step.
    try:
        hcfg = _load_json(LB_HEALTH_CONFIG, None)
        if hcfg and hcfg.get('enabled'):
            hcfg['servers'] = [s['address'] for s in servers if s.get('address')]
            _save_json(LB_HEALTH_CONFIG, hcfg)
    except Exception:
        pass

    return jsonify({'ok':True})

@security_bp.route('/api/security/loadbalancer', methods=['DELETE'])
def lb_delete():
    if not req(): return jsonify({'ok':False}), 401
    try: os.unlink(LB_CONF)
    except: pass
    sh('systemctl reload nginx 2>/dev/null')
    return jsonify({'ok':True})


# --- Load Balancer: shared JSON helpers -----------------------------------------
def _load_json(path, default):
    try: return __import__('json').load(open(path))
    except Exception: return default

def _save_json(path, data):
    import json
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    try: os.chmod(path, 0o600)
    except Exception: pass


# --- Load Balancer: TCP / Stream -------------------------------------------------
LB_STREAM_DIR  = '/etc/nginx/stream.d'
LB_STREAM_CONF = '/etc/nginx/stream.d/vortex_tcp_lb.conf'

def _find_stream_module_so():
    """Locate ngx_stream_module.so on disk — varies by distro and nginx source."""
    candidates = [
        '/usr/lib/nginx/modules/ngx_stream_module.so',       # Debian/Ubuntu
        '/usr/lib64/nginx/modules/ngx_stream_module.so',     # RHEL/CentOS/Alma/Rocky
        '/usr/share/nginx/modules/ngx_stream_module.so',     # some RHEL builds
    ]
    for p in candidates:
        if os.path.exists(p): return p
    # last resort: find it
    out, _, _ = sh('find /usr -name "ngx_stream_module.so" 2>/dev/null | head -1')
    return out or ''

def _nginx_has_stream_module():
    """Check if nginx can use the stream module right now."""
    # 1) compiled-in (static module)
    out, _, _ = sh('nginx -V 2>&1')
    if '--with-stream' in out and '--with-stream=dynamic' not in out:
        return True
    # 2) dynamic module .so exists on disk
    if not _find_stream_module_so():
        return False
    # 3) already enabled in modules-enabled (Debian auto-symlink)
    if sh('find /etc/nginx/modules-enabled -name "*stream*" 2>/dev/null')[0]:
        return True
    # 4) load_module directive already in nginx.conf
    try:
        conf = open('/etc/nginx/nginx.conf').read()
        if re.search(r'^\s*load_module\s+.*ngx_stream_module', conf, re.MULTILINE):
            return True
    except: pass
    return False

def _ensure_stream_load_module():
    """Ensure the load_module directive for stream is in nginx.conf.
    On Debian, apt auto-creates a symlink in modules-enabled so this
    is a no-op. On RHEL-family it must be added manually."""
    conf_path = '/etc/nginx/nginx.conf'
    if not os.path.exists(conf_path):
        return False, 'nginx.conf not found'
    content = open(conf_path).read()
    # Already has load_module or modules-enabled symlink covers it
    if re.search(r'^\s*load_module\s+.*ngx_stream_module', content, re.MULTILINE):
        return True, ''
    if sh('find /etc/nginx/modules-enabled -name "*stream*" 2>/dev/null')[0]:
        return True, ''
    # Find the .so path
    so_path = _find_stream_module_so()
    if not so_path:
        return False, 'stream module .so not found after install'
    # Use relative path if under standard modules dir, absolute otherwise
    if '/modules/ngx_stream_module.so' in so_path:
        directive = 'load_module modules/ngx_stream_module.so;'
    else:
        directive = f'load_module {so_path};'
    # Insert at top of nginx.conf (before any other blocks)
    new_content = directive + '\n' + content
    with open(conf_path, 'w') as f:
        f.write(new_content)
    return True, ''

def _ensure_stream_block():
    """Add a top-level `stream { include .../stream.d/*.conf; }` block to
    nginx.conf if one doesn't already exist. Required once — TCP/stream
    load balancing cannot live inside conf.d (that's only included from
    within the http {} block)."""
    os.makedirs(LB_STREAM_DIR, exist_ok=True)
    conf_path = '/etc/nginx/nginx.conf'
    if not os.path.exists(conf_path):
        return False, 'nginx.conf not found'
    content = open(conf_path).read()
    if re.search(r'^\s*stream\s*\{', content, re.MULTILINE):
        return True, ''
    addition = f"\nstream {{\n    include {LB_STREAM_DIR}/*.conf;\n}}\n"
    with open(conf_path, 'a') as f:
        f.write(addition)
    return True, ''

@security_bp.route('/api/security/loadbalancer/tcp')
def lb_tcp_status():
    if not req(): return jsonify({'ok':False}), 401
    has_module = _nginx_has_stream_module()
    if not os.path.exists(LB_STREAM_CONF):
        return jsonify({'ok':True,'configured':False,'servers':[],'method':'roundrobin',
                        'stream_module_available':has_module})
    content = open(LB_STREAM_CONF).read()
    servers = re.findall(r'^\s*server\s+([^\s;{}]+)(?:\s+weight=(\d+))?\s*;', content, re.MULTILINE)
    method = 'roundrobin'
    if 'least_conn' in content: method = 'leastconn'
    if re.search(r'\bhash\b', content): method = 'hash'
    port_m = re.search(r'^\s*listen\s+(\d+)', content, re.MULTILINE)
    server_list = [{'address':s[0],'weight':int(s[1]) if s[1] else 1} for s in servers]
    return jsonify({'ok':True,'configured':True,'servers':server_list,'method':method,
                    'port':port_m.group(1) if port_m else '', 'stream_module_available':has_module})

@security_bp.route('/api/security/loadbalancer/tcp/install-stream', methods=['POST'])
def lb_tcp_install_stream():
    """Auto-install nginx stream module for any supported distro."""
    if not req(): return jsonify({'ok':False}), 401
    if _nginx_has_stream_module():
        return jsonify({'ok':True,'message':'Stream module already available'})

    os_info = get_os()
    family  = os_info['family']
    pkg_mgr = os_info['pkg']
    steps   = []

    # --- Step 1: install the package ---
    if family == 'debian':
        cmd = 'DEBIAN_FRONTEND=noninteractive apt-get install -y libnginx-mod-stream'
        out, err, rc = sh(cmd, t=120)
        steps.append({'cmd': cmd, 'rc': rc, 'out': out, 'err': err})
        if rc != 0:
            # Try apt update first then retry
            sh('apt-get update -qq', t=60)
            out, err, rc = sh(cmd, t=120)
            steps.append({'cmd': cmd + ' (retry after update)', 'rc': rc})
            if rc != 0:
                return jsonify({'ok':False,
                    'error':f'Failed to install libnginx-mod-stream: {err}',
                    'steps':steps}), 500

    elif family in ('rhel', 'fedora'):
        # Official nginx.org packages bundle stream in the main package.
        # The .so may already exist — just needs load_module.
        so_path = _find_stream_module_so()
        if not so_path:
            # Try installing the distro's stream module package
            pkg_name = 'nginx-mod-stream'
            cmd = f'{pkg_mgr} install -y {pkg_name}'
            out, err, rc = sh(cmd, t=120)
            steps.append({'cmd': cmd, 'rc': rc, 'out': out, 'err': err})
            if rc != 0:
                # Package doesn't exist — nginx was likely built from source
                # or from a repo that bundles everything. Check one more time.
                so_path = _find_stream_module_so()
                if not so_path:
                    return jsonify({'ok':False,
                        'error':f'Could not install stream module. '
                                f'Package "{pkg_name}" not found in repos. '
                                f'If nginx was compiled from source, rebuild with --with-stream.',
                        'steps':steps}), 500
    else:
        return jsonify({'ok':False,
            'error':f'Unsupported OS family: {family}'}), 400

    # --- Step 2: ensure load_module directive exists ---
    nginx_conf_prev = open('/etc/nginx/nginx.conf').read() if os.path.exists('/etc/nginx/nginx.conf') else None
    ok, err = _ensure_stream_load_module()
    steps.append({'action': 'ensure_load_module', 'ok': ok, 'err': err})
    if not ok:
        return jsonify({'ok':False, 'error':f'load_module failed: {err}', 'steps':steps}), 500

    # --- Step 3: test nginx config ---
    out, err, rc = sh('nginx -t 2>&1')
    steps.append({'cmd': 'nginx -t', 'rc': rc, 'out': out, 'err': err})
    if rc != 0:
        if nginx_conf_prev is not None:
            with open('/etc/nginx/nginx.conf', 'w') as f: f.write(nginx_conf_prev)
        return jsonify({'ok':False,
            'error':f'nginx -t failed after install (nginx.conf restored): {out} {err}',
            'steps':steps}), 500

    # --- Step 4: reload nginx ---
    sh('systemctl reload nginx', t=10)
    steps.append({'action': 'nginx reloaded'})

    return jsonify({'ok':True, 'message':'Stream module installed and loaded', 'steps':steps})

@security_bp.route('/api/security/loadbalancer/tcp', methods=['PUT'])
def lb_tcp_save():
    if not req(): return jsonify({'ok':False}), 401
    if not _nginx_has_stream_module():
        return jsonify({'ok':False,
            'error':"nginx stream module not available. Use the Install button to set it up automatically."}), 400

    d       = request.get_json() or {}
    servers = d.get('servers', [])
    method  = d.get('method', 'roundrobin')   # roundrobin | leastconn | hash (by source IP)
    port    = d.get('port', '9000')
    if not servers: return jsonify({'ok':False,'error':'At least one server required'}), 400
    servers, verr = _lb_valid_servers(servers)
    if verr: return jsonify({'ok':False,'error':verr}), 400
    try:
        port_n = int(port)
        if not (1 <= port_n <= 65535): raise ValueError()
    except (ValueError, TypeError):
        return jsonify({'ok':False,'error':'Invalid port'}), 400
    if port_n in (8888,) or (_port_listening(port_n) and not os.path.exists(LB_STREAM_CONF)):
        return jsonify({'ok':False,'error':f'Port {port_n} is already in use'}), 400

    nginx_conf_prev = open('/etc/nginx/nginx.conf').read() if os.path.exists('/etc/nginx/nginx.conf') else None
    ok, err = _ensure_stream_block()
    if not ok: return jsonify({'ok':False,'error':err}), 500

    method_directive = ''
    if method == 'leastconn': method_directive = '    least_conn;\n'
    if method == 'hash':      method_directive = '    hash $remote_addr consistent;\n'

    server_lines = '\n'.join([
        f"    server {s['address']} weight={s.get('weight',1)};"
        for s in servers if s.get('address')
    ])
    if not server_lines:
        return jsonify({'ok':False,'error':'At least one valid server address required'}), 400

    conf = f"""# VortexPanel TCP Load Balancer — managed by VortexPanel
# Method: {method}
upstream vortex_tcp_backend {{
{method_directive}{server_lines}
}}

server {{
    listen {port_n};
    proxy_pass vortex_tcp_backend;
    proxy_timeout 10m;
    proxy_connect_timeout 5s;
    proxy_next_upstream on;
}}
"""
    os.makedirs(LB_STREAM_DIR, exist_ok=True)
    existed = os.path.exists(LB_STREAM_CONF)
    backup = open(LB_STREAM_CONF).read() if existed else None

    with open(LB_STREAM_CONF, 'w') as f: f.write(conf)
    test_out, test_err, test_rc = sh('nginx -t 2>&1')
    test = test_out + test_err
    if test_rc != 0 or 'failed' in test.lower():
        if existed:
            with open(LB_STREAM_CONF, 'w') as f: f.write(backup)
        else:
            try: os.unlink(LB_STREAM_CONF)
            except: pass
        if nginx_conf_prev is not None:
            with open('/etc/nginx/nginx.conf', 'w') as f: f.write(nginx_conf_prev)
        return jsonify({'ok':False,'error':test}), 400
    sh('systemctl reload nginx 2>/dev/null')

    # Open the port in the firewall (best-effort, both UFW and firewalld;
    # no firewall-cmd --reload, which would drop runtime fail2ban bans).
    _fw_open_tcp(port_n)

    return jsonify({'ok':True})

@security_bp.route('/api/security/loadbalancer/tcp', methods=['DELETE'])
def lb_tcp_delete():
    if not req(): return jsonify({'ok':False}), 401
    try: os.unlink(LB_STREAM_CONF)
    except Exception: pass
    sh('systemctl reload nginx 2>/dev/null')
    return jsonify({'ok':True})


# --- Load Balancer: Active Health Checks -----------------------------------------
LB_HEALTH_CONFIG = '/opt/vortexpanel/lb_health.json'
LB_HEALTH_STATE  = '/opt/vortexpanel/lb_health_state.json'
LB_HEALTH_LOG    = '/opt/vortexpanel/lb_health.log'
LB_HEALTH_SCRIPT = '/opt/vortexpanel/scripts/lb_healthcheck.py'
LB_HEALTH_SERVICE_FILE = '/etc/systemd/system/vortex-lb-healthcheck.service'
LB_HEALTH_SERVICE_NAME = 'vortex-lb-healthcheck'

_HEALTHCHECK_SCRIPT_BODY = '''#!/usr/bin/env python3
"""
VortexPanel Load Balancer — active health check daemon.

Open-source nginx has no built-in active health checking (that's an
nginx-plus-only feature). This script provides the same practical
result: it periodically probes each backend, and when one crosses the
configured failure threshold it comments that server out of the
upstream block, validates the new config with `nginx -t`, and reloads
nginx — then reverses the process automatically once the backend
recovers. Runs as a long-lived systemd service, not cron, so the
check interval can be sub-minute.
"""
import json, os, re, socket, subprocess, time, urllib.request

CONFIG  = "/opt/vortexpanel/lb_health.json"
STATE   = "/opt/vortexpanel/lb_health_state.json"
LOG     = "/opt/vortexpanel/lb_health.log"
LB_CONF = "/etc/nginx/conf.d/loadbalancer.conf"

def log(msg):
    try:
        with open(LOG, "a") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\\n")
        lines = open(LOG).readlines()
        if len(lines) > 500:
            with open(LOG, "w") as f:
                f.writelines(lines[-500:])
    except Exception:
        pass

def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def check_http(address, path, timeout):
    try:
        host, port = address.rsplit(":", 1)
        url = "http://" + host + ":" + port + path
        req = urllib.request.Request(url, headers={"User-Agent": "VortexPanel-HealthCheck"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 400
    except Exception:
        return False

def check_tcp(address, timeout):
    try:
        host, port = address.rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False

def rewrite_upstream(healthy_servers):
    if not os.path.exists(LB_CONF):
        return
    content = open(LB_CONF).read()
    new_lines = []
    changed = False
    for line in content.split("\\n"):
        m = re.match(r"^(\\s*)(#\\s*)?server\\s+([^\\s;{}]+)(\\s+weight=\\d+)?\\s*;.*$", line)
        if m:
            indent, was_commented, addr, weight = m.group(1), m.group(2), m.group(3), m.group(4) or ""
            is_healthy = addr in healthy_servers
            if is_healthy and was_commented:
                new_lines.append(indent + "server " + addr + weight + ";")
                changed = True
            elif not is_healthy and not was_commented:
                new_lines.append(indent + "#server " + addr + weight + "; # VortexPanel: marked unhealthy")
                changed = True
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    if not changed:
        return
    new_content = "\\n".join(new_lines)
    with open(LB_CONF, "w") as f:
        f.write(new_content)
    test = subprocess.run("nginx -t", shell=True, capture_output=True, text=True)
    if test.returncode == 0:
        subprocess.run("systemctl reload nginx", shell=True)
        log("upstream updated, healthy=" + ",".join(healthy_servers))
    else:
        with open(LB_CONF, "w") as f:
            f.write(content)
        log("nginx -t failed after health-check rewrite, rolled back: " + test.stderr[:200])

def run_once():
    cfg = load_json(CONFIG, None)
    if not cfg or not cfg.get("enabled"):
        return
    servers = cfg.get("servers", [])
    if not servers:
        return
    state = load_json(STATE, {})
    healthy = []
    for addr in servers:
        s = state.get(addr, {"fail": 0, "ok": 0, "healthy": True})
        timeout = cfg.get("timeout_seconds", 3)
        if cfg.get("protocol", "http") == "tcp":
            up = check_tcp(addr, timeout)
        else:
            up = check_http(addr, cfg.get("check_path", "/"), timeout)
        if up:
            s["ok"] += 1
            s["fail"] = 0
            if s["ok"] >= cfg.get("healthy_threshold", 2):
                if not s["healthy"]:
                    log(addr + " recovered, marking HEALTHY")
                s["healthy"] = True
        else:
            s["fail"] += 1
            s["ok"] = 0
            if s["fail"] >= cfg.get("unhealthy_threshold", 3):
                if s["healthy"]:
                    log(addr + " failed " + str(s["fail"]) + " checks, marking UNHEALTHY")
                s["healthy"] = False
        state[addr] = s
        if s["healthy"]:
            healthy.append(addr)
    save_json(STATE, state)

    if not healthy:
        # Fail open: never remove every backend from rotation even if all
        # checks fail (e.g. a network blip affecting the checker itself) —
        # a false-positive total outage is worse than serving through an
        # unconfirmed-healthy backend.
        log("WARNING: all backends report unhealthy — failing open, keeping all in rotation")
        healthy = servers

    rewrite_upstream(healthy)

def main():
    log("health check daemon started")
    while True:
        try:
            run_once()
        except Exception as e:
            log("error in check loop: " + str(e))
        cfg = load_json(CONFIG, {})
        time.sleep(max(5, cfg.get("interval_seconds", 10)))

if __name__ == "__main__":
    main()
'''

def _install_health_service():
    os.makedirs(os.path.dirname(LB_HEALTH_SCRIPT), exist_ok=True)
    with open(LB_HEALTH_SCRIPT, 'w') as f:
        f.write(_HEALTHCHECK_SCRIPT_BODY)
    os.chmod(LB_HEALTH_SCRIPT, 0o700)

    service = f"""[Unit]
Description=VortexPanel Load Balancer Active Health Check
After=network.target nginx.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {LB_HEALTH_SCRIPT}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    with open(LB_HEALTH_SERVICE_FILE, 'w') as f:
        f.write(service)
    sh('systemctl daemon-reload')

@security_bp.route('/api/security/loadbalancer/health')
def lb_health_status():
    if not req(): return jsonify({'ok':False}), 401
    cfg   = _load_json(LB_HEALTH_CONFIG, {'enabled':False,'check_path':'/','protocol':'http',
                                          'interval_seconds':10,'timeout_seconds':3,
                                          'unhealthy_threshold':3,'healthy_threshold':2,'servers':[]})
    state = _load_json(LB_HEALTH_STATE, {})
    service_active, _, _ = sh(f'systemctl is-active {LB_HEALTH_SERVICE_NAME} 2>/dev/null')
    log_tail = ''
    if os.path.exists(LB_HEALTH_LOG):
        try: log_tail = ''.join(open(LB_HEALTH_LOG).readlines()[-30:])
        except Exception: pass
    return jsonify({'ok':True, 'config':cfg, 'state':state,
                    'service_active': service_active.strip()=='active', 'log': log_tail})

@security_bp.route('/api/security/loadbalancer/health', methods=['PUT'])
def lb_health_save():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}

    # Pull current LB server list automatically so health checks always
    # match whatever's actually configured in the load balancer.
    lb = lb_status_data()
    servers = [s['address'] for s in lb.get('servers', [])]

    check_path = str(d.get('check_path', '/') or '/').strip()
    if not check_path.startswith('/') or re.search(r'[\s"\\]', check_path):
        return jsonify({'ok':False,'error':'check_path must be a URL path starting with /'}), 400
    try:
        cfg = {
          'enabled':              bool(d.get('enabled', False)),
          'protocol':             d.get('protocol', 'http') if d.get('protocol') in ('http','tcp') else 'http',
          'check_path':           check_path,
          'interval_seconds':     max(5, min(300, int(d.get('interval_seconds', 10)))),
          'timeout_seconds':      max(1, min(30, int(d.get('timeout_seconds', 3)))),
          'unhealthy_threshold':  max(1, min(10, int(d.get('unhealthy_threshold', 3)))),
          'healthy_threshold':    max(1, min(10, int(d.get('healthy_threshold', 2)))),
          'servers':              servers,
        }
    except (ValueError, TypeError):
        return jsonify({'ok':False,'error':'interval/timeout/threshold values must be numbers'}), 400
    _save_json(LB_HEALTH_CONFIG, cfg)

    if not os.path.exists(LB_HEALTH_SCRIPT):
        _install_health_service()

    if cfg['enabled']:
        sh(f'systemctl enable {LB_HEALTH_SERVICE_NAME} 2>/dev/null')
        sh(f'systemctl restart {LB_HEALTH_SERVICE_NAME} 2>/dev/null')
    else:
        sh(f'systemctl stop {LB_HEALTH_SERVICE_NAME} 2>/dev/null')
        # Restore any servers that were commented out, since checking is now off
        if os.path.exists(LB_CONF):
            content = open(LB_CONF).read()
            restored = re.sub(r'#server ([^\s;{}]+)(\s+weight=\d+)?; # VortexPanel: marked unhealthy',
                              r'server \1\2;', content)
            if restored != content:
                with open(LB_CONF, 'w') as f: f.write(restored)
                out, err, rc = sh('nginx -t 2>&1')
                if rc == 0: sh('systemctl reload nginx 2>/dev/null')

    return jsonify({'ok':True, 'config':cfg})


def lb_status_data():
    """Internal helper — same logic as lb_status() but returns plain dict
    for reuse by other routes instead of a Flask Response."""
    if not os.path.exists(LB_CONF):
        return {'configured':False,'servers':[],'method':'roundrobin'}
    content = open(LB_CONF).read()
    servers = _lb_parse_servers(content)
    method = 'roundrobin'
    if 'least_conn' in content: method = 'leastconn'
    if 'ip_hash'    in content: method = 'iphash'
    if re.search(r'^\s*hash\s+\$cookie_', content, re.MULTILINE): method = 'cookie'
    server_list = [{'address':s[0],'weight':int(s[1]) if s[1] else 1} for s in servers]
    return {'configured':True,'servers':server_list,'method':method}
# ===============================================================================
# WAF 2.0 — Phase 1: per-site engine mode + scoped rule exceptions
# ===============================================================================
# All state lives in vortex-exceptions.json and is compiled, in full, to
# vortex-exceptions.conf on every change. The generated rules key on
# SERVER_NAME, so per-site mode and scoped exceptions work identically on
# nginx AND Apache (via ModSecurity's per-request ctl: action) without any
# vhost surgery.
import ipaddress as _ipaddr

# Reserved SecRule id space — outside CRS (900000-999999) and the
# vortex-lists.conf range (_LIST_ID_BASE, 1050000-1053999).
_EXC_SITEMODE_BASE = 1820000
_EXC_RULE_BASE     = 1830000

_HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT'}

# --- WAF 2.0 module constants ------------------------------------------------
# These were referenced by the v3.5.0 WAF 2.0 merge but never defined (only
# the functions were extracted), so every endpoint touching them -- and the
# existing Blacklist/Whitelist save, via _coraza_sync -- died with NameError.

# CRS rule ranges whose exceptions need an explicit force=true: 941xxx is
# XSS and 942xxx SQL injection (matches the error message shown for them).
_EXC_ALWAYS_BLOCK_RANGES = [(941000, 941999), (942000, 942999)]

# ISO 3166-1 alpha-2 country code as returned in GEO:COUNTRY_CODE.
_ISO2_RE = re.compile(r'^[A-Z]{2}$')

# Response codes a block rule may answer with (strings: compared against
# str(user input)). Plain 4xx/5xx codes every engine (ModSecurity v2/v3,
# Coraza) and nginx's limit_req_status (400-599) accept; nginx's special 444
# is deliberately not offered since only nginx's own `return` honours it.
_WAF_STATUS_CODES = {'400', '403', '404', '406', '429', '451', '503'}

# SecRule id blocks for generated files, continuing the WAF 2.0 layout:
# lists 1050000-1053999, site mode 1820000+, exceptions 1830000+,
# region 1840000+, custom rules builder 1850000+. All stay clear of OWASP
# CRS (900000-999999) and of the ids coraza.conf-recommended uses (200000s).
_GEO_ID_BASE    = 1840000
_CUSTOM_ID_BASE = 1850000

# Custom-rules-builder condition fields -> (SecLang variable, operator).
_CUSTOM_FIELDS = {
    'ip':           ('REMOTE_ADDR', 'ipMatch'),            # comma-separated IPs/CIDRs
    'country':      ('GEO:COUNTRY_CODE', 'streq'),         # needs a GeoIP DB (not on Coraza)
    'method':       ('REQUEST_METHOD', 'streq'),
    'uri_prefix':   ('REQUEST_FILENAME', 'beginsWith'),    # path only, no query string
    'uri_contains': ('REQUEST_URI', 'contains'),
    'uri_regex':    ('REQUEST_URI', 'rx'),
    'query':        ('QUERY_STRING', 'contains'),
    'user_agent':   ('REQUEST_HEADERS:User-Agent', 'rx'),
    'referer':      ('REQUEST_HEADERS:Referer', 'rx'),
}

# limit_req_zone is only valid in the http{} context. Every supported
# nginx.conf (Debian/Ubuntu distro + nginx.org packages, RHEL) includes
# /etc/nginx/conf.d/*.conf inside http{} -- the load balancer conf above
# lives there for the same reason (the panel's own vhosts dir
# /etc/nginx/vortex is included next to it).
_RATELIMIT_CONF = '/etc/nginx/conf.d/vortex-ratelimit.conf'

# Caddy layout used by the rest of the panel (caddy.py, wp_toolkit._write_vhost):
# main Caddyfile importing per-site files from /etc/caddy/sites.
CADDYFILE   = '/etc/caddy/Caddyfile'
CADDY_SITES = '/etc/caddy/sites'

# Generated SecLang files for Caddy's Coraza engine. Kept apart from
# /etc/caddy/waf, which belongs to the older caddy-waf (fabriziosalmi) module.
CORAZA_DIR    = '/etc/caddy/coraza'
CORAZA_MARKER = os.path.join(CORAZA_DIR, '.coraza-installed')

# Protocol-integrity rules that can NEVER be excepted (request smuggling /
# splitting). Disabling these re-opens whole request-parsing attack classes,
# so the builder refuses them even with force=true.
_EXC_PROTECTED_RANGES = [(921000, 921999)]          # CRS: Protocol Attack
def _rid_in_ranges(rid, ranges):
    return any(lo <= rid <= hi for lo, hi in ranges)


def _exc_json(): return _waf_state_path('vortex-exceptions.json')


def _exc_conf(): return os.path.join(_modsec_dir(), 'vortex-exceptions.conf')


def _load_exceptions():
    if not os.path.exists(_exc_json()):
        return {}
    try:
        data = json.load(open(_exc_json()))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_exceptions(data):
    _write_json_state(_exc_json(), data)


def _valid_ip_or_cidr(v):
    try:
        _ipaddr.ip_network(v.strip(), strict=False)
        return True
    except ValueError:
        return False


def _valid_hostname(h):
    h = (h or '').strip().lower()
    if not h or len(h) > 253:
        return False
    return bool(re.fullmatch(
        r'(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)'
        r'(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*', h))


def _validate_exception(exc, force=False):
    """Validate + normalize ONE exception. Returns (ok, normalized_dict|error_str)."""
    url = (exc.get('url_prefix') or '').strip()
    if not url or not url.startswith('/'):
        return False, 'URL prefix must start with "/"'
    if url == '/':
        return False, 'A URL prefix of "/" disables the rule for the whole site — scope it to a real path'
    if len(url) > 512 or '\n' in url or '\r' in url:
        return False, 'URL prefix is invalid'

    methods = exc.get('methods') or []
    if not isinstance(methods, list):
        return False, 'methods must be a list'
    methods = [m.strip().upper() for m in methods if m and str(m).strip()]
    for m in methods:
        if m not in _HTTP_METHODS:
            return False, f'Unknown HTTP method: {m}'

    ips = exc.get('client_ips') or []
    if not isinstance(ips, list):
        return False, 'client_ips must be a list'
    ips = [i.strip() for i in ips if i and str(i).strip()]
    for i in ips:
        if not _valid_ip_or_cidr(i):
            return False, f'Invalid IP/CIDR: {i}'

    raw_ids = exc.get('rule_ids') or []
    if not isinstance(raw_ids, list) or not raw_ids:
        return False, 'At least one rule ID is required'
    rule_ids = []
    for r in raw_ids:
        try:
            rid = int(r)
        except (ValueError, TypeError):
            return False, f'Rule ID must be a number: {r}'
        if not (900000 <= rid <= 999999):
            return False, f'{rid} is not an OWASP CRS rule ID (expected 900000-999999)'
        if _rid_in_ranges(rid, _EXC_PROTECTED_RANGES):
            return False, f'Rule {rid} is a protected protocol-integrity rule and cannot be excepted'
        if _rid_in_ranges(rid, _EXC_ALWAYS_BLOCK_RANGES) and not force:
            return False, (f'Rule {rid} guards against SQLi/XSS. Excepting it needs an explicit '
                           f'override — resubmit with force=true if you are certain.')
        if rid not in rule_ids:
            rule_ids.append(rid)

    # The note is echoed into a "# ..." comment line of the generated conf:
    # a line break in it would start a new, live directive.
    note = re.sub(r'[\r\n]+', ' ', str(exc.get('note') or '')).strip()[:200]
    if re.search(r'\s', url) or '"' in url:
        return False, 'URL prefix must not contain spaces or quotes'
    return True, {'url_prefix': url, 'methods': methods, 'client_ips': ips,
                  'rule_ids': rule_ids, 'note': note}


def _compile_exceptions_text(model):
    """PURE: turn the exceptions model into ModSecurity config text.

    IDs are assigned sequentially from the reserved range at compile time —
    they only need to be unique within this file (regenerated wholesale on
    every change), so positional assignment is safe.

    Chain semantics (important): a ModSecurity chain fires its actions only
    when EVERY link matches. Non-disruptive actions attached to the chain
    STARTER would run as soon as the starter matches, so the ctl:ruleRemoveById
    actions are attached to the LAST link instead — they then execute only
    when the full (domain + path [+ method] [+ ip]) condition is met. Phase 1
    guarantees the removal lands before CRS evaluates in phase 2.
    """
    lines = ['# Auto-generated by VortexPanel WAF — DO NOT EDIT BY HAND.',
             '# Per-site engine mode + scoped rule exceptions. Regenerated in full on every change.']
    site_id = _EXC_SITEMODE_BASE
    exc_id  = _EXC_RULE_BASE
    for domain in sorted(model.keys()):
        if not _valid_hostname(domain):
            continue
        entry = model[domain] or {}
        dom = _modsec_str_escape(domain)

        mode = (entry.get('site_mode') or 'enforce').lower()
        if mode in ('detect', 'off'):
            site_id += 1
            ctl = 'ctl:ruleEngine=DetectionOnly' if mode == 'detect' else 'ctl:ruleEngine=Off'
            lines.append(f'# {domain}: site engine mode = {mode}')
            lines.append(f'SecRule SERVER_NAME "@streq {dom}" '
                         f'"id:{site_id},phase:1,pass,nolog,{ctl}"')

        for exc in entry.get('exceptions', []):
            ok, norm = _validate_exception(exc, force=True)  # stored entries were validated on write
            if not ok:
                continue
            exc_id += 1
            ctls = ','.join(f'ctl:ruleRemoveById={rid}' for rid in norm['rule_ids'])
            links = [('SERVER_NAME', f'@streq {dom}'),
                     ('REQUEST_FILENAME', f'@beginsWith {_modsec_str_escape(norm["url_prefix"])}')]
            if norm['methods']:
                links.append(('REQUEST_METHOD', '@rx ^(' + '|'.join(norm['methods']) + ')$'))
            if norm['client_ips']:
                ipm = ','.join(_modsec_str_escape(i) for i in norm['client_ips'])
                links.append(('REMOTE_ADDR', f'@ipMatch {ipm}'))

            lines.append(f'# {domain}: skip {norm["rule_ids"]} on {norm["url_prefix"]}'
                         + (f' ({norm["note"]})' if norm['note'] else ''))
            n = len(links)
            for idx, (var, op) in enumerate(links):
                if idx == 0:
                    action = f'id:{exc_id},phase:1,pass,nolog' + (f',{ctls}' if n == 1 else ',chain')
                    lines.append(f'SecRule {var} "{op}" "{action}"')
                elif idx == n - 1:
                    lines.append(f'    SecRule {var} "{op}" "{ctls}"')
                else:
                    lines.append(f'    SecRule {var} "{op}" "chain"')
    return '\n'.join(lines) + '\n'


def _ensure_exceptions_included():
    """Wire vortex-exceptions.conf into main.conf after modsecurity.conf and
    before the CRS rules, so ctl:ruleRemoveById lands in phase 1 before CRS.
    Idempotent. Apache auto-includes /etc/modsecurity/*.conf, so (like
    vortex-lists.conf) it must NOT be explicitly included there or the rule
    IDs load twice and Apache refuses to start."""
    if _modsec_target() == 'apache':
        return
    if not os.path.exists(_modsec_main()):
        return
    main = open(_modsec_main()).read()
    include_line = f'Include {_exc_conf()}'
    if include_line in main:
        return
    base_include = f'Include {_modsec_conf()}'
    if base_include in main:
        main = main.replace(base_include, f'{base_include}\n{include_line}', 1)
    else:
        main = f'{include_line}\n{main}'
    with open(_modsec_main(), 'w') as f:
        f.write(main)


def _write_exceptions(model):
    """Compile → write conf → wire include → config-test → reload, on EVERY
    web server present on this box. nginx/Apache share one generated file
    (via _modsec_dir); Caddy gets the same text mirrored through Coraza. Each
    engine validates and rolls back independently, so a bad edit can never
    take any server down, and a Caddy-only box (no ModSecurity target) is
    handled by simply skipping the nginx/Apache half. Returns (ok, error)."""
    modsec_ok, modsec_err = _apply_modsec_file(_exc_conf(), _compile_exceptions_text(model),
                                               _ensure_exceptions_included)
    caddy_ok, caddy_err = _coraza_sync()
    return _combine_engine_results(modsec_ok, modsec_err, caddy_ok, caddy_err)


def _combine_engine_results(modsec_ok, modsec_err, caddy_ok, caddy_err):
    """Fail if any PRESENT engine failed; name which one so the user can tell
    an nginx problem from a Caddy one. Because every engine regenerates
    wholesale from the stored model on every change, a one-engine failure is
    self-healing on the next successful save rather than permanent drift."""
    if not modsec_ok:
        return False, f'nginx/Apache: {modsec_err}'
    if not caddy_ok:
        return False, f'Caddy/Coraza: {caddy_err}'
    return True, ''


@security_bp.route('/api/security/waf/exceptions')
def waf_exceptions_list():
    if not req(): return jsonify({'ok': False}), 401
    model  = _load_exceptions()
    domain = request.args.get('domain', '').strip().lower()
    if domain:
        entry = model.get(domain, {})
        return jsonify({'ok': True, 'domain': domain,
                        'site_mode': entry.get('site_mode', 'enforce'),
                        'exceptions': entry.get('exceptions', [])})
    return jsonify({'ok': True, 'sites': model})


@security_bp.route('/api/security/waf/exceptions', methods=['POST'])
def waf_exceptions_add():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    domain = (d.get('domain') or '').strip().lower()
    if not _valid_hostname(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    ok, norm = _validate_exception(d, force=bool(d.get('force')))
    if not ok:
        return jsonify({'ok': False, 'error': norm}), 400
    import secrets as _secrets
    norm['id'] = 'exc_' + _secrets.token_hex(4)
    norm['note'] = norm.get('note', '')
    missing = _waf_engine_missing()
    if missing:
        return jsonify({'ok': False, 'error': missing}), 400
    model = _load_exceptions()
    entry = model.setdefault(domain, {'site_mode': 'enforce', 'exceptions': []})
    entry.setdefault('exceptions', []).append(norm)
    saved_ok, err = _commit_model(_exc_json(), model, lambda: _write_exceptions(model))
    if not saved_ok:
        return jsonify({'ok': False, 'error': f'WAF config test failed, change reverted: {err}'}), 400
    return jsonify({'ok': True, 'exception': norm})


@security_bp.route('/api/security/waf/exceptions/<exc_id>', methods=['DELETE'])
def waf_exceptions_delete(exc_id):
    if not req(): return jsonify({'ok': False}), 401
    domain = (request.args.get('domain') or '').strip().lower()
    model  = _load_exceptions()
    removed = False
    domains = [domain] if domain else list(model.keys())
    for dom in domains:
        entry = model.get(dom, {})
        before = entry.get('exceptions', [])
        after  = [e for e in before if e.get('id') != exc_id]
        if len(after) != len(before):
            entry['exceptions'] = after
            removed = True
    if not removed:
        return jsonify({'ok': False, 'error': 'Exception not found'}), 404
    saved_ok, err = _commit_model(_exc_json(), model, lambda: _write_exceptions(model))
    if not saved_ok:
        return jsonify({'ok': False, 'error': f'WAF config test failed, change reverted: {err}'}), 400
    return jsonify({'ok': True})


@security_bp.route('/api/security/waf/site-mode', methods=['POST'])
def waf_site_mode():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    domain = (d.get('domain') or '').strip().lower()
    mode   = (d.get('mode') or '').strip().lower()
    if not _valid_hostname(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    if mode not in ('enforce', 'detect', 'off'):
        return jsonify({'ok': False, 'error': 'mode must be enforce, detect, or off'}), 400
    missing = _waf_engine_missing()
    if missing:
        return jsonify({'ok': False, 'error': missing}), 400
    model = _load_exceptions()
    entry = model.setdefault(domain, {'site_mode': 'enforce', 'exceptions': []})
    entry['site_mode'] = mode
    saved_ok, err = _commit_model(_exc_json(), model, lambda: _write_exceptions(model))
    if not saved_ok:
        return jsonify({'ok': False, 'error': f'WAF config test failed, change reverted: {err}'}), 400
    return jsonify({'ok': True, 'domain': domain, 'mode': mode})


@security_bp.route('/api/security/waf/rule-catalog')
def waf_rule_catalog():
    """CRS category ranges + which are protected / always-block, so the UI can
    label and grey-out rules in the exception picker. Also does a best-effort
    scan of the installed CRS rules for id -> msg descriptions."""
    if not req(): return jsonify({'ok': False}), 401
    categories = [{'from': lo, 'to': hi, 'name': name} for lo, hi, name in CRS_CATEGORY_RANGES]
    rules = {}
    rules_dir = f'{_modsec_crs_dir()}/rules'
    if os.path.isdir(rules_dir):
        # CRS writes each rule's actions one per line ("id:941100,\" ...
        # "msg:'...',\"), so the old line-based grep never matched. Join
        # the backslash continuations, then pair each id with its msg.
        for fn in sorted(os.listdir(rules_dir)):
            if not fn.endswith('.conf'):
                continue
            try:
                text = open(os.path.join(rules_dir, fn), errors='replace').read()
            except Exception:
                continue
            text = re.sub(r'\\\n\s*', '', text)
            for m in re.finditer(r'"id:(\d{6}),(.*?)(?=\bid:\d{6},|\Z)', text, re.S):
                mm = re.search(r"msg:'([^']+)'", m.group(2))
                if mm:
                    rules.setdefault(m.group(1), mm.group(1)[:120])
    return jsonify({'ok': True, 'categories': categories, 'rules': rules,
                    'protected': [{'from': lo, 'to': hi} for lo, hi in _EXC_PROTECTED_RANGES],
                    'always_block': [{'from': lo, 'to': hi} for lo, hi in _EXC_ALWAYS_BLOCK_RANGES]})


@security_bp.route('/api/security/waf/recent-hits')
def waf_recent_hits():
    """Recent WAF interceptions from the audit log, to power 'Add exception
    from this hit'. Each hit carries the exact rule_id that fired + its path."""
    if not req(): return jsonify({'ok': False}), 401
    domain = (request.args.get('domain') or '').strip().lower()
    if not os.path.exists(_modsec_audit()):
        return jsonify({'ok': True, 'hits': [], 'exists': False})
    out, _, _ = sh(f'tail -n 4000 "{_modsec_audit()}" 2>/dev/null', t=20)
    entries = _parse_modsec_entries(out)
    hits, seen = [], set()
    for e in reversed(entries):
        rid = e.get('rule_id')
        if not rid:
            continue
        dom = (e.get('domain') or '').split(':')[0].lower()
        if domain and dom != domain:
            continue
        key = (dom, e.get('uri'), e.get('method'), rid)
        if key in seen:
            continue
        seen.add(key)
        hits.append({'domain': dom, 'uri': e.get('uri', ''), 'method': e.get('method', ''),
                     'rule_id': rid, 'category': _categorize_rule(rid),
                     'message': e.get('message', ''), 'ip': e.get('ip', ''),
                     'timestamp': e.get('timestamp', '')})
        if len(hits) >= 50:
            break
    return jsonify({'ok': True, 'hits': hits, 'exists': True})


def _geo_json():  return _waf_state_path('vortex-geo.json')


def _geo_conf():  return os.path.join(_modsec_dir(), 'vortex-geo.conf')


def _custom_json():return _waf_state_path('vortex-custom.json')


def _custom_conf():return os.path.join(_modsec_dir(), 'vortex-custom.conf')


def _load_json_file(path, default):
    if not os.path.exists(path): return default
    try:
        d = json.load(open(path)); return d if isinstance(d, type(default)) else default
    except Exception: return default


# GeoIP databases. libmodsecurity v3 (nginx) reads MaxMind-format .mmdb
# (GeoLite2 or the free DB-IP "country lite" file) and legacy GeoIP.dat;
# ModSecurity 2.9 (Apache) reliably reads only the legacy .dat format.
_GEO_DB_MMDB = ['/usr/share/GeoIP/GeoLite2-Country.mmdb', '/var/lib/GeoIP/GeoLite2-Country.mmdb',
                '/usr/share/GeoIP/dbip-country-lite.mmdb', '/etc/nginx/modsec/GeoLite2-Country.mmdb']
_GEO_DB_DAT  = ['/usr/share/GeoIP/GeoIP.dat']
GEO_DB_INSTALL_PATH = '/usr/share/GeoIP/dbip-country-lite.mmdb'


def _geo_db_present():
    order = (_GEO_DB_DAT + _GEO_DB_MMDB) if _modsec_target() == 'apache' else (_GEO_DB_MMDB + _GEO_DB_DAT)
    for p in order:
        if os.path.exists(p) and os.path.getsize(p) > 0: return p
    return ''


def _comment_safe(v, n=120):
    """Text echoed into a '# ...' comment of a generated conf: a line break
    would turn the rest of it into a live directive."""
    return re.sub(r'[\r\n]+', ' ', str(v or '')).strip()[:n]


def _waf_engine_missing():
    """Error text when there is no engine to apply WAF 2.0 changes to."""
    if _modsec_target() is None and not _coraza_present():
        return ('No WAF engine is installed. Install ModSecurity WAF from the App Store (nginx/Apache). '
                'Coraza for Caddy cannot be installed from the panel yet - it needs a Caddy build that includes coraza-caddy.')
    return ''


def _validate_geo(rule):
    if not isinstance(rule, dict):
        return False, 'rule must be an object'
    cc = str(rule.get('country') or '').strip().upper()
    if not _ISO2_RE.match(cc):
        return False, 'country must be a 2-letter ISO code (e.g. CN, RU)'
    action = str(rule.get('action') or 'block').lower()
    if action not in ('block', 'allow'):
        return False, 'action must be block or allow'
    status = str(rule.get('status') or '403')
    if status not in _WAF_STATUS_CODES:
        return False, f'status must be one of {sorted(_WAF_STATUS_CODES)}'
    return True, {'country': cc, 'action': action, 'status': status,
                  'note': _comment_safe(rule.get('note'))}


def _compile_geo_text(rules, engine='modsec'):
    """PURE-ish (reads which GeoIP DB exists). Chain semantics: ModSecurity
    and Coraza only accept disruptive actions (deny/status) and metadata
    (msg/log) on the chain STARTER -- the old text put them on the chained
    rule, which every engine rejects at load, so no region rule could ever
    be saved. Non-disruptive ctl: actions go on the last link so they only
    fire when the whole chain matched."""
    lines = ['# Auto-generated by VortexPanel WAF (Region). DO NOT EDIT.']
    valid = [n for ok, n in (_validate_geo(r) for r in rules) if ok]
    if engine == 'coraza':
        if valid:
            lines.append('# Region rules are not applied on Caddy/Coraza: this engine has no GeoIP lookup.')
        return '\n'.join(lines) + '\n'
    db = _geo_db_present()
    if not db:
        if valid:
            lines.append('# WARNING: no GeoIP database found — region rules are inactive until one is installed.')
        return '\n'.join(lines) + '\n'
    if valid:
        lines.append(f'SecGeoLookupDb {db}')
    rid = _GEO_ID_BASE
    for n in valid:
        rid += 1
        lines.append(f'# {n["country"]}: {n["action"]}' + (f' ({n["note"]})' if n['note'] else ''))
        if n['action'] == 'allow':
            lines.append(f'SecRule REMOTE_ADDR "@geoLookup" "id:{rid},phase:1,pass,nolog,chain"')
            lines.append(f'    SecRule GEO:COUNTRY_CODE "@streq {n["country"]}" "t:none,ctl:ruleEngine=Off"')
        else:
            lines.append(f'SecRule REMOTE_ADDR "@geoLookup" "id:{rid},phase:1,deny,status:{n["status"]},log,'
                         f'msg:\'VortexPanel Region block {n["country"]}\',chain"')
            lines.append(f'    SecRule GEO:COUNTRY_CODE "@streq {n["country"]}" "t:none"')
    return '\n'.join(lines) + '\n'


def _validate_custom(rule):
    if not isinstance(rule, dict):
        return False, 'rule must be an object'
    # The name goes into msg:'...' and a comment line: keep it to plain text.
    name = re.sub(r"[^A-Za-z0-9 _.,:()/@+-]", '', str(rule.get('name') or '')).strip()[:60]
    if not name:
        return False, 'name required'
    conds = rule.get('conditions') or []
    if not isinstance(conds, list) or not conds:
        return False, 'at least one condition required'
    norm_conds = []
    for c in conds:
        if not isinstance(c, dict):
            return False, 'each condition must be an object'
        f = str(c.get('field') or '').lower()
        if f not in _CUSTOM_FIELDS:
            return False, f'unknown field: {f} (allowed: {", ".join(sorted(_CUSTOM_FIELDS))})'
        val = str(c.get('value') or '').strip()
        if not val or '\n' in val or '\r' in val or len(val) > 512:
            return False, f'invalid value for {f}'
        if f == 'ip':
            parts = [x.strip() for x in val.split(',') if x.strip()]
            if not parts or not all(_valid_ip_or_cidr(x) for x in parts):
                return False, f'invalid IP/CIDR in condition: {val}'
            val = ','.join(parts)
        if f == 'method' and val.upper() not in _HTTP_METHODS:
            return False, f'invalid method: {val}'
        if f == 'country' and not _ISO2_RE.match(val.upper()):
            return False, f'invalid country code: {val}'
        if f == 'uri_prefix' and (not val.startswith('/') or re.search(r'\s', val)):
            return False, 'uri_prefix must be a path starting with /'
        if _CUSTOM_FIELDS[f][1] == 'rx':
            try: re.compile(val)
            except re.error as e: return False, f'invalid regular expression for {f}: {e}'
        norm_conds.append({'field': f, 'value': val.upper() if f in ('method', 'country') else val})
    action = str(rule.get('action') or 'block').lower()
    if action not in ('block', 'allow'):
        return False, 'action must be block or allow'
    status = str(rule.get('status') or '403')
    if status not in _WAF_STATUS_CODES:
        return False, 'invalid status code'
    domain = str(rule.get('domain') or '').strip().lower()
    if domain and not _valid_hostname(domain):
        return False, 'invalid domain'
    return True, {'name': name, 'conditions': norm_conds, 'action': action,
                  'status': status, 'domain': domain, 'enabled': bool(rule.get('enabled', True))}


def _compile_custom_text(rules, engine='modsec'):
    """PURE-ish. Same chain rule as _compile_geo_text: deny/status/log/msg on
    the starter, ctl:ruleEngine=Off on the last link. Rules with a country
    condition are left out (commented) where no GeoIP lookup exists --
    dropping just the condition would widen a block rule to everyone."""
    lines = ['# Auto-generated by VortexPanel WAF (Custom Rules). DO NOT EDIT.']
    rid = _CUSTOM_ID_BASE
    db = '' if engine == 'coraza' else _geo_db_present()
    valid = [n for ok, n in (_validate_custom(r) for r in rules) if ok and n.get('enabled', True)]
    needs_geo = any(c['field'] == 'country' for n in valid for c in n['conditions'])
    if needs_geo and db:
        # vortex-geo.conf already declares the DB when it has rules.
        geo_rules = [x for ok, x in (_validate_geo(r) for r in _load_json_file(_geo_json(), [])) if ok]
        if not geo_rules:
            lines.append(f'SecGeoLookupDb {db}')
    for n in valid:
        rid += 1
        has_geo = any(c['field'] == 'country' for c in n['conditions'])
        if has_geo and not db:
            lines.append(f'# custom rule "{n["name"]}" skipped: country condition needs GeoIP support')
            continue
        links = []
        if n['domain']:
            links.append(('SERVER_NAME', f'@streq {_modsec_str_escape(n["domain"])}'))
        # geoLookup must precede any GEO:COUNTRY_CODE check
        if has_geo:
            links.append(('REMOTE_ADDR', '@geoLookup'))
        for c in n['conditions']:
            var, op = _CUSTOM_FIELDS[c['field']]
            links.append((var, f'@{op} {_modsec_str_escape(c["value"])}'))
        if n['action'] == 'allow':
            start_act, last_act = 'pass,nolog', 'ctl:ruleEngine=Off'
        else:
            start_act = f"deny,status:{n['status']},log,msg:'VortexPanel Custom: {n['name']}'"
            last_act = ''
        lines.append(f'# custom rule: {n["name"]} -> {n["action"]}')
        m = len(links)
        for idx, (var, op) in enumerate(links):
            if m == 1:
                lines.append(f'SecRule {var} "{op}" "id:{rid},phase:1,{start_act}' + (f',{last_act}' if last_act else '') + '"')
            elif idx == 0:
                lines.append(f'SecRule {var} "{op}" "id:{rid},phase:1,{start_act},chain"')
            elif idx == m - 1:
                lines.append(f'    SecRule {var} "{op}" "t:none' + (f',{last_act}' if last_act else '') + '"')
            else:
                lines.append(f'    SecRule {var} "{op}" "t:none,chain"')
    return '\n'.join(lines) + '\n'


def _wire_extra_include(conf_path):
    """Include an extra vortex conf into main.conf (nginx only; Apache
    auto-includes /etc/modsecurity/*.conf). Idempotent."""
    if _modsec_target() == 'apache' or not os.path.exists(_modsec_main()):
        return
    main = open(_modsec_main()).read()
    line = f'Include {conf_path}'
    if line in main:
        return
    base = f'Include {_modsec_conf()}'
    main = main.replace(base, f'{base}\n{line}', 1) if base in main else f'{line}\n{main}'
    with open(_modsec_main(), 'w') as f:
        f.write(main)


def _apply_modsec_file(conf_path, text, wire):
    """Write one generated conf for nginx/Apache, wire it, config-test and
    reload -- or restore BOTH the conf and main.conf. (Deleting a brand-new
    conf while leaving its fresh Include in main.conf behind, as before,
    broke every later nginx reload.) Returns (ok, err); (True, '') when
    there is no ModSecurity on this box."""
    if _modsec_target() is None:
        return True, ''
    os.makedirs(_modsec_dir(), exist_ok=True)
    prev = open(conf_path).read() if os.path.exists(conf_path) else None
    main_prev = open(_modsec_main()).read() if os.path.exists(_modsec_main()) else None
    with open(conf_path, 'w') as f:
        f.write(text)
    wire()
    ok, err = _modsec_configtest()
    if not ok:
        if prev is not None:
            with open(conf_path, 'w') as f: f.write(prev)
        else:
            try: os.unlink(conf_path)
            except Exception: pass
        if main_prev is not None:
            with open(_modsec_main(), 'w') as f: f.write(main_prev)
        return False, err
    _modsec_reload()
    return True, ''


def _write_generated(conf_path, text):
    """Write a generated conf (geo/custom) to nginx/Apache if present, then
    mirror the whole model to Caddy/Coraza. Each engine configtests and rolls
    back on its own. A Caddy-only box skips the nginx/Apache half."""
    modsec_ok, modsec_err = _apply_modsec_file(conf_path, text, lambda: _wire_extra_include(conf_path))
    caddy_ok, caddy_err = _coraza_sync()
    return _combine_engine_results(modsec_ok, modsec_err, caddy_ok, caddy_err)


def _commit_model(path, data, apply):
    """Save a model JSON FIRST (the Coraza sync regenerates from the stored
    models, so saving afterwards left Caddy one change behind), apply it to
    the engines, and put the previous JSON back if any engine rejected it."""
    prev = open(path).read() if os.path.exists(path) else None
    _write_json_state(path, data)
    ok, err = apply()
    if not ok:
        if prev is None:
            try: os.unlink(path)
            except Exception: pass
        else:
            with open(path, 'w') as f: f.write(prev)
    return ok, err


@security_bp.route('/api/security/waf/geo', methods=['GET', 'POST'])
def waf_geo():
    if not req(): return jsonify({'ok': False}), 401
    rules = _load_json_file(_geo_json(), [])
    if request.method == 'GET':
        return jsonify({'ok': True, 'rules': rules, 'geoip_installed': bool(_geo_db_present()),
                        'geoip_db': _geo_db_present()})
    missing = _waf_engine_missing()
    if missing: return jsonify({'ok': False, 'error': missing}), 400
    if _modsec_target() is None:
        return jsonify({'ok': False, 'error': 'Region rules need ModSecurity (nginx/Apache); Coraza on Caddy has no GeoIP lookup.'}), 400
    if not _geo_db_present():
        return jsonify({'ok': False, 'error': 'No GeoIP database installed — install one first (POST /api/security/waf/geo/install-db).'}), 400
    ok, n = _validate_geo(request.get_json() or {})
    if not ok: return jsonify({'ok': False, 'error': n}), 400
    rules = [r for r in rules if (r.get('country') or '').upper() != n['country']]  # replace dup
    rules.append(n)
    saved, err = _commit_model(_geo_json(), rules,
                               lambda: _write_generated(_geo_conf(), _compile_geo_text(rules)))
    if not saved: return jsonify({'ok': False, 'error': f'config test failed, reverted: {err}'}), 400
    return jsonify({'ok': True, 'rules': rules})


@security_bp.route('/api/security/waf/geo/<code>', methods=['DELETE'])
def waf_geo_delete(code):
    if not req(): return jsonify({'ok': False}), 401
    code = code.strip().upper()
    rules = [r for r in _load_json_file(_geo_json(), []) if (r.get('country') or '').upper() != code]
    saved, err = _commit_model(_geo_json(), rules,
                               lambda: _write_generated(_geo_conf(), _compile_geo_text(rules)))
    if not saved: return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok': True, 'rules': rules})


@security_bp.route('/api/security/waf/geo/install-db', methods=['POST'])
def waf_geo_install_db():
    """Install a free country database so region rules can match: the
    distro's legacy GeoIP.dat (geoip-database / GeoIP-GeoLite-data) for
    ModSecurity 2 on Apache, the DB-IP "IP to Country Lite" .mmdb (CC BY 4.0,
    no licence key needed, unlike MaxMind GeoLite2) for libmodsecurity 3."""
    if not req(): return jsonify({'ok': False}), 401
    if _modsec_target() is None:
        return jsonify({'ok': False, 'error': 'ModSecurity is not installed.'}), 400
    log = []
    if _modsec_target() == 'apache':
        out, err, rc = sh('DEBIAN_FRONTEND=noninteractive apt-get install -y geoip-database 2>&1 || '
                          'dnf install -y GeoIP-GeoLite-data 2>&1', t=300)
        log.append((out or err)[-300:])
    else:
        import gzip, shutil, tempfile
        os.makedirs(os.path.dirname(GEO_DB_INSTALL_PATH), exist_ok=True)
        now = datetime.now()
        months = [now.strftime('%Y-%m'), (now.replace(day=1) - timedelta(days=1)).strftime('%Y-%m')]
        fd, tmp = tempfile.mkstemp(suffix='.mmdb.gz')
        os.close(fd)
        try:
            for ym in months:
                if _fetch(f'https://download.db-ip.com/free/dbip-country-lite-{ym}.mmdb.gz', tmp, t=120) == 0:
                    try:
                        with gzip.open(tmp, 'rb') as src, open(GEO_DB_INSTALL_PATH + '.tmp', 'wb') as dst:
                            shutil.copyfileobj(src, dst)
                        os.replace(GEO_DB_INSTALL_PATH + '.tmp', GEO_DB_INSTALL_PATH)
                        log.append(f'DB-IP country lite {ym} installed at {GEO_DB_INSTALL_PATH}')
                        break
                    except Exception as e:
                        log.append(f'{ym}: {e}')
                else:
                    log.append(f'{ym}: download failed')
        finally:
            try: os.unlink(tmp)
            except Exception: pass
    db = _geo_db_present()
    if not db:
        return jsonify({'ok': False, 'error': 'Could not install a GeoIP database.', 'log': log}), 502
    # Regenerate so the SecGeoLookupDb line and any waiting rules go live.
    ok1, err1 = _write_generated(_geo_conf(), _compile_geo_text(_load_json_file(_geo_json(), [])))
    ok2, err2 = _write_generated(_custom_conf(), _compile_custom_text(_load_json_file(_custom_json(), [])))
    if not (ok1 and ok2):
        return jsonify({'ok': False, 'db': db, 'log': log,
                        'error': f'Database installed but the WAF engine rejected it: {err1 or err2}'}), 400
    return jsonify({'ok': True, 'db': db, 'log': log,
                    'attribution': 'IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0' if db == GEO_DB_INSTALL_PATH else ''})


@security_bp.route('/api/security/waf/custom-rules-builder', methods=['GET', 'POST'])
def waf_custom_builder():
    if not req(): return jsonify({'ok': False}), 401
    rules = _load_json_file(_custom_json(), [])
    if request.method == 'GET':
        return jsonify({'ok': True, 'rules': rules, 'fields': sorted(_CUSTOM_FIELDS)})
    missing = _waf_engine_missing()
    if missing: return jsonify({'ok': False, 'error': missing}), 400
    ok, n = _validate_custom(request.get_json() or {})
    if not ok: return jsonify({'ok': False, 'error': n}), 400
    if any(c['field'] == 'country' for c in n['conditions']) and (_modsec_target() is None or not _geo_db_present()):
        return jsonify({'ok': False, 'error': 'Country conditions need ModSecurity with a GeoIP database installed.'}), 400
    import secrets as _s
    n['id'] = 'cr_' + _s.token_hex(4)
    rules.append(n)
    saved, err = _commit_model(_custom_json(), rules,
                               lambda: _write_generated(_custom_conf(), _compile_custom_text(rules)))
    if not saved: return jsonify({'ok': False, 'error': f'config test failed, reverted: {err}'}), 400
    return jsonify({'ok': True, 'rule': n})


@security_bp.route('/api/security/waf/custom-rules-builder/<rid>', methods=['DELETE'])
def waf_custom_delete(rid):
    if not req(): return jsonify({'ok': False}), 401
    before = _load_json_file(_custom_json(), [])
    rules = [r for r in before if r.get('id') != rid]
    if len(rules) == len(before):
        return jsonify({'ok': False, 'error': 'Rule not found'}), 404
    saved, err = _commit_model(_custom_json(), rules,
                               lambda: _write_generated(_custom_conf(), _compile_custom_text(rules)))
    if not saved: return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok': True})


@security_bp.route('/api/security/waf/lists/export')
def waf_lists_export():
    if not req(): return jsonify({'ok': False}), 401
    return jsonify({'ok': True, 'lists': _load_lists()})


@security_bp.route('/api/security/waf/lists/import', methods=['POST'])
def waf_lists_import():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    incoming = d.get('lists') or {}
    if not isinstance(incoming, dict):
        return jsonify({'ok': False, 'error': 'lists must be an object'}), 400
    mode = d.get('mode', 'merge')
    if mode not in ('merge', 'replace'):
        return jsonify({'ok': False, 'error': 'mode must be merge or replace'}), 400
    cur = _load_lists()
    for k in ('ip_whitelist', 'ip_blacklist', 'ua_blacklist', 'url_blacklist'):
        raw = incoming.get(k) or []
        if not isinstance(raw, list):
            return jsonify({'ok': False, 'error': f'{k} must be a list'}), 400
        vals = [str(x).strip() for x in raw if str(x).strip()]
        if k.startswith('ip_'):
            bad = [v for v in vals if not _valid_ip(v)]
            if bad:
                return jsonify({'ok': False, 'error': f'Invalid IP/CIDR in {k}: {", ".join(bad[:5])}'}), 400
        if mode == 'replace':
            cur[k] = vals
        else:
            cur[k] = sorted(set((cur.get(k) or []) + vals))

    def _apply():
        modsec_ok, modsec_err = _apply_modsec_file(_modsec_lists_conf(), _render_lists_conf(cur),
                                                   _ensure_lists_included)
        caddy_ok, caddy_err = _coraza_sync()
        return _combine_engine_results(modsec_ok, modsec_err, caddy_ok, caddy_err)
    ok, err = _commit_model(_modsec_lists_json(), cur, _apply)
    if not ok:
        return jsonify({'ok': False, 'error': f'config test failed, reverted: {err}'}), 400
    return jsonify({'ok': True, 'lists': cur})


def _ratelimit_json(): return _waf_state_path('vortex-ratelimit.json')


def _validate_ratelimit(r):
    if not isinstance(r, dict): return False, 'rule must be an object'
    name = re.sub(r'[^a-zA-Z0-9_]', '', str(r.get('name') or ''))[:32]
    if not name: return False, 'name required (letters/digits/underscore)'
    url = str(r.get('url') or '/').strip()
    if not url.startswith('/') or re.search(r'[\s;{}"]', url): return False, 'url must be a path starting with /'
    rps_raw = r.get('rps', 10)
    try: rps = int(rps_raw)
    except (ValueError, TypeError): return False, 'rps must be a number'
    if not (1 <= rps <= 100000): return False, 'rps out of range (1-100000)'
    burst_raw = r.get('burst')
    if burst_raw in (None, ''): burst_raw = rps * 2
    try: burst = int(burst_raw)
    except (ValueError, TypeError): return False, 'burst must be a number'
    if not (0 <= burst <= 1000000): return False, 'burst out of range'
    status = str(r.get('status') or '503')
    if status not in _WAF_STATUS_CODES: return False, 'invalid status'
    domain = str(r.get('domain') or '').strip().lower()
    if domain and not _valid_hostname(domain): return False, 'invalid domain'
    return True, {'name': name, 'url': url, 'rps': rps, 'burst': burst, 'status': status,
                  'domain': domain}


def _compile_ratelimit_zones(rules):
    """Generate the http-context limit_req_zone directives (safe in conf.d).
    No http-level limit_req_status here: a second one anywhere else in the
    http context is a duplicate-directive error that takes nginx down; the
    per-rule status goes into the location snippet instead."""
    lines = ['# Auto-generated by VortexPanel WAF (Rate Limit). DO NOT EDIT.']
    seen = set()
    for r in rules:
        ok, n = _validate_ratelimit(r)
        if not ok or n['name'] in seen: continue
        seen.add(n['name'])
        lines.append(f'limit_req_zone $binary_remote_addr zone=vortex_{n["name"]}:10m rate={n["rps"]}r/s;')
    return '\n'.join(lines) + '\n'


def _ratelimit_location_snippet(n):
    """The lines a site's matching location block should carry."""
    return (f'limit_req zone=vortex_{n["name"]} burst={n["burst"]} nodelay; '
            f'limit_req_status {n["status"]};')


def _nginx_present():
    _, _, rc = sh('command -v nginx >/dev/null 2>&1')
    return rc == 0 and os.path.exists('/etc/nginx/nginx.conf')


def _apply_ratelimit(rules):
    """Write the zones file, nginx -t, reload -- or restore the previous
    file. Deleting a zone a site still references fails nginx -t, and the old
    delete path left that broken file in place for the next reload."""
    prev = open(_RATELIMIT_CONF).read() if os.path.exists(_RATELIMIT_CONF) else None
    os.makedirs(os.path.dirname(_RATELIMIT_CONF), exist_ok=True)
    with open(_RATELIMIT_CONF, 'w') as f:
        f.write(_compile_ratelimit_zones(rules))
    out, err, rc = sh('nginx -t 2>&1')
    if rc != 0:
        if prev is not None:
            with open(_RATELIMIT_CONF, 'w') as f: f.write(prev)
        else:
            try: os.unlink(_RATELIMIT_CONF)
            except Exception: pass
        return False, (out or err)
    sh('systemctl reload nginx 2>/dev/null')
    return True, ''


@security_bp.route('/api/security/waf/ratelimit', methods=['GET', 'POST'])
def waf_ratelimit():
    if not req(): return jsonify({'ok': False}), 401
    rules = _load_json_file(_ratelimit_json(), [])
    if request.method == 'GET':
        return jsonify({'ok': True, 'rules': rules, 'nginx': _nginx_present()})
    if not _nginx_present():
        return jsonify({'ok': False, 'error': 'Rate limiting zones are an nginx feature and nginx is not installed.'}), 400
    ok, n = _validate_ratelimit(request.get_json() or {})
    if not ok: return jsonify({'ok': False, 'error': n}), 400
    import secrets as _s
    n['id'] = 'rl_' + _s.token_hex(4)
    n['snippet'] = _ratelimit_location_snippet(n)
    rules = [r for r in rules if r.get('name') != n['name']] + [n]
    ok, err = _commit_model(_ratelimit_json(), rules, lambda: _apply_ratelimit(rules))
    if not ok:
        return jsonify({'ok': False, 'error': f'nginx config test failed, reverted: {err}'}), 400
    warning = ''
    try:
        if 'conf.d/*.conf' not in open('/etc/nginx/nginx.conf').read():
            warning = 'nginx.conf does not include /etc/nginx/conf.d/*.conf, so the zone is not loaded.'
    except Exception:
        pass
    return jsonify({'ok': True, 'rules': rules, 'warning': warning})


@security_bp.route('/api/security/waf/ratelimit/<rid>', methods=['DELETE'])
def waf_ratelimit_delete(rid):
    if not req(): return jsonify({'ok': False}), 401
    before = _load_json_file(_ratelimit_json(), [])
    rules = [r for r in before if r.get('id') != rid]
    if len(rules) == len(before):
        return jsonify({'ok': False, 'error': 'Rule not found'}), 404
    if os.path.exists(_RATELIMIT_CONF) and _nginx_present():
        ok, err = _commit_model(_ratelimit_json(), rules, lambda: _apply_ratelimit(rules))
        if not ok:
            return jsonify({'ok': False, 'error': 'nginx rejected the change (is the zone still used by a site\'s '
                                                  f'limit_req line? remove that first), reverted: {err}'}), 400
    else:
        _write_json_state(_ratelimit_json(), rules)
    return jsonify({'ok': True, 'rules': rules})


def _aggregate_waf(entries):
    """PURE: turn parsed ModSecurity entries into dashboard aggregates."""
    from collections import Counter
    total = len(entries)
    by_ip, by_uri, by_cat, by_hour = Counter(), Counter(), Counter(), Counter()
    for e in entries:
        ip = e.get('ip')
        if ip: by_ip[ip] += 1
        if e.get('uri'): by_uri[e['uri'][:120]] += 1
        by_cat[_categorize_rule(e.get('rule_id'))] += 1
        dt = _entry_datetime(e)
        if dt: by_hour[dt.strftime('%H')] += 1
    timeline = [{'hour': f'{h:02d}', 'count': by_hour.get(f'{h:02d}', 0)} for h in range(24)]
    return {
        'malicious': total,
        'top_attackers': [{'ip': ip, 'count': c} for ip, c in by_ip.most_common(15)],
        'top_uris':      [{'uri': u, 'count': c} for u, c in by_uri.most_common(10)],
        'categories':    [{'name': n, 'count': c} for n, c in by_cat.most_common()],
        'timeline':      timeline,
    }


@security_bp.route('/api/security/waf/overview')
def waf_overview():
    if not req(): return jsonify({'ok': False}), 401
    if not os.path.exists(_modsec_audit()):
        return jsonify({'ok': True, 'exists': False, 'malicious': 0, 'top_attackers': [],
                        'top_uris': [], 'categories': [], 'timeline': [], 'engine': _engine_state()})
    out, _, _ = sh(f'tail -n 2000 "{_modsec_audit()}" 2>/dev/null')
    agg = _aggregate_waf(_parse_modsec_entries(out))
    agg.update({'ok': True, 'exists': True, 'engine': _engine_state(),
                'paranoia': _paranoia_level() if _modsec_installed() else 0,
                'geoip_installed': bool(_geo_db_present())})
    return jsonify(agg)


def _coraza_conf_paths():
    """The four generated SecLang files Caddy's Coraza directives Include.
    Same content as the nginx/Apache copies — regenerated from the same model."""
    return {
        'lists':      os.path.join(CORAZA_DIR, 'vortex-lists.conf'),
        'geo':        os.path.join(CORAZA_DIR, 'vortex-geo.conf'),
        'custom':     os.path.join(CORAZA_DIR, 'vortex-custom.conf'),
        'exceptions': os.path.join(CORAZA_DIR, 'vortex-exceptions.conf'),
    }


def _coraza_present():
    """True only when a Caddy binary that genuinely loads coraza_waf is the
    running binary. The marker is written by the App Store build after it has
    validated the module against the new binary, so this is authoritative even
    though `caddy list-modules` cannot distinguish coraza from the old
    caddy-waf (both are http.handlers.waf)."""
    # Nothing in the panel writes the marker yet, so also identify Coraza by
    # the Go module path compiled into the binary (build-info / --packages),
    # which does tell coraza-caddy apart from fabriziosalmi/caddy-waf.
    out, _, rc = sh('caddy list-modules --packages 2>/dev/null', t=15)
    if rc != 0 or 'http.handlers.waf' not in out:
        return False
    if os.path.exists(CORAZA_MARKER) or 'corazawaf/coraza-caddy' in out:
        return True
    bi, _, _ = sh('caddy build-info 2>/dev/null', t=15)
    return 'corazawaf/coraza-caddy' in bi


def _coraza_directives_block():
    """The per-site coraza_waf block, identical for every site — per-site
    behaviour is already baked into the rules (keyed on SERVER_NAME), so the
    wiring never has to differ between sites. CRS itself is loaded from
    Coraza's own embedded copy via load_owasp_crs; only the VortexPanel files
    are Included from disk. Order mirrors the nginx/Apache main.conf exactly:
    lists (whitelist ruleEngine=Off first) → region/custom → exceptions
    (ctl:ruleRemoveById in phase 1) → CRS setup → CRS rules → engine on."""
    p = _coraza_conf_paths()
    return (
        '    coraza_waf {\n'
        '        load_owasp_crs\n'
        '        directives `\n'
        '        Include @coraza.conf-recommended\n'
        f'        Include {p["lists"]}\n'
        f'        Include {p["geo"]}\n'
        f'        Include {p["custom"]}\n'
        f'        Include {p["exceptions"]}\n'
        '        Include @crs-setup.conf.example\n'
        '        Include @owasp_crs/*.conf\n'
        '        SecRuleEngine On\n'
        '        `\n'
        '    }\n'
    )


def _coraza_compile_all():
    """PURE-ish: build the four files' text from the CURRENT stored model,
    reusing the exact same compile functions the nginx/Apache path uses. No
    rule logic lives here — this is only which model feeds which file."""
    return {
        'lists':      _render_lists_conf(_load_lists()),
        'geo':        _compile_geo_text(_load_json_file(_geo_json(), []), engine='coraza'),
        'custom':     _compile_custom_text(_load_json_file(_custom_json(), []), engine='coraza'),
        'exceptions': _compile_exceptions_text(_load_exceptions()),
    }


def _caddy_configtest():
    """Validate the whole Caddyfile against the running binary. Returns (ok, out)."""
    if not os.path.exists(CADDYFILE):
        return True, ''   # nothing to break yet
    # Exit status only: validate logs JSON lines at INFO level whose text can
    # contain "error"/"invalid" (site names, log fields) on a valid config.
    # Provisioning a large config can take a while -- 10s killed it early.
    out, err, rc = sh(f'caddy validate --config {CADDYFILE} --adapter caddyfile 2>&1', t=90)
    blob = (out or '') + (err or '')
    return rc == 0, blob[-1500:]


def _coraza_sync():
    """Regenerate every Caddy WAF file from the shared model, validate, and
    reload — rolling every file back on a failed validate so a bad change can
    never take Caddy's sites down. No-op (success) when Coraza isn't installed,
    so callers can invoke it unconditionally. Returns (ok, error)."""
    if not _coraza_present():
        return True, ''
    os.makedirs(CORAZA_DIR, exist_ok=True)
    paths   = _coraza_conf_paths()
    text    = _coraza_compile_all()
    backups = {}
    for key, path in paths.items():
        backups[path] = open(path).read() if os.path.exists(path) else None
        with open(path, 'w') as f:
            f.write(text[key])
    ok, out = _caddy_configtest()
    if not ok:
        for path, prev in backups.items():
            if prev is not None:
                with open(path, 'w') as f:
                    f.write(prev)
            else:
                try: os.unlink(path)
                except Exception: pass
        return False, out
    sh('systemctl reload caddy 2>/dev/null')
    return True, ''


def _split_caddy_block(content):
    """Split at the FIRST '{' and its real matching '}' via brace counting —
    the same discipline websites_core._split_site_block uses, kept local so
    this module has no import cycle. Returns (header, inner, trailing) or
    (None, None, None)."""
    start = content.find('{')
    if start == -1:
        return None, None, None
    depth = 0
    for i in range(start, len(content)):
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
            if depth == 0:
                return content[:start+1], content[start+1:i], content[i:]
    return None, None, None


def _caddyfile_has_global_block(content):
    """True if the file opens with a global options block (a bare '{' before
    any site address), rather than a site block (address then '{')."""
    stripped = re.sub(r'(?m)^\s*#.*$', '', content).strip()
    return stripped.startswith('{')


def _ensure_coraza_global_order(content):
    """PURE: guarantee `order coraza_waf first` is present in the global
    options block, adding the block if the Caddyfile has none. Idempotent."""
    if re.search(r'order\s+coraza_waf\s+first', content):
        return content
    if _caddyfile_has_global_block(content):
        header, inner, trailing = _split_caddy_block(content)
        if header is not None:
            return header + '\n    order coraza_waf first' + inner + trailing
    # No global block — prepend one.
    return '{\n    order coraza_waf first\n}\n\n' + content


def _site_has_coraza(content):
    return bool(re.search(r'\bcoraza_waf\s*\{', content))


def _wire_coraza_into_site(content):
    """PURE: insert the coraza_waf block as the first directive inside a Caddy
    site block. Returns (new_content, error). Idempotent — returns the content
    unchanged if the site already has a coraza_waf block."""
    if _site_has_coraza(content):
        return content, ''
    header, inner, trailing = _split_caddy_block(content)
    if header is None:
        return None, 'no balanced site block found'
    return header + '\n' + _coraza_directives_block() + inner + trailing, ''


def _unwire_coraza_from_site(content):
    """PURE: remove a coraza_waf { ... } block from a site config, brace-safe.
    Returns (new_content, changed)."""
    m = re.search(r'[ \t]*coraza_waf\s*\{', content)
    if not m:
        return content, False
    start = content.find('{', m.start())
    depth = 0
    for i in range(start, len(content)):
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
            if depth == 0:
                # swallow one trailing newline for tidiness
                end = i + 1
                if end < len(content) and content[end] == '\n':
                    end += 1
                return content[:m.start()] + content[end:], True
    return content, False


@security_bp.route('/api/security/waf/caddy/status')
def waf_caddy_status():
    """Whether Coraza is the live Caddy engine, which sites carry it, and
    whether Caddy's generated config currently matches the shared model."""
    if not req(): return jsonify({'ok': False}), 401
    present = _coraza_present()
    wired_sites = []
    for fn, fp in _caddy_site_files():
        try:
            if _site_has_coraza(open(fp).read()):
                wired_sites.append(fn.rsplit('.', 1)[0])
        except Exception:
            pass
    in_sync = True
    if present:
        want = _coraza_compile_all()
        for key, path in _coraza_conf_paths().items():
            have = open(path).read() if os.path.exists(path) else ''
            if have != want[key]:
                in_sync = False
                break
    return jsonify({
        'ok': True, 'installed': present, 'engine': 'coraza',
        'wired_sites': wired_sites, 'in_sync': in_sync,
        'shares_model_with': ['nginx', 'apache'],
        'geoip_note': 'Region rules need a Coraza binary built with GeoIP support; '
                      'exceptions, per-site mode, custom rules and lists apply fully.',
    })


@security_bp.route('/api/security/waf/caddy/sync', methods=['POST'])
def waf_caddy_sync():
    """Regenerate Caddy's WAF config from the shared model on demand."""
    if not req(): return jsonify({'ok': False}), 401
    if not _coraza_present():
        return jsonify({'ok': False, 'error': 'Coraza engine is not installed — add it from the App Store (Security → Caddy WAF / Coraza).'}), 400
    ok, err = _coraza_sync()
    if not ok:
        return jsonify({'ok': False, 'error': f'Caddy config test failed, reverted: {err}'}), 400
    return jsonify({'ok': True})


@security_bp.route('/api/security/waf/caddy/site', methods=['POST'])
def waf_caddy_enable_site():
    """Turn the unified WAF on for one Caddy site: ensure the global order
    directive, wire the coraza_waf block in, sync config, validate, reload."""
    if not req(): return jsonify({'ok': False}), 401
    if not _coraza_present():
        return jsonify({'ok': False, 'error': 'Coraza engine is not installed.'}), 400
    domain = ((request.get_json() or {}).get('domain') or '').strip().lower()
    if not _valid_hostname(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    fp = _caddy_site_file(domain)
    if not fp:
        return jsonify({'ok': False, 'error': f'No Caddy site config found for {domain}'}), 404
    # Make sure the generated files exist before a site references them.
    ok, err = _coraza_sync()
    if not ok:
        return jsonify({'ok': False, 'error': f'Config sync failed, reverted: {err}'}), 400
    original = open(fp).read()
    new_site, werr = _wire_coraza_into_site(original)
    if new_site is None:
        return jsonify({'ok': False, 'error': werr}), 400
    prev_caddyfile = open(CADDYFILE).read() if os.path.exists(CADDYFILE) else None
    if prev_caddyfile is not None:
        with open(CADDYFILE, 'w') as f:
            f.write(_ensure_coraza_global_order(prev_caddyfile))
    with open(fp, 'w') as f:
        f.write(new_site)
    ok, out = _caddy_configtest()
    if not ok:
        with open(fp, 'w') as f:
            f.write(original)
        if prev_caddyfile is not None:
            with open(CADDYFILE, 'w') as f:
                f.write(prev_caddyfile)
        return jsonify({'ok': False, 'error': f'Caddy validation failed, reverted: {out}'}), 400
    sh('systemctl reload caddy 2>/dev/null')
    return jsonify({'ok': True, 'domain': domain})


@security_bp.route('/api/security/waf/caddy/site', methods=['DELETE'])
def waf_caddy_disable_site():
    if not req(): return jsonify({'ok': False}), 401
    domain = (request.args.get('domain') or '').strip().lower()
    if not _valid_hostname(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    fp = _caddy_site_file(domain)
    if not fp:
        return jsonify({'ok': False, 'error': f'No Caddy site config found for {domain}'}), 404
    original = open(fp).read()
    new_site, changed = _unwire_coraza_from_site(original)
    if not changed:
        return jsonify({'ok': True, 'message': 'Site was not running the unified WAF'})
    with open(fp, 'w') as f:
        f.write(new_site)
    ok, out = _caddy_configtest()
    if not ok:
        with open(fp, 'w') as f:
            f.write(original)
        return jsonify({'ok': False, 'error': f'Caddy validation failed, reverted: {out}'}), 400
    sh('systemctl reload caddy 2>/dev/null')
    return jsonify({'ok': True, 'domain': domain})