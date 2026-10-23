"""`vortexpanel` - manage the panel from the server's shell (as root).

Installed as /usr/local/bin/vortexpanel by install.sh. Every command works
while the panel is stopped or broken, so it is also the recovery tool:
forgotten password, lost 2FA phone, locked-out IP, unknown login path.
"""
import argparse
import json
import os
import re
import secrets
import shutil
import socket
import string
import subprocess
import sys
import time

INSTALL_DIR = '/opt/vortexpanel'
CONFIG_FILE = os.path.join(INSTALL_DIR, 'config.json')
UNIT = '/etc/systemd/system/vortexpanel.service'
SSL_DIR = os.path.join(INSTALL_DIR, 'ssl')

os.environ.setdefault('VP_NO_INIT', '1')
sys.path.insert(0, INSTALL_DIR)


def sh(cmd, t=60):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
    return r.stdout.strip(), r.stderr.strip(), r.returncode


def die(msg, code=1):
    sys.stdout.flush()
    print(f'Error: {msg}', file=sys.stderr)
    sys.exit(code)


def need_root():
    if os.geteuid() != 0:
        die('run this command as root (sudo vortexpanel ...)')


def load_cfg():
    try:
        return json.load(open(CONFIG_FILE))
    except Exception:
        return {}


def save_cfg(cfg):
    tmp = CONFIG_FILE + '.tmp.cli'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_FILE)


def unit_text():
    try:
        return open(UNIT).read()
    except Exception:
        return ''


def bind():
    m = re.search(r'(?:--bind|-b)\s+(\S+):(\d+)', unit_text())
    return (m.group(1), int(m.group(2))) if m else ('0.0.0.0', 8888)


def scheme():
    return 'https' if '--certfile' in unit_text() else 'http'


def public_ip():
    out, _, _ = sh("ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"src\") print $(i+1)}'")
    if out:
        return out.split()[0]
    out, _, _ = sh("hostname -I 2>/dev/null | awk '{print $1}'")
    return out or 'SERVER-IP'


def health(tries=30):
    import ssl
    import urllib.request
    _, port = bind()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    for i in range(tries):
        for host in ('127.0.0.1', '[::1]'):
            try:
                if op.open(f'{scheme()}://{host}:{port}/api/health', timeout=3).status == 200:
                    return True
            except Exception:
                pass
        time.sleep(1)
    return False


def restart(wait=True):
    sh('systemctl daemon-reload; systemctl restart vortexpanel', t=60)
    if wait:
        ok = health()
        print('Panel is running.' if ok else 'The panel did not answer yet - see: vortexpanel logs')
        return ok
    return True


def creds_mod():
    from panel.routes import auth
    return auth


def rand(n, alphabet=string.ascii_lowercase + string.digits):
    return ''.join(secrets.choice(alphabet) for _ in range(n))


# --- commands --------------------------------------------------------------------
def cmd_info(a):
    cfg = load_cfg()
    _, port = bind()
    path = cfg.get('security_path') or ''
    host = (cfg.get('panel_domain') if cfg.get('panel_domain_enforced') else '') or public_ip()
    try:
        user = json.load(open(os.path.join(INSTALL_DIR, 'credentials.json'))).get('username', 'admin')
    except Exception:
        user = '?'
    active = sh('systemctl is-active vortexpanel')[0]
    ver = ''
    try:
        from panel import updater
        ver = updater.current_version()
    except Exception:
        pass
    print(f'VortexPanel {ver}  ({active})')
    print(f'  Address:   {scheme()}://{host}:{port}/{path}')
    print(f'  Username:  {user}')
    pw_file = os.path.join(INSTALL_DIR, 'admin_password.txt')
    if os.path.exists(pw_file):
        print(f'  Password:  {open(pw_file).read().strip()}   (initial password, removed after the first sign-in)')
    else:
        print('  Password:  (set by you)  -  forgot it? vortexpanel reset-password')
    if scheme() == 'https' and 'panel.crt' in unit_text():
        print('  HTTPS:     self-signed certificate - your browser shows a warning once; '
              'add a domain and Let\'s Encrypt in Settings > Panel SSL to remove it')
    if cfg.get('allowed_ips'):
        print(f'  Allowed IPs: {", ".join(cfg["allowed_ips"])}   (vortexpanel allow-ip clear)')
    print('Commands: vortexpanel --help')


def cmd_reset_password(a):
    need_root()
    auth = creds_mod()
    pw = a.password or rand(16, string.ascii_letters + string.digits)
    if len(pw) < 8:
        die('the password must be at least 8 characters')
    target = a.user
    if target:
        from panel import users as U
        u = U.find_user_by_name(target)
        if not u:
            creds = auth.get_credentials()
            if creds.get('username') != target:
                die(f'no account named {target}')
            target = None
        else:
            U.update_user(u['id'], {'password_hash': auth._hash_password(pw),
                                    'session_version': secrets.token_hex(8)})
    if not target:
        creds = auth.get_credentials()
        creds['password_hash'] = auth._hash_password(pw)
        creds['session_version'] = secrets.token_hex(8)
        auth.save_credentials(creds)
        target = creds.get('username', 'admin')
    auth._clear_attempts('acct:admin')
    print(f'New password for {target}: {pw}')
    print('All existing sessions of this account were signed out.')


def cmd_username(a):
    need_root()
    auth = creds_mod()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._@-]{2,63}', a.name):
        die('3-64 characters: letters, digits, dot, dash, underscore or @')
    creds = auth.get_credentials()
    creds['username'] = a.name
    creds['session_version'] = secrets.token_hex(8)
    auth.save_credentials(creds)
    print(f'Administrator username is now: {a.name}')


def cmd_disable_2fa(a):
    need_root()
    auth = creds_mod()
    if a.user:
        from panel import users as U
        u = U.find_user_by_name(a.user)
        if u:
            U.update_user(u['id'], {'totp_secret': None, 'totp_enabled': None, 'totp_last_step': None,
                                    'backup_codes': None, 'session_version': secrets.token_hex(8)})
            print(f'Two-factor authentication turned off for {a.user}.')
            return
    creds = auth.get_credentials()
    for k in ('totp_secret', 'totp_enabled', 'totp_last_step', 'backup_codes'):
        creds.pop(k, None)
    creds['session_version'] = secrets.token_hex(8)
    auth.save_credentials(creds)
    print(f'Two-factor authentication turned off for {creds.get("username", "admin")}. '
          'Turn it on again in Settings > Security.')


def port_free(port):
    for fam, addr in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
        s = socket.socket(fam, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((addr, port))
        except OSError as e:
            if fam == socket.AF_INET6 and e.errno in (97, 99):   # no IPv6
                continue
            return False
        finally:
            s.close()
    return True


def set_unit(host=None, port=None, tls=None):
    """Rewrite the unit's --bind / --certfile / --keyfile."""
    text = unit_text()
    if not text:
        die('the vortexpanel service is not installed')
    h, p = bind()
    host = host or h
    port = port or p
    text = re.sub(r'(--bind|-b)\s+\S+:\d+', f'--bind {host}:{port}', text, count=1)
    if tls is not None:
        text = re.sub(r'\s*--certfile\s+\S+', '', text)
        text = re.sub(r'\s*--keyfile\s+\S+', '', text)
        if tls:
            crt, key = tls
            text = re.sub(r'(--bind\s+\S+:\d+)', rf'\1 --certfile {crt} --keyfile {key}', text, count=1)
    with open(UNIT + '.tmp', 'w') as f:
        f.write(text)
    os.replace(UNIT + '.tmp', UNIT)


def firewall_open(port):
    sh(f'command -v ufw >/dev/null && ufw allow {port}/tcp')
    sh(f'command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1 && '
       f'firewall-cmd --permanent --add-port={port}/tcp && firewall-cmd --reload')


def cmd_port(a):
    need_root()
    port = a.port
    if not 1024 <= port <= 65535:
        die('the port must be between 1024 and 65535')
    _, old = bind()
    if port == old:
        print(f'The panel already uses port {port}.')
        return
    if not port_free(port):
        die(f'port {port} is already in use')
    old_unit = unit_text()
    set_unit(port=port)
    firewall_open(port)
    if not restart():
        with open(UNIT, 'w') as f:
            f.write(old_unit)
        restart()
        die(f'the panel did not start on port {port}; port {old} was restored')
    cfg = load_cfg()
    cfg['port'] = port
    save_cfg(cfg)
    print(f'The panel now listens on port {port}. Remove the old rule when you no longer need it: '
          f'ufw delete allow {old}/tcp')
    cmd_info(a)


def cmd_path(a):
    need_root()
    cfg = load_cfg()
    v = (a.value or '').strip().strip('/')
    if v in ('off', 'none', 'disable'):
        v = ''
    elif v in ('', 'random'):
        v = rand(8)
    if v and not re.fullmatch(r'[A-Za-z0-9_-]{4,64}', v):
        die('4-64 characters: letters, digits, dash or underscore')
    cfg['security_path'] = v
    save_cfg(cfg)
    print('Login path turned off.' if not v else f'Login path is now /{v}')
    cmd_info(a)


def cmd_domain(a):
    need_root()
    cfg = load_cfg()
    if a.value in ('off', 'none', ''):
        cfg['panel_domain'] = ''
        cfg['panel_domain_enforced'] = False
        save_cfg(cfg)
        print('The panel answers on any address again.')
    else:
        die('set the panel domain in Settings > Panel; here it can only be turned off: vortexpanel domain off')


def gen_selfsigned():
    os.makedirs(SSL_DIR, mode=0o700, exist_ok=True)
    ip = public_ip()
    san = f'IP:{ip}' if re.fullmatch(r'[0-9.]+', ip) else 'DNS:localhost'
    out, err, rc = sh(f'openssl req -x509 -nodes -days 3650 -newkey rsa:2048 '
                      f'-keyout {SSL_DIR}/panel.key.new -out {SSL_DIR}/panel.crt.new '
                      f'-subj "/CN={ip}/O=VortexPanel/OU=Panel" -addext "subjectAltName={san}" 2>&1')
    if rc != 0:
        die('openssl failed: ' + (out or err)[-300:])
    os.chmod(f'{SSL_DIR}/panel.key.new', 0o600)
    os.replace(f'{SSL_DIR}/panel.key.new', f'{SSL_DIR}/panel.key')
    os.replace(f'{SSL_DIR}/panel.crt.new', f'{SSL_DIR}/panel.crt')
    return f'{SSL_DIR}/panel.crt', f'{SSL_DIR}/panel.key'


def cmd_ssl(a):
    need_root()
    cfg = load_cfg()
    old_unit = unit_text()
    if a.mode == 'off':
        set_unit(tls=False)
        cfg['ssl_enabled'] = False
        msg = 'HTTPS turned off. The panel now uses plain HTTP - only do this behind a VPN or SSH tunnel.'
    else:
        crt, key = gen_selfsigned()
        set_unit(tls=(crt, key))
        cfg['ssl_enabled'] = True
        msg = 'HTTPS turned on with a new self-signed certificate.'
    if not restart():
        with open(UNIT, 'w') as f:
            f.write(old_unit)
        restart()
        die('the panel did not start; the previous setting was restored')
    save_cfg(cfg)
    print(msg)
    cmd_info(a)


def cmd_allow_ip(a):
    need_root()
    cfg = load_cfg()
    if a.action == 'clear':
        cfg['allowed_ips'] = []
        print('IP allowlist cleared: the panel accepts every address again.')
    elif a.action == 'add' and a.ip:
        import ipaddress
        try:
            ipaddress.ip_network(a.ip, strict=False)
        except ValueError:
            die(f'not an IP address or CIDR: {a.ip}')
        cfg.setdefault('allowed_ips', [])
        if a.ip not in cfg['allowed_ips']:
            cfg['allowed_ips'].append(a.ip)
        print(f'Added {a.ip}. Allowed: {", ".join(cfg["allowed_ips"])}')
    else:
        print('Allowed IPs: ' + (', '.join(cfg.get('allowed_ips') or []) or 'any'))
        return
    save_cfg(cfg)


def cmd_unlock(a):
    need_root()
    lf = os.path.join(INSTALL_DIR, 'lockout.json')
    try:
        os.remove(lf)
    except FileNotFoundError:
        pass
    print('All sign-in lockouts were cleared.')
    if sh('systemctl is-active vortexpanel')[0] == 'active':
        restart()     # clears the in-memory counters too


def cmd_service(a):
    need_root()
    if a.cmd == 'restart':
        restart()
    elif a.cmd == 'start':
        sh('systemctl start vortexpanel')
        print('Panel is running.' if health() else 'The panel did not answer - see: vortexpanel logs')
    elif a.cmd == 'stop':
        sh('systemctl stop vortexpanel')
        print('Panel stopped. Websites and services keep running.')
    elif a.cmd == 'status':
        os.system('systemctl status vortexpanel --no-pager -n 0')
        print('Health check:', 'OK' if health(3) else 'not answering')


def cmd_logs(a):
    os.system(f'journalctl -u vortexpanel -n {int(a.lines)} --no-pager; '
              f'tail -n {int(a.lines)} /var/log/vortexpanel/error.log 2>/dev/null')


def cmd_update(a):
    need_root()
    from panel import updater
    if a.check:
        c = updater.check()
        print(f'Installed: {c["current"]}   Latest release: {c["latest"]}')
        print('An update is available: vortexpanel update' if c.get('has_update') else 'Up to date.')
        return
    try:
        v = updater.run_update(a.version or '', log=lambda m: print(m, flush=True), wait_restart=True,
                               force_unsigned=a.allow_unsigned)
        print(f'VortexPanel {v} is installed and running.')
    except Exception as e:
        die(str(e))


def cmd_rollback(a):
    need_root()
    from panel import updater
    try:
        v = updater.rollback(log=lambda m: print(m, flush=True))
        print(f'Rolled back to {v or "the previous version"}.')
    except Exception as e:
        die(str(e))


def cmd_backup(a):
    need_root()
    from panel import panelbackup
    path = panelbackup.create(note='cli')
    print(f'Panel settings backup: {path}')


def cmd_users(a):
    from panel import users as U
    auth = creds_mod()
    c = auth.get_credentials()
    print(f'{c.get("username", "admin"):<24} admin  (primary)')
    for u in U.list_users():
        print(f'{u["username"]:<24} {u["role"]:<6} {"disabled" if u.get("disabled") else ""} '
              f'{",".join(u.get("sites") or [])}')


def cmd_plugins(a):
    from panel import plugins as P
    act = a.action
    if act == 'list':
        off = P.disabled_ids()
        found = P.discover()
        if P.safe_mode():
            print('Safe mode is ON: the panel loads no plugins (vortexpanel plugins safe-mode off).')
        if not found:
            print(f'No plugins in {P.PLUGINS_DIR}')
        cv = P.core_version()
        for pid, d, man, err in found:
            man = man or {}
            st = 'error: ' + err if err else ('disabled' if pid in off else
                 ('incompatible: needs ' + man.get('requires_core', '') if not P.version_matches(cv, man.get('requires_core', '')) else 'enabled'))
            print(f'{pid:<16} {man.get("version", ""):<10} {st}')
        return
    if act in ('enable', 'disable'):
        need_root()
        if not a.id:
            die('Usage: vortexpanel plugins ' + act + ' <id>')
        if a.id not in [x[0] for x in P.discover()]:
            die(f'No plugin "{a.id}" in {P.PLUGINS_DIR}')
        P.set_enabled(a.id, act == 'enable')
        print(f'Plugin {a.id} {act}d. Restarting the panel...', flush=True)
        os.system('systemctl restart vortexpanel')
        return
    if act == 'safe-mode':
        need_root()
        on = (a.id or 'on') == 'on'
        P.set_safe_mode(on)
        print(f'Safe mode {"on: plugins are not loaded" if on else "off"}. Restarting the panel...', flush=True)
        os.system('systemctl restart vortexpanel')


def cmd_app_versions(a):
    from panel import appversions
    st = appversions.refresh(force=True) if a.action == 'refresh' else appversions.status()
    if st.get('in_use'):
        print(f"Tested versions list #{st['serial']} ({st.get('issued', '')[:10]}) from {st.get('server')}")
    else:
        print('Using the built-in App Store versions (no tested list yet).')
    if st.get('error'):
        print('Last check: ' + st['error'])


def cmd_app_test(a):
    from panel import apptest
    sys.exit(apptest.main(a.rest or ['status']))


def main(argv=None):
    p = argparse.ArgumentParser(prog='vortexpanel', description='Manage VortexPanel from the shell.')
    sp = p.add_subparsers(dest='command')
    sp.add_parser('info', help='show the address, username and status (default)').set_defaults(fn=cmd_info)
    x = sp.add_parser('reset-password', help='set a new password (random if none is given)')
    x.add_argument('password', nargs='?')
    x.add_argument('--user', help='another panel account (default: the administrator)')
    x.set_defaults(fn=cmd_reset_password)
    x = sp.add_parser('username', help='change the administrator username')
    x.add_argument('name')
    x.set_defaults(fn=cmd_username)
    x = sp.add_parser('disable-2fa', help='turn off two-factor authentication (lost phone)')
    x.add_argument('--user')
    x.set_defaults(fn=cmd_disable_2fa)
    x = sp.add_parser('port', help='move the panel to another port')
    x.add_argument('port', type=int)
    x.set_defaults(fn=cmd_port)
    x = sp.add_parser('path', help='set the login path: a value, "random" or "off"')
    x.add_argument('value', nargs='?', default='random')
    x.set_defaults(fn=cmd_path)
    x = sp.add_parser('domain', help='"off" removes the panel domain restriction')
    x.add_argument('value')
    x.set_defaults(fn=cmd_domain)
    x = sp.add_parser('ssl', help='"self" = new self-signed certificate, "off" = plain HTTP')
    x.add_argument('mode', choices=['self', 'off'])
    x.set_defaults(fn=cmd_ssl)
    x = sp.add_parser('allow-ip', help='show, add to or clear the IP allowlist')
    x.add_argument('action', nargs='?', choices=['list', 'add', 'clear'], default='list')
    x.add_argument('ip', nargs='?')
    x.set_defaults(fn=cmd_allow_ip)
    sp.add_parser('unlock', help='clear sign-in lockouts').set_defaults(fn=cmd_unlock)
    sp.add_parser('users', help='list panel accounts').set_defaults(fn=cmd_users)
    for c in ('restart', 'start', 'stop', 'status'):
        x = sp.add_parser(c, help=f'{c} the panel service')
        x.set_defaults(fn=cmd_service, cmd=c)
    x = sp.add_parser('logs', help='show recent panel logs')
    x.add_argument('-n', '--lines', default=50)
    x.set_defaults(fn=cmd_logs)
    x = sp.add_parser('update', help='install the latest signed release')
    x.add_argument('version', nargs='?')
    x.add_argument('--check', action='store_true', help='only check')
    x.add_argument('--allow-unsigned', action='store_true', help='install even if the signature cannot be verified')
    x.set_defaults(fn=cmd_update)
    sp.add_parser('rollback', help='go back to the version before the last update').set_defaults(fn=cmd_rollback)
    sp.add_parser('backup', help='back up the panel settings and accounts').set_defaults(fn=cmd_backup)
    x = sp.add_parser('plugins', help='list, enable or disable plugins; "safe-mode on|off" loads none')
    x.add_argument('action', nargs='?', choices=['list', 'enable', 'disable', 'safe-mode'], default='list')
    x.add_argument('id', nargs='?')
    x.set_defaults(fn=cmd_plugins)
    x = sp.add_parser('app-versions', help='tested App Store versions from the licence server: status or refresh')
    x.add_argument('action', nargs='?', choices=['status', 'refresh'], default='status')
    x.set_defaults(fn=cmd_app_versions)
    x = sp.add_parser('app-test', help='App Store test runner (test servers only): setup | run | status')
    x.add_argument('rest', nargs=argparse.REMAINDER)
    x.set_defaults(fn=cmd_app_test)
    a = p.parse_args(argv)
    if not getattr(a, 'fn', None):
        a = p.parse_args(['info'])
    a.fn(a)


if __name__ == '__main__':
    main()
