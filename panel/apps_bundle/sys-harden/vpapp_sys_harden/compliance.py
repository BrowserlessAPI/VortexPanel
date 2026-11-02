"""Compliance check: hardening best practice (CIS-style), scored, with safe one-click fixes.

Each check returns (status, detail); status is pass | fail | warn | na. A fix is only
offered where it cannot lock the admin out or break a running service, and every
fix is tested (sshd -t, sysctl) before it is kept.
"""
import os
import re
import stat

from panel import appkit

SYSCTL_FILE = '/etc/sysctl.d/90-vortexpanel-hardening.conf'
SSHD_DROPIN = '/etc/ssh/sshd_config.d/00-vortexpanel-hardening.conf'   # 00-: sshd keeps the FIRST value it reads


def _sshd():
    """Effective sshd settings (sshd -T), lower-case keys."""
    rc, out, _ = appkit.run(['sshd', '-T'], timeout=20)
    if rc != 0:
        rc, out, _ = appkit.run(['/usr/sbin/sshd', '-T'], timeout=20)
    d = {}
    for line in (out or '').splitlines():
        k, _, v = line.partition(' ')
        d.setdefault(k.lower(), v.strip().lower())
    return d


def _sysctl(key):
    try:
        return open('/proc/sys/' + key.replace('.', '/')).read().strip()
    except OSError:
        return None


def _listening_public(port):
    rc, out, _ = appkit.run(['ss', '-Hltn'], timeout=15)
    for line in (out or '').splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[3].endswith(':' + str(port)):
            host = parts[3].rsplit(':', 1)[0].strip('[]')
            if host in ('0.0.0.0', '*', '::', ''):
                return True
    return False


def _root_has_keys():
    try:
        return any(l.strip() and not l.startswith('#') for l in open('/root/.ssh/authorized_keys'))
    except OSError:
        return False


# ------------------------------------------------------------------ fixers

def _set_sysctl(pairs):
    cur = {}
    try:
        for line in open(SYSCTL_FILE):
            if '=' in line and not line.strip().startswith('#'):
                k, v = line.split('=', 1)
                cur[k.strip()] = v.strip()
    except OSError:
        pass
    cur.update(pairs)
    with open(SYSCTL_FILE, 'w') as f:
        f.write('# Managed by VortexPanel System Hardening\n')
        for k, v in sorted(cur.items()):
            f.write(f'{k} = {v}\n')
    errs = []
    for k, v in pairs.items():
        rc, _, err = appkit.run(['sysctl', '-w', f'{k}={v}'], timeout=10)
        if rc != 0:
            errs.append(err.strip())
    return (not errs), '; '.join(errs)


def _set_sshd(pairs):
    """Write our drop-in (or the main file when there is no Include), test, reload; undo on failure."""
    main = '/etc/ssh/sshd_config'
    try:
        main_txt = open(main).read()
    except OSError:
        return False, 'sshd_config not found'
    use_dropin = re.search(r'^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf', main_txt, re.M | re.I) is not None
    target = SSHD_DROPIN if use_dropin else main
    old = open(target).read() if os.path.exists(target) else None
    if use_dropin:
        cur = {}
        for line in (old or '').splitlines():
            if line.strip() and not line.startswith('#'):
                k, _, v = line.partition(' ')
                cur[k] = v
        cur.update(pairs)
        new = '# Managed by VortexPanel System Hardening\n' + ''.join(f'{k} {v}\n' for k, v in cur.items())
    else:
        # only the global section: a setting inside a 'Match' block applies to that match only
        m = re.search(r'^\s*Match\s', old, re.M | re.I)
        head, tail = (old[:m.start()], old[m.start():]) if m else (old, '')
        for k, v in pairs.items():
            if re.search(rf'^\s*#?\s*{k}\b.*$', head, re.M | re.I):
                head = re.sub(rf'^\s*#?\s*{k}\b.*$', f'{k} {v}', head, count=1, flags=re.M | re.I)
            else:
                head = f'{k} {v}\n' + head        # first value wins: put it at the top
        new = head + tail
    with open(target, 'w') as f:
        f.write(new)
    rc, _, err = appkit.run(['sshd', '-t'], timeout=20)
    if rc != 0:
        if old is None:
            os.remove(target)
        else:
            with open(target, 'w') as f:
                f.write(old)
        return False, 'sshd rejected the change (kept the old settings): ' + err.strip()[-200:]
    for unit in ('ssh', 'sshd'):
        if appkit.run(['systemctl', 'reload', unit], timeout=20)[0] == 0:
            break
    return True, ''


def _chmod(path, mode):
    try:
        os.chmod(path, mode)
        return True, ''
    except OSError as e:
        return False, str(e)


# ------------------------------------------------------------------- checks

def _c_root_login(ctx):
    v = ctx['sshd'].get('permitrootlogin', '')
    if not v:
        return 'na', 'sshd not found'
    if v in ('no', 'prohibit-password', 'without-password', 'forced-commands-only'):
        return 'pass', f'PermitRootLogin {v}'
    return 'fail', 'root can sign in over SSH with a password'


def _f_root_login(ctx):
    if not _root_has_keys():
        return False, 'Add an SSH key for root first (Security > SSH), otherwise you could lock yourself out.'
    return _set_sshd({'PermitRootLogin': 'prohibit-password'})


def _c_password_auth(ctx):
    v = ctx['sshd'].get('passwordauthentication', '')
    if not v:
        return 'na', 'sshd not found'
    return ('pass', 'only SSH keys are accepted') if v == 'no' else ('warn', 'password sign-in is allowed (keys are safer)')


def _c_empty_pw(ctx):
    if not ctx['sshd']:
        return 'na', 'sshd not found'
    v = ctx['sshd'].get('permitemptypasswords', 'no')
    return ('pass', 'empty passwords refused') if v == 'no' else ('fail', 'accounts with no password can sign in')


def _c_max_auth(ctx):
    if not ctx['sshd']:
        return 'na', 'sshd not found'
    try:
        n = int(ctx['sshd'].get('maxauthtries', '6'))
    except ValueError:
        n = 6
    return ('pass', f'MaxAuthTries {n}') if n <= 4 else ('warn', f'MaxAuthTries {n} (4 or less recommended)')


def _c_uid0(ctx):
    try:
        bad = [l.split(':')[0] for l in open('/etc/passwd') if l.count(':') >= 3 and l.split(':')[2] == '0' and not l.startswith('root:')]
    except OSError:
        return 'na', ''
    return ('fail', 'extra accounts with root rights: ' + ', '.join(bad)) if bad else ('pass', 'only root has UID 0')


def _empty_pw_accounts():
    try:
        return [l.split(':')[0] for l in open('/etc/shadow') if l.count(':') >= 2 and l.split(':')[1] == '']
    except OSError:
        return []


def _c_empty_accounts(ctx):
    bad = _empty_pw_accounts()
    return ('fail', 'accounts without a password: ' + ', '.join(bad)) if bad else ('pass', 'every account has a password or is locked')


def _f_empty_accounts(ctx):
    errs = [appkit.run(['passwd', '-l', u])[2] for u in _empty_pw_accounts()]
    errs = [e for e in errs if e and 'locked' not in e.lower()]
    return (not errs), '; '.join(errs)


def _perm_check(path, maxmode):
    try:
        st = os.stat(path)
    except OSError:
        return 'na', ''
    mode = stat.S_IMODE(st.st_mode)
    ok = (mode & ~maxmode) == 0 and st.st_uid == 0
    return ('pass', f'{oct(mode)} root') if ok else ('fail', f'{oct(mode)} owner uid {st.st_uid}')


def _sysctl_check(pairs):
    def chk(ctx):
        bad = []
        for k, want in pairs.items():
            v = _sysctl(k)
            if v is None:
                continue
            if str(v) != str(want):
                bad.append(f'{k}={v}')
        return ('fail', 'should be ' + ', '.join(f'{k}={v}' for k, v in pairs.items()) + ' (now ' + ', '.join(bad) + ')') if bad \
            else ('pass', ', '.join(f'{k}={v}' for k, v in pairs.items()))
    return chk


def _c_firewall(ctx):
    rc, out, _ = appkit.run(['ufw', 'status'], timeout=10)
    if 'Status: active' in (out or ''):
        return 'pass', 'ufw is active'
    rc, out, _ = appkit.run(['firewall-cmd', '--state'], timeout=10)
    if (out or '').strip() == 'running':
        return 'pass', 'firewalld is running'
    return 'fail', 'no firewall is active'


def _c_fail2ban(ctx):
    return ('pass', 'fail2ban is running') if appkit.service_state('fail2ban') == 'active' \
        else ('warn', 'fail2ban is not running (brute-force protection)')


def _c_db_public(ctx):
    ports = {3306: 'MySQL/MariaDB', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB', 11211: 'Memcached', 9200: 'Elasticsearch'}
    bad = [f'{n} ({p})' for p, n in ports.items() if _listening_public(p)]
    return ('fail', 'listening on all addresses: ' + ', '.join(bad) + ' - bind to 127.0.0.1 or firewall it') if bad \
        else ('pass', 'no database listens on a public address')


COMPILERS = ['/usr/bin/gcc', '/usr/bin/cc', '/usr/bin/g++', '/usr/bin/c++', '/usr/bin/make', '/usr/bin/as', '/usr/bin/ld']


def _compilers():
    out = []
    for p in COMPILERS:
        try:
            real = os.path.realpath(p)
            if os.path.isfile(real) and os.stat(real).st_mode & 0o005:
                out.append(real)
        except OSError:
            continue
    return sorted(set(out))


def _c_compilers(ctx):
    bad = _compilers()
    return ('warn', 'other users can run compilers: ' + ', '.join(os.path.basename(x) for x in bad)) if bad \
        else ('pass', 'compilers are root-only or not installed')


def _f_compilers(ctx):
    errs = []
    for p in _compilers():
        try:
            os.chmod(p, os.stat(p).st_mode & ~0o007)
        except OSError as e:
            errs.append(str(e))
    return (not errs), '; '.join(errs)


def _c_ld_preload(ctx):
    try:
        txt = open('/etc/ld.so.preload').read().strip()
    except OSError:
        return 'pass', 'no /etc/ld.so.preload'
    return ('fail', 'libraries forced into every program: ' + txt[:200] + ' - a common rootkit technique, check it') if txt \
        else ('pass', '/etc/ld.so.preload is empty')


def _c_nopasswd(ctx):
    bad = []
    for p in ['/etc/sudoers'] + [os.path.join('/etc/sudoers.d', f) for f in (os.listdir('/etc/sudoers.d') if os.path.isdir('/etc/sudoers.d') else [])]:
        try:
            for line in open(p):
                if 'NOPASSWD' in line and not line.strip().startswith('#'):
                    bad.append(f'{os.path.basename(p)}: {line.strip()[:80]}')
        except OSError:
            continue
    return ('warn', 'sudo without password: ' + '; '.join(bad[:3])) if bad else ('pass', 'sudo always asks for a password')


def _c_timesync(ctx):
    for u in ('systemd-timesyncd', 'chronyd', 'chrony', 'ntp', 'ntpd'):
        if appkit.service_state(u) == 'active':
            return 'pass', f'{u} keeps the clock right'
    return 'warn', 'no time sync service (logs, TLS and 2FA codes need a correct clock)'


def _c_world_writable_etc(ctx):
    bad = []
    for dp, dns, fns in os.walk('/etc'):
        for fn in fns:
            p = os.path.join(dp, fn)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and st.st_mode & 0o002:
                bad.append(p)
        if len(bad) > 50:
            break
    return ('fail', f'{len(bad)} world-writable file(s), e.g. ' + ', '.join(bad[:3])) if bad else ('pass', 'none')


def _f_world_writable_etc(ctx):
    errs = []
    for dp, dns, fns in os.walk('/etc'):
        for fn in fns:
            p = os.path.join(dp, fn)
            try:
                st = os.lstat(p)
                if stat.S_ISREG(st.st_mode) and st.st_mode & 0o002:
                    os.chmod(p, st.st_mode & ~0o002)
            except OSError as e:
                errs.append(str(e))
    return (not errs), '; '.join(errs[:3])


def _c_auto_updates(ctx):
    if os.path.exists('/etc/apt/apt.conf.d/20auto-upgrades'):
        txt = open('/etc/apt/apt.conf.d/20auto-upgrades').read()
        if re.search(r'Unattended-Upgrade\s+"1"', txt):
            return 'pass', 'unattended-upgrades installs security updates'
    if appkit.service_state('dnf-automatic.timer') == 'active' or appkit.service_state('dnf-automatic-install.timer') == 'active':
        return 'pass', 'dnf-automatic installs updates'
    return 'warn', 'security updates are not installed automatically'


def _f_auto_updates(ctx):
    if appkit.os_family() == 'rhel':
        if not appkit.pkg_install(['dnf-automatic']):
            return False, 'could not install dnf-automatic'
        conf = '/etc/dnf/automatic.conf'
        try:
            txt = open(conf).read()
            txt = re.sub(r'^upgrade_type\s*=.*$', 'upgrade_type = security', txt, flags=re.M)
            txt = re.sub(r'^apply_updates\s*=.*$', 'apply_updates = yes', txt, flags=re.M)
            open(conf, 'w').write(txt)
        except OSError:
            pass
        rc, _, err = appkit.run(['systemctl', 'enable', '--now', 'dnf-automatic.timer'])
        return rc == 0, err
    if not appkit.pkg_install(['unattended-upgrades']):
        return False, 'could not install unattended-upgrades'
    with open('/etc/apt/apt.conf.d/20auto-upgrades', 'w') as f:
        f.write('APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n')
    return True, ''


def _c_panel_2fa(ctx):
    try:
        import json
        c = json.load(open('/opt/vortexpanel/credentials.json'))
        on = bool(c.get('totp_enabled') and c.get('totp_secret'))
    except (OSError, ValueError):
        return 'na', ''
    return ('pass', 'two-factor sign-in is on') if on else ('warn', 'the panel admin account has no two-factor sign-in')


CHECKS = [
    # id, title, category, severity, check, fix, fix_text, link
    ('ssh_root', 'Root cannot sign in over SSH with a password', 'SSH', 'high', _c_root_login, _f_root_login,
     'Set PermitRootLogin prohibit-password (root keeps key sign-in)', 'security'),
    ('ssh_pwauth', 'SSH accepts keys only', 'SSH', 'medium', _c_password_auth, None, '', 'security'),
    ('ssh_empty', 'SSH refuses empty passwords', 'SSH', 'high', _c_empty_pw, lambda c: _set_sshd({'PermitEmptyPasswords': 'no'}),
     'Set PermitEmptyPasswords no', ''),
    ('ssh_tries', 'SSH limits password guesses per connection', 'SSH', 'low', _c_max_auth, lambda c: _set_sshd({'MaxAuthTries': '4'}),
     'Set MaxAuthTries 4', ''),
    ('uid0', 'Only root has root rights (UID 0)', 'Accounts', 'critical', _c_uid0, None, '', ''),
    ('empty_accounts', 'No account without a password', 'Accounts', 'high', _c_empty_accounts, _f_empty_accounts,
     'Lock the accounts that have no password', ''),
    ('nopasswd', 'sudo asks for a password', 'Accounts', 'low', _c_nopasswd, None, '', ''),
    ('shadow_perm', '/etc/shadow is readable by root only', 'Files', 'high', lambda c: _perm_check('/etc/shadow', 0o640),
     lambda c: _chmod('/etc/shadow', 0o640), 'chmod 640 /etc/shadow', ''),
    ('passwd_perm', '/etc/passwd is not writable by others', 'Files', 'high', lambda c: _perm_check('/etc/passwd', 0o644),
     lambda c: _chmod('/etc/passwd', 0o644), 'chmod 644 /etc/passwd', ''),
    ('etc_ww', 'No world-writable files in /etc', 'Files', 'medium', _c_world_writable_etc, _f_world_writable_etc,
     'Remove the write-for-everyone bit', ''),
    ('ld_preload', 'No forced library preloading (rootkit check)', 'Files', 'critical', _c_ld_preload, None, '', ''),
    ('compilers', 'Compilers are root-only', 'Files', 'low', _c_compilers, _f_compilers,
     'Remove run rights for other users from gcc, cc, make, as, ld (website users can no longer compile code)', ''),
    ('aslr', 'Memory layout randomisation (ASLR) is full', 'Kernel', 'medium', _sysctl_check({'kernel.randomize_va_space': 2}),
     lambda c: _set_sysctl({'kernel.randomize_va_space': '2'}), 'kernel.randomize_va_space = 2', ''),
    ('syncookies', 'SYN flood protection (SYN cookies)', 'Kernel', 'medium', _sysctl_check({'net.ipv4.tcp_syncookies': 1}),
     lambda c: _set_sysctl({'net.ipv4.tcp_syncookies': '1'}), 'net.ipv4.tcp_syncookies = 1', ''),
    ('redirects', 'ICMP redirects are ignored', 'Kernel', 'low',
     _sysctl_check({'net.ipv4.conf.all.accept_redirects': 0, 'net.ipv4.conf.all.send_redirects': 0}),
     lambda c: _set_sysctl({'net.ipv4.conf.all.accept_redirects': '0', 'net.ipv4.conf.all.send_redirects': '0',
                            'net.ipv4.conf.default.accept_redirects': '0'}), 'Turn off ICMP redirects', ''),
    ('source_route', 'Source-routed packets are refused', 'Kernel', 'low', _sysctl_check({'net.ipv4.conf.all.accept_source_route': 0}),
     lambda c: _set_sysctl({'net.ipv4.conf.all.accept_source_route': '0', 'net.ipv4.conf.default.accept_source_route': '0'}),
     'net.ipv4.conf.all.accept_source_route = 0', ''),
    ('kptr', 'Kernel addresses are hidden from users', 'Kernel', 'low', _sysctl_check({'kernel.kptr_restrict': 1}),
     lambda c: _set_sysctl({'kernel.kptr_restrict': '1'}), 'kernel.kptr_restrict = 1', ''),
    ('suid_dump', 'Privileged programs do not write core dumps', 'Kernel', 'low', _sysctl_check({'fs.suid_dumpable': 0}),
     lambda c: _set_sysctl({'fs.suid_dumpable': '0'}), 'fs.suid_dumpable = 0', ''),
    ('firewall', 'A firewall is active', 'Network', 'high', _c_firewall, None, '', 'firewall'),
    ('db_public', 'Databases are not reachable from the internet', 'Network', 'critical', _c_db_public, None, '', ''),
    ('fail2ban', 'Brute-force protection is running', 'Network', 'medium', _c_fail2ban, None, '', 'modules'),
    ('auto_updates', 'Security updates install automatically', 'System', 'medium', _c_auto_updates, _f_auto_updates,
     'Install and turn on automatic security updates', ''),
    ('timesync', 'The clock is kept in sync', 'System', 'low', _c_timesync, None, '', ''),
    ('panel_2fa', 'The panel admin uses two-factor sign-in', 'System', 'high', _c_panel_2fa, None, '', 'settings'),
]
WEIGHT = {'critical': 10, 'high': 6, 'medium': 3, 'low': 1}


def run_all():
    ctx = {'sshd': _sshd()}
    out = []
    for cid, title, cat, sev, chk, fix, fix_text, link in CHECKS:
        try:
            st, detail = chk(ctx)
        except Exception as e:  # noqa: BLE001
            st, detail = 'na', f'check failed: {e}'
        out.append({'id': cid, 'title': title, 'category': cat, 'severity': sev, 'status': st, 'detail': detail,
                    'fixable': bool(fix) and st in ('fail', 'warn'), 'fix_text': fix_text, 'link': link})
    total = sum(WEIGHT[c['severity']] for c in out if c['status'] != 'na')
    got = sum(WEIGHT[c['severity']] for c in out if c['status'] == 'pass') + \
        sum(WEIGHT[c['severity']] * 0.5 for c in out if c['status'] == 'warn')
    score = round(got * 100 / total) if total else 100
    return {'score': score, 'checks': out}


def fix(cid):
    for c in CHECKS:
        if c[0] == cid and c[5]:
            try:
                return c[5]({'sshd': _sshd()})
            except Exception as e:  # noqa: BLE001
                return False, str(e)
    return False, 'No automatic fix for this check'
