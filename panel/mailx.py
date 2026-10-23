"""Mail server extras: spam filter (Rspamd), DKIM signing, autoresponders (Sieve),
daily sending limits (Postfix policy service), and the SPF / DKIM / DMARC / MX
records of each mail domain.

Everything here is optional on top of the base setup in routes/mail.py and is
applied with backups: a configuration that does not validate (postfix check,
doveconf -n, rspamadm configtest) is put back and the services keep running
with the previous one.

Files
  data/mail/settings.json        spam filter and default limits (panel)
  data/mail/limits.json          per-mailbox / per-domain limits, groups (hosting accounts)
  data/mail/autoresponders.json  autoresponder settings per mailbox
  /etc/postfix/vp_limits.json    limits as read by the policy service (generated)
  /var/lib/vortexpanel/mail/     counters (sqlite) and limit events (policy service, user vmail)
  /var/lib/vortexpanel/dkim/     DKIM private keys (read by rspamd)
"""
import base64
import datetime
import json
import os
import random
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import threading
import time

INSTALL_DIR = '/opt/vortexpanel'
DATA = os.path.join(INSTALL_DIR, 'data', 'mail')
SETTINGS = os.path.join(DATA, 'settings.json')
LIMITS = os.path.join(DATA, 'limits.json')
AUTORESP = os.path.join(DATA, 'autoresponders.json')
INSTALL_STATE = os.path.join(DATA, 'install.json')
POLICY_LIMITS = '/etc/postfix/vp_limits.json'
STATE_DIR = '/var/lib/vortexpanel/mail'
COUNTS_DB = os.path.join(STATE_DIR, 'counts.db')
EVENTS = os.path.join(STATE_DIR, 'events.jsonl')
DKIM_DIR = '/var/lib/vortexpanel/dkim'
VMAIL_BASE = '/var/mail/vhosts'
# mailbox Sieve scripts live outside the maildir (a .dovecot.sieve in the maildir root
# looks like a mail folder to Dovecot when the home and the maildir are the same)
SIEVE_USERS = '/var/mail/vp-sieve'
SIEVE_DIR = '/etc/dovecot/sieve'
DOVECOT_EXTRA = '/etc/dovecot/conf.d/98-vortexpanel-sieve.conf'
RSPAMD_LOCAL = '/etc/rspamd/local.d'
RSPAMD_FILES = ('redis.conf', 'worker-proxy.inc', 'actions.conf', 'milter_headers.conf', 'dkim_signing.conf',
                'multimap.conf', 'greylist.conf', 'vp_allow_addr.map', 'vp_allow_dom.map',
                'vp_block_addr.map', 'vp_block_dom.map')
POLICY_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mail_policy.py')
POLICY_SCRIPT = '/usr/local/lib/vortexpanel/mail_policy.py'   # readable by vmail (the panel folder is not)
SENDMAIL_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vp_sendmail.py')
SENDMAIL_WRAPPER = '/usr/local/lib/vortexpanel/vp-sendmail'     # PHP sendmail_path of hosting accounts
COUNT_SOCKET = '/run/vortexpanel/mailcount.sock'
COUNT_UNIT = 'vortexpanel-mailcount'
MILTER = 'inet:localhost:11332'
SELECTOR = 'default'

DEFAULTS = {
    'spam': {'enabled': True, 'junk_score': 6.0, 'reject_score': 15.0, 'greylist': False, 'learn': True,
             'allow': [], 'block': []},
    'limits': {'mailbox': 500, 'domain': 2000, 'alert': True},
    'dmarc_policy': 'quarantine',
}

_lock = threading.Lock()


# ------------------------------------------------------------------ small helpers
def run(args, timeout=120, input_text=None):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, input=input_text)
        return r.returncode, (r.stdout or '').strip(), (r.stderr or r.stdout or '').strip()
    except FileNotFoundError:
        return 127, '', f'{args[0]} not found'
    except subprocess.TimeoutExpired:
        return 124, '', f'{args[0]} timed out'


def _read_json(path, default):
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, type(default)) else default
    except (OSError, ValueError):
        return default


def _write_json(path, data, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _write_text(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.vp-tmp'
    with open(tmp, 'w') as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _backup(paths):
    """{path: content or None} for later restore."""
    out = {}
    for p in paths:
        try:
            with open(p) as f:
                out[p] = f.read()
        except OSError:
            out[p] = None
    return out


def _restore(saved):
    for p, content in saved.items():
        try:
            if content is None:
                if os.path.exists(p):
                    os.unlink(p)
            else:
                with open(p, 'w') as f:
                    f.write(content)
        except OSError:
            pass


def _postconf(key):
    rc, out, _ = run(['postconf', '-h', key], timeout=30)
    return out if rc == 0 else ''


def _deep_merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = _deep_merge(base[k], v) if isinstance(base.get(k), dict) and isinstance(v, dict) else v
    return out


def os_family():
    try:
        txt = open('/etc/os-release').read().lower()
    except OSError:
        return 'debian'
    return 'rhel' if re.search(r'^id(_like)?=.*(rhel|fedora|centos)', txt, re.M) else 'debian'


EMAIL_RE = re.compile(r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$')
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')


# ------------------------------------------------------------------ settings
def settings():
    return _deep_merge(DEFAULTS, _read_json(SETTINGS, {}))


def save_settings(new):
    cur = settings()
    sp = new.get('spam') or {}
    for k in ('enabled', 'greylist', 'learn'):
        if k in sp:
            cur['spam'][k] = bool(sp[k])
    for k, lo, hi in (('junk_score', 1, 50), ('reject_score', 2, 100)):
        if k in sp:
            try:
                cur['spam'][k] = max(lo, min(hi, round(float(sp[k]), 1)))
            except (TypeError, ValueError):
                raise ValueError(f'{k.replace("_", " ")} must be a number')
    if cur['spam']['reject_score'] <= cur['spam']['junk_score']:
        raise ValueError('The refuse score must be higher than the Junk score')
    for k in ('allow', 'block'):
        if k in sp:
            items = sp[k] if isinstance(sp[k], list) else str(sp[k]).splitlines()
            clean = []
            for it in items:
                it = str(it).strip().lower()
                if not it:
                    continue
                if it.startswith('*@'):
                    it = it[2:]
                if not (EMAIL_RE.match(it) or DOMAIN_RE.match(it)):
                    raise ValueError(f'"{it}" is not an email address or a domain')
                clean.append(it)
            cur['spam'][k] = sorted(set(clean))[:2000]
    lim = new.get('limits') or {}
    for k in ('mailbox', 'domain'):
        if k in lim:
            try:
                cur['limits'][k] = max(0, min(1000000, int(lim[k])))
            except (TypeError, ValueError):
                raise ValueError('Limits must be whole numbers (0 = unlimited)')
    if 'alert' in lim:
        cur['limits']['alert'] = bool(lim['alert'])
    if new.get('dmarc_policy') in ('none', 'quarantine', 'reject'):
        cur['dmarc_policy'] = new['dmarc_policy']
    _write_json(SETTINGS, cur)
    return cur


def limits():
    data = _read_json(LIMITS, {})
    data.setdefault('mailbox', {})
    data.setdefault('domain', {})
    data.setdefault('groups', {})
    return data


def set_mailbox_limit(email, value):
    """value None = server default, 0 = unlimited."""
    email = email.lower()
    with _lock:
        data = limits()
        if value is None or value == '':
            data['mailbox'].pop(email, None)
        else:
            data['mailbox'][email] = max(0, min(1000000, int(value)))
        _write_json(LIMITS, data)
    export_limits()


def set_group(name, domains, account_limit=None, mailbox_limit=None, uid=None):
    """Limits for a group of domains (a hosting account): account_limit counts all
    mailboxes of all its domains together; mailbox_limit is the default per mailbox.
    None removes the value (server defaults apply). uid: the account's Linux user,
    so mail its websites send (vp-sendmail) counts toward the group."""
    if not re.fullmatch(r'[a-z0-9_.:-]{1,64}', name or ''):
        raise ValueError('invalid group name')
    with _lock:
        data = limits()
        g = {'domains': sorted({d.lower() for d in domains if DOMAIN_RE.match((d or '').lower())})}
        if account_limit is not None:
            g['limit'] = max(0, int(account_limit))
        if mailbox_limit is not None:
            g['mailbox_limit'] = max(0, int(mailbox_limit))
        if uid is not None:
            g['uid'] = int(uid)
        data['groups'][name] = g
        _write_json(LIMITS, data)
    export_limits()
    if uid is not None:
        ensure_web_mail_counter()


def remove_group(name):
    with _lock:
        data = limits()
        if data['groups'].pop(name, None) is not None:
            _write_json(LIMITS, data)
    export_limits()


def export_limits():
    """The file the policy service reads (world-readable, no secrets)."""
    s = settings()
    data = limits()
    out = {'default_mailbox': int(s['limits']['mailbox']), 'default_domain': int(s['limits']['domain']),
           'mailbox': data['mailbox'], 'domain': data['domain'], 'groups': data['groups'],
           'uids': {str(g['uid']): n for n, g in data['groups'].items() if 'uid' in g},
           'events': bool(s['limits'].get('alert', True))}
    if os.path.isdir('/etc/postfix'):
        _write_text(POLICY_LIMITS, json.dumps(out, indent=1, sort_keys=True), 0o644)


# ------------------------------------------------------------------ counters (read side)
def _db():
    if not os.path.exists(COUNTS_DB):
        return None
    con = sqlite3.connect(COUNTS_DB, timeout=5)
    return con


def sent_today():
    """{key: n} for today: 'mbx:<email>', 'dom:<domain>', 'grp:<group>'."""
    con = _db()
    if con is None:
        return {}
    try:
        day = datetime.date.today().isoformat()
        return {k: n for k, n in con.execute('SELECT key, n FROM counts WHERE day=?', (day,))}
    except sqlite3.Error:
        return {}
    finally:
        con.close()


def effective_mailbox_limit(email, lim=None, st=None):
    lim = lim or limits()
    st = st or settings()
    email = email.lower()
    if email in lim['mailbox']:
        return int(lim['mailbox'][email])
    dom = email.split('@', 1)[-1]
    for g in lim['groups'].values():
        if dom in g.get('domains', []) and 'mailbox_limit' in g:
            return int(g['mailbox_limit'])
    return int(st['limits']['mailbox'])


def ensure_web_mail_counter():
    """The socket vp-sendmail asks before website mail goes out (systemd, one short
    process per message, running as vmail like the Postfix policy service)."""
    if not os.path.isdir('/run/systemd/system') or not os.path.isdir('/etc/postfix'):
        return False
    install_policy_script()
    try:
        src = open(SENDMAIL_SRC).read()
        if not os.path.exists(SENDMAIL_WRAPPER) or open(SENDMAIL_WRAPPER).read() != src:
            os.makedirs(os.path.dirname(SENDMAIL_WRAPPER), exist_ok=True)
            _write_text(SENDMAIL_WRAPPER, src, 0o755)
    except OSError:
        return False
    os.makedirs(STATE_DIR, exist_ok=True)
    sock = (f'[Unit]\nDescription=VortexPanel website mail counter\n\n[Socket]\nListenStream={COUNT_SOCKET}\n'
            'SocketMode=0666\nAccept=yes\nMaxConnections=64\n\n[Install]\nWantedBy=sockets.target\n')
    svc = ('[Unit]\nDescription=VortexPanel website mail counter (one check)\n\n[Service]\n'
           f'ExecStart=/usr/bin/python3 -I {POLICY_SCRIPT} --peer\nStandardInput=socket\nStandardOutput=journal\n'
           'User=vmail\nGroup=vmail\nTimeoutSec=20\n')
    changed = False
    for name, text in ((f'{COUNT_UNIT}.socket', sock), (f'{COUNT_UNIT}@.service', svc)):
        p = f'/etc/systemd/system/{name}'
        if not os.path.exists(p) or open(p).read() != text:
            _write_text(p, text, 0o644)
            changed = True
    if changed:
        run(['systemctl', 'daemon-reload'])
    rc, _, _ = run(['systemctl', 'is-active', '--quiet', f'{COUNT_UNIT}.socket'])
    if changed or rc != 0:
        run(['systemctl', 'enable', f'{COUNT_UNIT}.socket'])
        run(['systemctl', 'restart', f'{COUNT_UNIT}.socket'])
    return True


def refused_today():
    con = _db()
    if con is None:
        return 0
    try:
        day = datetime.date.today().isoformat()
        row = con.execute("SELECT SUM(n) FROM counts WHERE day=? AND key LIKE 'refused:%'", (day,)).fetchone()
        return int(row[0] or 0)
    except sqlite3.Error:
        return 0
    finally:
        con.close()


def top_refused_today():
    con = _db()
    if con is None:
        return ''
    try:
        day = datetime.date.today().isoformat()
        row = con.execute("SELECT key, n FROM counts WHERE day=? AND key LIKE 'refused:%' ORDER BY n DESC LIMIT 1",
                          (day,)).fetchone()
        return row[0].split(':', 1)[1] if row else ''
    except sqlite3.Error:
        return ''
    finally:
        con.close()


def new_events(offset):
    """(events, new_offset) from the policy service's event file."""
    try:
        size = os.path.getsize(EVENTS)
    except OSError:
        return [], 0
    if offset > size:
        offset = 0
    out = []
    with open(EVENTS) as f:
        f.seek(offset)
        for line in f:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        offset = f.tell()
    return out, offset


# ------------------------------------------------------------------ components
def components():
    return {
        'rspamd': bool(shutil.which('rspamd')) or os.path.exists('/usr/bin/rspamd'),
        'redis': bool(shutil.which('redis-server')),
        'sieve': _sieve_installed(),
        'rspamd_active': run(['systemctl', 'is-active', 'rspamd'], timeout=15)[1] == 'active',
        'dovecot_version': '.'.join(map(str, dovecot_version())),
    }


def _sieve_installed():
    for p in ('/usr/lib/dovecot/modules/lib90_sieve_plugin.so', '/usr/lib64/dovecot/lib90_sieve_plugin.so',
              '/usr/lib64/dovecot/modules/lib90_sieve_plugin.so', '/usr/lib/dovecot/lib90_sieve_plugin.so'):
        if os.path.exists(p):
            return True
    return bool(shutil.which('sievec'))


def dovecot_version():
    rc, out, _ = run(['dovecot', '--version'], timeout=15)
    m = re.match(r'\s*(\d+)\.(\d+)', out or '')
    return (int(m.group(1)), int(m.group(2))) if (rc == 0 and m) else (0, 0)


def install_state():
    return _read_json(INSTALL_STATE, {})


def start_install():
    """Install Rspamd and the Sieve plugin in the background, then apply."""
    st = install_state()
    if st.get('running') and time.time() - st.get('started', 0) < 1800:
        raise RuntimeError('An install is already running')
    state = {'running': True, 'started': int(time.time()), 'lines': ['Installing the spam filter and Sieve...'], 'ok': None}
    _write_json(INSTALL_STATE, state)

    def say(msg):
        state['lines'].append(msg)
        _write_json(INSTALL_STATE, state)

    def job():
        try:
            fam = os_family()
            env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
            if fam == 'debian':
                cmds = [['apt-get', 'update'], ['apt-get', 'install', '-y', 'rspamd', 'dovecot-sieve']]
                if not shutil.which('redis-server'):
                    cmds.append(['apt-get', 'install', '-y', 'redis-server'])
            else:
                rel = ''
                try:
                    rel = re.search(r'^VERSION_ID="?(\d+)', open('/etc/os-release').read(), re.M).group(1)
                except (OSError, AttributeError):
                    pass
                cmds = []
                if not shutil.which('rspamd'):
                    say('Adding the Rspamd package repository (rspamd.com)')
                    try:
                        import urllib.request
                        repo = urllib.request.urlopen(f'https://rspamd.com/rpm-stable/centos-{rel or "9"}/rspamd.repo',
                                                      timeout=30).read().decode()
                        _write_text('/etc/yum.repos.d/rspamd.repo', repo)
                        cmds.append(['rpm', '--import', 'https://rspamd.com/rpm-stable/gpg.key'])
                    except Exception as e:  # noqa: BLE001
                        raise RuntimeError(f'could not add the Rspamd repository: {e}')
                pm = 'dnf' if shutil.which('dnf') else 'yum'
                cmds.append([pm, 'install', '-y', 'rspamd', 'dovecot-pigeonhole'] + ([] if shutil.which('redis-server') else ['redis']))
            for c in cmds:
                say('$ ' + ' '.join(c))
                r = subprocess.run(c, capture_output=True, text=True, timeout=1800, env=env)
                tail = (r.stdout + r.stderr).strip().splitlines()[-4:]
                for t in tail:
                    say('  ' + t[:200])
                if r.returncode != 0:
                    raise RuntimeError(f'{c[0]} failed (exit {r.returncode})')
            for unit in ('redis-server', 'redis'):
                if run(['systemctl', 'cat', unit], timeout=15)[0] == 0:
                    run(['systemctl', 'enable', '--now', unit], timeout=120)
                    break
            run(['systemctl', 'enable', '--now', 'rspamd'], timeout=120)
            say('Installed. Connecting it to Postfix and Dovecot...')
            log = []
            err = apply_all(log)
            for l in log:
                say(l)
            if err:
                raise RuntimeError(err)
            state['ok'] = True
            say('Spam filter and autoresponders are ready.')
        except Exception as e:  # noqa: BLE001
            state['ok'] = False
            say(f'FAILED: {e}')
        finally:
            state['running'] = False
            _write_json(INSTALL_STATE, state)

    threading.Thread(target=job, daemon=True).start()
    return state


# ------------------------------------------------------------------ apply: postfix
def install_policy_script():
    """Copy the policy service where the vmail user can run it (also after panel updates)."""
    try:
        with open(POLICY_SRC) as f:
            src = f.read()
        cur = open(POLICY_SCRIPT).read() if os.path.exists(POLICY_SCRIPT) else None
        if cur != src:
            os.makedirs(os.path.dirname(POLICY_SCRIPT), exist_ok=True)
            os.chmod(os.path.dirname(POLICY_SCRIPT), 0o755)
            _write_text(POLICY_SCRIPT, src, 0o755)
    except OSError:
        pass


def _postfix_policy(log):
    """Daily sending limits: a Postfix policy service checked at the end of each
    message sent by a signed-in mailbox."""
    os.makedirs(STATE_DIR, exist_ok=True)
    run(['chown', 'vmail:vmail', STATE_DIR])
    install_policy_script()
    os.chmod(STATE_DIR, 0o750)
    export_limits()
    rc, _, err = run(['postconf', '-M',
                      f'vppolicy/unix=vppolicy unix - n n - 0 spawn user=vmail argv=/usr/bin/python3 {POLICY_SCRIPT}'])
    if rc != 0:
        return f'postconf -M vppolicy: {err}'
    for st in ('vppolicy_time_limit = 3600',
               'smtpd_end_of_data_restrictions = check_policy_service unix:private/vppolicy'):
        rc, _, err = run(['postconf', '-e', st])
        if rc != 0:
            return f'postconf -e "{st}": {err}'
    log.append('sending limits checked by the panel policy service')
    return ''


def _postfix_milter(log, on):
    cur = [m.strip() for m in re.split(r'[,\s]+', _postconf('smtpd_milters')) if m.strip()]
    cur_ns = [m.strip() for m in re.split(r'[,\s]+', _postconf('non_smtpd_milters')) if m.strip()]
    want = [m for m in cur if m != MILTER] + ([MILTER] if on else [])
    want_ns = [m for m in cur_ns if m != MILTER] + ([MILTER] if on else [])
    sets = [f'smtpd_milters = {", ".join(want)}', f'non_smtpd_milters = {", ".join(want_ns)}']
    if on:
        sets += ['milter_protocol = 6', 'milter_default_action = accept',
                 'milter_mail_macros = i {mail_addr} {client_addr} {client_name} {auth_authen}']
    for st in sets:
        rc, _, err = run(['postconf', '-e', st])
        if rc != 0:
            return f'postconf -e "{st}": {err}'
    log.append('Postfix passes mail through Rspamd (spam check and DKIM signing)' if on else
               'Rspamd is not connected to Postfix')
    return ''


# ------------------------------------------------------------------ apply: rspamd
def _rspamd_user():
    for u in ('_rspamd', 'rspamd'):
        if run(['id', u], timeout=10)[0] == 0:
            return u
    return 'root'


def _redis_conf():
    """Rspamd keeps what it learns (Bayes), greylisting and fuzzy data in Redis."""
    pw = ''
    for p in ('/etc/redis/redis.conf', '/etc/redis.conf', '/etc/redis/default.conf'):
        try:
            m = re.search(r'^\s*requirepass\s+(\S+)', open(p).read(), re.M)
        except OSError:
            continue
        if m:
            pw = m.group(1).strip('"')
        break
    return ('# Managed by VortexPanel\nservers = "127.0.0.1:6379";\n'
            + (f'password = "{pw}";\n' if pw and re.fullmatch(r'[^"\\\s]{1,128}', pw) else ''))


def _rspamd_files(s):
    sp = s['spam']
    on = bool(sp['enabled'])
    junk, rej = float(sp['junk_score']), float(sp['reject_score'])
    acts = (f'reject = {rej};\nadd_header = {junk};\n'
            + (f'greylist = {max(1.0, junk - 2)};\n' if sp['greylist'] else 'greylist = null;\n')
            if on else 'reject = null;\nadd_header = null;\ngreylist = null;\nrewrite_subject = null;\n')
    files = {
        'redis.conf': _redis_conf(),
        'worker-proxy.inc': ('# Managed by VortexPanel\nmilter = yes;\ntimeout = 120s;\n'
                             'bind_socket = "localhost:11332";\nupstream "local" {\n  default = yes;\n  self_scan = yes;\n}\n'),
        'actions.conf': '# Managed by VortexPanel (Mail Server > Spam & limits)\n' + acts,
        'milter_headers.conf': ('# Managed by VortexPanel\nuse = ["x-spam-status", "authentication-results"];\n'
                                'skip_local = true;\nskip_authenticated = true;\n'),
        'dkim_signing.conf': (f'# Managed by VortexPanel\npath = "{DKIM_DIR}/$domain.$selector.key";\n'
                              f'selector = "{SELECTOR}";\nallow_username_mismatch = true;\nuse_esld = false;\n'
                              'sign_local = true;\nsign_authenticated = true;\ncheck_pubkey = false;\n'
                              'allow_hdrfrom_mismatch = false;\n'),
        'greylist.conf': '# Managed by VortexPanel\nenabled = ' + ('true' if (on and sp['greylist']) else 'false') + ';\n',
        'multimap.conf': (
            '# Managed by VortexPanel (allow and block lists)\n'
            f'VP_ALLOW_ADDR {{ type = "from"; filter = "email:addr"; map = "{RSPAMD_LOCAL}/vp_allow_addr.map"; score = -20.0; description = "Allowed by the server administrator"; }}\n'
            f'VP_ALLOW_DOM {{ type = "from"; filter = "email:domain"; map = "{RSPAMD_LOCAL}/vp_allow_dom.map"; score = -20.0; description = "Allowed by the server administrator"; }}\n'
            f'VP_BLOCK_ADDR {{ type = "from"; filter = "email:addr"; map = "{RSPAMD_LOCAL}/vp_block_addr.map"; action = "reject"; message = "Blocked by the server administrator"; description = "Blocked sender"; }}\n'
            f'VP_BLOCK_DOM {{ type = "from"; filter = "email:domain"; map = "{RSPAMD_LOCAL}/vp_block_dom.map"; action = "reject"; message = "Blocked by the server administrator"; description = "Blocked sender domain"; }}\n'),
        'vp_allow_addr.map': '\n'.join(x for x in sp['allow'] if '@' in x) + '\n',
        'vp_allow_dom.map': '\n'.join(x for x in sp['allow'] if '@' not in x) + '\n',
        'vp_block_addr.map': '\n'.join(x for x in sp['block'] if '@' in x) + '\n',
        'vp_block_dom.map': '\n'.join(x for x in sp['block'] if '@' not in x) + '\n',
    }
    return files


def _apply_rspamd(log, s):
    if not os.path.isdir('/etc/rspamd'):
        return 'Rspamd is not installed'
    paths = [os.path.join(RSPAMD_LOCAL, n) for n in RSPAMD_FILES]
    saved = _backup(paths)
    user = _rspamd_user()
    for name, text in _rspamd_files(s).items():
        path = os.path.join(RSPAMD_LOCAL, name)
        if name == 'redis.conf':
            # holds the Redis password: readable by root and Rspamd only
            _write_text(path, text, 0o640)
            run(['chown', f'root:{user}' if user != 'root' else 'root:root', path])
        else:
            _write_text(path, text, 0o644)
    os.makedirs(DKIM_DIR, exist_ok=True)
    run(['chown', '-R', f'root:{user}' if user != 'root' else 'root:root', DKIM_DIR])
    os.chmod(DKIM_DIR, 0o750)
    rc, out, err = run(['rspamadm', 'configtest'], timeout=120)
    if rc != 0:
        _restore(saved)
        return f'Rspamd rejected the configuration, the previous one was kept: {(err or out)[-400:]}'
    rc, _, err = run(['systemctl', 'restart', 'rspamd'], timeout=120)
    if rc != 0:
        _restore(saved)
        run(['systemctl', 'restart', 'rspamd'], timeout=120)
        return f'Rspamd did not restart, the previous configuration was restored: {err[-300:]}'
    log.append('Rspamd configured' + (' (spam check on)' if s['spam']['enabled'] else ' (spam check off, DKIM signing on)'))
    return ''


# ------------------------------------------------------------------ apply: dovecot sieve
SIEVE_BEFORE = """# Managed by VortexPanel: spam goes to Junk
require ["fileinto", "mailbox"];
if anyof (header :is "X-Spam" "Yes", header :contains "X-Spam-Status" "Yes,") {
  fileinto :create "Junk";
  stop;
}
"""
LEARN_SPAM = """require ["vnd.dovecot.pipe", "copy", "imapsieve"];
pipe :copy "vp-learn" ["spam"];
"""
LEARN_HAM = """require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];
if environment :matches "imap.mailbox" "*" { set "mailbox" "${1}"; }
if string "${mailbox}" "Trash" { stop; }
pipe :copy "vp-learn" ["ham"];
"""
LEARN_BIN = """#!/bin/sh
# Managed by VortexPanel: teach Rspamd from messages moved into or out of Junk
case "$1" in spam|ham) ;; *) exit 0 ;; esac
exec /usr/bin/rspamc -h localhost:11334 "learn_$1" >/dev/null 2>&1
"""


def _dovecot_conf(ver, learn):
    if ver >= (2, 4):
        conf = ("# Managed by VortexPanel: Sieve (autoresponders, spam to Junk). Dovecot 2.4 syntax.\n"
                "protocol lmtp {\n  mail_plugins {\n    sieve = yes\n  }\n}\n"
                f"sieve_script personal {{\n  driver = file\n  path = {SIEVE_USERS}/%{{user | domain}}/%{{user | username}}/scripts\n"
                f"  active_path = {SIEVE_USERS}/%{{user | domain}}/%{{user | username}}/active.sieve\n}}\n"
                f"sieve_script vp_before {{\n  type = before\n  driver = file\n  path = {SIEVE_DIR}/vp-before.sieve\n}}\n"
                "namespace inbox {\n  mailbox Junk {\n    auto = subscribe\n    special_use = \\Junk\n  }\n}\n")
        return conf
    conf = ("# Managed by VortexPanel: Sieve (autoresponders, spam to Junk, learning). Do not edit by hand.\n"
            "protocol lmtp {\n  mail_plugins = $mail_plugins sieve\n}\n"
            "namespace inbox {\n  mailbox Junk {\n    auto = subscribe\n    special_use = \\Junk\n  }\n}\n"
            "plugin {\n"
            f"  sieve = file:{SIEVE_USERS}/%d/%n/scripts;active={SIEVE_USERS}/%d/%n/active.sieve\n"
            f"  sieve_before = {SIEVE_DIR}/vp-before.sieve\n")
    if learn:
        conf += ("  sieve_plugins = sieve_imapsieve sieve_extprograms\n"
                 "  sieve_global_extensions = +vnd.dovecot.pipe +vnd.dovecot.environment\n"
                 f"  sieve_pipe_bin_dir = {SIEVE_DIR}/bin\n"
                 "  imapsieve_mailbox1_name = Junk\n"
                 "  imapsieve_mailbox1_causes = COPY APPEND\n"
                 f"  imapsieve_mailbox1_before = file:{SIEVE_DIR}/vp-learn-spam.sieve\n"
                 "  imapsieve_mailbox2_name = *\n"
                 "  imapsieve_mailbox2_from = Junk\n"
                 "  imapsieve_mailbox2_causes = COPY\n"
                 f"  imapsieve_mailbox2_before = file:{SIEVE_DIR}/vp-learn-ham.sieve\n")
    conf += "}\n"
    if learn:
        conf += "protocol imap {\n  mail_plugins = $mail_plugins imap_sieve\n}\n"
    return conf


BASE_CONF = '/etc/dovecot/conf.d/99-vortexpanel.conf'
VMAIL_HOME = '/var/mail/vp-home'


def _dovecot_base_home():
    """Older setups used the maildir as the Dovecot home, so vacation's memory file
    (.dovecot.lda-dupes) appeared as a mail folder. Move the home out of the maildir."""
    try:
        from panel.routes.mail import _dovecot_conf as base_conf
    except Exception:  # noqa: BLE001
        return ''
    if not os.path.exists(BASE_CONF):
        return ''
    want = base_conf(dovecot_version())
    cur = open(BASE_CONF).read()
    os.makedirs(VMAIL_HOME, exist_ok=True)
    run(['chown', 'vmail:vmail', VMAIL_HOME])
    os.chmod(VMAIL_HOME, 0o770)
    if cur == want or VMAIL_HOME in cur:
        return ''
    _write_text(BASE_CONF, want, 0o644)
    if run(['doveconf', '-n'], timeout=60)[0] != 0:
        _write_text(BASE_CONF, cur, 0o644)
        return 'Dovecot rejected the updated mailbox home, nothing was changed'
    # move what Dovecot kept in the old home (the maildir root) to the new one
    for dom in os.listdir(VMAIL_BASE) if os.path.isdir(VMAIL_BASE) else []:
        ddir = os.path.join(VMAIL_BASE, dom)
        if not os.path.isdir(ddir):
            continue
        for user in os.listdir(ddir):
            mdir = os.path.join(ddir, user)
            for name in ('.dovecot.lda-dupes', '.dovecot.lda-dupes.locks', '.dovecot.sieve', '.dovecot.sieve.log', '.dovecot.svbin'):
                p = os.path.join(mdir, name)
                if os.path.lexists(p):
                    dst = os.path.join(VMAIL_HOME, dom, user)
                    os.makedirs(dst, exist_ok=True)
                    try:
                        if os.path.islink(p) or name.endswith(('.sieve', '.svbin', '.log')):
                            os.unlink(p) if not os.path.isdir(p) else shutil.rmtree(p, ignore_errors=True)
                        else:
                            shutil.move(p, os.path.join(dst, name))
                    except OSError:
                        pass
            if os.path.isdir(os.path.join(mdir, 'sieve')) and not os.path.isdir(os.path.join(mdir, 'sieve', 'cur')):
                shutil.rmtree(os.path.join(mdir, 'sieve'), ignore_errors=True)
    run(['chown', '-R', 'vmail:vmail', VMAIL_HOME])
    return ''


def learn_supported():
    return dovecot_version() < (2, 4)


def _apply_dovecot(log, s):
    if not os.path.isdir('/etc/dovecot/conf.d'):
        return 'Dovecot is not installed'
    if not _sieve_installed():
        return 'The Dovecot Sieve plugin is not installed'
    ver = dovecot_version()
    learn = bool(s['spam'].get('learn')) and ver < (2, 4) and components()['rspamd']
    base_err = _dovecot_base_home()
    if base_err:
        return base_err
    files = {os.path.join(SIEVE_DIR, 'vp-before.sieve'): (SIEVE_BEFORE, 0o644),
             os.path.join(SIEVE_DIR, 'vp-learn-spam.sieve'): (LEARN_SPAM, 0o644),
             os.path.join(SIEVE_DIR, 'vp-learn-ham.sieve'): (LEARN_HAM, 0o644),
             os.path.join(SIEVE_DIR, 'bin', 'vp-learn'): (LEARN_BIN, 0o755),
             DOVECOT_EXTRA: (_dovecot_conf(ver, learn), 0o644)}
    saved = _backup(list(files))
    for p, (text, mode) in files.items():
        _write_text(p, text, mode)
    if shutil.which('sievec'):
        for n in ('vp-before.sieve', 'vp-learn-spam.sieve', 'vp-learn-ham.sieve'):
            if n != 'vp-before.sieve' and not learn:
                continue
            rc, _, err = run(['sievec', os.path.join(SIEVE_DIR, n)], timeout=60)
            if rc != 0 and n == 'vp-before.sieve':
                _restore(saved)
                return f'sievec {n}: {err[-300:]}'
    rc, _, err = run(['doveconf', '-n'], timeout=60)
    if rc != 0:
        _restore(saved)
        return f'Dovecot rejected the Sieve configuration, the previous one was kept: {err[-400:]}'
    rc, _, err = run(['systemctl', 'restart', 'dovecot'], timeout=120)
    if rc != 0:
        _restore(saved)
        run(['systemctl', 'restart', 'dovecot'], timeout=120)
        return f'Dovecot did not restart, the previous configuration was restored: {err[-300:]}'
    log.append('Dovecot Sieve on (autoresponders, spam to Junk' + (', learning from Junk)' if learn else ')'))
    return ''


# ------------------------------------------------------------------ apply everything
def apply_all(log, only=None):
    """Apply the extras that are installed. Returns '' or an error (configs that
    failed to validate are put back)."""
    if not os.path.isdir('/etc/postfix'):
        return 'Postfix is not installed'
    s = settings()
    comp = components()
    pf_saved = _backup(['/etc/postfix/main.cf', '/etc/postfix/master.cf'])
    errors = []
    if only in (None, 'postfix'):
        err = _postfix_policy(log)
        if not err and comp['rspamd']:
            err = _postfix_milter(log, True)
        if not err:
            rc, _, perr = run(['postfix', 'check'], timeout=60)
            if rc != 0:
                err = f'postfix check: {perr[-300:]}'
        if err:
            _restore(pf_saved)
            errors.append(err + ' (Postfix configuration put back)')
        else:
            rc, _, rerr = run(['systemctl', 'reload', 'postfix'], timeout=120)
            if rc != 0:
                _restore(pf_saved)
                run(['systemctl', 'restart', 'postfix'], timeout=120)
                errors.append(f'Postfix did not reload, configuration put back: {rerr[-200:]}')
    if comp['rspamd'] and only in (None, 'rspamd'):
        for d in mail_domains():
            ensure_dkim_key(d)
        err = _apply_rspamd(log, s)
        if err:
            errors.append(err)
    if comp['sieve'] and only in (None, 'dovecot'):
        err = _apply_dovecot(log, s)
        if err:
            errors.append(err)
        else:
            for email in list(_read_json(AUTORESP, {}).keys()):
                _write_autoresponder(email)
    return '; '.join(errors)


def maintenance():
    """Run every few minutes (panel.tasks backups): keep the policy service current after
    panel updates and connect it on mail servers set up before it existed."""
    try:
        from panel.routes.mail import _mail_configured
        if not os.path.isdir('/etc/postfix') or not _mail_configured():
            return ''
    except Exception:  # noqa: BLE001
        return ''
    install_policy_script()
    if not os.path.exists(SETTINGS):
        # a mail server from before sending limits existed: keep sending unlimited
        # until the administrator sets limits (Mail Server > Spam & limits)
        cur = settings()
        cur['limits']['mailbox'] = 0
        cur['limits']['domain'] = 0
        _write_json(SETTINGS, cur)
        export_limits()
    if any('uid' in g for g in limits()['groups'].values()):
        ensure_web_mail_counter()
    if 'vppolicy' not in _postconf('smtpd_end_of_data_restrictions'):
        log = []
        err = apply_all(log, only='postfix')
        return err or 'mail sending limits connected'
    return ''


# ------------------------------------------------------------------ autoresponders
def _sieve_str(s):
    return '"' + str(s).replace('\\', '\\\\').replace('"', '\\"') + '"'


def _sieve_text(body):
    lines = str(body).replace('\r\n', '\n').replace('\r', '\n').split('\n')
    out = ['text:']
    for l in lines:
        out.append('.' + l if l.startswith('.') else l)
    out.append('.')
    return '\n'.join(out) + '\n'


def _sieve_home(email):
    user, dom = email.split('@', 1)
    return os.path.join(SIEVE_USERS, dom, user)


def get_autoresponder(email):
    return _read_json(AUTORESP, {}).get(email.lower()) or {
        'enabled': False, 'subject': '', 'body': '', 'start': '', 'end': '', 'days': 3}


def autoresponder_status(email, ar=None):
    ar = ar or get_autoresponder(email)
    if not ar.get('enabled'):
        return 'off'
    today = datetime.date.today().isoformat()
    if ar.get('end') and ar['end'] < today:
        return 'ended'
    if ar.get('start') and ar['start'] > today:
        return 'scheduled'
    return 'on'


def save_autoresponder(email, d):
    email = email.lower()
    if not EMAIL_RE.match(email):
        raise ValueError('Invalid mailbox')
    ar = {'enabled': bool(d.get('enabled')),
          'subject': str(d.get('subject') or '').strip()[:200],
          'body': str(d.get('body') or '').strip()[:8000],
          'start': str(d.get('start') or '').strip(), 'end': str(d.get('end') or '').strip(),
          'days': d.get('days', 3)}
    for k in ('start', 'end'):
        if ar[k] and not re.fullmatch(r'\d{4}-\d{2}-\d{2}', ar[k]):
            raise ValueError('Dates must be YYYY-MM-DD')
    if ar['start'] and ar['end'] and ar['end'] < ar['start']:
        raise ValueError('The end date is before the start date')
    try:
        ar['days'] = max(1, min(30, int(ar['days'])))
    except (TypeError, ValueError):
        raise ValueError('Days must be a number from 1 to 30')
    if ar['enabled'] and not ar['body']:
        raise ValueError('Write the reply message')
    if any(c in ar['subject'] for c in '\r\n'):
        raise ValueError('The subject must be one line')
    if ar['enabled'] and not _sieve_installed():
        raise ValueError('Autoresponders need the Sieve plugin: Mail Server > Spam & limits > Install')
    with _lock:
        data = _read_json(AUTORESP, {})
        data[email] = ar
        _write_json(AUTORESP, data)
    _write_autoresponder(email)
    return ar


def delete_autoresponder(email):
    email = email.lower()
    with _lock:
        data = _read_json(AUTORESP, {})
        if data.pop(email, None) is not None:
            _write_json(AUTORESP, data)
    home = _sieve_home(email)
    if os.path.isdir(home):
        shutil.rmtree(home, ignore_errors=True)


def _write_autoresponder(email):
    ar = get_autoresponder(email)
    user, dom = email.split('@', 1)
    if not os.path.isdir(os.path.join(VMAIL_BASE, dom, user)):
        return
    home = _sieve_home(email)
    sdir = os.path.join(home, 'scripts')
    os.makedirs(sdir, exist_ok=True)
    for d in (SIEVE_USERS, os.path.join(SIEVE_USERS, dom), home):
        run(['chown', 'vmail:vmail', d])
        os.chmod(d, 0o750)
    script = os.path.join(sdir, 'vortex.sieve')
    req = ['vacation']
    cond = []
    if ar.get('start') or ar.get('end'):
        req += ['date', 'relational']
        if ar.get('start'):
            cond.append(f'currentdate :value "ge" "date" {_sieve_str(ar["start"])}')
        if ar.get('end'):
            cond.append(f'currentdate :value "le" "date" {_sieve_str(ar["end"])}')
    noreply = ('not address :localpart :matches "from" ["*noreply*", "*no-reply*", "*donotreply*", '
               '"*do-not-reply*", "mailer-daemon", "postmaster"]')
    cond.append(noreply)
    action = (f'vacation :days {int(ar.get("days") or 3)} :from {_sieve_str(email)} '
              + (f':subject {_sieve_str(ar["subject"])} ' if ar.get('subject') else '')
              + f':addresses [{_sieve_str(email)}]\n{_sieve_text(ar.get("body") or "")};')   # text: ends with '.' on its own line
    text = f'# Managed by VortexPanel (autoresponder for {email})\nrequire {json.dumps(sorted(set(req)))};\n'
    if ar.get('enabled'):
        text += f'if allof ({", ".join(cond)}) {{\n{action}\n}}\n'
    _write_text(script, text, 0o640)
    link = os.path.join(home, 'active.sieve')
    try:
        if os.path.islink(link) or os.path.exists(link):
            os.unlink(link)
        os.symlink('scripts/vortex.sieve', link)
    except OSError:
        pass
    run(['chown', '-R', 'vmail:vmail', sdir])
    run(['chown', '-h', 'vmail:vmail', link])
    # an older layout kept the script in the maildir; remove it
    old = os.path.join(VMAIL_BASE, dom, user, '.dovecot.sieve')
    if os.path.islink(old):
        try:
            os.unlink(old)
            shutil.rmtree(os.path.join(VMAIL_BASE, dom, user, 'sieve'), ignore_errors=True)
        except OSError:
            pass


# ------------------------------------------------------------------ DKIM keys and DNS records
def mail_domains():
    out = []
    try:
        for line in open('/etc/postfix/virtual_mailbox_domains'):
            t = line.split()
            if t and not t[0].startswith('#'):
                out.append(t[0].lower())
    except OSError:
        pass
    return out


def dkim_key_path(domain):
    return os.path.join(DKIM_DIR, f'{domain}.{SELECTOR}.key')


def ensure_dkim_key(domain, renew=False):
    """Create (or reuse an older opendkim key) the private key; returns the TXT value."""
    if not DOMAIN_RE.match(domain):
        raise ValueError('Invalid domain')
    path = dkim_key_path(domain)
    os.makedirs(DKIM_DIR, exist_ok=True)
    if renew or not os.path.exists(path):
        legacy = f'/etc/opendkim/keys/{domain}/default.private'
        if not renew and os.path.exists(legacy):
            shutil.copyfile(legacy, path)
        else:
            rc, _, err = run(['openssl', 'genrsa', '-out', path + '.new', '2048'], timeout=60)
            if rc != 0:
                raise RuntimeError(f'openssl genrsa: {err}')
            os.replace(path + '.new', path)
        user = _rspamd_user()
        run(['chown', f'root:{user}' if user != 'root' else 'root:root', path])
        os.chmod(path, 0o640)
    r = subprocess.run(['openssl', 'rsa', '-in', path, '-pubout', '-outform', 'DER'], capture_output=True, timeout=60)
    if r.returncode != 0 or not r.stdout:
        raise RuntimeError('openssl rsa: ' + r.stderr.decode('utf-8', 'replace')[-200:])
    der = r.stdout
    return 'v=DKIM1; k=rsa; p=' + base64.b64encode(der).decode()


def server_ipv4():
    rc, out, _ = run(['ip', '-4', 'route', 'get', '1.1.1.1'], timeout=10)
    m = re.search(r'\bsrc\s+(\d+\.\d+\.\d+\.\d+)', out or '')
    return m.group(1) if m else ''


def wanted_records(domain):
    s = settings()
    ip = server_ipv4()
    recs = [{'name': 'SPF', 'type': 'TXT', 'host': '@',
             'value': f'v=spf1 mx a{(" ip4:" + ip) if ip else ""} ~all'}]
    try:
        recs.append({'name': 'DKIM', 'type': 'TXT', 'host': f'{SELECTOR}._domainkey', 'value': ensure_dkim_key(domain)})
    except Exception as e:  # noqa: BLE001
        recs.append({'name': 'DKIM', 'type': 'TXT', 'host': f'{SELECTOR}._domainkey', 'value': '', 'error': str(e)})
    recs.append({'name': 'DMARC', 'type': 'TXT', 'host': '_dmarc',
                 'value': f'v=DMARC1; p={s["dmarc_policy"]}; rua=mailto:postmaster@{domain}'})
    recs.append({'name': 'MX', 'type': 'MX', 'host': '@', 'value': f'10 mail.{domain}'})
    if ip:
        recs.append({'name': 'Mail host', 'type': 'A', 'host': 'mail', 'value': ip})
    return recs


def _txt_chunks(value):
    return ' '.join('"' + value[i:i + 250].replace('"', '\\"') + '"' for i in range(0, len(value), 250))


def _local_zone(domain):
    try:
        from panel.routes import dns as dnsmod
        zf = dnsmod._zone_file(domain)
        return dnsmod, zf if os.path.exists(zf) else None
    except Exception:  # noqa: BLE001
        return None, None


def _norm(v):
    return re.sub(r'"\s*"', '', ' '.join(str(v).split())).strip('"').rstrip('.').lower()


def records_status(domain):
    """Each wanted record with status: 'ok' (found with the same value), 'different'
    (a record of that kind exists with another value), 'missing'."""
    recs = wanted_records(domain)
    dnsmod, zf = _local_zone(domain)
    local = []
    if zf:
        try:
            local = dnsmod._parse_records(open(zf).read())
        except OSError:
            local = []
    for r in recs:
        fqdn = domain if r['host'] == '@' else f'{r["host"]}.{domain}'
        if zf:
            have = [x for x in local if x['type'] == r['type'] and x['host'] in (r['host'], fqdn + '.')]
            vals = [_norm(x['value']) for x in have]
            r['where'] = 'zone'
        else:
            vals = [_norm(v) for v in dns_query(fqdn, r['type'])]
            r['where'] = 'public'
        if r['name'] == 'SPF':
            vals = [v for v in vals if v.startswith('v=spf1')]
        elif r['name'] == 'DMARC':
            vals = [v for v in vals if v.startswith('v=dmarc1')]
        elif r['name'] == 'DKIM':
            vals = [v for v in vals if 'v=dkim1' in v or 'p=' in v]
        want = _norm(r['value'])
        if not r['value']:
            r['status'] = 'error'
        elif any(v == want or (r['type'] == 'MX' and v.split()[-1:] == want.split()[-1:]) for v in vals):
            r['status'] = 'ok'
        elif vals:
            r['status'] = 'different'
            r['found'] = vals[0][:300]
        else:
            r['status'] = 'missing'
    return {'records': recs, 'local_zone': bool(zf)}


def add_records_to_zone(domain, log=None):
    """Add the missing mail records to this server's DNS zone (never replaces
    an existing SPF, DMARC, MX or mail A record)."""
    dnsmod, zf = _local_zone(domain)
    if not zf:
        return 0
    st = records_status(domain)
    content = open(zf).read()
    added = 0
    for r in st['records']:
        if r['status'] != 'missing' or not r['value']:
            continue
        value = _txt_chunks(r['value']) if r['type'] == 'TXT' else r['value']
        line, err = dnsmod._record_line({'host': r['host'], 'type': r['type'], 'value': value, 'ttl': '3600'})
        if err:
            if log is not None:
                log.append(f'{r["name"]}: {err}')
            continue
        content = content.rstrip('\n') + '\n' + line + '\n'
        added += 1
    if added:
        content = dnsmod._bump_serial(content)
        err = dnsmod._write_zone_checked(domain, zf, content)
        if err:
            if log is not None:
                log.append(f'DNS zone not changed: {err}')
            return 0
    if log is not None:
        log.append(f'{added} mail record(s) added to the DNS zone of {domain}' if added else
                   f'mail records of {domain} already in its DNS zone')
    return added


def on_domain_added(domain):
    """New mail domain: DKIM key, records in the local zone, rspamd picks the key up."""
    log = []
    try:
        ensure_dkim_key(domain)
        log.append('DKIM key created')
    except Exception as e:  # noqa: BLE001
        log.append(f'DKIM key: {e}')
    try:
        if _local_zone(domain)[1]:
            add_records_to_zone(domain, log)
        else:
            log.append('Add its SPF, DKIM, DMARC and MX records at your DNS provider (Mail Server > DKIM / SPF / DMARC)')
    except Exception as e:  # noqa: BLE001
        log.append(f'DNS records: {e}')
    return log


# ------------------------------------------------------------------ minimal DNS client (TXT, MX, A)
_QTYPES = {'A': 1, 'MX': 15, 'TXT': 16}


def _resolvers():
    out = []
    try:
        for line in open('/etc/resolv.conf'):
            t = line.split()
            if len(t) >= 2 and t[0] == 'nameserver':
                out.append(t[1])
    except OSError:
        pass
    return [r for r in out if ':' not in r] + ['1.1.1.1', '8.8.8.8']


def _read_name(msg, off):
    labels, jumped, end = [], False, off
    for _ in range(64):
        n = msg[off]
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack('!H', msg[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            off, jumped = ptr, True
            continue
        off += 1
        if n == 0:
            break
        labels.append(msg[off:off + n].decode('ascii', 'replace'))
        off += n
    return '.'.join(labels), (end if jumped else off)


def dns_query(name, qtype, timeout=3.0):
    """Answers as strings ('' list when nothing). TXT strings are joined."""
    qt = _QTYPES.get(qtype)
    if not qt:
        return []
    qid = random.randint(0, 65535)
    q = struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip('.').split('.'):
        q += bytes([len(label)]) + label.encode('ascii')
    q += b'\x00' + struct.pack('!HH', qt, 1)
    for server in _resolvers()[:3]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(q, (server, 53))
            msg = s.recv(4096)
            s.close()
        except OSError:
            continue
        if len(msg) < 12 or struct.unpack('!H', msg[:2])[0] != qid:
            continue
        an = struct.unpack('!H', msg[6:8])[0]
        off = 12
        _, off = _read_name(msg, off)
        off += 4
        out = []
        for _ in range(an):
            _, off = _read_name(msg, off)
            rtype, _, _, rdlen = struct.unpack('!HHIH', msg[off:off + 10])
            off += 10
            rdata = msg[off:off + rdlen]
            if rtype == qt == 16:
                parts, i = [], 0
                while i < len(rdata):
                    ln = rdata[i]
                    parts.append(rdata[i + 1:i + 1 + ln].decode('utf-8', 'replace'))
                    i += 1 + ln
                out.append(''.join(parts))
            elif rtype == qt == 15:
                pref = struct.unpack('!H', rdata[:2])[0]
                host, _ = _read_name(msg, off + 2)
                out.append(f'{pref} {host}')
            elif rtype == qt == 1 and rdlen == 4:
                out.append('.'.join(str(b) for b in rdata))
            off += rdlen
        return out
    return []


# ------------------------------------------------------------------ statistics (last 24 hours)
def stats_24h():
    out = {'checked': 0, 'junk': 0, 'rejected': 0, 'greylisted': 0, 'sent': 0,
           'refused_limit': refused_today(), 'refused_top': top_refused_today()}
    log = None
    for p in ('/var/log/rspamd/rspamd.log',):
        if os.path.exists(p):
            log = p
    if log:
        since = (datetime.datetime.now() - datetime.timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        rx = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*rspamd_task_write_log.*\(default: [TFS] '
                        r'\((no action|add header|reject|greylist|soft reject|rewrite subject)\)')
        try:
            with open(log, errors='replace') as f:
                for line in f:
                    m = rx.match(line)
                    if not m or m.group(1) < since:
                        continue
                    out['checked'] += 1
                    a = m.group(2)
                    if a in ('add header', 'rewrite subject'):
                        out['junk'] += 1
                    elif a == 'reject':
                        out['rejected'] += 1
                    elif a in ('greylist', 'soft reject'):
                        out['greylisted'] += 1
        except OSError:
            pass
    con = _db()
    if con is not None:
        try:
            day = datetime.date.today().isoformat()
            row = con.execute("SELECT SUM(n) FROM counts WHERE day=? AND key LIKE 'mbx:%'", (day,)).fetchone()
            out['sent'] = int(row[0] or 0)
        except sqlite3.Error:
            pass
        finally:
            con.close()
    return out
