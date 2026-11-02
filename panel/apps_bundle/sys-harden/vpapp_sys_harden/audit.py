"""Log audit: sign-ins, failed sign-ins, sudo, su and account changes from the
system auth log (auth.log / secure) or the journal when there is no file."""
import os
import re
import time

from panel import appkit

PATTERNS = [
    ('login', 'ok', re.compile(r'sshd\[\d+\]: Accepted (\S+) for (\S+) from (\S+)')),
    ('login_failed', 'bad', re.compile(r'sshd\[\d+\]: Failed (\S+) for (?:invalid user )?(\S+) from (\S+)')),
    ('invalid_user', 'bad', re.compile(r'sshd\[\d+\]: Invalid user (\S*) from (\S+)')),
    ('sudo', 'info', re.compile(r'sudo(?:\[\d+\])?:\s+(\S+) : .*?COMMAND=(.*)$')),
    ('su', 'info', re.compile(r'su(?:\[\d+\])?: .*session opened for user (\S+?)(?:\(uid=\d+\))? by (\S*)')),
    ('user_added', 'warn', re.compile(r'useradd\[\d+\]: new user: name=([^,]+)')),
    ('user_deleted', 'warn', re.compile(r'userdel\[\d+\]: delete user .(\S+?).')),
    ('password_changed', 'warn', re.compile(r'(?:passwd|chpasswd)\[\d+\]: .*password changed for (\S+)')),
    ('group_added', 'info', re.compile(r'groupadd\[\d+\]: new group: name=([^,]+)')),
]
LABELS = {'login': 'Signed in', 'login_failed': 'Failed sign-in', 'invalid_user': 'Unknown user', 'sudo': 'sudo',
          'su': 'su', 'user_added': 'User added', 'user_deleted': 'User deleted', 'password_changed': 'Password changed',
          'group_added': 'Group added'}


def _lines(max_bytes=4 * 1024 * 1024):
    for p in ('/var/log/auth.log', '/var/log/secure'):
        if os.path.isfile(p):
            with open(p, 'rb') as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - max_bytes))
                return f.read().decode('utf-8', 'replace').splitlines(), p
    rc, out, _ = appkit.run(['journalctl', '--no-pager', '-o', 'short-iso', '-n', '20000',
                             '_COMM=sshd', '+', '_COMM=sudo', '+', '_COMM=su', '+', '_COMM=useradd', '+',
                             '_COMM=userdel', '+', '_COMM=passwd'], timeout=30)
    return (out or '').splitlines(), 'journal'


def _ts(line):
    m = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
    if m:
        try:
            return int(time.mktime(time.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S')))
        except ValueError:
            return 0
    m = re.match(r'^(\w{3})\s+(\d+) (\d{2}:\d{2}:\d{2})', line)
    if m:
        y = time.localtime().tm_year
        try:
            t = int(time.mktime(time.strptime(f'{y} {m.group(1)} {m.group(2)} {m.group(3)}', '%Y %b %d %H:%M:%S')))
            return t - 365 * 86400 if t > time.time() + 86400 else t
        except ValueError:
            return 0
    return 0


def events(kind='', q='', limit=500):
    lines, source = _lines()
    out = []
    for line in reversed(lines):
        for k, tone, rx in PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            if kind and k != kind and not (kind == 'failed' and k in ('login_failed', 'invalid_user')):
                break
            g = m.groups()
            ev = {'t': _ts(line), 'kind': k, 'label': LABELS[k], 'tone': tone, 'user': '', 'ip': '', 'detail': ''}
            if k == 'login':
                ev.update(detail=g[0], user=g[1], ip=g[2])
            elif k == 'login_failed':
                ev.update(detail=g[0], user=g[1], ip=g[2])
            elif k == 'invalid_user':
                ev.update(user=g[0], ip=g[1])
            elif k == 'sudo':
                ev.update(user=g[0], detail=g[1][:200])
            elif k == 'su':
                ev.update(user=g[1] or '?', detail='became ' + g[0])
            else:
                ev.update(user=g[0])
            if q and q.lower() not in (ev['user'] + ' ' + ev['ip'] + ' ' + ev['detail']).lower():
                break
            out.append(ev)
            break
        if len(out) >= limit:
            break
    return out, source


def summary():
    evs, source = events(limit=20000)
    day = time.time() - 86400
    recent = [e for e in evs if e['t'] >= day]
    ips = {}
    for e in recent:
        if e['kind'] in ('login_failed', 'invalid_user') and e['ip']:
            ips[e['ip']] = ips.get(e['ip'], 0) + 1
    return {'source': source,
            'logins_24h': sum(1 for e in recent if e['kind'] == 'login'),
            'failed_24h': sum(1 for e in recent if e['kind'] in ('login_failed', 'invalid_user')),
            'sudo_24h': sum(1 for e in recent if e['kind'] == 'sudo'),
            'account_changes_24h': sum(1 for e in recent if e['kind'] in ('user_added', 'user_deleted', 'password_changed')),
            'top_failed_ips': sorted(({'ip': k, 'n': v} for k, v in ips.items()), key=lambda r: -r['n'])[:10],
            'last_logins': [e for e in evs if e['kind'] == 'login'][:10]}
