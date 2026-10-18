"""SSH sign-in records for Security > SSH sign-ins and the SSH alert rule.

Reads sshd's messages from the journal (or /var/log/auth.log, /var/log/secure
when the journal has none) and turns them into events:
  {'time', 'result': accepted|failed|invalid_user, 'user', 'ip', 'port', 'method'}
"""
import os
import re
import subprocess
import time
from datetime import datetime

_ACCEPT = re.compile(r'Accepted (\S+) for (\S+) from (\S+) port (\d+)')
_FAIL = re.compile(r'Failed (\S+) for (invalid user )?(\S+) from (\S+) port (\d+)')
_INVALID = re.compile(r'Invalid user (\S*) from (\S+)(?: port (\d+))?')


def _parse_line(ts, msg):
    m = _ACCEPT.search(msg)
    if m:
        return {'time': ts, 'result': 'accepted', 'method': m.group(1), 'user': m.group(2), 'ip': m.group(3), 'port': m.group(4)}
    m = _FAIL.search(msg)
    if m:
        return {'time': ts, 'result': 'invalid_user' if m.group(2) else 'failed', 'method': m.group(1),
                'user': m.group(3), 'ip': m.group(4), 'port': m.group(5)}
    m = _INVALID.search(msg)
    if m and 'Failed' not in msg:
        return {'time': ts, 'result': 'invalid_user', 'method': '', 'user': m.group(1) or '?', 'ip': m.group(2), 'port': m.group(3) or ''}
    return None


def _journal(since):
    try:
        out = subprocess.run(['journalctl', '--no-pager', '-o', 'short-unix', '--since', '@%d' % int(since),
                              '_COMM=sshd', '+', '_COMM=sshd-session'],
                             capture_output=True, text=True, timeout=60).stdout
    except Exception:
        return None
    rows = []
    for line in out.splitlines():
        parts = line.split(' ', 2)
        if len(parts) < 3:
            continue
        try:
            ts = float(parts[0])
        except ValueError:
            continue
        rows.append((ts, parts[2]))
    return rows


def _logfile(since):
    for path in ('/var/log/auth.log', '/var/log/secure'):
        if not os.path.exists(path):
            continue
        rows = []
        year = datetime.now().year
        try:
            with open(path, errors='replace') as f:
                for line in f.readlines()[-20000:]:
                    if 'sshd' not in line:
                        continue
                    ts = None
                    m = re.match(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)', line)
                    if m:
                        ts = datetime.fromisoformat(m.group(1)).timestamp()
                    else:
                        m = re.match(r'^([A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)', line)
                        if m:
                            try:
                                ts = datetime.strptime(f'{year} {m.group(1)}', '%Y %b %d %H:%M:%S').timestamp()
                            except ValueError:
                                ts = None
                    if ts and ts >= since:
                        rows.append((ts, line))
        except OSError:
            continue
        return rows
    return []


def events(since=None, days=7, limit=5000):
    since = since or (time.time() - days * 86400)
    rows = _journal(since)
    if not rows:
        rows = _logfile(since)
    out = []
    for ts, msg in rows:
        e = _parse_line(ts, msg)
        if e:
            out.append(e)
    return out[-limit:]


def summary(days=7):
    evs = events(days=days)
    acc = [e for e in evs if e['result'] == 'accepted']
    bad = [e for e in evs if e['result'] != 'accepted']
    by_ip = {}
    for e in bad:
        d = by_ip.setdefault(e['ip'], {'ip': e['ip'], 'count': 0, 'last': 0, 'users': set()})
        d['count'] += 1
        d['last'] = max(d['last'], e['time'])
        d['users'].add(e['user'])
    top = sorted(by_ip.values(), key=lambda x: -x['count'])[:50]
    for t in top:
        t['users'] = sorted(t['users'])[:8]
    return {'accepted': list(reversed(acc))[:200], 'failed_total': len(bad), 'failed_recent': list(reversed(bad))[:200],
            'top_failed_ips': top, 'days': days}
