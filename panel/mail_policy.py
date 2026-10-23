#!/usr/bin/python3
"""Postfix policy service: daily sending limits per mailbox, per domain and per
hosting account. Started by Postfix (master.cf "vppolicy ... spawn user=vmail"),
checked at the end of every message a signed-in mailbox sends. Standard library
only (runs with the system Python, not the panel's virtualenv).

Limits:  /etc/postfix/vp_limits.json (written by the panel)
Counts:  /var/lib/vortexpanel/mail/counts.db (sqlite, one row per day and key)
Events:  /var/lib/vortexpanel/mail/events.jsonl (a mailbox or account reached its limit)

Website mail of hosting accounts (PHP mail() through vp_sendmail.py):
  mail_policy.py --peer      one connection on stdin (systemd socket, Accept=yes); the
                             caller's Linux UID (SO_PEERCRED) picks the account
  mail_policy.py --count <group> <recipients> [<sender>]   exit 0 = allowed, 1 = over the limit
"""
import datetime
import json
import os
import socket
import sqlite3
import struct
import sys
import time

LIMITS = '/etc/postfix/vp_limits.json'
STATE = '/var/lib/vortexpanel/mail'
DB = os.path.join(STATE, 'counts.db')
EVENTS = os.path.join(STATE, 'events.jsonl')


def load_limits():
    try:
        with open(LIMITS) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def db():
    con = sqlite3.connect(DB, timeout=10, isolation_level=None)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('CREATE TABLE IF NOT EXISTS counts (day TEXT, key TEXT, n INTEGER, PRIMARY KEY (day, key))')
    con.execute('CREATE TABLE IF NOT EXISTS alerted (day TEXT, key TEXT, PRIMARY KEY (day, key))')
    return con


def limits_for(sender, lim, group=None):
    """[(key, limit, label)] that apply to a message from this sender."""
    sender = (sender or '').lower()
    dom = sender.split('@', 1)[1] if '@' in sender else ''
    grp_name, grp = None, None
    for name, g in (lim.get('groups') or {}).items():
        if (group and name == group) or (dom and dom in (g.get('domains') or [])):
            grp_name, grp = name, g
            break
    out = []
    if sender and '@' in sender:
        if sender in (lim.get('mailbox') or {}):
            m = int(lim['mailbox'][sender])
        elif grp is not None and 'mailbox_limit' in grp:
            m = int(grp['mailbox_limit'])
        else:
            m = int(lim.get('default_mailbox', 0) or 0)
        out.append((f'mbx:{sender}', m, sender))
    if grp is not None:
        # no own number: the server's per-domain default applies to the account
        out.append((f'grp:{grp_name}', int(grp.get('limit', lim.get('default_domain', 0)) or 0), f'account {grp_name}'))
    elif dom:
        d = (lim.get('domain') or {}).get(dom, lim.get('default_domain', 0))
        out.append((f'dom:{dom}', int(d or 0), dom))
    return out


def check_and_count(sender, recipients, group=None):
    """(allowed, message). Counts only when allowed."""
    lim = load_limits()
    keys = limits_for(sender, lim, group)
    if not keys:
        return True, ''
    day = datetime.date.today().isoformat()
    n = max(1, int(recipients or 1))
    con = None
    try:
        con = db()
        con.execute('BEGIN IMMEDIATE')
        for key, limit, label in keys:
            row = con.execute('SELECT n FROM counts WHERE day=? AND key=?', (day, key)).fetchone()
            used = row[0] if row else 0
            if limit and used + n > limit:
                ref = f'refused:{sender or group}'
                con.execute('INSERT INTO counts (day, key, n) VALUES (?, ?, ?) '
                            'ON CONFLICT(day, key) DO UPDATE SET n = n + excluded.n', (day, ref, n))
                first = con.execute('INSERT OR IGNORE INTO alerted (day, key) VALUES (?, ?)', (day, key)).rowcount
                con.execute('COMMIT')
                if first and lim.get('events', True):
                    try:
                        with open(EVENTS, 'a') as f:
                            f.write(json.dumps({'time': int(time.time()), 'key': key, 'label': label,
                                                'limit': limit, 'sender': sender}) + '\n')
                    except OSError:
                        pass
                return False, (f'Daily sending limit reached for {label} ({limit} emails per day). '
                               'Try again tomorrow or ask your host for a higher limit.')
        for key, limit, label in keys:
            con.execute('INSERT INTO counts (day, key, n) VALUES (?, ?, ?) '
                        'ON CONFLICT(day, key) DO UPDATE SET n = n + excluded.n', (day, key, n))
        con.execute('DELETE FROM counts WHERE day < ?', ((datetime.date.today() - datetime.timedelta(days=40)).isoformat(),))
        con.execute('DELETE FROM alerted WHERE day < ?', (day,))
        con.execute('COMMIT')
        return True, ''
    except Exception:  # noqa: BLE001 - never block mail because of a counter problem
        try:
            if con is not None:
                con.execute('ROLLBACK')
        except Exception:  # noqa: BLE001
            pass
        return True, ''
    finally:
        if con is not None:
            con.close()


def serve():
    attrs = {}
    for line in sys.stdin:
        line = line.rstrip('\n')
        if line:
            k, _, v = line.partition('=')
            attrs[k] = v
            continue
        action = 'DUNNO'
        user = attrs.get('sasl_username', '')
        if user and attrs.get('protocol_state', '').upper() == 'END-OF-MESSAGE':
            sender = user if '@' in user else attrs.get('sender', '')
            try:
                rc = int(attrs.get('recipient_count') or 1)
            except ValueError:
                rc = 1
            ok, msg = check_and_count(sender, rc)
            if not ok:
                action = 'REJECT 5.7.1 ' + msg
        sys.stdout.write(f'action={action}\n\n')
        sys.stdout.flush()
        attrs = {}


def peer():
    """One website-mail check: 'count <n>' -> 'OK' or 'REJECT <message>'."""
    conn = socket.socket(fileno=0)
    try:
        _pid, uid, _gid = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                              struct.calcsize('3i')))
        line = conn.makefile('rb').readline(200).decode('ascii', 'replace').split()
        n = int(line[1]) if len(line) == 2 and line[0] == 'count' else 1
        group = (load_limits().get('uids') or {}).get(str(uid))
        ok, msg = check_and_count('', n, group=group) if group else (True, '')
        conn.sendall(b'OK\n' if ok else ('REJECT ' + msg + '\n').encode())
    except Exception:  # noqa: BLE001
        try:
            conn.sendall(b'OK\n')
        except OSError:
            pass
    finally:
        conn.close()


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '--peer':
        peer()
        sys.exit(0)
    if len(sys.argv) >= 4 and sys.argv[1] == '--count':
        ok, msg = check_and_count(sys.argv[4] if len(sys.argv) > 4 else '', sys.argv[3], group=sys.argv[2])
        if not ok:
            sys.stderr.write(msg + '\n')
        sys.exit(0 if ok else 1)
    serve()
