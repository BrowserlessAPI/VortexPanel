#!/usr/bin/python3 -I
"""sendmail for the websites of hosting accounts (PHP sendmail_path).

Asks the panel's counter (a local socket that knows which Linux user is
calling) whether the account may still send today, then hands the message to
the real sendmail. When the counter is not reachable the message is sent:
counting never blocks mail.
"""
import os
import re
import socket
import subprocess
import sys

SOCK = '/run/vortexpanel/mailcount.sock'
SENDMAIL = '/usr/sbin/sendmail'
VALUE_OPTS = {'-f', '-F', '-O', '-o', '-B', '-N', '-R', '-V', '-X', '-L', '-r', '-C', '-h', '-p'}


def recipients(args, data):
    n = 0
    prev = ''
    for a in args:
        if not a.startswith('-') and prev not in VALUE_OPTS and '@' in a:
            n += 1
        prev = a
    if '-t' in args:
        head = re.split(rb'\r?\n\r?\n', data, maxsplit=1)[0].decode('utf-8', 'replace')
        head = re.sub(r'\r?\n[ \t]+', ' ', head)
        for line in head.splitlines():
            name, _, value = line.partition(':')
            # with Resent-* headers Postfix sends to those instead: count both
            if name.strip().lower() in ('to', 'cc', 'bcc', 'resent-to', 'resent-cc', 'resent-bcc'):
                n += len(re.findall(r'[^\s<>,;"]+@[^\s<>,;"]+', value))
    return max(1, n)


def main():
    args = sys.argv[1:]
    data = sys.stdin.buffer.read()
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(SOCK)
        s.sendall(f'count {recipients(args, data)}\n'.encode())
        reply = s.makefile('rb').readline().decode('utf-8', 'replace').strip()
        s.close()
        if reply.startswith('REJECT'):
            sys.stderr.write(reply[6:].strip() + '\n')
            return 1
    except OSError:
        pass
    return subprocess.run([SENDMAIL] + args, input=data).returncode


if __name__ == '__main__':
    sys.exit(main())
