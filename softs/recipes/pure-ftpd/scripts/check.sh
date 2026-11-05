#!/bin/bash
. "$(dirname "$0")/lib.sh"
B="$VP_CURRENT/sbin/pure-ftpd"
[ -x "$B" ] || fail "$B is missing from this build"
out="$("$B" -h 2>&1 </dev/null)"
v="$(echo "$out" | sed -n 's/^pure-ftpd v\([0-9.]*\).*/\1/p' | head -1)"
# the version is also in the program itself ("pure-ftpd v1.0.54 [privsep]")
[ -n "$v" ] || v="$(grep -aoE 'pure-ftpd v[0-9]+\.[0-9]+\.[0-9]+' "$B" | head -1 | sed 's/^pure-ftpd v//')"
if [ "$v" != "$VP_VERSION" ]; then
  echo "pure-ftpd -h said: $(echo "$out" | head -5)"
  [ -f /var/log/pure-ftpd.vortex.log ] && { echo "start log:"; tail -15 /var/log/pure-ftpd.vortex.log; }
  fail "expected Pure-FTPd $VP_VERSION, found '$v'"
fi
if ! wait_port 21 15; then
  if has_systemd; then journalctl -u pure-ftpd -n 20 --no-pager 2>/dev/null
  else
    tail -20 /var/log/pure-ftpd.vortex.log 2>/dev/null
    # pure-ftpd reports why it stops only to syslog: without a syslog (containers), listen
    # on /dev/log for a few seconds while it starts again, and show what it says
    if [ ! -S /dev/log ] && command -v python3 >/dev/null; then
      python3 - <<'PY' &
import socket, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.bind('/dev/log'); s.settimeout(1)
end = time.time() + 8
while time.time() < end:
    try:
        print('syslog:', s.recv(4096).decode(errors='replace'), flush=True)
    except OSError:
        pass
PY
      sleep 1
      pkill -x pure-ftpd 2>/dev/null; "$VP_CURRENT/sbin/vp-pure-ftpd-run" >/dev/null 2>&1 &
      sleep 8; rm -f /dev/log
    fi
  fi
  echo "configuration in use:"; grep -vE '^\s*(#|$)' /run/pure-ftpd/pure-ftpd.conf 2>/dev/null | head -40
  fail "Pure-FTPd does not listen on port 21"
fi
say "Pure-FTPd $v is running"
