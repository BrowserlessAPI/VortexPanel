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
  if has_systemd; then journalctl -u pure-ftpd -n 20 --no-pager 2>/dev/null; else tail -20 /var/log/pure-ftpd.vortex.log 2>/dev/null; fi
  fail "Pure-FTPd does not listen on port 21"
fi
say "Pure-FTPd $v is running"
