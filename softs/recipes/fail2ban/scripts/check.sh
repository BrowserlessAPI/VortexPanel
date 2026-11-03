#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$("$VP_CURRENT/bin/fail2ban-client" --version 2>/dev/null | sed -n 's/.*v\([0-9][0-9.]*\).*/\1/p' | head -1)"
[ "$v" = "$VP_VERSION" ] || fail "expected Fail2ban $VP_VERSION, found '$v'"
for i in $(seq 1 20); do
  "$VP_CURRENT/bin/fail2ban-client" ping 2>/dev/null | grep -q pong && { say "Fail2ban $v answers"; exit 0; }
  sleep 1
done
fail "fail2ban-server does not answer"
