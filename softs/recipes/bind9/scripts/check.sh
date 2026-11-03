#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$("$VP_CURRENT/sbin/named" -v 2>/dev/null | awk '{print $2}')"
[ "$v" = "$VP_VERSION" ] || fail "expected BIND $VP_VERSION, found '$v'"
for i in $(seq 1 30); do
  "$VP_CURRENT/sbin/rndc" status 2>/dev/null | grep -q 'server is up and running' && { say "BIND $v answers"; exit 0; }
  sleep 1
done
fail "named does not answer rndc status"
