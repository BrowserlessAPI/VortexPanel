#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$("$VP_CURRENT/bin/supervisord" --version 2>/dev/null)"
[ "$v" = "$VP_VERSION" ] || fail "expected Supervisor $VP_VERSION, found '$v'"
if [ -e /etc/supervisor/supervisord.conf ]; then CONF=/etc/supervisor/supervisord.conf; else CONF=/etc/supervisord.conf; fi
for i in $(seq 1 15); do
  p="$("$VP_CURRENT/bin/supervisorctl" -c "$CONF" pid 2>/dev/null)"
  [[ "$p" =~ ^[0-9]+$ ]] && { say "Supervisor $v is running (pid $p)"; exit 0; }
  sleep 1
done
fail "supervisord does not answer supervisorctl"
