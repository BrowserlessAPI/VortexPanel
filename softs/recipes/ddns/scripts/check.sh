#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$("$VP_CURRENT/sbin/ddclient" --version=short 2>/dev/null)"
[ "$v" = "$VP_VERSION" ] || fail "expected ddclient $VP_VERSION, found '$v'"
for i in $(seq 1 10); do
  if has_systemd; then systemctl is-active --quiet ddclient && { say "ddclient $v is running"; exit 0; }
  else pgrep -f '(^|/)ddclient( |$)' >/dev/null && { say "ddclient $v is running"; exit 0; }; fi
  sleep 1
done
fail "ddclient does not stay running (check the configuration file)"
