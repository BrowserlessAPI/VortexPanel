#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$(/usr/local/lsws/bin/openlitespeed -v 2>&1 | sed -n 's|.*LiteSpeed/\([0-9.]*\).*|\1|p' | head -1)"
[ "$v" = "$VP_VERSION" ] || fail "expected OpenLiteSpeed $VP_VERSION, found '$v'"
for i in $(seq 1 20); do
  /usr/local/lsws/bin/lswsctrl status 2>/dev/null | grep -q 'running' && { say "OpenLiteSpeed $v is running"; exit 0; }
  sleep 1
done
fail "OpenLiteSpeed is not running (see /usr/local/lsws/logs/error.log)"
