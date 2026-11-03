#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$("$VP_CURRENT/sbin/pure-ftpd" -h 2>&1 | sed -n 's/^pure-ftpd v\([0-9.]*\).*/\1/p' | head -1)"
[ "$v" = "$VP_VERSION" ] || fail "expected Pure-FTPd $VP_VERSION, found '$v'"
wait_port 21 15 || fail "Pure-FTPd does not listen on port 21"
say "Pure-FTPd $v is running"
