#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$("$VP_CURRENT/bin/caddy" version | awk '{print $1}' | sed 's/^v//')"
[ "$v" = "$VP_VERSION" ] || fail "expected Caddy $VP_VERSION, found '$v'"
wait_port 80 15 || fail "Caddy does not listen on port 80"
say "Caddy $v is running"
