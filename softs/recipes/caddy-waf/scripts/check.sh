#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$("$VP_CURRENT/bin/caddy" version | awk '{print $1}' | sed 's/^v//')"
[ "$v" = "$VP_VERSION" ] || fail "expected Caddy $VP_VERSION, found '$v'"
"$VP_CURRENT/bin/caddy" list-modules 2>/dev/null | grep -q '^http.handlers.waf' || fail "the WAF module is not in this Caddy build"
wait_port 80 15 || fail "Caddy does not listen on port 80"
say "Caddy $v with WAF ($(sed -n 's/^caddy-waf //p' "$VP_CURRENT/share/BUILDINFO" 2>/dev/null)) is running"
