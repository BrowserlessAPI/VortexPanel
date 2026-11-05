#!/bin/bash
. "$(dirname "$0")/lib.sh"
out="$(/usr/bin/node --version 2>&1)"
v="$(echo "$out" | sed -n 's/^v\([0-9.]*\)$/\1/p')"
[ "$v" = "$VP_VERSION" ] || fail "expected Node.js $VP_VERSION, node says: $(echo "$out" | head -3)"
/usr/bin/npm --version >/dev/null 2>&1 || fail "npm does not run: $(/usr/bin/npm --version 2>&1 | head -3)"
say "Node.js $v"
