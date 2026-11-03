#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$(/usr/bin/node --version 2>/dev/null | sed 's/^v//')"
[ "$v" = "$VP_VERSION" ] || fail "expected Node.js $VP_VERSION, found '$v'"
/usr/bin/npm --version >/dev/null 2>&1 || fail "npm does not run"
say "Node.js $v"
