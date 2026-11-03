#!/bin/bash
. "$(dirname "$0")/lib.sh"
set -e
for b in node npm npx corepack; do [ -e "$VP_PREFIX/bin/$b" ] && link "$VP_CURRENT/bin/$b" "/usr/bin/$b"; done
true
