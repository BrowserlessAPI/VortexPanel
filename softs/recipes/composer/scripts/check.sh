#!/bin/bash
. "$(dirname "$0")/lib.sh"
command -v php >/dev/null 2>&1 || { say "PHP is not installed yet; Composer $VP_VERSION is in place"; exit 0; }
v="$(COMPOSER_ALLOW_SUPERUSER=1 /usr/local/bin/composer --version --no-ansi 2>/dev/null | awk '{print $3}')"
[ "$v" = "$VP_VERSION" ] || fail "expected Composer $VP_VERSION, found '$v'"
say "Composer $v"
