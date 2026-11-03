#!/bin/bash
. "$(dirname "$0")/lib.sh"
V="$VP_TRACK"
got="$("/usr/bin/php$V" -r 'echo PHP_VERSION;' 2>/dev/null)"
[ "$got" = "$VP_VERSION" ] || fail "expected PHP $VP_VERSION, found '$got'"
for i in $(seq 1 15); do [ -S "/run/php/php$V-fpm.sock" ] && break; sleep 1; done
[ -S "/run/php/php$V-fpm.sock" ] || fail "php$V-fpm socket is missing"
"/usr/bin/php$V" -m | grep -qi '^mysqli$' || fail "mysqli extension does not load"
# every extension switched on for PHP-FPM must load with this version
LOADED="$("$VP_CURRENT/sbin/php-fpm" -c "/etc/php/$V/fpm/php.ini" -m 2>&1 | tr 'A-Z' 'a-z')"
echo "$LOADED" | grep -qi 'warning\|unable to load' && fail "PHP-FPM $VP_VERSION reports: $(echo "$LOADED" | grep -i 'warning\|unable' | head -2)"
for l in /etc/php/$V/fpm/conf.d/*.ini; do
  name="$(grep -oE '^[[:space:]]*(zend_)?extension[[:space:]]*=[[:space:]]*[^[:space:];]+' "$l" 2>/dev/null | head -1 | sed -E 's/.*=[[:space:]]*//; s/\.so$//; s|.*/||')"
  [ -n "$name" ] || continue
  [ "$name" = opcache ] && name="zend opcache"
  echo "$LOADED" | grep -qx "$name" || fail "extension $name is switched on but does not load in $VP_VERSION"
done
say "PHP $got is running"
