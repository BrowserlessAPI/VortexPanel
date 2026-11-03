#!/bin/bash
. "$(dirname "$0")/lib.sh"
V="$VP_TRACK"; ETC=/etc/php/$V
"$VP_CURRENT/sbin/php-fpm" -t -y "$ETC/fpm/php-fpm.conf" -c "$ETC/fpm/php.ini" >/dev/null 2>&1 \
  || fail "php-fpm $VP_VERSION rejected the configuration"
if has_systemd; then
  systemctl restart "php$V-fpm"
else
  [ -s "/run/php/php$V-fpm.pid" ] && kill -QUIT "$(cat "/run/php/php$V-fpm.pid")" 2>/dev/null; sleep 1
  mkdir -p /run/php
  "$VP_CURRENT/sbin/php-fpm" -y "$ETC/fpm/php-fpm.conf" -c "$ETC/fpm/php.ini"
fi
