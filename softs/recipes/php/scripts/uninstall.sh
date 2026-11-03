#!/bin/bash
# Remove PHP X.Y (its /etc/php/X.Y configuration is kept).
. "$(dirname "$0")/lib.sh"
V="$VP_TRACK"
svc_stop "php$V-fpm"
has_systemd && systemctl disable "php$V-fpm" >/dev/null 2>&1 || true
[ -s "/run/php/php$V-fpm.pid" ] && kill -QUIT "$(cat "/run/php/php$V-fpm.pid")" 2>/dev/null || true
rm -f "/etc/systemd/system/php$V-fpm.service"
has_systemd && systemctl daemon-reload || true
grep -q "VortexPanel PHP $V" "/usr/bin/php$V" 2>/dev/null && rm -f "/usr/bin/php$V"
unlink_ours "/usr/sbin/php-fpm$V"
for t in phpize php-config; do unlink_ours "/usr/bin/$t$V"; done
[ "$(readlink /usr/bin/php)" = "/usr/bin/php$V" ] && rm -f /usr/bin/php
# a failed switch: put the distro PHP's extension links back
if [ "$VP_ACTION" = abort ]; then
  for sapi in fpm cli; do
    d="/etc/php/$V/$sapi/conf.d.vortex-switch"
    [ -d "$d" ] && { mv -f "$d"/* "/etc/php/$V/$sapi/conf.d/" 2>/dev/null; rmdir "$d"; }
  done
fi
true
