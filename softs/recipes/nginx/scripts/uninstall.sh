#!/bin/bash
# Remove the program; /etc/nginx (sites, certificates) is kept.
. "$(dirname "$0")/lib.sh"
svc_stop nginx
has_systemd && systemctl disable nginx >/dev/null 2>&1 || true
[ -s /run/nginx.pid ] && kill -QUIT "$(cat /run/nginx.pid)" 2>/dev/null || true
rm -f /etc/systemd/system/nginx.service
has_systemd && systemctl daemon-reload || true
unlink_ours /usr/sbin/nginx
# a failed switch: give the reinstalled distro nginx its own nginx.conf back
if [ "$VP_ACTION" = abort ] && [ -e /etc/nginx/nginx.conf.vortex-before-switch ]; then
  mv -f /etc/nginx/nginx.conf.vortex-before-switch /etc/nginx/nginx.conf
fi
true
