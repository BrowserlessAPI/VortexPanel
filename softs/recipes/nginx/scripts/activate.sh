#!/bin/bash
# Test the configuration with the (new) binary, then restart without dropping it if the test fails.
. "$(dirname "$0")/lib.sh"
"$VP_CURRENT/sbin/nginx" -t -q -c /etc/nginx/nginx.conf || fail "nginx -t rejected the configuration with $VP_VERSION"
if has_systemd; then
  # a binary upgrade needs a restart (a reload keeps the old binary running)
  systemctl restart nginx
else
  [ -s /run/nginx.pid ] && kill -QUIT "$(cat /run/nginx.pid)" 2>/dev/null; sleep 1
  "$VP_CURRENT/sbin/nginx" -c /etc/nginx/nginx.conf
fi
