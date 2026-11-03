#!/bin/bash
. "$(dirname "$0")/lib.sh"
if has_systemd; then systemctl restart redis-server
else
  "$VP_CURRENT/bin/redis-cli" shutdown nosave >/dev/null 2>&1 || true; sleep 1; mkdir -p /run/redis; chown redis:redis /run/redis
  su -s /bin/sh redis -c "$VP_CURRENT/bin/redis-server /etc/redis/redis.conf --daemonize yes --supervised no"
fi
