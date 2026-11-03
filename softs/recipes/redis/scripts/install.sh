#!/bin/bash
. "$(dirname "$0")/lib.sh"
set -e
ensure_user redis /var/lib/redis
install -d -m 0750 -o redis -g redis /var/lib/redis /var/log/redis
install -d -m 0755 /etc/redis
if [ ! -e /etc/redis/redis.conf ]; then
  sed -e 's/^bind .*/bind 127.0.0.1 -::1/' -e 's/^daemonize .*/daemonize no/' -e 's/^# *supervised .*/supervised systemd/' \
      -e 's|^dir .*|dir /var/lib/redis|' -e 's|^logfile .*|logfile /var/log/redis/redis-server.log|' \
      -e 's|^pidfile .*|pidfile /run/redis/redis-server.pid|' "$VP_PREFIX/share/redis.conf" > /etc/redis/redis.conf
  chown redis:redis /etc/redis/redis.conf; chmod 0640 /etc/redis/redis.conf
fi
for b in redis-server redis-cli redis-benchmark redis-check-aof redis-check-rdb redis-sentinel; do
  [ -e "$VP_PREFIX/bin/$b" ] && link "$VP_CURRENT/bin/$b" "/usr/bin/$b"
done
write_unit redis-server.service <<UNIT
[Unit]
Description=Redis data store (VortexPanel build)
After=network.target

[Service]
Type=notify
User=redis
Group=redis
RuntimeDirectory=redis
RuntimeDirectoryMode=0755
ExecStart=$VP_CURRENT/bin/redis-server /etc/redis/redis.conf --supervised systemd --daemonize no
ExecStop=$VP_CURRENT/bin/redis-cli shutdown
Restart=always
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
Alias=redis.service
UNIT
svc_enable redis-server
