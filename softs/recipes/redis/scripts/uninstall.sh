#!/bin/bash
. "$(dirname "$0")/lib.sh"
svc_stop redis-server; has_systemd && systemctl disable redis-server >/dev/null 2>&1 || true
rm -f /etc/systemd/system/redis-server.service; has_systemd && systemctl daemon-reload || true
for b in redis-server redis-cli redis-benchmark redis-check-aof redis-check-rdb redis-sentinel; do unlink_ours "/usr/bin/$b"; done
