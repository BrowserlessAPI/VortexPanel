#!/bin/bash
# Remove the program; /etc/memcached.conf or /etc/sysconfig/memcached is kept.
. "$(dirname "$0")/lib.sh"
svc_stop memcached; has_systemd && systemctl disable memcached >/dev/null 2>&1 || true
has_systemd || pkill -x memcached 2>/dev/null || true
rm -f /etc/systemd/system/memcached.service; has_systemd && systemctl daemon-reload || true
unlink_ours /usr/bin/memcached
true
