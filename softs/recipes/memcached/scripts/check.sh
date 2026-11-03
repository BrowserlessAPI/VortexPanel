#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$("$VP_CURRENT/bin/memcached" -V 2>/dev/null | awk '{print $2}')"
[ "$v" = "$VP_VERSION" ] || fail "expected Memcached $VP_VERSION, found '$v'"
PORT=11211
if [ -f /etc/memcached.conf ]; then
  p="$(sed -n 's/^[[:space:]]*-p[[:space:]]\{1,\}\([0-9]\{1,\}\).*/\1/p' /etc/memcached.conf | tail -1)"; PORT="${p:-11211}"
elif [ -f /etc/sysconfig/memcached ]; then
  p="$(. /etc/sysconfig/memcached; echo "${PORT:-}")"; PORT="${p:-11211}"
fi
if [ "$PORT" != 0 ] && wait_port "$PORT" 15; then say "Memcached $v answers on port $PORT"; exit 0; fi
# listening on another address or only on a socket: the process must at least be running
for i in $(seq 1 10); do pgrep -x memcached >/dev/null && { say "Memcached $v is running"; exit 0; }; sleep 1; done
fail "Memcached does not start"
