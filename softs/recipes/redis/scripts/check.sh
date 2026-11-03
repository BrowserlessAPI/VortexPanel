#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$("$VP_CURRENT/bin/redis-server" --version | sed -n 's/.*v=\([0-9.]*\).*/\1/p')"
[ "$v" = "$VP_VERSION" ] || fail "expected Redis $VP_VERSION, found '$v'"
# the server's own port and password (requirepass is a normal panel setting)
PORT="$(awk '$1=="port"{print $2}' /etc/redis/redis.conf 2>/dev/null | tail -1)"; PORT="${PORT:-6379}"
export REDISCLI_AUTH="$(awk '$1=="requirepass"{print $2}' /etc/redis/redis.conf 2>/dev/null | tail -1 | tr -d '"')"
[ -n "$REDISCLI_AUTH" ] || unset REDISCLI_AUTH
SOCK="$(awk '$1=="unixsocket"{print $2}' /etc/redis/redis.conf 2>/dev/null | tail -1)"
for i in $(seq 1 15); do
  r="$("$VP_CURRENT/bin/redis-cli" -p "$PORT" ping 2>/dev/null)"
  [ "$r" != PONG ] && [ "$PORT" = 0 ] && [ -n "$SOCK" ] && r="$("$VP_CURRENT/bin/redis-cli" -s "$SOCK" ping 2>/dev/null)"
  [ "$r" = PONG ] && { say "Redis $v answers"; exit 0; }
  sleep 1
done
fail "Redis does not answer PING"
