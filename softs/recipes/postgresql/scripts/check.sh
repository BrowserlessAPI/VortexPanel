#!/bin/bash
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/pg_common.sh"
v="$("$VP_CURRENT/bin/postgres" --version | awk '{print $NF}')"
[ "$v" = "$VP_VERSION" ] || fail "expected PostgreSQL $VP_VERSION, found '$v'"
cd /tmp
PORT="$(pgval port)"; PORT="${PORT:-5432}"
SOCK="$(pgval unix_socket_directories | cut -d, -f1 | tr -d " '")"; SOCK="${SOCK:-/run/postgresql}"
for i in $(seq 1 300); do
  r="$(asp "$VP_CURRENT/bin/psql" -XAt -h "$SOCK" -p "$PORT" -d postgres -c 'SHOW server_version' 2>/dev/null)"
  case "$r" in "$VP_VERSION"*) say "PostgreSQL $r answers to the postgres user on $SOCK port $PORT"; exit 0 ;; esac
  if has_systemd && ! systemctl is-active --quiet postgresql && [ "$i" -gt 5 ]; then
    systemctl status postgresql --no-pager -l 2>&1 | tail -15; fail "postgresql is not running"
  fi
  sleep 1
done
fail "PostgreSQL does not answer on $SOCK port $PORT"
