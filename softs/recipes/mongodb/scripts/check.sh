#!/bin/bash
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/mongo_common.sh"
v="$("$VP_CURRENT/bin/mongod" --version | sed -n 's/^db version v\([0-9.]*\).*/\1/p')"
[ "$v" = "$VP_VERSION" ] || fail "expected MongoDB $VP_VERSION, found '$v'"
PORT="$(mport)"
for i in $(seq 1 300); do
  # ping and buildInfo need no login, also on a server with authorization enabled
  # the local socket first: it works when bindIp is a private address only or TLS is required
  r=""
  for pre in "$(yval pathPrefix)" /tmp; do
    [ -n "$pre" ] && [ -S "$pre/mongodb-$PORT.sock" ] || continue
    r="$("$VP_CURRENT/bin/mongosh" --quiet "mongodb://$(printf '%s' "$pre/mongodb-$PORT.sock" | sed 's|/|%2F|g')" \
          --eval 'db.adminCommand({ping:1}).ok + " " + db.version()' 2>/dev/null | tail -1)"
    break
  done
  [ -n "$r" ] || r="$("$VP_CURRENT/bin/mongosh" --quiet --port "$PORT" --eval 'db.adminCommand({ping:1}).ok + " " + db.version()' 2>/dev/null | tail -1)"
  case "$r" in "1 $VP_VERSION") say "MongoDB $VP_VERSION answers on port $PORT"; exit 0 ;; esac
  if has_systemd && ! systemctl is-active --quiet mongod && [ "$i" -gt 5 ]; then
    systemctl status mongod --no-pager -l 2>&1 | tail -15; fail "mongod is not running"
  fi
  sleep 1
done
fail "MongoDB does not answer on port $PORT"
