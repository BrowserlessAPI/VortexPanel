#!/bin/bash
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/mongo_common.sh"
if has_systemd; then
  systemctl restart mongod
else
  stop_direct
  U="$(muser)"
  runuser -u "$U" -- "$VP_CURRENT/bin/mongod" --config "$CONF" --fork --logpath /var/log/mongodb/mongod-direct.log \
    >/dev/null 2>&1 || runuser -u "$U" -- "$VP_CURRENT/bin/mongod" --config "$CONF" --fork
fi
