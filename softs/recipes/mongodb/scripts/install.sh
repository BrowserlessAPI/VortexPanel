#!/bin/bash
# System integration for MongoDB (idempotent; runs before the version switch).
# /etc/mongod.conf and the data folder are never replaced.
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/mongo_common.sh"
set -e
DB="$(dbpath)"; U="$(muser)"
ensure_user "$U" "$DB"
if [ ! -e "$CONF" ]; then
  cat > "$CONF" <<CONF
# MongoDB (VortexPanel build)
storage:
  dbPath: $DB
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
net:
  port: 27017
  bindIp: 127.0.0.1
processManagement:
  timeZoneInfo: /usr/share/zoneinfo
CONF
  chmod 0644 "$CONF"
fi
if [ "$VP_ACTION" = migrate ] && [ -d "$DB" ]; then data_backup "$DB" mongod; fi
install -d -m 0755 -o "$U" -g "$(id -gn "$U")" "$DB"
LOG="$(yval path)"
case "$LOG" in /*) install -d -m 0755 -o "$U" -g "$(id -gn "$U")" "$(dirname "$LOG")" ;; esac
for b in mongod mongos mongosh; do [ -e "$VP_PREFIX/bin/$b" ] && link "$VP_CURRENT/bin/$b" "/usr/bin/$b"; done

write_unit mongod.service <<UNIT
[Unit]
Description=MongoDB database server (VortexPanel build)
Documentation=https://docs.mongodb.org/manual
After=network-online.target
Wants=network-online.target

[Service]
User=$U
Group=$(id -gn "$U")
Environment="MONGODB_CONFIG_OVERRIDE_NOFORK=1"
RuntimeDirectory=mongodb
RuntimeDirectoryMode=0755
ExecStart=$VP_CURRENT/bin/mongod --config $CONF
LimitFSIZE=infinity
LimitCPU=infinity
LimitAS=infinity
LimitNOFILE=64000
LimitNPROC=64000
LimitMEMLOCK=infinity
TasksMax=infinity
TasksAccounting=false
TimeoutStopSec=600

[Install]
WantedBy=multi-user.target
UNIT
svc_enable mongod
