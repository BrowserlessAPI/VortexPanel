#!/bin/bash
# Remove the program. /etc/mongod.conf and the data are kept.
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/mongo_common.sh"
svc_stop mongod
has_systemd && systemctl disable mongod >/dev/null 2>&1 || true
has_systemd || stop_direct
rm -f /etc/systemd/system/mongod.service
has_systemd && systemctl daemon-reload || true
for b in mongod mongos mongosh; do unlink_ours "/usr/bin/$b"; done
if [ "$VP_ACTION" = abort ]; then data_restore "$(dbpath)" mongod; fi
true
