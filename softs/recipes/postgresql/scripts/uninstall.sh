#!/bin/bash
# Remove the program. The cluster (data and configuration) is kept.
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/pg_common.sh"
svc_stop postgresql
has_systemd && systemctl disable postgresql >/dev/null 2>&1 || true
has_systemd || stop_direct
rm -f /etc/systemd/system/postgresql.service
has_systemd && systemctl daemon-reload || true
for b in psql pg_dump pg_dumpall pg_restore createdb dropdb createuser dropuser pg_isready vacuumdb reindexdb \
         clusterdb pg_basebackup pg_receivewal pgbench pg_config; do
  unlink_ours "/usr/bin/$b"
done
if [ "$VP_ACTION" = abort ] && [ -n "$PGDATA" ]; then
  # a failed switch: the operating system's PostgreSQL gets its data back as it was
  data_restore "$PGDATA" postgresql
fi
rm -f "$ENVF"; rmdir /etc/vortex 2>/dev/null
true
