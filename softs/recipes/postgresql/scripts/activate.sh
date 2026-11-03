#!/bin/bash
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/pg_common.sh"
if has_systemd; then
  systemctl restart postgresql
else
  stop_direct
  install -d -m 2775 -o postgres -g postgres /run/postgresql
  touch /var/log/vortex-postgresql.log; chown postgres:postgres /var/log/vortex-postgresql.log
  ( cd /tmp && asp "$VP_CURRENT/bin/pg_ctl" -D "$PGDATA" ${PGOPTS:+-o "$PGOPTS"} -l /var/log/vortex-postgresql.log -w -t 300 start )
fi
