#!/bin/bash
# System integration for PostgreSQL (idempotent; runs before the version switch).
# A server switched from the operating system's PostgreSQL keeps its cluster: the
# data folder and (Debian/Ubuntu) /etc/postgresql/<major>/main stay as they are.
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/pg_common.sh"
set -e
ensure_user postgres /var/lib/postgresql /bin/bash
install -d -m 2775 -o postgres -g postgres /run/postgresql

if [ -n "$PGDATA" ] && [ -f "$PGDATA/PG_VERSION" ] && [ "$(cat "$PGDATA/PG_VERSION")" != "$MAJOR" ]; then
  fail "this server's PostgreSQL cluster ($PGDATA) is version $(cat "$PGDATA/PG_VERSION"); this build is $MAJOR. A major version change needs pg_upgrade and is never automatic."
fi
if [ -z "$PGDATA" ] || [ ! -f "$PGDATA/PG_VERSION" ]; then
  PGDATA=""; PGOPTS=""
  for d in "/var/lib/postgresql/$MAJOR/main" "/var/lib/pgsql/$MAJOR/data" /var/lib/pgsql/data; do
    if [ -f "$d/PG_VERSION" ] && [ "$(cat "$d/PG_VERSION")" = "$MAJOR" ]; then PGDATA="$d"; break; fi
  done
  if [ "$PGDATA" = "/var/lib/postgresql/$MAJOR/main" ] && [ -f "/etc/postgresql/$MAJOR/main/postgresql.conf" ]; then
    PGOPTS="-c config_file=/etc/postgresql/$MAJOR/main/postgresql.conf"
  fi
  if [ -z "$PGDATA" ] && [ "$VP_ACTION" = migrate ]; then
    other="$(cat /var/lib/postgresql/*/main/PG_VERSION /var/lib/pgsql/*/data/PG_VERSION /var/lib/pgsql/data/PG_VERSION 2>/dev/null | sort -u | tr '\n' ' ')"
    [ -z "$other" ] || fail "this server's PostgreSQL data is version ${other% }; this build is $MAJOR. Choose the ${other% } track, or upgrade the cluster with pg_upgrade first."
  fi
fi
FRESH=""
[ -n "$PGDATA" ] || { PGDATA="/var/lib/postgresql/$MAJOR/main"; FRESH=1; }
install -d -m 0755 /etc/vortex
printf '# VortexPanel PostgreSQL cluster (read by postgresql.service)\nPGDATA=%s\nPGOPTS="%s"\n' "$PGDATA" "$PGOPTS" > "$ENVF"

if [ "$VP_ACTION" = migrate ] && [ -z "$FRESH" ]; then data_backup "$PGDATA" postgresql; fi

if [ -n "$FRESH" ]; then
  install -d -m 0755 -o postgres -g postgres "$(dirname "$PGDATA")"
  install -d -m 0700 -o postgres -g postgres "$PGDATA"
  [ -z "$(ls -A "$PGDATA")" ] || fail "$PGDATA is not empty but holds no PostgreSQL $MAJOR data; nothing was changed"
  say "creating a new cluster in $PGDATA"
  ( cd /tmp && asp "$VP_PREFIX/bin/initdb" -D "$PGDATA" -E UTF8 --locale=C.UTF-8 --auth-local=peer --auth-host=scram-sha-256 >/dev/null ) \
    || ( cd /tmp && rm -rf "${PGDATA:?}"/* && asp "$VP_PREFIX/bin/initdb" -D "$PGDATA" -E UTF8 --no-locale --auth-local=peer --auth-host=scram-sha-256 >/dev/null ) \
    || fail "initdb failed"
fi
chown postgres:postgres "$PGDATA"; chmod 0700 "$PGDATA"

for b in psql pg_dump pg_dumpall pg_restore createdb dropdb createuser dropuser pg_isready vacuumdb reindexdb \
         clusterdb pg_basebackup pg_receivewal pgbench pg_config; do
  [ -e "$VP_PREFIX/bin/$b" ] && link "$VP_CURRENT/bin/$b" "/usr/bin/$b"
done

write_unit postgresql.service <<UNIT
[Unit]
Description=PostgreSQL $MAJOR database server (VortexPanel build)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=postgres
Group=postgres
EnvironmentFile=$ENVF
Environment=PG_OOM_ADJUST_FILE=/proc/self/oom_score_adj
Environment=PG_OOM_ADJUST_VALUE=0
RuntimeDirectory=postgresql
RuntimeDirectoryMode=2775
RuntimeDirectoryPreserve=yes
ExecStart=$VP_CURRENT/bin/postgres -D \${PGDATA} \$PGOPTS
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
KillSignal=SIGINT
TimeoutSec=infinity
OOMScoreAdjust=-900

[Install]
WantedBy=multi-user.target
UNIT
svc_enable postgresql
