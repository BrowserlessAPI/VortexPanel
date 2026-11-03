# Shared by the PostgreSQL scripts (sourced after lib.sh).
# /etc/vortex/postgresql.env names the cluster this build runs:
#   PGDATA  the data folder;  PGOPTS  "-c config_file=..." when the configuration lives
#   outside the data folder (Debian/Ubuntu clusters: /etc/postgresql/<major>/main).
ENVF=/etc/vortex/postgresql.env
MAJOR="${VP_VERSION%%.*}"
PGDATA=""; PGOPTS=""
[ -f "$ENVF" ] && . "$ENVF"
asp() { runuser -u postgres -- "$@"; }
pgval() { asp "$VP_CURRENT/bin/postgres" -D "$PGDATA" $PGOPTS -C "$1" 2>/dev/null | tail -1; }
pg_running() { [ -n "$PGDATA" ] && asp "$VP_CURRENT/bin/pg_ctl" -D "$PGDATA" status >/dev/null 2>&1; }
stop_direct() {     # VP_INIT=none: stop a server started without systemd
  [ -n "$PGDATA" ] && [ -f "$PGDATA/postmaster.pid" ] || return 0
  local b="$VP_CURRENT/bin/pg_ctl"; [ -x "$b" ] || b="$VP_PREFIX/bin/pg_ctl"
  asp "$b" -D "$PGDATA" -m fast -w -t 300 stop >/dev/null 2>&1 || true
}
