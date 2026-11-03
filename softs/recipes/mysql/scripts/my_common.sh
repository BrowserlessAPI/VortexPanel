# Shared by the MySQL scripts (sourced after lib.sh).
# The server and client read the usual files: /etc/my.cnf, /etc/mysql/my.cnf and what
# they include. Values the configuration does not set are the panel's defaults.
PD="$VP_PREFIX/bin/my_print_defaults"
[ -x "$PD" ] || PD="$VP_CURRENT/bin/my_print_defaults"
# opt GROUP KEY  (key with - or _)
opt() { "$PD" "$1" 2>/dev/null | sed -nE "s/^--$(echo "$2" | sed 's/[-_]/[-_]/g')=//p" | tail -1; }
datadir()  { local d; d="$(opt mysqld datadir)"; echo "${d:-/var/lib/mysql}"; }
srv_sock() { local s; s="$(opt mysqld socket)"; echo "${s:-/run/mysqld/mysqld.sock}"; }
main_cnf() {
  if [ -e /etc/mysql/my.cnf ]; then echo /etc/mysql/my.cnf
  elif [ -e /etc/my.cnf ]; then echo /etc/my.cnf
  elif [ "${VP_FAMILY:-deb}" = rpm ]; then echo /etc/my.cnf
  else echo /etc/mysql/my.cnf; fi
}
DEFAULTS_NAME=zz-vortexpanel-defaults.cnf
# ensure_defaults: datadir/socket/pid-file for the server and the socket for clients,
# only where the configuration has none (the packaged builds compile those in; this
# build would otherwise use /usr/local/mysql/data and /tmp/mysql.sock)
ensure_defaults() {
  local srv="" cli="" sock text d main
  [ -n "$(opt mysqld datadir)" ] || srv="${srv}datadir = /var/lib/mysql"$'\n'
  [ -n "$(opt mysqld socket)" ]  || srv="${srv}socket = /run/mysqld/mysqld.sock"$'\n'
  [ -n "$(opt mysqld pid-file)" ] || srv="${srv}pid-file = /run/mysqld/mysqld.pid"$'\n'
  sock="$(srv_sock)"
  [ -n "$(opt client socket)" ] || cli="socket = $sock"$'\n'
  [ -n "$srv$cli" ] || return 0
  text="# VortexPanel: values the rest of the configuration does not set"$'\n'
  [ -n "$srv" ] && text="$text[mysqld]"$'\n'"$srv"
  [ -n "$cli" ] && text="$text[client]"$'\n'"$cli"
  for d in /etc/mysql/conf.d /etc/mysql/mysql.conf.d /etc/my.cnf.d /etc/mysql/mariadb.conf.d; do
    [ -d "$d" ] || continue
    printf '%s' "$text" > "$d/$DEFAULTS_NAME"
    if [ -n "$(opt mysqld datadir)" ] && [ -n "$(opt mysqld socket)" ] && [ -n "$(opt client socket)" ]; then
      say "defaults written to $d/$DEFAULTS_NAME"; return 0
    fi
    rm -f "$d/$DEFAULTS_NAME"       # that folder is not read
  done
  main="$(main_cnf)"
  { echo; echo "# --- VortexPanel defaults begin"; printf '%s' "$text"; echo "# --- VortexPanel defaults end"; } >> "$main"
  say "defaults added to $main"
}
remove_defaults() {
  rm -f /etc/mysql/conf.d/$DEFAULTS_NAME /etc/mysql/mysql.conf.d/$DEFAULTS_NAME /etc/my.cnf.d/$DEFAULTS_NAME \
        /etc/mysql/mariadb.conf.d/$DEFAULTS_NAME
  local f
  for f in /etc/mysql/my.cnf /etc/my.cnf; do
    [ -f "$f" ] && grep -q '^# --- VortexPanel defaults begin' "$f" && \
      sed -i --follow-symlinks '/^# --- VortexPanel defaults begin/,/^# --- VortexPanel defaults end/d' "$f"
  done
  true
}
# root over the socket, as the panel connects
sql() { "$VP_CURRENT/bin/mysql" --socket="$(srv_sock)" -uroot -NB "$@"; }
mysqld_pids() { pgrep -x mysqld 2>/dev/null; }
stop_direct() {     # VP_INIT=none: stop a server started without systemd
  local i p
  p="$(mysqld_pids)"; [ -n "$p" ] || return 0
  kill -TERM $p 2>/dev/null
  for i in $(seq 1 120); do [ -z "$(mysqld_pids)" ] && return 0; sleep 1; done
  kill -KILL $(mysqld_pids) 2>/dev/null; true
}
