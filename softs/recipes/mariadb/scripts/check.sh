#!/bin/bash
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/my_common.sh"
v="$("$VP_CURRENT/bin/$SERVER_BIN" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+-MariaDB' | head -1)"
v="${v%-MariaDB}"
[ "$v" = "$VP_VERSION" ] || fail "expected MariaDB $VP_VERSION, found '$v'"
for i in $(seq 1 600); do
  r="$(sql -e 'SELECT VERSION()' 2>/dev/null)"
  case "$r" in
    "$VP_VERSION"*)
      # system tables of the new version (a no-op when they are current)
      if [ "$VP_ACTION" != install ]; then
        UP=""; for n in mariadb-upgrade mysql_upgrade; do [ -z "$UP" ] && [ -x "$VP_CURRENT/bin/$n" ] && UP="$VP_CURRENT/bin/$n"; done
        [ -n "$UP" ] && { "$UP" --socket="$(srv_sock)" -uroot --silent >/dev/null 2>&1 || say "warning: mariadb-upgrade reported a problem; run it by hand"; }
      fi
      say "MariaDB $r answers as root over $(srv_sock)"; exit 0 ;;
  esac
  if [ -z "$r" ] && "$VP_CURRENT/bin/mariadb" --socket="$(srv_sock)" -uroot -e 'SELECT 1' 2>&1 | grep -q 'Access denied'; then
    say "MariaDB $v is running (root needs a password here, so the panel's socket login is not available)"; exit 0
  fi
  if has_systemd && ! systemctl is-active --quiet mariadb && [ "$i" -gt 5 ]; then
    systemctl status mariadb --no-pager -l 2>&1 | tail -15; fail "mariadb is not running"
  fi
  sleep 1
done
fail "MariaDB does not answer as root over $(srv_sock)"
