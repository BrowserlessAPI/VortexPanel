#!/bin/bash
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/my_common.sh"
v="$("$VP_CURRENT/bin/mysqld" --version 2>&1 | sed -n 's/.*Ver \([0-9.]*\).*/\1/p')"
[ "$v" = "$VP_VERSION" ] || fail "expected MySQL $VP_VERSION, found '$v'"
# a data upgrade after a version change can take a while on a big server
for i in $(seq 1 600); do
  r="$(sql -e 'SELECT VERSION()' 2>/dev/null)"
  case "$r" in "$VP_VERSION"*) say "MySQL $r answers as root over $(srv_sock)"; exit 0 ;; esac
  # root with a password (set outside the panel): the server answering is enough
  if [ -z "$r" ] && "$VP_CURRENT/bin/mysql" --socket="$(srv_sock)" -uroot -e 'SELECT 1' 2>&1 | grep -q 'Access denied'; then
    say "MySQL $v is running (root needs a password here, so the panel's socket login is not available)"; exit 0
  fi
  if has_systemd && ! systemctl is-active --quiet mysql && [ "$i" -gt 5 ]; then
    systemctl status mysql --no-pager -l 2>&1 | tail -15; fail "mysql is not running"
  fi
  sleep 1
done
fail "MySQL does not answer as root over $(srv_sock)"
