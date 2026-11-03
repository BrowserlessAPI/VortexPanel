#!/bin/bash
# System integration for MariaDB (idempotent; runs before the version switch).
# Data and configuration are never replaced: a server switched from the operating
# system's MariaDB keeps /etc/mysql (or /etc/my.cnf.d) and /var/lib/mysql as they are.
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/my_common.sh"
set -e
ensure_user mysql /var/lib/mysql

if ! ldconfig -p | grep -q 'libaio\.so\.1 '; then
  t64="$(ldconfig -p | awk '/libaio\.so\.1t64 /{print $NF; exit}')"
  if [ -n "$t64" ]; then ln -sfn "$(basename "$t64")" "$(dirname "$t64")/libaio.so.1"; ldconfig; say "libaio.so.1 -> $(basename "$t64")"; fi
fi

MAIN="$(main_cnf)"
if [ ! -e /etc/mysql/my.cnf ] && [ ! -e /etc/my.cnf ]; then
  if [ "$MAIN" = /etc/my.cnf ]; then INC=/etc/my.cnf.d; else INC=/etc/mysql/mariadb.conf.d; fi
  install -d -m 0755 "$(dirname "$MAIN")" "$INC"
  cat > "$MAIN" <<CONF
# MariaDB (VortexPanel build). Settings in $INC/*.cnf are read after this file.
[client-server]
socket                = /run/mysqld/mysqld.sock

[mariadbd]
user                  = mysql
datadir               = /var/lib/mysql
pid-file              = /run/mysqld/mariadb.pid
log-error             = /var/log/mysql/error.log
bind-address          = 127.0.0.1
max_connections       = 300
innodb_buffer_pool_size = 256M
character-set-server  = utf8mb4
collation-server      = utf8mb4_unicode_ci

!includedir $INC/
CONF
  chmod 0644 "$MAIN"
fi
ensure_defaults

DATADIR="$(datadir)"
SOCK="$(srv_sock)"
install -d -m 0755 -o mysql -g mysql "$(dirname "$SOCK")"
LOGERR="$(opt mysqld log-error)"
case "$LOGERR" in /*) install -d -o mysql -g mysql "$(dirname "$LOGERR")"; touch "$LOGERR"; chown mysql:mysql "$LOGERR" ;; esac

# MySQL 8's data folder (data dictionary in mysql.ibd) cannot be opened by MariaDB
if [ -e "$DATADIR/mysql.ibd" ]; then
  fail "$DATADIR holds MySQL 8 data. MariaDB cannot use it: uninstall MySQL and move that folder away first (export the databases with mysqldump to bring them over)."
fi

if [ "$VP_ACTION" = migrate ] && [ -d "$DATADIR" ]; then data_backup "$DATADIR" mariadb; fi

if [ ! -d "$DATADIR/mysql" ]; then
  install -d -m 0750 -o mysql -g mysql "$DATADIR"
  [ -z "$(ls -A "$DATADIR" 2>/dev/null | grep -v '^lost+found$')" ] || fail "$DATADIR is not empty but holds no MariaDB data; nothing was changed"
  say "initializing a new data folder in $DATADIR"
  INSTALL_DB=""
  for n in mariadb-install-db mysql_install_db; do [ -z "$INSTALL_DB" ] && [ -x "$VP_PREFIX/scripts/$n" ] && INSTALL_DB="$VP_PREFIX/scripts/$n"; done
  [ -n "$INSTALL_DB" ] || fail "mariadb-install-db is missing from this build"
  # root@localhost signs in over the socket (unix_socket); no password is set
  "$INSTALL_DB" --user=mysql --basedir="$VP_PREFIX" --datadir="$DATADIR" --auth-root-authentication-method=socket \
      --skip-test-db >/dev/null || fail "initializing the data folder failed"
fi

for f in "$VP_PREFIX"/bin/*; do
  b="$(basename "$f")"
  case "$b" in mariadbd|mysqld) link "$VP_CURRENT/bin/$b" "/usr/sbin/$b" ;; *) link "$VP_CURRENT/bin/$b" "/usr/bin/$b" ;; esac
done

write_unit mariadb.service <<UNIT
[Unit]
Description=MariaDB database server (VortexPanel build)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=mysql
Group=mysql
RuntimeDirectory=mysqld
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
ExecStart=$VP_CURRENT/bin/$SERVER_BIN --basedir=$VP_CURRENT --lc-messages-dir=$VP_CURRENT/share --plugin-dir=$VP_CURRENT/lib/plugin
KillSignal=SIGTERM
SendSIGKILL=no
TimeoutStartSec=900
TimeoutStopSec=900
Restart=on-abort
RestartSec=5s
LimitNOFILE=32768
PrivateTmp=false

[Install]
WantedBy=multi-user.target
Alias=mysql.service
Alias=mysqld.service
UNIT
svc_enable mariadb
