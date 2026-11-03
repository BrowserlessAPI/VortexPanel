#!/bin/bash
# System integration for MySQL (idempotent; runs before the version switch).
# Data and configuration are never replaced: a server switched from the operating
# system's MySQL keeps /etc/mysql (or /etc/my.cnf) and /var/lib/mysql as they are.
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/my_common.sh"
set -e
ensure_user mysql /var/lib/mysql

# Ubuntu 24.04 / Debian 13 name the AIO library libaio.so.1t64
if ! ldconfig -p | grep -q 'libaio\.so\.1 '; then
  t64="$(ldconfig -p | awk '/libaio\.so\.1t64 /{print $NF; exit}')"
  if [ -n "$t64" ]; then ln -sfn "$(basename "$t64")" "$(dirname "$t64")/libaio.so.1"; ldconfig; say "libaio.so.1 -> $(basename "$t64")"; fi
fi

# Ubuntu's mysql-server registered /etc/mysql/mysql.cnf as the my.cnf alternative; once
# that package is removed, my.cnf falls back to a file that does not read mysql.conf.d,
# and the server's own settings (bind-address, buffers, sql_mode) would be ignored
if [ -f /etc/mysql/mysql.cnf ] && [ -d /etc/mysql/mysql.conf.d ] && \
   [ "$(readlink -f /etc/mysql/my.cnf 2>/dev/null)" != /etc/mysql/mysql.cnf ]; then
  if [ -L /etc/mysql/my.cnf ] && command -v update-alternatives >/dev/null 2>&1; then
    update-alternatives --install /etc/mysql/my.cnf my.cnf /etc/mysql/mysql.cnf 200 >/dev/null
    update-alternatives --set my.cnf /etc/mysql/mysql.cnf >/dev/null
    say "my.cnf points at /etc/mysql/mysql.cnf again (it reads mysql.conf.d)"
  elif [ ! -e /etc/mysql/my.cnf ]; then
    ln -s /etc/mysql/mysql.cnf /etc/mysql/my.cnf
  elif ! grep -qE '^[[:space:]]*!includedir[[:space:]]+/etc/mysql/mysql\.conf\.d' /etc/mysql/my.cnf; then
    printf '\n!includedir /etc/mysql/mysql.conf.d/\n' >> /etc/mysql/my.cnf
    say "my.cnf reads /etc/mysql/mysql.conf.d again"
  fi
fi
MAIN="$(main_cnf)"
if [ ! -e /etc/mysql/my.cnf ] && [ ! -e /etc/my.cnf ]; then
  # first install on a server without any MySQL configuration
  if [ "$MAIN" = /etc/my.cnf ]; then INC=/etc/my.cnf.d; else INC=/etc/mysql/conf.d; fi
  install -d -m 0755 "$(dirname "$MAIN")" "$INC"
  cat > "$MAIN" <<CONF
# MySQL (VortexPanel build). Settings in $INC/*.cnf are read after this file.
[mysqld]
user                  = mysql
datadir               = /var/lib/mysql
socket                = /run/mysqld/mysqld.sock
pid-file              = /run/mysqld/mysqld.pid
log-error             = /var/log/mysql/error.log
bind-address          = 127.0.0.1
mysqlx-bind-address   = 127.0.0.1
max_connections       = 300
innodb_buffer_pool_size = 256M

[client]
socket                = /run/mysqld/mysqld.sock

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

# MariaDB's data folder cannot be opened by MySQL (and the reverse)
if [ -e "$DATADIR/aria_log_control" ] || [ -e "$DATADIR/mariadb_upgrade_info" ]; then
  fail "$DATADIR holds MariaDB data. MySQL cannot use it: uninstall MariaDB and move that folder away first."
fi

# switching from the operating system's MySQL: copy the data before this version opens it
if [ "$VP_ACTION" = migrate ] && [ -d "$DATADIR" ]; then data_backup "$DATADIR" mysql; fi

if [ ! -e "$DATADIR/mysql.ibd" ] && [ ! -d "$DATADIR/mysql" ]; then
  install -d -m 0750 -o mysql -g mysql "$DATADIR"
  [ -z "$(ls -A "$DATADIR" 2>/dev/null | grep -v '^lost+found$')" ] || fail "$DATADIR is not empty but holds no MySQL data; nothing was changed"
  say "initializing a new data folder in $DATADIR"
  INIT="$(mktemp)"
  cat > "$INIT" <<'SQL'
INSTALL PLUGIN auth_socket SONAME 'auth_socket.so';
ALTER USER 'root'@'localhost' IDENTIFIED WITH auth_socket;
SQL
  chmod 0644 "$INIT"
  "$VP_PREFIX/bin/mysqld" --initialize-insecure --user=mysql --basedir="$VP_PREFIX" --datadir="$DATADIR" \
      --lc-messages-dir="$VP_PREFIX/share" --plugin-dir="$VP_PREFIX/lib/plugin" --init-file="$INIT" \
      --log-error-verbosity=2 || { rm -f "$INIT"; fail "initializing the data folder failed"; }
  rm -f "$INIT"
  say "root signs in over the local socket (auth_socket); no password is set"
fi

for f in "$VP_PREFIX"/bin/*; do
  b="$(basename "$f")"
  case "$b" in mysqld) link "$VP_CURRENT/bin/mysqld" /usr/sbin/mysqld ;; *) link "$VP_CURRENT/bin/$b" "/usr/bin/$b" ;; esac
done

write_unit mysql.service <<UNIT
[Unit]
Description=MySQL Community Server (VortexPanel build)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mysql
Group=mysql
RuntimeDirectory=mysqld
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
ExecStart=$VP_CURRENT/bin/mysqld --basedir=$VP_CURRENT --lc-messages-dir=$VP_CURRENT/share --plugin-dir=$VP_CURRENT/lib/plugin
TimeoutStartSec=900
TimeoutStopSec=900
Restart=on-failure
RestartPreventExitStatus=1
LimitNOFILE=10000
PrivateTmp=false

[Install]
WantedBy=multi-user.target
Alias=mysqld.service
UNIT
svc_enable mysql
