#!/bin/bash
# Remove the program. /var/lib/mysql and the configuration are kept.
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/my_common.sh"
svc_stop mariadb
has_systemd && systemctl disable mariadb >/dev/null 2>&1 || true
has_systemd || stop_direct
rm -f /etc/systemd/system/mariadb.service
has_systemd && systemctl daemon-reload || true
for f in "$VP_PREFIX"/bin/*; do
  b="$(basename "$f")"; unlink_ours "/usr/bin/$b"
done
unlink_ours /usr/sbin/mysqld; unlink_ours /usr/sbin/mariadbd
if [ "$VP_ACTION" = abort ]; then
  # a failed switch: the operating system's MariaDB gets its data and configuration back as they were
  data_restore "$(datadir)" mariadb
  remove_defaults
fi
true
