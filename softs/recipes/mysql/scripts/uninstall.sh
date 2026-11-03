#!/bin/bash
# Remove the program. /var/lib/mysql and the configuration are kept.
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/my_common.sh"
svc_stop mysql
has_systemd && systemctl disable mysql >/dev/null 2>&1 || true
has_systemd || stop_direct
rm -f /etc/systemd/system/mysql.service
has_systemd && systemctl daemon-reload || true
for f in "$VP_PREFIX"/bin/*; do
  b="$(basename "$f")"; unlink_ours "/usr/bin/$b"
done
unlink_ours /usr/sbin/mysqld
if [ "$VP_ACTION" = abort ]; then
  # a failed switch: the operating system's MySQL gets its data and configuration back as they were
  data_restore "$(datadir)" mysql
  remove_defaults
fi
true
