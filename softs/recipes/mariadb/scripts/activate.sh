#!/bin/bash
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/my_common.sh"
if has_systemd; then
  systemctl restart mariadb
else
  stop_direct
  install -d -m 0755 -o mysql -g mysql "$(dirname "$(srv_sock)")"
  nohup "$VP_CURRENT/bin/$SERVER_BIN" --basedir="$VP_CURRENT" --lc-messages-dir="$VP_CURRENT/share" \
      --plugin-dir="$VP_CURRENT/lib/plugin" --user=mysql >/var/log/vortex-mariadbd.out 2>&1 &
fi
