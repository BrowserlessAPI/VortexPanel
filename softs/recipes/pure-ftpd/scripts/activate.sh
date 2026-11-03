#!/bin/bash
. "$(dirname "$0")/lib.sh"
if has_systemd; then systemctl restart pure-ftpd
else
  pkill -x pure-ftpd 2>/dev/null; sleep 1
  nohup "$VP_CURRENT/sbin/vp-pure-ftpd-run" >/var/log/pure-ftpd.vortex.log 2>&1 &
fi
