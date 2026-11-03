#!/bin/bash
. "$(dirname "$0")/lib.sh"
if has_systemd; then
  systemctl restart ddclient
else
  pkill -f '(^|/)ddclient( |$)' 2>/dev/null || true; sleep 1
  setsid "$VP_CURRENT/sbin/vp-ddclient-start" </dev/null >/dev/null 2>&1 &
fi
