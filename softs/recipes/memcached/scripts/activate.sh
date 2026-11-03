#!/bin/bash
. "$(dirname "$0")/lib.sh"
if has_systemd; then
  systemctl restart memcached
else
  pkill -x memcached 2>/dev/null || true; sleep 1
  setsid "$VP_CURRENT/bin/vp-memcached-start" </dev/null >/dev/null 2>&1 &
fi
