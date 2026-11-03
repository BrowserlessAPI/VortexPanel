#!/bin/bash
. "$(dirname "$0")/lib.sh"
if has_systemd; then
  systemctl restart clamav-freshclam
  systemctl restart clamav-daemon
else
  pkill -x freshclam 2>/dev/null || true; pkill -x clamd 2>/dev/null || true; sleep 1
  install -d -m 0755 -o clamav -g clamav /run/clamav
  "$VP_CURRENT/vp-bin/freshclam" -d >/dev/null 2>&1 || true
  if ls /var/lib/clamav/main.c[vl]d >/dev/null 2>&1; then "$VP_CURRENT/vp-bin/clamd"; fi
fi
