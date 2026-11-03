#!/bin/bash
# Remove the program; named.conf, zones and keys are kept.
. "$(dirname "$0")/lib.sh"
svc_stop named; has_systemd && systemctl disable named >/dev/null 2>&1 || true
has_systemd || pkill -x named 2>/dev/null || true
rm -f /etc/systemd/system/named.service; has_systemd && systemctl daemon-reload || true
for d in /usr/sbin /usr/bin; do
  for l in "$d"/*; do
    [ -L "$l" ] && readlink "$l" | grep -q '^/usr/local/vortex/bind9/' && unlink_ours "$l"
  done
done
true
