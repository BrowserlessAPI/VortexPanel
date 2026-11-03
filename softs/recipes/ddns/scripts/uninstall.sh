#!/bin/bash
# Remove the program; the configuration file is kept.
. "$(dirname "$0")/lib.sh"
svc_stop ddclient; has_systemd && systemctl disable ddclient >/dev/null 2>&1 || true
has_systemd || pkill -f '/ddclient( |$)' 2>/dev/null || true
rm -f /etc/systemd/system/ddclient.service; has_systemd && systemctl daemon-reload || true
unlink_ours /usr/sbin/ddclient
true
