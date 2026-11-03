#!/bin/bash
# Remove the program; accounts and configuration in /etc/pure-ftpd are kept.
. "$(dirname "$0")/lib.sh"
svc_stop pure-ftpd; has_systemd && systemctl disable pure-ftpd >/dev/null 2>&1 || true
pkill -x pure-ftpd 2>/dev/null || true
rm -f /etc/systemd/system/pure-ftpd.service; has_systemd && systemctl daemon-reload || true
for b in pure-ftpd pure-ftpwho pure-uploadscript pure-quotacheck pure-authd pure-certd pure-mrtginfo; do unlink_ours "/usr/sbin/$b"; done
for b in pure-pw pure-pwconvert pure-statsdecode; do unlink_ours "/usr/bin/$b"; done
true
