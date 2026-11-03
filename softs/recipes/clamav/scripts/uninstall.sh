#!/bin/bash
# Remove the program; configuration and the signature databases are kept.
. "$(dirname "$0")/lib.sh"
for s in clamav-daemon-signatures.path clamav-daemon clamav-freshclam; do svc_stop "$s"; has_systemd && systemctl disable "$s" >/dev/null 2>&1 || true; done
has_systemd || { pkill -x clamd 2>/dev/null; pkill -x freshclam 2>/dev/null; } || true
rm -f /etc/systemd/system/clamav-daemon-signatures.path /etc/systemd/system/clamav-daemon.service /etc/systemd/system/clamav-freshclam.service
has_systemd && systemctl daemon-reload || true
for b in clamscan clamdscan clamdtop clamconf clambc clamsubmit freshclam sigtool; do unlink_ours "/usr/bin/$b"; done
for b in clamd clamonacc; do unlink_ours "/usr/sbin/$b"; done
true
