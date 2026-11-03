#!/bin/bash
# System integration for ClamAV (idempotent; runs before the version switch).
# Configuration stays where the server has it: /etc/clamav/clamd.conf + freshclam.conf
# (Debian/Ubuntu), or /etc/clamd.d/scan.conf + /etc/freshclam.conf (RHEL family).
# A fresh server gets the Debian layout. Signature databases in /var/lib/clamav are kept.
. "$(dirname "$0")/lib.sh"
set -e
ensure_user clamav /var/lib/clamav
install -d -m 0755 -o clamav -g clamav /var/lib/clamav /var/log/clamav
install -d -m 0755 /etc/clamav
if [ ! -e /etc/clamav/clamd.conf ] && [ ! -e /etc/clamd.d/scan.conf ]; then
  cat > /etc/clamav/clamd.conf <<'C'
# ClamAV daemon settings (VortexPanel). See clamd.conf(5).
LocalSocket /run/clamav/clamd.ctl
LocalSocketGroup clamav
LocalSocketMode 666
FixStaleSocket yes
User clamav
DatabaseDirectory /var/lib/clamav
PidFile /run/clamav/clamd.pid
LogFile /var/log/clamav/clamav.log
LogTime yes
LogRotate yes
ExitOnOOM yes
SelfCheck 3600
C
fi
if [ ! -e /etc/clamav/freshclam.conf ] && [ ! -e /etc/freshclam.conf ]; then
  cat > /etc/clamav/freshclam.conf <<'C'
# ClamAV signature updates (VortexPanel). See freshclam.conf(5).
DatabaseDirectory /var/lib/clamav
DatabaseOwner clamav
UpdateLogFile /var/log/clamav/freshclam.log
LogTime yes
LogRotate yes
PidFile /run/clamav/freshclam.pid
DatabaseMirror database.clamav.net
Checks 12
NotifyClamd /etc/clamav/clamd.conf
C
  [ -e /etc/clamav/clamd.conf ] || sed -i 's|^NotifyClamd .*|NotifyClamd /etc/clamd.d/scan.conf|' /etc/clamav/freshclam.conf
fi
install -d -m 0755 -o clamav -g clamav /run/clamav
for b in clamscan clamdscan clamdtop clamconf clambc clamsubmit freshclam sigtool; do
  [ -e "$VP_PREFIX/vp-bin/$b" ] && link "$VP_CURRENT/vp-bin/$b" "/usr/bin/$b"
done
for b in clamd clamonacc; do [ -e "$VP_PREFIX/vp-bin/$b" ] && link "$VP_CURRENT/vp-bin/$b" "/usr/sbin/$b"; done
# a first install needs the signatures before clamd can start
if ! ls /var/lib/clamav/main.c[vl]d >/dev/null 2>&1; then
  say "downloading the virus signatures (first install)"
  timeout 900 "$VP_PREFIX/vp-bin/freshclam" --stdout >/dev/null 2>&1 \
    || say "the signature download did not finish; clamav-freshclam keeps trying, the scanner starts once it has them"
fi
write_unit clamav-freshclam.service <<UNIT
[Unit]
Description=ClamAV virus database updater (VortexPanel build)
Documentation=man:freshclam(1) man:freshclam.conf(5)
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=$VP_CURRENT/vp-bin/freshclam -d --foreground=true
StandardOutput=journal
RuntimeDirectory=clamav
RuntimeDirectoryPreserve=yes
# systemd hands /run/clamav to root on start; clamd and freshclam drop to the clamav user
ExecStartPre=/bin/chown clamav:clamav /run/clamav
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
UNIT
write_unit clamav-daemon.service <<UNIT
[Unit]
Description=Clam AntiVirus userspace daemon (VortexPanel build)
Documentation=man:clamd(8) man:clamd.conf(5)
Wants=network-online.target
After=network-online.target clamav-freshclam.service
# clamd refuses to start without signatures; freshclam starts it once they are there
ConditionPathExistsGlob=/var/lib/clamav/main.{c[vl]d,inc}
ConditionPathExistsGlob=/var/lib/clamav/daily.{c[vl]d,inc}

[Service]
ExecStart=$VP_CURRENT/vp-bin/clamd --foreground=true
ExecReload=/bin/kill -USR2 \$MAINPID
RuntimeDirectory=clamav
RuntimeDirectoryPreserve=yes
# systemd hands /run/clamav to root on start; clamd and freshclam drop to the clamav user
ExecStartPre=/bin/chown clamav:clamav /run/clamav
TimeoutStartSec=420
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
# a first install whose signature download did not finish: start the scanner as soon as
# freshclam has written them (NotifyClamd only reloads a scanner that already runs)
write_unit clamav-daemon-signatures.path <<UNIT
[Unit]
Description=Start the ClamAV scanner once its signatures are downloaded (VortexPanel build)

[Path]
PathExistsGlob=/var/lib/clamav/daily.c[vl]d
Unit=clamav-daemon.service

[Install]
WantedBy=multi-user.target
UNIT
svc_enable clamav-freshclam
svc_enable clamav-daemon
svc_enable clamav-daemon-signatures.path
has_systemd && systemctl start clamav-daemon-signatures.path 2>/dev/null || true
