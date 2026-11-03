#!/bin/bash
# System integration for Pure-FTPd. Accounts (/etc/pure-ftpd/pureftpd.passwd, .pdb)
# and the configuration (either layout) are kept as they are.
. "$(dirname "$0")/lib.sh"
set -e
install -d -m 0755 /etc/pure-ftpd
D=/etc/pure-ftpd
if [ ! -d "$D/conf" ] && [ ! -f "$D/pure-ftpd.conf" ] && [ ! -f /etc/pure-ftpd.conf ]; then
  # fresh install: upstream sample with panel accounts (PureDB) and chrooted users
  sed -E -e 's/^#?[[:space:]]*PureDB[[:space:]].*/PureDB                       \/etc\/pure-ftpd\/pureftpd.pdb/' \
         -e 's/^#?[[:space:]]*ChrootEveryone[[:space:]].*/ChrootEveryone               yes/' \
         -e 's/^#?[[:space:]]*NoAnonymous[[:space:]].*/NoAnonymous                  yes/' \
         -e 's/^#?[[:space:]]*Daemonize[[:space:]].*/Daemonize                    no/' \
         -e 's/^#?[[:space:]]*PassivePortRange[[:space:]].*/PassivePortRange             39000 40000/' \
         -e 's/^[[:space:]]*(UnixAuthentication|PAMAuthentication)[[:space:]].*/# \1 yes/' \
         "$VP_PREFIX/share/pure-ftpd.conf.sample" > "$D/pure-ftpd.conf"
  grep -qE '^PureDB[[:space:]]' "$D/pure-ftpd.conf" || echo 'PureDB                       /etc/pure-ftpd/pureftpd.pdb' >> "$D/pure-ftpd.conf"
fi
# pure-ftpd does not start with PureDB enabled and no .pdb file
[ -e "$D/pureftpd.passwd" ] || install -m 0600 /dev/null "$D/pureftpd.passwd"
[ -s "$D/pureftpd.pdb" ] || "$VP_PREFIX/bin/pure-pw" mkdb "$D/pureftpd.pdb" -f "$D/pureftpd.passwd" >/dev/null 2>&1 || true
for b in pure-ftpd pure-ftpwho pure-uploadscript pure-quotacheck pure-authd pure-certd pure-mrtginfo; do
  [ -e "$VP_PREFIX/sbin/$b" ] && link "$VP_CURRENT/sbin/$b" "/usr/sbin/$b"
done
for b in pure-pw pure-pwconvert pure-statsdecode; do
  [ -e "$VP_PREFIX/bin/$b" ] && link "$VP_CURRENT/bin/$b" "/usr/bin/$b"
done
write_unit pure-ftpd.service <<UNIT
[Unit]
Description=Pure-FTPd FTP server (VortexPanel build)
After=network.target syslog.target

[Service]
Type=simple
ExecStart=$VP_CURRENT/sbin/vp-pure-ftpd-run
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
svc_enable pure-ftpd
