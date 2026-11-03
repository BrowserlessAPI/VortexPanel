#!/bin/bash
set -e
pure-pw useradd vpsmoke -u nobody -d /tmp -f /etc/pure-ftpd/pureftpd.passwd -m <<< $'Sm0ke-pass\nSm0ke-pass' >/dev/null
pure-pw show vpsmoke -f /etc/pure-ftpd/pureftpd.passwd >/dev/null
pure-pw userdel vpsmoke -f /etc/pure-ftpd/pureftpd.passwd -F /etc/pure-ftpd/pureftpd.pdb -m
r="$(exec 3<>/dev/tcp/127.0.0.1/21; head -c 3 <&3)"
[ "$r" = 220 ] || { echo "Pure-FTPd does not greet on port 21 ($r)"; exit 1; }
echo "Pure-FTPd smoke test passed"
