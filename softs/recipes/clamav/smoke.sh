#!/bin/bash
# Engine test without the network: a signature made here for the EICAR test file must
# detect it (CI addresses are often refused by the signature mirrors).
set -e
clamscan --version
sigtool --version >/dev/null
d="$(mktemp -d)"
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$d/eicar.com"
sigtool --md5 "$d/eicar.com" > "$d/test.hdb"
rc=0; clamscan --no-summary -d "$d/test.hdb" "$d/eicar.com" || rc=$?
rm -rf "$d"
[ "$rc" = 1 ] || { echo "clamscan did not detect the EICAR test file (rc=$rc)"; exit 1; }
# The scanner service under systemd. CI has no signatures (clamd is not started without
# them), so start the real clamav-daemon unit with a test signature: this is what found
# the units handing /run/clamav back to root (clamd could not create its socket).
if [ -d /run/systemd/system ] && systemctl cat clamav-daemon >/dev/null 2>&1 && ! clamdscan --ping 1 >/dev/null 2>&1; then
  o=/run/systemd/system/clamav-daemon.service.d
  install -d "$o"
  printf '[Unit]\nConditionPathExistsGlob=\n' > "$o/vp-smoke.conf"
  printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/vp-eicar.com
  sigtool --md5 /tmp/vp-eicar.com > /var/lib/clamav/vp-smoke.hdb
  chown clamav:clamav /var/lib/clamav/vp-smoke.hdb 2>/dev/null || true
  systemctl daemon-reload
  systemctl restart clamav-freshclam 2>/dev/null || true      # its restart is what reset the folder
  systemctl restart clamav-daemon
  ok=""
  for i in $(seq 1 60); do clamdscan --ping 1 >/dev/null 2>&1 && { ok=1; break; }; sleep 2; done
  rc=0; [ -n "$ok" ] && { clamdscan --no-summary --stream /tmp/vp-eicar.com || rc=$?; }
  systemctl stop clamav-daemon
  rm -f "$o/vp-smoke.conf" /var/lib/clamav/vp-smoke.hdb /tmp/vp-eicar.com; systemctl daemon-reload
  [ -n "$ok" ] || { echo "clamav-daemon does not answer under systemd"; journalctl -u clamav-daemon --no-pager | tail -15; ls -ld /run/clamav; exit 1; }
  [ "$rc" = 1 ] || { echo "clamd did not detect the EICAR test file (rc=$rc)"; exit 1; }
  echo "clamav-daemon answers under systemd"
fi
echo "ClamAV smoke test passed"
