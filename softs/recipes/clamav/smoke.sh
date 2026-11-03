#!/bin/bash
set -e
clamscan --version
sigtool --version >/dev/null
if ls /var/lib/clamav/main.c[vl]d >/dev/null 2>&1; then
  d="$(mktemp -d)"
  printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$d/eicar.com"
  rc=0; clamscan --no-summary "$d/eicar.com" || rc=$?
  rm -rf "$d"
  [ "$rc" = 1 ] || { echo "clamscan did not detect the EICAR test file"; exit 1; }
fi
echo "ClamAV smoke test passed"
