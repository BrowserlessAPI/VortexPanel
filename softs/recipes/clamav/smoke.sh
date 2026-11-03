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
echo "ClamAV smoke test passed"
