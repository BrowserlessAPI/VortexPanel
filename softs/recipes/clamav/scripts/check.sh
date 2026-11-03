#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$("$VP_CURRENT/vp-bin/clamscan" --version 2>/dev/null | sed -n 's/^ClamAV \([0-9][0-9.]*\).*/\1/p')"
[ "$v" = "$VP_VERSION" ] || fail "expected ClamAV $VP_VERSION, found '$v'"
if ! ls /var/lib/clamav/main.c[vl]d >/dev/null 2>&1; then
  say "ClamAV $v is installed; the scanner starts once the first signature download has finished"
  exit 0
fi
# loading the signatures takes a minute or two
for i in $(seq 1 90); do
  "$VP_CURRENT/vp-bin/clamdscan" --ping 1 >/dev/null 2>&1 && { say "ClamAV $v scanner answers"; exit 0; }
  sleep 2
done
fail "clamd does not answer"
