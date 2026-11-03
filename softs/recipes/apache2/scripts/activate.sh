#!/bin/bash
# Test the configuration with the new binary, then restart (a graceful reload keeps
# the old binary running).
. "$(dirname "$0")/lib.sh"
if [ "$VP_FAMILY" = deb ]; then W="$VP_CURRENT/sbin/apache2"; SVC=apache2; else W="$VP_CURRENT/sbin/httpd"; SVC=httpd; fi
out="$("$W" -t 2>&1)" || fail "the configuration test failed with Apache $VP_VERSION: $(echo "$out" | tail -3)"
if has_systemd; then
  systemctl restart $SVC
else
  "$W" -k stop >/dev/null 2>&1 || true
  for i in $(seq 1 10); do pgrep -x httpd >/dev/null || break; sleep 1; done
  "$W" -k start
fi
