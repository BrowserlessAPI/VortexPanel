#!/bin/bash
. "$(dirname "$0")/lib.sh"
"$VP_CURRENT/bin/fail2ban-client" -t >/dev/null || fail "fail2ban rejected the configuration with $VP_VERSION (fail2ban-client -t)"
if has_systemd; then
  systemctl restart fail2ban
else
  "$VP_CURRENT/bin/fail2ban-client" stop >/dev/null 2>&1 || true; sleep 1
  mkdir -p /run/fail2ban
  "$VP_CURRENT/bin/fail2ban-client" -x start >/dev/null
fi
