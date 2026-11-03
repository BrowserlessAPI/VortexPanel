#!/bin/bash
# Remove the program; /etc/fail2ban (jails, filters, ban database) is kept.
. "$(dirname "$0")/lib.sh"
svc_stop fail2ban; has_systemd && systemctl disable fail2ban >/dev/null 2>&1 || true
has_systemd || "$VP_CURRENT/bin/fail2ban-client" stop >/dev/null 2>&1 || true
rm -f /etc/systemd/system/fail2ban.service; has_systemd && systemctl daemon-reload || true
for b in fail2ban-client fail2ban-server fail2ban-regex; do unlink_ours "/usr/bin/$b"; done
# a failed switch: the reinstalled distro package gets its own stock files back
if [ "$VP_ACTION" = abort ] && [ -d /etc/fail2ban/.vortex-before-switch ]; then
  cp -a /etc/fail2ban/.vortex-before-switch/. /etc/fail2ban/ && rm -rf /etc/fail2ban/.vortex-before-switch
  rm -f /etc/fail2ban/.vortex-stock.sha256
fi
true
