#!/bin/bash
# Remove the program; supervisord.conf and the program definitions are kept.
. "$(dirname "$0")/lib.sh"
if [ -e /etc/supervisor/supervisord.conf ]; then CONF=/etc/supervisor/supervisord.conf; else CONF=/etc/supervisord.conf; fi
for n in supervisor supervisord; do
  svc_stop "$n"; has_systemd && systemctl disable "$n" >/dev/null 2>&1 || true
done
has_systemd || "$VP_CURRENT/bin/supervisorctl" -c "$CONF" shutdown >/dev/null 2>&1 || true
rm -f /etc/systemd/system/supervisor.service /etc/systemd/system/supervisord.service
has_systemd && systemctl daemon-reload || true
for b in supervisord supervisorctl echo_supervisord_conf pidproxy; do unlink_ours "/usr/bin/$b"; done
true
