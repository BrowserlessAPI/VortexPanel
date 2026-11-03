#!/bin/bash
. "$(dirname "$0")/lib.sh"
if [ -e /etc/supervisor/supervisord.conf ]; then CONF=/etc/supervisor/supervisord.conf; NAME=supervisor
else CONF=/etc/supervisord.conf; NAME=supervisord; fi
if has_systemd; then
  systemctl restart "$NAME"
else
  "$VP_CURRENT/bin/supervisorctl" -c "$CONF" shutdown >/dev/null 2>&1 || true
  for i in $(seq 1 10); do pgrep -f 'bin/supervisord' >/dev/null || break; sleep 1; done
  mkdir -p /run/supervisor
  "$VP_CURRENT/bin/supervisord" -c "$CONF"
fi
