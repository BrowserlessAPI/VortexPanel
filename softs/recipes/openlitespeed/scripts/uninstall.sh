#!/bin/bash
# Stop and unregister the service. /usr/local/lsws (configuration, virtual hosts,
# lsphp, logs) is kept.
. "$(dirname "$0")/lib.sh"
# never touch an OpenLiteSpeed that the LiteSpeed repository package owns
if { command -v dpkg >/dev/null && dpkg -s openlitespeed 2>/dev/null | grep -q '^Status: install ok installed'; } || \
   { command -v rpm >/dev/null && rpm -q openlitespeed >/dev/null 2>&1; }; then
  exit 0
fi
L=/usr/local/lsws
[ -x "$L/bin/lswsctrl" ] && "$L/bin/lswsctrl" stop >/dev/null 2>&1 || true
svc_stop lsws
[ -x "$L/admin/misc/rc-uninst.sh" ] && "$L/admin/misc/rc-uninst.sh" >/dev/null 2>&1 || true
has_systemd && systemctl daemon-reload || true
true
