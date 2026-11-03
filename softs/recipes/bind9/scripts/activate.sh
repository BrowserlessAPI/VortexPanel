#!/bin/bash
. "$(dirname "$0")/lib.sh"
if [ -f /etc/bind/named.conf ]; then CONF=/etc/bind/named.conf; else CONF=/etc/named.conf; fi
"$VP_CURRENT/bin/named-checkconf" "$CONF" || fail "named-checkconf rejected $CONF with BIND $VP_VERSION"
if has_systemd; then
  systemctl restart named
else
  "$VP_CURRENT/sbin/rndc" stop >/dev/null 2>&1 || pkill -x named 2>/dev/null || true
  for i in $(seq 1 10); do pgrep -x named >/dev/null || break; sleep 1; done
  setsid "$VP_CURRENT/sbin/vp-named-start" </dev/null >/dev/null 2>&1 &
fi
