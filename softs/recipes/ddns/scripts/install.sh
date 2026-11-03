#!/bin/bash
# System integration for ddclient (idempotent; runs before the version switch).
# The existing configuration file is kept; a fresh server gets a commented template.
. "$(dirname "$0")/lib.sh"
set -e
if [ ! -e /etc/ddclient.conf ] && [ ! -e /etc/ddclient/ddclient.conf ]; then
  if [ "$VP_FAMILY" = rpm ]; then CONF=/etc/ddclient/ddclient.conf; install -d -m 0755 /etc/ddclient; else CONF=/etc/ddclient.conf; fi
  cat > "$CONF" <<'C'
# ddclient settings (VortexPanel). Add your provider and host names below,
# see https://ddclient.net/ for every provider's options.
daemon=300
syslog=yes
ssl=yes
usev4=webv4, webv4=ipify-ipv4
#
# Example (Cloudflare):
# protocol=cloudflare, zone=example.com, login=token, password=YOUR-API-TOKEN
# home.example.com
C
  chmod 0600 "$CONF"
fi
install -d -m 0700 /var/cache/ddclient
link "$VP_CURRENT/sbin/ddclient" /usr/sbin/ddclient
write_unit ddclient.service <<UNIT
[Unit]
Description=Dynamic DNS Update Client (VortexPanel build)
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=exec
ExecStart=$VP_CURRENT/sbin/vp-ddclient-start
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
UNIT
svc_enable ddclient
