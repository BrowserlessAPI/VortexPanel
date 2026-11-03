#!/bin/bash
# Caddy with the WAF module takes over /usr/bin/caddy and caddy.service. The plain
# Caddy build (if installed) stays on disk and is used again when this is removed.
. "$(dirname "$0")/lib.sh"
set -e
ensure_user caddy /var/lib/caddy
install -d -m 0755 /etc/caddy; install -d -m 0750 -o caddy -g caddy /var/lib/caddy /var/log/caddy
[ -e /etc/caddy/Caddyfile ] || printf ':80 {\n\troot * /usr/share/caddy\n\tfile_server\n}\n' > /etc/caddy/Caddyfile
install -d /usr/share/caddy; [ -e /usr/share/caddy/index.html ] || echo '<h1>Caddy</h1>' > /usr/share/caddy/index.html
# the rule files the panel's per-site WAF settings point at (kept when they exist)
install -d -m 0755 /etc/caddy/waf
for f in rules.json ip_blacklist.txt dns_blacklist.txt; do
  [ -e "/etc/caddy/waf/$f" ] || install -m 0644 "$VP_PREFIX/share/waf/$f" "/etc/caddy/waf/$f"
done
link "$VP_CURRENT/bin/caddy" /usr/bin/caddy
write_unit caddy.service <<UNIT
[Unit]
Description=Caddy with WAF (VortexPanel build)
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart=$VP_CURRENT/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=$VP_CURRENT/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT
svc_enable caddy
