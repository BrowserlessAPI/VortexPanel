#!/bin/bash
. "$(dirname "$0")/lib.sh"
set -e
ensure_user caddy /var/lib/caddy
install -d -m 0755 /etc/caddy; install -d -m 0750 -o caddy -g caddy /var/lib/caddy /var/log/caddy
[ -e /etc/caddy/Caddyfile ] || printf ':80 {\n\troot * /usr/share/caddy\n\tfile_server\n}\n' > /etc/caddy/Caddyfile
install -d /usr/share/caddy; [ -e /usr/share/caddy/index.html ] || echo '<h1>Caddy</h1>' > /usr/share/caddy/index.html
# Caddy WAF (the same Caddy built with the waf module) owns /usr/bin/caddy and the
# service while it is installed; this build is used again when Caddy WAF is removed.
if [ -x /usr/local/vortex/caddy-waf/current/bin/caddy ]; then
  say "Caddy WAF is installed: it keeps running the service (this version is kept for when it is removed)"
  exit 0
fi
link "$VP_CURRENT/bin/caddy" /usr/bin/caddy
write_unit caddy.service <<UNIT
[Unit]
Description=Caddy (VortexPanel build)
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
