#!/bin/bash
. "$(dirname "$0")/lib.sh"
# the service and /usr/bin/caddy belong to Caddy WAF while it is installed
[ -x /usr/local/vortex/caddy-waf/current/bin/caddy ] && exit 0
svc_stop caddy; has_systemd && systemctl disable caddy >/dev/null 2>&1 || true
rm -f /etc/systemd/system/caddy.service; has_systemd && systemctl daemon-reload || true
unlink_ours /usr/bin/caddy
