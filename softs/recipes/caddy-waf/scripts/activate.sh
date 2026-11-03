#!/bin/bash
. "$(dirname "$0")/lib.sh"
"$VP_CURRENT/bin/caddy" validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 || fail "caddy validate rejected the Caddyfile"
if has_systemd; then systemctl restart caddy
else pkill -x caddy 2>/dev/null; sleep 1; "$VP_CURRENT/bin/caddy" start --config /etc/caddy/Caddyfile >/dev/null 2>&1; fi
