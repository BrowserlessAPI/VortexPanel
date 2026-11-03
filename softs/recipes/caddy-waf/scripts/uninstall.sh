#!/bin/bash
# Hand /usr/bin/caddy and caddy.service back to the plain Caddy build when it is
# installed; otherwise remove them. /etc/caddy and /var/lib/caddy are kept.
. "$(dirname "$0")/lib.sh"
PLAIN=/usr/local/vortex/caddy/current
if [ -x "$PLAIN/bin/caddy" ]; then
  link "$PLAIN/bin/caddy" /usr/bin/caddy
  sed -e "s|/usr/local/vortex/caddy-waf/current/bin/caddy|$PLAIN/bin/caddy|g" \
      -e 's|^Description=.*|Description=Caddy (VortexPanel build)|' /etc/systemd/system/caddy.service | write_unit caddy.service
  if has_systemd; then systemctl restart caddy 2>/dev/null || true
  else pkill -x caddy 2>/dev/null; sleep 1; "$PLAIN/bin/caddy" start --config /etc/caddy/Caddyfile >/dev/null 2>&1 || true; fi
  say "Caddy runs on the plain VortexPanel build again (without the WAF module)"
  exit 0
fi
svc_stop caddy; has_systemd && systemctl disable caddy >/dev/null 2>&1 || true
pkill -x caddy 2>/dev/null || true
rm -f /etc/systemd/system/caddy.service; has_systemd && systemctl daemon-reload || true
unlink_ours /usr/bin/caddy
true
