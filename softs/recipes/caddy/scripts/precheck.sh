#!/bin/bash
# Before anything on the server changes: this version must accept the server's own
# Caddyfile. (While Caddy WAF is installed it runs the sites, not this build.)
. "$(dirname "$0")/lib.sh"
[ -f /etc/caddy/Caddyfile ] || exit 0
[ -x /usr/local/vortex/caddy-waf/current/bin/caddy ] && exit 0
out="$("$VP_PREFIX/bin/caddy" validate --config /etc/caddy/Caddyfile 2>&1)" || {
  echo "$out" | tail -8
  fail "Caddy $VP_VERSION does not accept /etc/caddy/Caddyfile; the update was not installed and nothing changed"
}
say "Caddy $VP_VERSION accepts /etc/caddy/Caddyfile"
