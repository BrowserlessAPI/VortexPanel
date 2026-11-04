#!/bin/bash
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/sites.sh"
# 2.11.8.1 = Caddy 2.11.8 rebuilt with a newer caddy-waf release
want="$(echo "$VP_VERSION" | cut -d. -f1-3)"
v="$("$VP_CURRENT/bin/caddy" version | awk '{print $1}' | sed 's/^v//')"
[ "$v" = "$want" ] || fail "expected Caddy $want, found '$v'"
"$VP_CURRENT/bin/caddy" list-modules 2>/dev/null | grep -q '^http.handlers.waf' || fail "the WAF module is not in this Caddy build"
wait_port 80 15 || fail "Caddy does not listen on port 80"
# an update: every site that answered before must still answer (else it is rolled back)
if [ "$VP_ACTION" = update ] && [ -s /var/lib/vortex-caddy/sites-before ]; then
  sites_compare /var/lib/vortex-caddy/sites-before
  rm -f /var/lib/vortex-caddy/sites-before
fi
say "Caddy $v with WAF ($(sed -n 's/^caddy-waf //p' "$VP_CURRENT/share/BUILDINFO" 2>/dev/null)) is running"
