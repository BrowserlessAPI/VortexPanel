#!/bin/bash
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/sites.sh"
v="$("$VP_CURRENT/bin/caddy" version | awk '{print $1}' | sed 's/^v//')"
[ "$v" = "$VP_VERSION" ] || fail "expected Caddy $VP_VERSION, found '$v'"
wait_port 80 15 || fail "Caddy does not listen on port 80"
# an update of the build that serves the sites: every site that answered before must
# still answer (else it is rolled back). While Caddy WAF is installed it serves them.
if [ "$VP_ACTION" = update ] && [ ! -x /usr/local/vortex/caddy-waf/current/bin/caddy ] \
   && [ -s /var/lib/vortex-caddy/sites-before ]; then
  sites_compare /var/lib/vortex-caddy/sites-before
fi
rm -f /var/lib/vortex-caddy/sites-before
say "Caddy $v is running"
