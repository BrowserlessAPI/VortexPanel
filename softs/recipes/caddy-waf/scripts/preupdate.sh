#!/bin/bash
# The previous version still serves the sites here: record how each one answers.
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/sites.sh"
install -d -m 0700 /var/lib/vortex-caddy
sites_snapshot /var/lib/vortex-caddy/sites-before
