#!/bin/bash
# The library is found by the Nginx module through its run path and by everything else
# through the dynamic linker (ld.so.conf.d). Both point at .../current.
. "$(dirname "$0")/lib.sh"
set -e
link "$VP_CURRENT/bin/modsec-rules-check" /usr/bin/modsec-rules-check
echo /usr/local/vortex/libmodsecurity/current/lib > /etc/ld.so.conf.d/vortex-libmodsecurity.conf
ldconfig
# the ModSecurity WAF module's config files (only where missing)
install -d /etc/nginx/modsec 2>/dev/null || true
if [ -d /etc/nginx/modsec ]; then
  [ -e /etc/nginx/modsec/unicode.mapping ] || cp "$VP_PREFIX/share/unicode.mapping" /etc/nginx/modsec/ 2>/dev/null || true
fi
true
