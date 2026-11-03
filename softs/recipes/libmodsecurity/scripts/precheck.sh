#!/bin/bash
# Before anything changes: never install a library older than the one the Nginx build's
# ModSecurity module was compiled against (it could miss symbols the module needs).
. "$(dirname "$0")/lib.sh"
B=/usr/local/vortex/nginx/current/share/BUILDINFO
[ -f "$B" ] || exit 0
need="$(awk '$1=="modsecurity"{print $2; exit}' "$B")"
[ -n "$need" ] || exit 0
lower="$(printf '%s\n%s\n' "$VP_VERSION" "$need" | sort -V | head -1)"
if [ "$lower" = "$VP_VERSION" ] && [ "$VP_VERSION" != "$need" ]; then
  fail "the Nginx build's ModSecurity module needs libmodsecurity $need or newer; this is $VP_VERSION. Nothing was changed."
fi
say "libmodsecurity $VP_VERSION fits the Nginx build's module (built against $need)"
