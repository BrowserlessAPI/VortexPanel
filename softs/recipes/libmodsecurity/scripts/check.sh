#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$(cat "$VP_CURRENT/share/VERSION" 2>/dev/null)"
[ "$v" = "$VP_VERSION" ] || fail "expected libmodsecurity $VP_VERSION, found '$v'"
T="$(mktemp)"; printf 'SecRuleEngine DetectionOnly\n' > "$T"
"$VP_CURRENT/bin/modsec-rules-check" "$T" >/dev/null 2>&1 || { rm -f "$T"; fail "modsec-rules-check cannot load a rule file"; }
rm -f "$T"
ldconfig -p | grep -q "/usr/local/vortex/libmodsecurity/current/lib/libmodsecurity.so.3" || fail "the dynamic linker does not find libmodsecurity.so.3"
# Nginx with the WAF on must still pass its configuration test with this library
if grep -qE '^[[:space:]]*load_module[[:space:]]+[^;]*ngx_http_modsecurity_module\.so' /etc/nginx/nginx.conf 2>/dev/null; then
  nginx -t -q 2>/dev/null || fail "nginx -t fails with this ModSecurity library"
fi
say "libmodsecurity $v is in use"
