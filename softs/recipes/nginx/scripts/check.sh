#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$("$VP_CURRENT/sbin/nginx" -v 2>&1 | sed -n 's|.*nginx/||p')"
[ "$v" = "$VP_VERSION" ] || fail "expected nginx $VP_VERSION, found '$v'"
for i in $(seq 1 15); do [ -s /run/nginx.pid ] && kill -0 "$(cat /run/nginx.pid)" 2>/dev/null && break; sleep 1; done
kill -0 "$(cat /run/nginx.pid 2>/dev/null)" 2>/dev/null || fail "nginx is not running"
# the WAF on: the ModSecurity module must load with the library this server has
if grep -qE '^[[:space:]]*load_module[[:space:]]+[^;]*ngx_http_modsecurity_module\.so' /etc/nginx/nginx.conf 2>/dev/null; then
  out="$("$VP_CURRENT/sbin/nginx" -t 2>&1)" || fail "nginx -t fails with the ModSecurity module: $(echo "$out" | tail -3)"
fi
say "nginx $v is running"
