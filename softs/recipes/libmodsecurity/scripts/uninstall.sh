#!/bin/bash
# Refused while Nginx loads the ModSecurity module and no other copy of the library
# exists: Nginx would no longer start.
. "$(dirname "$0")/lib.sh"
if [ "$VP_ACTION" = uninstall ] && grep -qE '^[[:space:]]*load_module[[:space:]]+[^;]*ngx_http_modsecurity_module\.so' /etc/nginx/nginx.conf 2>/dev/null; then
  other=""
  for f in /usr/lib/x86_64-linux-gnu/libmodsecurity.so.3 /usr/lib/aarch64-linux-gnu/libmodsecurity.so.3 /usr/lib64/libmodsecurity.so.3; do
    [ -e "$f" ] && other="$f"
  done
  [ -n "$other" ] || refuse "Nginx loads the ModSecurity module (WAF on). Uninstall the ModSecurity WAF first; the library was not removed."
fi
unlink_ours /usr/bin/modsec-rules-check
rm -f /etc/ld.so.conf.d/vortex-libmodsecurity.conf
ldconfig
true
