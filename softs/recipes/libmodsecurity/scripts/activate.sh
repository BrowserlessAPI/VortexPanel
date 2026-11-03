#!/bin/bash
# A new library version: Nginx loads it on restart (a reload keeps the old one mapped).
. "$(dirname "$0")/lib.sh"
ldconfig
if grep -qE '^[[:space:]]*load_module[[:space:]]+[^;]*ngx_http_modsecurity_module\.so' /etc/nginx/nginx.conf 2>/dev/null; then
  if [ "$VP_ACTION" != install ] && [ "$VP_ACTION" != migrate ] && has_systemd && systemctl is-active --quiet nginx; then
    nginx -t -q && systemctl restart nginx
  elif [ "$VP_ACTION" = migrate ] && has_systemd && systemctl is-active --quiet nginx; then
    nginx -t -q && systemctl restart nginx
  fi
fi
true
