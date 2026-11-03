#!/bin/bash
# System integration for Nginx (idempotent; runs before the version switch).
. "$(dirname "$0")/lib.sh"
set -e
ensure_user nginx /var/cache/nginx
install -d -m 0755 /etc/nginx /etc/nginx/conf.d /etc/nginx/stream.d /var/log/nginx /usr/share/nginx /var/cache/nginx
# temp folders belong to the user the workers run as (www-data on a switched Debian server)
NUSER="$(grep -oE '^[[:space:]]*user[[:space:]]+[^;[:space:]]+' /etc/nginx/nginx.conf 2>/dev/null | awk '{print $2}' | head -1)"
NUSER="${NUSER:-nginx}"; getent passwd "$NUSER" >/dev/null || NUSER=nginx
for t in client_temp proxy_temp fastcgi_temp uwsgi_temp scgi_temp; do
  install -d -m 0700 -o "$NUSER" -g "$(id -gn "$NUSER")" "/var/cache/nginx/$t"
done
# a switched Debian server loads distro modules (now removed) from modules-enabled;
# this build has them compiled in
if [ "$VP_ACTION" = migrate ] && grep -qE '^[[:space:]]*include[[:space:]]+/etc/nginx/modules-enabled/' /etc/nginx/nginx.conf; then
  cp -p /etc/nginx/nginx.conf /etc/nginx/nginx.conf.vortex-before-switch
  sed -i -E 's|^([[:space:]]*include[[:space:]]+/etc/nginx/modules-enabled/.*)$|# \1   # VortexPanel build: modules are built in|' /etc/nginx/nginx.conf
fi
# a switched server with the WAF on loads a ModSecurity module compiled for the old Nginx:
# use the one built with this Nginx instead (abort puts the old nginx.conf back)
if [ "$VP_ACTION" = migrate ] && grep -qE '^[[:space:]]*load_module[[:space:]]+[^;]*ngx_http_modsecurity_module\.so' /etc/nginx/nginx.conf \
   && ! grep -qE "^[[:space:]]*load_module[[:space:]]+$VP_CURRENT/modules/ngx_http_modsecurity_module\.so" /etc/nginx/nginx.conf; then
  [ -e /etc/nginx/nginx.conf.vortex-before-switch ] || cp -p /etc/nginx/nginx.conf /etc/nginx/nginx.conf.vortex-before-switch
  sed -i -E "s|^([[:space:]]*load_module[[:space:]]+)[^;]*ngx_http_modsecurity_module\.so;|\1$VP_CURRENT/modules/ngx_http_modsecurity_module.so;|" /etc/nginx/nginx.conf
  say "nginx.conf now loads the ModSecurity module built with this Nginx"
fi
# every module nginx.conf loads from the version folder must exist in this version
for so in $(grep -oE '^[[:space:]]*load_module[[:space:]]+[^;]+' /etc/nginx/nginx.conf 2>/dev/null | awk '{print $2}'); do
  case "$so" in
    "$VP_CURRENT"/modules/*) [ -e "$VP_PREFIX/modules/$(basename "$so")" ] || fail "nginx.conf loads $(basename "$so"), which this build does not include" ;;
  esac
done
# the WAF (ModSecurity module loaded): the module needs libmodsecurity.so.3, from the
# VortexPanel library (its run path) or, on servers set up before it, the system's
if grep -qE '^[[:space:]]*load_module[[:space:]]+[^;]*ngx_http_modsecurity_module\.so' /etc/nginx/nginx.conf 2>/dev/null; then
  found=""
  for f in /usr/local/vortex/libmodsecurity/current/lib/libmodsecurity.so.3 /usr/lib/x86_64-linux-gnu/libmodsecurity.so.3 \
           /usr/lib/aarch64-linux-gnu/libmodsecurity.so.3 /usr/lib64/libmodsecurity.so.3 /usr/lib/libmodsecurity.so.3; do
    [ -e "$f" ] && { found="$f"; break; }
  done
  [ -n "$found" ] || fail "nginx.conf loads the ModSecurity module, but libmodsecurity.so.3 is not installed. Reinstall the ModSecurity WAF from the App Store (it installs the VortexPanel library), then update Nginx."
fi
SHARE="$VP_PREFIX/share"
for f in mime.types fastcgi_params fastcgi.conf scgi_params uwsgi_params koi-utf koi-win win-utf; do
  [ -e "/etc/nginx/$f" ] || cp "$SHARE/conf/$f" "/etc/nginx/$f"
done
[ -d /usr/share/nginx/html ] || cp -r "$SHARE/html" /usr/share/nginx/html
if [ ! -e /etc/nginx/nginx.conf ]; then
  cat > /etc/nginx/nginx.conf <<'CONF'
user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log notice;
pid        /run/nginx.pid;

events {
    worker_connections  4096;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';
    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    tcp_nopush      on;
    keepalive_timeout  65;
    server_tokens   off;
    client_max_body_size 128m;
    gzip  on;

    include /etc/nginx/conf.d/*.conf;
}

stream {
    include /etc/nginx/stream.d/*.conf;
}
CONF
  [ -e /etc/nginx/conf.d/default.conf ] || cat > /etc/nginx/conf.d/default.conf <<'CONF'
server {
    listen       80 default_server;
    server_name  _;
    root         /usr/share/nginx/html;
    index        index.html;
}
CONF
fi
link "$VP_CURRENT/sbin/nginx" /usr/sbin/nginx
# logrotate like the nginx.org package
[ -d /etc/logrotate.d ] && [ ! -e /etc/logrotate.d/nginx ] && cat > /etc/logrotate.d/nginx <<'CONF'
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 nginx adm
    sharedscripts
    postrotate
        [ -s /run/nginx.pid ] && kill -USR1 `cat /run/nginx.pid`
    endscript
}
CONF
write_unit nginx.service <<UNIT
[Unit]
Description=nginx - high performance web server (VortexPanel build)
Documentation=https://nginx.org/en/docs/
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=$VP_CURRENT/sbin/nginx -t -q
ExecStart=$VP_CURRENT/sbin/nginx -c /etc/nginx/nginx.conf
ExecReload=/bin/sh -c "$VP_CURRENT/sbin/nginx -t -q && /bin/kill -s HUP \$MAINPID"
ExecStop=/bin/sh -c "/bin/kill -s QUIT \$MAINPID"
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT
svc_enable nginx
# HTTP/3 (QUIC) needs UDP 443, as with the panel's other nginx installs
if [ "$VP_ACTION" = install ] || [ "$VP_ACTION" = migrate ]; then
  (ufw status 2>/dev/null | grep -q "Status: active" && ufw allow 443/udp >/dev/null 2>&1) || true
  (firewall-cmd --state >/dev/null 2>&1 && firewall-cmd --add-port=443/udp --permanent >/dev/null 2>&1 \
     && firewall-cmd --add-port=443/udp >/dev/null 2>&1) || true
fi
true
