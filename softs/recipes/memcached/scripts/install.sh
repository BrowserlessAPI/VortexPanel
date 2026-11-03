#!/bin/bash
# System integration for Memcached (idempotent; runs before the version switch).
. "$(dirname "$0")/lib.sh"
set -e
if [ "$VP_FAMILY" = deb ]; then U=memcache; else U=memcached; fi
ensure_user "$U" /nonexistent
# settings file: keep the existing one; a fresh server gets the distro's default
if [ ! -e /etc/memcached.conf ] && [ ! -e /etc/sysconfig/memcached ]; then
  if [ "$VP_FAMILY" = deb ]; then
    cat > /etc/memcached.conf <<CONF
# memcached settings (VortexPanel). One option per line, see memcached -h.
-m 64
-p 11211
-u memcache
-l 127.0.0.1
-c 1024
logfile /var/log/memcached.log
CONF
  else
    install -d /etc/sysconfig
    cat > /etc/sysconfig/memcached <<CONF
PORT="11211"
USER="memcached"
MAXCONN="1024"
CACHESIZE="64"
OPTIONS="-l 127.0.0.1"
CONF
  fi
fi
link "$VP_CURRENT/bin/memcached" /usr/bin/memcached
write_unit memcached.service <<UNIT
[Unit]
Description=memcached daemon (VortexPanel build)
After=network.target

[Service]
ExecStart=$VP_CURRENT/bin/vp-memcached-start
Restart=on-failure
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT
svc_enable memcached
