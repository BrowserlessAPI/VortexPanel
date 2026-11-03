#!/bin/bash
# System integration for BIND9 (idempotent; runs before the version switch).
# named.conf, zones and keys stay where the server has them; a fresh server gets a
# minimal authoritative setup in the layout the panel's DNS pages use.
. "$(dirname "$0")/lib.sh"
set -e
# link a program unless a still-installed OS package owns that path (dig from dnsutils)
link_free() { if [ ! -e "$2" ] || { [ -L "$2" ] && readlink "$2" | grep -q '^/usr/local/vortex/'; }; then link "$1" "$2"; fi; }
if [ -e /etc/bind/named.conf ] || { [ "$VP_FAMILY" = deb ] && [ ! -e /etc/named.conf ]; }; then
  U=bind; ensure_user bind /var/cache/bind
  install -d -m 2755 -o root -g bind /etc/bind
  install -d -m 0775 -o root -g bind /var/cache/bind /var/lib/bind /var/log/named
  install -d -m 2775 -o root -g bind /etc/bind/zones
  if [ ! -e /etc/bind/named.conf ]; then
    cat > /etc/bind/named.conf <<'C'
// BIND configuration (VortexPanel)
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
C
    [ -e /etc/bind/named.conf.options ] || cat > /etc/bind/named.conf.options <<'C'
options {
	directory "/var/cache/bind";
	listen-on { any; };
	listen-on-v6 { any; };
	allow-query { any; };
	recursion no;
	allow-transfer { none; };
	dnssec-validation auto;
};
C
    [ -e /etc/bind/named.conf.local ] || echo '// zones (VortexPanel)' > /etc/bind/named.conf.local
    chgrp bind /etc/bind/named.conf /etc/bind/named.conf.options /etc/bind/named.conf.local
  fi
  KEY=/etc/bind/rndc.key
else
  U=named; ensure_user named /var/named
  install -d -m 0750 -o root -g named /var/named
  install -d -m 0770 -o named -g named /var/named/data /var/named/dynamic
  if [ ! -e /etc/named.conf ]; then
    cat > /etc/named.conf <<'C'
// BIND configuration (VortexPanel)
options {
	directory "/var/named";
	dump-file "/var/named/data/cache_dump.db";
	statistics-file "/var/named/data/named_stats.txt";
	managed-keys-directory "/var/named/dynamic";
	session-keyfile "/run/named/session.key";
	listen-on port 53 { any; };
	listen-on-v6 port 53 { any; };
	allow-query { any; };
	recursion no;
	allow-transfer { none; };
	dnssec-validation auto;
	pid-file "/run/named/named.pid";
};
include "/etc/named.rfc1912.zones";
C
    [ -e /etc/named.rfc1912.zones ] || echo '// zones (VortexPanel)' > /etc/named.rfc1912.zones
    chgrp named /etc/named.conf /etc/named.rfc1912.zones; chmod 0640 /etc/named.conf
  fi
  # (also for a named.conf this script wrote earlier) DNSSEC managed keys must be writable
  if grep -q '^// BIND configuration (VortexPanel)' /etc/named.conf && ! grep -q 'managed-keys-directory' /etc/named.conf; then
    sed -i 's|^\(\s*statistics-file .*\)$|\1\n\tmanaged-keys-directory "/var/named/dynamic";|' /etc/named.conf
  fi
  KEY=/etc/rndc.key
fi
# rndc talks to named with this key (named loads it automatically)
if [ ! -e "$KEY" ] && [ ! -e "$(dirname "$KEY")/rndc.conf" ]; then
  "$VP_PREFIX/sbin/rndc-confgen" -a -c "$KEY" >/dev/null 2>&1 || "$VP_PREFIX/sbin/tsig-keygen" -a hmac-sha256 rndc-key > "$KEY"
  chown root:"$U" "$KEY"; chmod 0640 "$KEY"
fi
for f in "$VP_PREFIX"/sbin/*; do n="$(basename "$f")"; [ "$n" = vp-named-start ] && continue; link_free "$VP_CURRENT/sbin/$n" "/usr/sbin/$n"; done
for f in "$VP_PREFIX"/bin/*; do n="$(basename "$f")"; link_free "$VP_CURRENT/bin/$n" "/usr/bin/$n"; done
ALIAS=""; [ "$U" = bind ] && ALIAS="Alias=bind9.service"
write_unit named.service <<UNIT
[Unit]
Description=BIND Domain Name Server (VortexPanel build)
Documentation=man:named(8)
After=network.target
Wants=nss-lookup.target
Before=nss-lookup.target

[Service]
Type=simple
ExecStart=$VP_CURRENT/sbin/vp-named-start
ExecReload=$VP_CURRENT/sbin/rndc reload
ExecStop=$VP_CURRENT/sbin/rndc stop
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
$ALIAS
UNIT
if has_systemd; then systemctl reenable named >/dev/null 2>&1 || systemctl enable named >/dev/null 2>&1 || true; fi
