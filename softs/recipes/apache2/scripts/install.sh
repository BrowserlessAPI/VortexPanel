#!/bin/bash
# System integration for Apache (idempotent; runs before the version switch).
# Debian/Ubuntu: /etc/apache2 layout, apache2.service (alias httpd.service)
# RHEL family:   /etc/httpd layout, httpd.service (alias apache2.service)
# Existing configuration, sites and certificates are kept as they are.
. "$(dirname "$0")/lib.sh"
set -e
UTILS="ab htpasswd htdigest htdbm htcacheclean logresolve rotatelogs httxt2dbm checkgid fcgistarter"

if [ "$VP_FAMILY" = deb ]; then
  E=/etc/apache2
  [ -e $E/apache2.conf ] || bash "$(dirname "$0")/layout.sh" deb
  # Debian's mods-available/*.load files point at /usr/lib/apache2/modules
  M=/usr/lib/apache2/modules
  if [ -d $M ] && [ ! -L $M ]; then
    left="$(ls -A $M 2>/dev/null | tr '\n' ' ')"
    [ -z "$left" ] || fail "$M still holds modules from other packages ($left); remove those packages first"
    rmdir $M
  fi
  install -d /usr/lib/apache2
  link "$VP_CURRENT/modules" $M
  . "$(dirname "$0")/php_fpm.sh"
  # switching from the OS packages: PHP served by mod_php (now removed) moves to PHP-FPM
  [ "$VP_ACTION" = migrate ] && php_to_fpm
  # ModSecurity v2 comes with this build (Debian's module files, only when missing)
  [ -e $E/mods-available/security2.load ] || printf '# Depends: unique_id\nLoadModule security2_module /usr/lib/apache2/modules/mod_security2.so\n' > $E/mods-available/security2.load
  [ -e $E/mods-available/security2.conf ] || cat > $E/mods-available/security2.conf <<'CONF'
<IfModule security2_module>
	# Default Debian dir for modsecurity's persistent data
	SecDataDir /var/cache/modsecurity

	# Include all the *.conf files in /etc/modsecurity.
	IncludeOptional /etc/modsecurity/*.conf
</IfModule>
CONF
  install -d -m 0750 /var/cache/modsecurity
  chown www-data:www-data /var/cache/modsecurity 2>/dev/null || true
  install -d -m 0755 /etc/modsecurity
  for f in modsecurity.conf-recommended unicode.mapping; do
    [ -e /etc/modsecurity/$f ] || [ ! -e "$VP_PREFIX/share/modsecurity/$f" ] || cp "$VP_PREFIX/share/modsecurity/$f" /etc/modsecurity/$f
  done
  # every module the configuration loads must exist in this build
  missing=""
  for f in $E/mods-enabled/*.load; do
    [ -e "$f" ] || continue
    for so in $(awk 'tolower($1)=="loadmodule"{print $3}' "$f"); do
      [ -e "$VP_PREFIX/modules/$(basename "$so")" ] || missing="$missing $(basename "$so")"
    done
  done
  [ -z "$missing" ] || fail "the configuration loads modules this build does not include:$missing"
  link "$VP_CURRENT/sbin/apache2" /usr/sbin/apache2
  link "$VP_CURRENT/sbin/apachectl" /usr/sbin/apache2ctl
  link "$VP_CURRENT/sbin/apachectl" /usr/sbin/apachectl
  for t in a2enmod a2dismod a2ensite a2dissite a2enconf a2disconf a2query; do
    link "$VP_CURRENT/sbin/$t" "/usr/sbin/$t"
  done
  for u in $UTILS; do [ -e "$VP_PREFIX/bin/$u" ] && link "$VP_CURRENT/bin/$u" "/usr/bin/$u"; done
  install -d -m 0755 /var/log/apache2 /var/www
  write_unit apache2.service <<UNIT
[Unit]
Description=The Apache HTTP Server (VortexPanel build)
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
Environment=APACHE_STARTED_BY_SYSTEMD=true
PIDFile=/run/apache2/apache2.pid
ExecStart=$VP_CURRENT/sbin/apache2 -k start
ExecStop=$VP_CURRENT/sbin/apache2 -k graceful-stop
ExecReload=$VP_CURRENT/sbin/apache2 -k graceful
KillMode=mixed
PrivateTmp=true
Restart=on-abort

[Install]
WantedBy=multi-user.target
Alias=httpd.service
UNIT
  svc_enable apache2
  exit 0
fi

# ------------------------------------------------------------------ RHEL family
H=/etc/httpd
[ -e $H/conf/httpd.conf ] || bash "$(dirname "$0")/layout.sh" rpm
link "$VP_CURRENT/modules" $H/modules
# ModSecurity v2 comes with this build (loaded; it does nothing until rules turn it on)
[ -e $H/conf.modules.d/10-mod_security.conf ] || [ -e $H/conf.modules.d/10-vortex-security2.conf ] || \
  printf '<IfModule !unique_id_module>\n  LoadModule unique_id_module modules/mod_unique_id.so\n</IfModule>\nLoadModule security2_module modules/mod_security2.so\n' \
  > $H/conf.modules.d/10-vortex-security2.conf
install -d -m 0755 /etc/modsecurity
for f in modsecurity.conf-recommended unicode.mapping; do
  [ -e /etc/modsecurity/$f ] || [ ! -e "$VP_PREFIX/share/modsecurity/$f" ] || cp "$VP_PREFIX/share/modsecurity/$f" /etc/modsecurity/$f
done
link "$VP_CURRENT/sbin/httpd" /usr/sbin/httpd
link "$VP_CURRENT/sbin/apachectl" /usr/sbin/apachectl
for u in $UTILS; do [ -e "$VP_PREFIX/bin/$u" ] && link "$VP_CURRENT/bin/$u" "/usr/bin/$u"; done
write_unit httpd.service <<UNIT
[Unit]
Description=The Apache HTTP Server (VortexPanel build)
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
RuntimeDirectory=httpd
RuntimeDirectoryMode=0710
PIDFile=/run/httpd/httpd.pid
ExecStart=$VP_CURRENT/sbin/httpd -k start
ExecStop=$VP_CURRENT/sbin/httpd -k graceful-stop
ExecReload=$VP_CURRENT/sbin/httpd -k graceful
KillMode=mixed
PrivateTmp=true
Restart=on-abort

[Install]
WantedBy=multi-user.target
Alias=apache2.service
UNIT
svc_enable httpd
