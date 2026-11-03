#!/bin/bash
# PHP X.Y system integration: Debian layout, own systemd unit, per-version links.
. "$(dirname "$0")/lib.sh"
set -e
V="$VP_TRACK"; ETC=/etc/php/$V
getent group www-data >/dev/null || groupadd -r www-data
getent passwd www-data >/dev/null || useradd -r -g www-data -d /var/www -s /usr/sbin/nologin www-data 2>/dev/null \
  || useradd -r -g www-data -d /var/www -s /sbin/nologin www-data
install -d -m 0755 "$ETC/fpm/conf.d" "$ETC/fpm/pool.d" "$ETC/cli/conf.d" "$ETC/mods-available" /run/php /var/log
EXTDIR="$(ls -d "$VP_PREFIX"/lib/php/extensions/*/ | head -1)"
[ -e "$ETC/fpm/php.ini" ] || cp "$VP_PREFIX/share/conf/php.ini-production" "$ETC/fpm/php.ini"
[ -e "$ETC/cli/php.ini" ] || cp "$VP_PREFIX/share/conf/php.ini-production" "$ETC/cli/php.ini"
# extension_dir must follow the version link, not one release
for ini in "$ETC/fpm/php.ini" "$ETC/cli/php.ini"; do
  if grep -q '^extension_dir' "$ini"; then sed -i "s|^extension_dir.*|extension_dir = \"$VP_CURRENT/lib/php/extensions/$(basename "$EXTDIR")\"|" "$ini"
  else echo "extension_dir = \"$VP_CURRENT/lib/php/extensions/$(basename "$EXTDIR")\"" >> "$ini"; fi
done
# Debian-style module switches; common ones on by default on a first install
ON="opcache mysqli pdo_mysql curl gd intl zip bcmath exif soap sodium sockets calendar ftp bz2 gmp xsl"
for so in "$EXTDIR"/*.so; do
  [ -e "$so" ] || continue
  m="$(basename "$so" .so)"
  kw=extension; [ "$m" = opcache ] || [ "$m" = xdebug ] && kw=zend_extension
  [ -e "$ETC/mods-available/$m.ini" ] || printf '; priority=20\n%s=%s.so\n' "$kw" "$m" > "$ETC/mods-available/$m.ini"
  if { [ "${VP_ACTION}" = install ] || [ "${VP_ACTION}" = migrate ]; } && echo " $ON " | grep -q " $m "; then
    pr=20; [ "$m" = opcache ] && pr=10
    for s in fpm cli; do [ -e "$ETC/$s/conf.d/$pr-$m.ini" ] || ln -s "$ETC/mods-available/$m.ini" "$ETC/$s/conf.d/$pr-$m.ini"; done
  fi
done
# switched from distro PHP: its conf.d links name extensions; drop the ones this
# build has built in or does not have (PHP would print warnings or fail to start)
if [ "$VP_ACTION" = migrate ]; then
  for sapi in fpm cli; do
    for l in "$ETC/$sapi/conf.d/"*.ini; do
      [ -e "$l" ] || [ -L "$l" ] || continue
      name="$(grep -oE '^[[:space:]]*(zend_)?extension[[:space:]]*=[[:space:]]*[^[:space:];]+' "$l" 2>/dev/null | head -1 | sed -E 's/.*=[[:space:]]*//; s/\.so$//; s|.*/||')"
      [ -n "$name" ] || continue
      [ -e "$EXTDIR/$name.so" ] || { say "conf.d: $(basename "$l") ($name) is not a separate module in this build - set aside";
                                    mkdir -p "$ETC/$sapi/conf.d.vortex-switch"; mv -f "$l" "$ETC/$sapi/conf.d.vortex-switch/"; }
    done
  done
fi
WEB_USER="$(grep -oE '^[[:space:]]*user[[:space:]]+[^;[:space:]]+' /etc/nginx/nginx.conf 2>/dev/null | awk '{print $2}' | head -1)"
WEB_USER="${WEB_USER:-www-data}"
[ -e "$ETC/fpm/php-fpm.conf" ] || cat > "$ETC/fpm/php-fpm.conf" <<CONF
[global]
pid = /run/php/php$V-fpm.pid
error_log = /var/log/php$V-fpm.log
include = $ETC/fpm/pool.d/*.conf
CONF
[ -e "$ETC/fpm/pool.d/www.conf" ] || cat > "$ETC/fpm/pool.d/www.conf" <<CONF
[www]
user = www-data
group = www-data
listen = /run/php/php$V-fpm.sock
listen.owner = $WEB_USER
listen.group = $WEB_USER
listen.mode = 0660
pm = dynamic
pm.max_children = 20
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 4
CONF
# commands: phpX.Y reads the CLI configuration, php-fpmX.Y the FPM one
cat > "/usr/bin/php$V" <<WRAP
#!/bin/sh
# VortexPanel PHP $V
PHP_INI_SCAN_DIR=$ETC/cli/conf.d exec $VP_CURRENT/bin/php -c $ETC/cli/php.ini "\$@"
WRAP
chmod 0755 "/usr/bin/php$V"
link "$VP_CURRENT/sbin/php-fpm" "/usr/sbin/php-fpm$V"
for t in phpize php-config; do link "$VP_CURRENT/bin/$t" "/usr/bin/$t$V"; done
[ -e /usr/bin/php ] || link "/usr/bin/php$V" /usr/bin/php
write_unit "php$V-fpm.service" <<UNIT
[Unit]
Description=PHP $V FastCGI Process Manager (VortexPanel build)
After=network.target

[Service]
Type=$( [ -e "$VP_PREFIX/share/conf/systemd-notify" ] && echo notify || echo simple )
PIDFile=/run/php/php$V-fpm.pid
RuntimeDirectory=php
RuntimeDirectoryPreserve=yes
ExecStartPre=$VP_CURRENT/sbin/php-fpm -t -y $ETC/fpm/php-fpm.conf -c $ETC/fpm/php.ini
ExecStart=$VP_CURRENT/sbin/php-fpm --nodaemonize -y $ETC/fpm/php-fpm.conf -c $ETC/fpm/php.ini
ExecReload=/bin/kill -USR2 \$MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
svc_enable "php$V-fpm"
