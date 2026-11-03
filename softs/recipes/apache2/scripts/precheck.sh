#!/bin/bash
# Runs before anything changes. A switch from the OS packages removes libapache2-mod-php:
# PHP then runs through PHP-FPM, so every PHP version mod_php serves must have PHP-FPM.
. "$(dirname "$0")/lib.sh"
[ "$VP_ACTION" = migrate ] && [ "$VP_FAMILY" = deb ] || exit 0
E="${VP_APACHE_ETC:-/etc/apache2}"
missing=""
for f in "$E"/mods-enabled/php*.load; do
  [ -e "$f" ] || continue
  v="$(basename "$f" .load)"; v="${v#php}"
  [[ "$v" =~ ^[0-9]+\.[0-9]+$ ]] || continue
  if dpkg -s "php$v-fpm" 2>/dev/null | grep -q '^Status: install ok installed' || [ -e "/usr/local/vortex/php/$v" ]; then
    say "PHP $v: served by mod_php now, PHP-FPM $v is available - websites move to PHP-FPM"
  else
    missing="$missing $v"
  fi
done
# PHP settings in the Apache configuration that PHP-FPM cannot take over (listed with file:line)
[ -n "$(ls "$E"/mods-enabled/php*.load 2>/dev/null)" ] && \
  { python3 "$(dirname "$0")/php_fpm_switch.py" precheck || exit 1; }
if [ -n "$missing" ]; then
  for v in $missing; do
    echo "[$VP_APP] PHP $v runs inside Apache (mod_php) and has no PHP-FPM. Install PHP $v from the App Store first, then switch Apache again." >&2
  done
  exit 1
fi
exit 0
