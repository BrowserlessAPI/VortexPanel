# Sourced by install.sh (Debian layout). php_to_fpm: the PHP versions mod_php served
# (mods-enabled/phpX.Y.load) are served by PHP-FPM instead:
#   - the php module is disabled (its files stay in mods-available)
#   - proxy_fcgi + setenvif are enabled
#   - conf-available/vortex-php-fpm.conf sends .php files to /run/php/vortex-modphp-X.Y.sock
#     (a pool with the settings PHP had under mod_php; the www pool is not changed)
#     (server-wide; a site's own SetHandler still wins inside that site)
#   - mpm_prefork (needed by mod_php only) becomes mpm_event when nothing else needs prefork
#   - PHP-FPM X.Y is enabled and started
# precheck.sh already made sure PHP-FPM exists for every such version.
php_to_fpm() {
  local E="${VP_APACHE_ETC:-/etc/apache2}" f v vers="" use=""
  for f in "$E"/mods-enabled/php*.load; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    v="$(basename "$f" .load)"; v="${v#php}"
    [[ "$v" =~ ^[0-9]+\.[0-9]+$ ]] || continue
    vers="$vers $v"
  done
  [ -n "$vers" ] || return 0
  printf '%s\n' $vers > "$E/.vortex-mod-php-versions"
  for v in $vers; do
    rm -f "$E/mods-enabled/php$v.load" "$E/mods-enabled/php$v.conf"
    say "mod_php $v disabled (PHP-FPM $v serves PHP from now on)"
  done
  use="$(printf '%s\n' $vers | sort -V | tail -1)"
  # php_value/php_flag/php_admin_* in the Apache configuration and .htaccess, and the
  # apache2/php.ini settings, carried over to PHP-FPM pools of their own (files outside /etc/apache2 are backed
  # up and listed in /var/lib/vortex-apache-switch/changes.json for a failed switch)
  rm -rf "${VP_SWITCH_STATE:-/var/lib/vortex-apache-switch}"
  python3 "$(dirname "$0")/php_fpm_switch.py" convert "$use" || fail "the PHP settings could not be moved to PHP-FPM (see above)"
  "$VP_PREFIX/sbin/a2enmod" -q proxy proxy_fcgi setenvif >/dev/null
  if [ ! -e "$E/conf-available/vortex-php-fpm.conf" ]; then
    cat > "$E/conf-available/vortex-php-fpm.conf" <<CONF
# VortexPanel: PHP through PHP-FPM $use, pool vortex-modphp (replaces mod_php, removed when Apache moved to the
# VortexPanel build). A website's own SetHandler for PHP takes precedence inside that website.
<FilesMatch ".+\.ph(?:ar|p|tml)\$">
    SetHandler "proxy:unix:/run/php/vortex-modphp-$use.sock|fcgi://localhost"
</FilesMatch>
<FilesMatch ".+\.phps\$">
    Require all denied
</FilesMatch>
<FilesMatch "^\.ph(?:ar|p|ps|tml)\$">
    Require all denied
</FilesMatch>
CONF
  fi
  ln -sfn ../conf-available/vortex-php-fpm.conf "$E/conf-enabled/vortex-php-fpm.conf"
  # prefork was only there for mod_php; event serves PHP-FPM better. Kept when another
  # enabled module needs a non-threaded server (itk, ruid2).
  if [ -e "$E/mods-enabled/mpm_prefork.load" ] && ! ls "$E"/mods-enabled/{mpm_itk,ruid2,php}*.load >/dev/null 2>&1; then
    rm -f "$E/mods-enabled/mpm_prefork.load" "$E/mods-enabled/mpm_prefork.conf"
    "$VP_PREFIX/sbin/a2enmod" -q mpm_event >/dev/null
    say "mpm_prefork replaced by mpm_event"
  fi
  for v in $vers; do
    if has_systemd; then
      systemctl enable "php$v-fpm" >/dev/null 2>&1 || true
      # restart: the new pools (vortex-modphp and the websites' own) load now
      systemctl restart "php$v-fpm" 2>/dev/null || fail "PHP-FPM $v did not start with the converted settings"
    fi
  done
}
