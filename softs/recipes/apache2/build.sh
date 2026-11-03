# Apache httpd 2.4 against the system APR, APR-util, PCRE2 and OpenSSL. Every module
# and MPM is a shared module (like the distribution packages); the few Debian builds
# in statically (unixd, log_config, logio, version, watchdog) are static here too, so
# Debian's mods-available/*.load files match.
cd "$SRC"; tar -xjf "$SOURCE_FILE"; cd httpd-"$VERSION"
APR=$(command -v apr-1-config); APU=$(command -v apu-1-config); PCRE=$(command -v pcre2-config)
./configure --prefix="$PREFIX" --with-apr="$APR" --with-apr-util="$APU" --with-pcre="$PCRE" \
  --enable-mods-shared=all --enable-mpms-shared=all --with-mpm=event \
  --enable-mods-static="unixd log_config logio version watchdog" \
  --enable-ssl --enable-http2 --enable-proxy-http2 --enable-cgi --enable-cgid \
  --enable-pie
make -j"$JOBS"
make install DESTDIR="$DEST"
rm -rf "$DEST$PREFIX/manual" "$DEST$PREFIX/htdocs" "$DEST$PREFIX/cgi-bin" "$DEST$PREFIX/logs"
[ -f "$DEST$PREFIX/modules/mod_ssl.so" ] && [ -f "$DEST$PREFIX/modules/mod_http2.so" ] && [ -f "$DEST$PREFIX/modules/mod_mpm_event.so" ] \
  || { echo "[build] mod_ssl, mod_http2 or mod_mpm_event was not built"; exit 3; }

# ---- ModSecurity v2 (mod_security2), built with this httpd's apxs ----------------------
# apxs reads its build files from the install prefix: install there too (throwaway container)
make install >/dev/null
MS_TAG="$(git ls-remote --tags --refs https://github.com/owasp-modsecurity/ModSecurity.git | sed 's|.*refs/tags/||' \
          | grep -E '^v2\.9\.[0-9]+$' | sort -V | tail -1)"
[ -n "$MS_TAG" ] || { echo "[build] cannot find a ModSecurity v2.9 release"; exit 3; }
MS_V="${MS_TAG#v}"
cd "$SRC"
curl -fsSL --retry 4 -o ms.tgz "https://github.com/owasp-modsecurity/ModSecurity/releases/download/$MS_TAG/modsecurity-$MS_TAG.tar.gz"
curl -fsSL --retry 4 -o ms.sha256 "https://github.com/owasp-modsecurity/ModSecurity/releases/download/$MS_TAG/modsecurity-$MS_TAG.tar.gz.sha256" \
  && { want="$(awk '{print $1}' ms.sha256)"; [ "$want" = "$(sha256sum ms.tgz | awk '{print $1}')" ] || { echo "[build] ModSecurity checksum mismatch"; exit 3; }; } \
  || echo "[build] no .sha256 published for $MS_TAG; TLS download only"
mkdir ms; tar -xzf ms.tgz -C ms --strip-components=1 --no-same-owner; cd ms
MSCONF="--with-apxs=$PREFIX/bin/apxs --disable-mlogc"   # libxml2, curl, yajl, lua: found automatically
if ./configure --help | grep -q -- '--with-pcre2'; then MSCONF="$MSCONF --with-pcre2=$(command -v pcre2-config)"; fi
./configure $MSCONF >/dev/null
make -j"$JOBS" >/dev/null
install -m 0755 apache2/.libs/mod_security2.so "$DEST$PREFIX/modules/mod_security2.so"
install -d "$DEST$PREFIX/share/modsecurity"
cp modsecurity.conf-recommended unicode.mapping "$DEST$PREFIX/share/modsecurity/"
cd "$SRC/httpd-$VERSION"
install -d "$DEST$PREFIX/share"
printf 'httpd %s\nmodsecurity %s\n' "$VERSION" "$MS_V" > "$DEST$PREFIX/share/BUILDINFO"
cat "$DEST$PREFIX/share/BUILDINFO"

# ---- commands for the distribution's layout (chosen by the target's family) ----------
S="$DEST$PREFIX/sbin"; install -d "$S"
if [ "$FAMILY" = deb ]; then
cat > "$S/apache2" <<'W'
#!/bin/sh
# VortexPanel: Apache with the Debian layout (/etc/apache2, environment from envvars)
[ -r /etc/apache2/envvars ] && . /etc/apache2/envvars
for d in "${APACHE_RUN_DIR:-/run/apache2}" "${APACHE_LOCK_DIR:-/var/lock/apache2}" "${APACHE_LOG_DIR:-/var/log/apache2}"; do
  [ -d "$d" ] || mkdir -p "$d" 2>/dev/null
done
[ -n "${APACHE_LOCK_DIR:-}" ] && [ -n "${APACHE_RUN_USER:-}" ] && chown "$APACHE_RUN_USER" "$APACHE_LOCK_DIR" 2>/dev/null
exec "$(dirname "$(readlink -f "$0")")/../bin/httpd" -d /etc/apache2 -f /etc/apache2/apache2.conf "$@"
W
SVC=apache2; RUN=apache2
else
cat > "$S/httpd" <<'W'
#!/bin/sh
# VortexPanel: Apache with the RHEL layout (ServerRoot /etc/httpd)
[ -d /run/httpd ] || mkdir -p /run/httpd 2>/dev/null
exec "$(dirname "$(readlink -f "$0")")/../bin/httpd" -d /etc/httpd "$@"
W
SVC=httpd; RUN=httpd
fi
cat > "$S/apachectl" <<W
#!/bin/sh
# VortexPanel: apachectl / apache2ctl
BIN="\$(dirname "\$(readlink -f "\$0")")/$RUN"
svc() { [ -d /run/systemd/system ] && [ -e /etc/systemd/system/$SVC.service ]; }
case "\${1:-}" in
  start|stop|restart)        if svc; then exec systemctl "\$1" $SVC; else exec "\$BIN" -k "\$1"; fi ;;
  graceful|reload)           if svc; then exec systemctl reload $SVC; else exec "\$BIN" -k graceful; fi ;;
  graceful-stop)             if svc; then exec systemctl stop $SVC; else exec "\$BIN" -k graceful-stop; fi ;;
  configtest|-t)             exec "\$BIN" -t ;;
  status|fullstatus)         exec systemctl status $SVC --no-pager ;;
  -*)                        exec "\$BIN" "\$@" ;;
  *)                         echo "usage: \$0 start|stop|restart|graceful|graceful-stop|configtest|status|-V|-M|-S|-t"; exit 1 ;;
esac
W
if [ "$FAMILY" = deb ]; then
cat > "$S/a2enmod" <<'W'
#!/bin/bash
# VortexPanel: a2enmod / a2dismod / a2ensite / a2dissite / a2enconf / a2disconf / a2query
# for the Debian /etc/apache2 layout (same files and links as Debian's tools).
E=/etc/apache2
me="$(basename "$0")"; quiet=0
say() { [ "$quiet" = 1 ] || echo "$@"; }
tell() { say "To activate the new configuration, you need to run:"; say "  systemctl $1 apache2"; }

mod_on() {  # NAME [as-dependency]
  local m="$1" dep c changed=0
  [ -e "$E/mods-available/$m.load" ] || { echo "ERROR: Module $m does not exist!" >&2; return 1; }
  for c in $(sed -n 's/^#[[:space:]]*Conflicts:[[:space:]]*//p' "$E/mods-available/$m.load"); do
    [ -e "$E/mods-enabled/$c.load" ] && { echo "ERROR: Module $c is enabled - cannot proceed due to conflicts. It needs to be disabled first!" >&2; return 1; }
  done
  for dep in $(sed -n 's/^#[[:space:]]*Depends:[[:space:]]*//p' "$E/mods-available/$m.load"); do
    mod_on "$dep" 1 || return 1
  done
  for f in load conf; do
    if [ -e "$E/mods-available/$m.$f" ] && [ ! -e "$E/mods-enabled/$m.$f" ]; then
      ln -sfn "../mods-available/$m.$f" "$E/mods-enabled/$m.$f"; changed=1
    fi
  done
  if [ "$changed" = 1 ]; then
    [ -n "${2:-}" ] && say "Considering dependency $m for $DEPOF:"
    say "Enabling module $m."
  elif [ -z "${2:-}" ]; then say "Module $m already enabled"; fi
  return 0
}
mod_off() {
  local m="$1" any=0
  for f in load conf; do [ -L "$E/mods-enabled/$m.$f" ] && { rm -f "$E/mods-enabled/$m.$f"; any=1; }; done
  if [ "$any" = 1 ]; then say "Module $m disabled."; else
    [ -e "$E/mods-available/$m.load" ] || { echo "ERROR: Module $m does not exist!" >&2; return 1; }
    say "Module $m already disabled"; fi
}
obj_on() {  # KIND(sites|conf) NAME
  local k="$1" n="${2%.conf}"
  [ -e "$E/$k-available/$n.conf" ] || { echo "ERROR: ${k%s} $n does not exist!" >&2; return 1; }
  if [ -e "$E/$k-enabled/$n.conf" ]; then say "${k%s} $n already enabled"; return 0; fi
  ln -sfn "../$k-available/$n.conf" "$E/$k-enabled/$n.conf"; say "Enabling ${k%s} $n."
}
obj_off() {
  local k="$1" n="${2%.conf}"
  if [ -L "$E/$k-enabled/$n.conf" ] || [ -e "$E/$k-enabled/$n.conf" ]; then rm -f "$E/$k-enabled/$n.conf"; say "${k%s} $n disabled."
  else [ -e "$E/$k-available/$n.conf" ] || { echo "ERROR: ${k%s} $n does not exist!" >&2; return 1; }; say "${k%s} $n already disabled"; fi
}

query() {  # a2query -m|-s|-c [NAME] | -M | -v
  local flag="$1" n="${2:-}" k ext=conf
  case "$flag" in
    -M) for c in "$E"/mods-enabled/mpm_*.load; do [ -e "$c" ] && { basename "$c" .load | sed 's/^mpm_//'; return 0; }; done; return 1 ;;
    -v) "$(dirname "$(readlink -f "$0")")/../bin/httpd" -v | sed -n 's|.*Apache/\([0-9.]*\).*|\1|p'; return 0 ;;
    -m) k=mods; ext=load ;; -s) k=sites ;; -c) k=conf ;;
    *) echo "usage: a2query -m [MODULE] | -s [SITE] | -c [CONF] | -M | -v" >&2; return 1 ;;
  esac
  if [ -z "$n" ]; then
    for f in "$E/$k-enabled"/*."$ext"; do [ -e "$f" ] && say "$(basename "$f" ."$ext") (enabled by site administrator)"; done; return 0
  fi
  n="${n%.$ext}"
  if [ -e "$E/$k-enabled/$n.$ext" ]; then say "$n (enabled by site administrator)"; return 0; fi
  case "$k" in mods) k=module ;; sites) k=site ;; esac
  say "No ${k%s} matches $n"; return 32
}

args=()
for a in "$@"; do case "$a" in -q|--quiet) quiet=1 ;; -f|--force|-m|-p|--purge|-M|-s|-c|-v) args+=("$a") ;; -*) ;; *) args+=("$a") ;; esac; done
set -- "${args[@]}"
rc=0; changed=0
case "$me" in
  a2query) [ "${1:-}" = -q ] && shift; query "$@"; exit $? ;;
  a2enmod)  for x in "$@"; do [[ "$x" == -* ]] && continue; x="${x%.load}"; x="${x#mod_}"; DEPOF="$x"; mod_on "$x" && changed=1 || rc=1; done; [ "$changed" = 1 ] && tell restart ;;
  a2dismod) for x in "$@"; do [[ "$x" == -* ]] && continue; x="${x%.load}"; x="${x#mod_}"; mod_off "$x" && changed=1 || rc=1; done; [ "$changed" = 1 ] && tell restart ;;
  a2ensite) for x in "$@"; do [[ "$x" == -* ]] && continue; obj_on sites "$x" && changed=1 || rc=1; done; [ "$changed" = 1 ] && tell reload ;;
  a2dissite) for x in "$@"; do [[ "$x" == -* ]] && continue; obj_off sites "$x" && changed=1 || rc=1; done; [ "$changed" = 1 ] && tell reload ;;
  a2enconf) for x in "$@"; do [[ "$x" == -* ]] && continue; obj_on conf "$x" && changed=1 || rc=1; done; [ "$changed" = 1 ] && tell reload ;;
  a2disconf) for x in "$@"; do [[ "$x" == -* ]] && continue; obj_off conf "$x" && changed=1 || rc=1; done; [ "$changed" = 1 ] && tell reload ;;
  *) echo "unknown command $me" >&2; exit 1 ;;
esac
exit $rc
W
for t in a2dismod a2ensite a2dissite a2enconf a2disconf a2query; do ln -sf a2enmod "$S/$t"; done
fi
chmod 0755 "$S"/*
