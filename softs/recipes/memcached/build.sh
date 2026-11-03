# memcached.org release tarball (ready to configure). TLS and SASL enabled like the distro packages.
cd "$SRC"; tar -xzf "$SOURCE_FILE" --no-same-owner; cd memcached-"$VERSION"
./configure --prefix="$PREFIX" --enable-tls --enable-sasl
make -j"$JOBS"
make install DESTDIR="$DEST"
rm -rf "$DEST$PREFIX/include"
# start wrapper: reads the server's own settings file, whichever layout this OS uses
cat > "$DEST$PREFIX/bin/vp-memcached-start" <<'WRAP'
#!/bin/sh
# Debian/Ubuntu: /etc/memcached.conf (one option per line, "-m 64").
# RHEL family:   /etc/sysconfig/memcached (PORT USER MAXCONN CACHESIZE OPTIONS).
BIN="$(dirname "$(readlink -f "$0")")/memcached"
ARGS=""; LOG=""; RUNAS=""
if [ -f /etc/memcached.conf ]; then
  ARGS="$(sed -e 's/#.*//' /etc/memcached.conf | grep -E '^[[:space:]]*-' | grep -vE '^[[:space:]]*-d[[:space:]]*$' | tr '\n' ' ')"
  LOG="$(sed -n 's/^[[:space:]]*logfile[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' /etc/memcached.conf | tail -1)"
elif [ -f /etc/sysconfig/memcached ]; then
  PORT=11211; USER=memcached; MAXCONN=1024; CACHESIZE=64; OPTIONS=""
  . /etc/sysconfig/memcached
  ARGS="-p ${PORT} -u ${USER} -m ${CACHESIZE} -c ${MAXCONN} ${OPTIONS}"
fi
case " $ARGS " in *" -u "*) ;; *)
  for u in memcache memcached nobody; do id "$u" >/dev/null 2>&1 && { RUNAS="-u $u"; break; }; done ;;
esac
[ -n "$LOG" ] && exec >>"$LOG" 2>&1
# shellcheck disable=SC2086
exec "$BIN" $ARGS $RUNAS
WRAP
chmod 0755 "$DEST$PREFIX/bin/vp-memcached-start"
