# ISC release tarball. The configuration folder is the one this OS family uses, so
# named, rndc and rndc-confgen find named.conf and rndc.key without extra options.
cd "$SRC"; tar -xJf "$SOURCE_FILE" --no-same-owner; cd bind-"$VERSION"
if [ "$FAMILY" = deb ]; then ETC=/etc/bind; else ETC=/etc; fi
./configure --prefix="$PREFIX" --sysconfdir="$ETC" --localstatedir=/var --runstatedir=/run \
            --disable-static --with-libidn2 --with-json-c --with-libxml2 --enable-linux-caps
make -j"$JOBS"
make install DESTDIR="$DEST"
rm -rf "$DEST$PREFIX/include" "$DEST$PREFIX/share/doc"
find "$DEST$PREFIX/lib" -name '*.la' -delete 2>/dev/null || true
# configuration and state folders are the server's, never part of the version folder
rm -rf "$DEST$ETC" "$DEST/var" "$DEST/run"
cat > "$DEST$PREFIX/sbin/vp-named-start" <<'WRAP'
#!/bin/sh
# Start named with the server's own layout:
#   Debian/Ubuntu: /etc/bind/named.conf, user bind, options in /etc/default/named
#   RHEL family:   /etc/named.conf, user named, options in /etc/sysconfig/named
D="$(dirname "$(readlink -f "$0")")"
OPTIONS=""
if [ -f /etc/bind/named.conf ]; then
  CONF=/etc/bind/named.conf; U=bind
  [ -f /etc/default/named ] && . /etc/default/named
  [ -f /etc/default/bind9 ] && . /etc/default/bind9
else
  CONF=/etc/named.conf; U=named
  [ -f /etc/sysconfig/named ] && . /etc/sysconfig/named
  [ -n "${NAMEDCONF:-}" ] && CONF="$NAMEDCONF"
fi
case " $OPTIONS " in *" -u "*) ;; *) OPTIONS="-u $U $OPTIONS" ;; esac
case " $OPTIONS " in *" -c "*) ;; *) OPTIONS="-c $CONF $OPTIONS" ;; esac
install -d -m 0775 -o root -g "$U" /run/named 2>/dev/null || install -d /run/named
"$D/../bin/named-checkconf" "$CONF" || exit 1
# shellcheck disable=SC2086
exec "$D/named" -f $OPTIONS "$@"
WRAP
chmod 0755 "$DEST$PREFIX/sbin/vp-named-start"
