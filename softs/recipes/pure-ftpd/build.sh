cd "$SRC"; tar -xzf "$SOURCE_FILE"; cd pure-ftpd-"$VERSION"
./configure --prefix="$PREFIX" --sysconfdir=/etc/pure-ftpd --localstatedir=/var \
  --with-everything --with-tls --with-pam --with-certfile=/etc/ssl/private/pure-ftpd.pem
make -j"$JOBS"
make install DESTDIR="$DEST"
install -d "$DEST$PREFIX/share"
cp pure-ftpd.conf "$DEST$PREFIX/share/pure-ftpd.conf.sample"
rm -rf "$DEST/etc" "$DEST$PREFIX/share/man"
# Starts pure-ftpd from either configuration layout the panel manages:
#   Debian/Ubuntu  /etc/pure-ftpd/conf/<Keyword> files + /etc/pure-ftpd/auth/NN* links
#   RHEL / fresh   /etc/pure-ftpd/pure-ftpd.conf
install -d "$DEST$PREFIX/sbin"
cat > "$DEST$PREFIX/sbin/vp-pure-ftpd-run" <<'RUN'
#!/bin/bash
# VortexPanel: run pure-ftpd in the foreground with the server's configuration.
set -e
BIN="$(dirname "$(readlink -f "$0")")/pure-ftpd"
D=/etc/pure-ftpd
if [ -d "$D/conf" ]; then
  # one file per keyword (Debian layout) -> a pure-ftpd.conf; the auth/ links give the
  # order of the authentication methods
  install -d -m 0755 /run/pure-ftpd
  OUT=/run/pure-ftpd/pure-ftpd.conf; TMP="$OUT.$$"
  AUTHKEYS=" PureDB UnixAuthentication PAMAuthentication MySQLConfigFile PGSQLConfigFile LDAPConfigFile ExtAuth "
  : > "$TMP"
  if [ -d "$D/auth" ]; then
    for a in $(ls "$D/auth" | sort); do
      k="$(basename "$(readlink "$D/auth/$a" 2>/dev/null || echo "$a")")"
      v="$(head -1 "$D/conf/$k" 2>/dev/null | tr -d '\r')"
      [ -n "$v" ] && [ "$v" != no ] && echo "$k $v" >> "$TMP"
    done
  fi
  # keywords this pure-ftpd understands (from its own sample configuration); Debian's
  # names that differ are mapped, anything unknown is left out with a note in the journal
  SAMPLE="$(dirname "$BIN")/../share/pure-ftpd.conf.sample"
  KNOWN=" $(sed -nE 's/^#?[[:space:]]*([A-Z][A-Za-z0-9]+)[[:space:]].*/\1/p' "$SAMPLE" 2>/dev/null | sort -u | tr '\n' ' ') "
  for f in "$D"/conf/*; do
    [ -f "$f" ] || continue
    k="$(basename "$f")"
    case "$k" in FSCharset) k=FileSystemCharset ;; esac
    if [ "$KNOWN" != "  " ] && [ "${KNOWN#* $k }" = "$KNOWN" ]; then
      echo "pure-ftpd: $D/conf/$(basename "$f") is not a pure-ftpd.conf setting; skipped" >&2; continue
    fi
    case "$AUTHKEYS" in *" $k "*) continue ;; esac
    [ "$k" = Daemonize ] && continue
    v="$(head -1 "$f" | tr -d '\r')"
    [ -n "$v" ] && echo "$k $v" >> "$TMP"
  done
  if [ ! -f /proc/net/if_inet6 ] && ! grep -qiE '^IPV(4|6)Only[[:space:]]+yes' "$TMP"; then echo 'IPV4Only yes' >> "$TMP"; fi
  mv -f "$TMP" "$OUT"
  exec "$BIN" "$OUT"
fi
for C in "$D/pure-ftpd.conf" /etc/pure-ftpd.conf; do
  if [ -f "$C" ]; then
    # run in the foreground (no Daemonize); on a system without IPv6, listen on IPv4 only
    # (pure-ftpd does not start when it cannot open its IPv6 socket)
    install -d -m 0755 /run/pure-ftpd
    grep -viE '^[[:space:]]*Daemonize[[:space:]]' "$C" > /run/pure-ftpd/pure-ftpd.conf
    if [ ! -f /proc/net/if_inet6 ] && ! grep -qiE '^[[:space:]]*IPV(4|6)Only[[:space:]]+yes' "$C"; then
      echo 'IPV4Only                     yes' >> /run/pure-ftpd/pure-ftpd.conf
    fi
    exec "$BIN" /run/pure-ftpd/pure-ftpd.conf
  fi
done
echo "no Pure-FTPd configuration found in $D" >&2; exit 1
RUN
chmod 0755 "$DEST$PREFIX/sbin/vp-pure-ftpd-run"
