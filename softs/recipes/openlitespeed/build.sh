# Official OpenLiteSpeed binary release (GitHub release asset, TLS download).
cd "$SRC"
NAME="openlitespeed-$VERSION-$ARCH-linux.tgz"
curl -fsSL --retry 4 -o "$NAME" "https://github.com/litespeedtech/openlitespeed/releases/download/v$VERSION/$NAME"
install -d "$DEST$PREFIX/dist"
tar -xzf "$NAME" -C "$DEST$PREFIX/dist" --strip-components=1 --no-same-owner
[ -f "$DEST$PREFIX/dist/bin/openlitespeed" ] && [ -f "$DEST$PREFIX/dist/install.sh" ] || { echo "[build] unexpected archive layout"; exit 3; }
[ "$(tr -d '[:space:]' < "$DEST$PREFIX/dist/VERSION")" = "$VERSION" ] || { echo "[build] VERSION file does not match $VERSION"; exit 3; }
# the upstream installer fetches its admin PHP binary and this server's IP over plain HTTP
sed -i -e 's#http://www\.litespeedtech\.com/#https://www.litespeedtech.com/#g' \
       -e 's#http://cyberpanel\.sh/#https://cyberpanel.sh/#g' "$DEST$PREFIX/dist/_in.sh"
# the installer looks up this server's public IP from cyberpanel.sh for the WebAdmin
# certificate but never uses it (that line is commented out upstream); without a time
# limit the lookup can hang for hours, so it is removed
grep -qE '^[[:space:]]*testMyIP[[:space:]]*$' "$DEST$PREFIX/dist/_in.sh" || { echo "[build] installer layout changed (testMyIP)"; exit 3; }
sed -i -E 's/^([[:space:]]*)testMyIP[[:space:]]*$/\1MYIP=127.0.0.1   # VortexPanel: lookup removed (unused)/' "$DEST$PREFIX/dist/_in.sh"
rm -rf "$DEST$PREFIX/dist/docs"
