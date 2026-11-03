# Official static release binary (checksums verified against the release's checksums file).
GOARCH=amd64; [ "$ARCH" = aarch64 ] && GOARCH=arm64
NAME="caddy_${VERSION}_linux_${GOARCH}.tar.gz"
cd "$SRC"
[ -n "${SOURCE_FILE:-}" ] || SOURCE_FILE="$(fetch "https://github.com/caddyserver/caddy/releases/download/v$VERSION/$NAME")"
curl -fsSL "https://github.com/caddyserver/caddy/releases/download/v$VERSION/caddy_${VERSION}_checksums.txt" -o sums.txt
want="$(awk -v n="$NAME" '$2==n{print $1}' sums.txt)"
got="$(sha512sum "$SOURCE_FILE" | awk '{print $1}')"
[ -n "$want" ] && [ "$want" = "$got" ] || { echo "caddy checksum mismatch"; exit 3; }
mkdir x; tar -xzf "$SOURCE_FILE" -C x --no-same-owner
install -D -m 0755 x/caddy "$DEST$PREFIX/bin/caddy"
