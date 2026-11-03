# Official Node.js Linux binaries, checked against SHASUMS256.txt.
NA=x64; [ "$ARCH" = aarch64 ] && NA=arm64
NAME="node-v$VERSION-linux-$NA.tar.xz"
cd "$SRC"
curl -fsSL "https://nodejs.org/dist/v$VERSION/SHASUMS256.txt" -o SHASUMS256.txt
SOURCE_FILE="$(fetch "https://nodejs.org/dist/v$VERSION/$NAME" "$(awk -v n="$NAME" '$2==n{print $1}' SHASUMS256.txt)")"
mkdir -p "$DEST$PREFIX"
tar -xJf "$SOURCE_FILE" -C "$DEST$PREFIX" --strip-components=1 --no-same-owner
# npm global installs (npm i -g pm2) go to /usr/local, not into this version's folder
printf 'prefix=/usr/local\n' > "$DEST$PREFIX/lib/node_modules/npm/npmrc"
rm -rf "$DEST$PREFIX/share/doc" "$DEST$PREFIX/CHANGELOG.md"
