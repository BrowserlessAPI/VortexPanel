# MongoDB's release tarball for this system (resolve.py) and the newest mongosh release.
# the tarball resolve.py picked from MongoDB's download index (in_container.sh downloaded
# it and checked the SHA-256 from that index)
cd "$SRC"
[ -n "${SOURCE_FILE:-}" ] && [ -f "$SOURCE_FILE" ] || { echo "[build] no MongoDB tarball was resolved for $TARGET-$ARCH"; exit 3; }
if [ -z "${VP_SHA256:-}" ]; then
  curl -fsSL --retry 3 -o sum.txt "$VP_URL.sha256"
  want="$(awk '{print $1}' sum.txt)"; have="$(sha256sum "$SOURCE_FILE" | awk '{print $1}')"
  [ -n "$want" ] && [ "$want" = "$have" ] || { echo "[build] MongoDB checksum mismatch"; exit 3; }
fi
got="$SOURCE_FILE"
echo "[build] using $got"
mkdir x; tar -xzf "$got" -C x --no-same-owner
install -d "$DEST$PREFIX/bin" "$DEST$PREFIX/share"
for b in mongod mongos; do
  f="$(echo x/*/bin/$b)"; [ -f "$f" ] && install -m 0755 "$f" "$DEST$PREFIX/bin/$b"
done
[ -x "$DEST$PREFIX/bin/mongod" ] || { echo "[build] mongod missing from $got"; exit 3; }
cp x/*/LICENSE* x/*/README* "$DEST$PREFIX/share/" 2>/dev/null || true

# mongosh (the shell; independent release cycle, self-contained build)
MA=x64; [ "$ARCH" = aarch64 ] && MA=arm64
tag="$(curl -fsSI https://github.com/mongodb-js/mongosh/releases/latest | sed -n 's|^[Ll]ocation: .*/tag/v\([0-9.]*\).*|\1|p' | tr -d '\r')"
[ -n "$tag" ] || { echo "[build] cannot find the latest mongosh release"; exit 3; }
S="mongosh-$tag-linux-$MA.tgz"
curl -fsSL --retry 3 -o "$S" "https://github.com/mongodb-js/mongosh/releases/download/v$tag/$S"
mkdir y; tar -xzf "$S" -C y --no-same-owner
install -m 0755 y/*/bin/mongosh "$DEST$PREFIX/bin/mongosh"
f="$(echo y/*/bin/mongosh_crypt_v1.so)"; [ -f "$f" ] && install -m 0644 "$f" "$DEST$PREFIX/bin/" || true
echo "$tag" > "$DEST$PREFIX/share/mongosh-version"
"$DEST$PREFIX/bin/mongod" --version | head -1
