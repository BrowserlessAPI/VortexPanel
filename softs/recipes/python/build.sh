# Relocatable CPython from python-build-standalone (runs on glibc >= 2.17).
U="VP_ASSET_$ARCH"; U="${!U:-}"
[ -n "$U" ] || { echo "no python-build-standalone asset for $ARCH"; exit 3; }
cd "$SRC"
F="$(fetch "$U")"
curl -fsSL "$U.sha256" -o sum.txt 2>/dev/null && { echo "$(cut -d' ' -f1 sum.txt)  $F" | sha256sum -c - >/dev/null || { echo "checksum mismatch"; exit 3; }; }
mkdir -p "$DEST$PREFIX"
tar -xzf "$F" -C "$DEST$PREFIX" --strip-components=1 --no-same-owner
"$DEST$PREFIX/bin/python3" -c 'import ssl, sqlite3, venv' || { echo "python build is incomplete"; exit 3; }
