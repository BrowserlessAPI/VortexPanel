# libmodsecurity v3 from the official release tarball (configure already generated,
# libinjection and mbedTLS included). Lua, MaxMind and ssdeep are used when this system has them.
cd "$SRC"; tar -xzf "$SOURCE_FILE" --no-same-owner
cd modsecurity-v"$VERSION"
# EL8's libmaxminddb takes a non-const MMDB_s*; the call does not modify it, so the
# const conversion is allowed there instead of building without GeoIP rules
EXTRA_CXX="-O2 -g"; [ "$TARGET" = el8 ] && EXTRA_CXX="$EXTRA_CXX -fpermissive"
CXXFLAGS="${CXXFLAGS:-} $EXTRA_CXX" ./configure --prefix="$PREFIX" --disable-static --disable-doxygen-doc --disable-examples \
  --with-pcre2 --with-lmdb --with-yajl --with-maxmind --with-curl --with-libxml >/dev/null 2>&1 \
|| CXXFLAGS="${CXXFLAGS:-} $EXTRA_CXX" ./configure --prefix="$PREFIX" --disable-static --disable-doxygen-doc --disable-examples --with-pcre2
make -j"$JOBS"
make install DESTDIR="$DEST" >/dev/null
rm -rf "$DEST$PREFIX"/lib/*.la "$DEST$PREFIX/lib/pkgconfig"
[ -e "$DEST$PREFIX/lib/libmodsecurity.so.3" ] || { echo "[build] libmodsecurity.so.3 missing"; exit 3; }
[ -x "$DEST$PREFIX/bin/modsec-rules-check" ] || { echo "[build] modsec-rules-check missing"; exit 3; }
install -d "$DEST$PREFIX/share"
echo "$VERSION" > "$DEST$PREFIX/share/VERSION"
cp -a modsecurity.conf-recommended unicode.mapping "$DEST$PREFIX/share/" 2>/dev/null || true
find "$DEST$PREFIX" -type f \( -perm -u+x -o -name '*.so*' \) -print0 | while IFS= read -r -d '' f; do
  file -b "$f" | grep -q 'ELF.*not stripped' && strip --strip-unneeded "$f" 2>/dev/null || true
done
LD_LIBRARY_PATH="$DEST$PREFIX/lib" "$DEST$PREFIX/bin/modsec-rules-check" "$DEST$PREFIX/share/modsecurity.conf-recommended" \
  || { echo "[build] modsec-rules-check cannot load the recommended configuration"; exit 3; }
