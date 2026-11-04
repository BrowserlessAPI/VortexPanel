# Oracle's generic Linux build (glibc 2.28: EL8 and newer, Ubuntu 20.04+, Debian 10+).
# The "minimal" tarball is stripped and has no test suite; the full one is used when
# a release has no minimal tarball for this processor, and is trimmed the same way.
SER="$(echo "$VERSION" | cut -d. -f1,2)"
cd "$SRC"
# the tarball resolve.py found (downloaded by in_container.sh)
[ -n "${SOURCE_FILE:-}" ] && xz -t "$SOURCE_FILE" || { echo "[build] no valid MySQL $VERSION tarball for $ARCH"; exit 3; }
got="$SOURCE_FILE"
echo "[build] using $got"
mkdir x; tar -xJf "$got" -C x --no-same-owner
D="$(echo x/mysql-*)"
rm -rf "$D/mysql-test" "$D/docs" "$D/man" "$D/LICENSE.router" "$D/README.router"
# debug builds only (mysqld-debug, lib/plugin/debug): libraries such as
# libabsl_debugging_internal.so are needed by the server
rm -f "$D/bin/mysqld-debug" "$D/bin/mariadbd-debug"; rm -rf "$D/lib/plugin/debug" "$D/lib/debug"
# strip the full tarball's binaries (the minimal one already is)
find "$D/bin" "$D/lib" -type f \( -perm -u+x -o -name '*.so*' \) -print0 | while IFS= read -r -d '' f; do
  file -b "$f" | grep -q 'ELF.*not stripped' && strip --strip-unneeded "$f" 2>/dev/null || true
done
install -d "$DEST$PREFIX"
cp -a "$D"/. "$DEST$PREFIX/"
"$DEST$PREFIX/bin/mysqld" --version 2>/dev/null || ldd "$DEST$PREFIX/bin/mysqld" | grep 'not found' || true
