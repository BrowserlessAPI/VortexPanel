# x86_64: MariaDB Foundation binary tarball (systemd variant). aarch64: the same release
# compiled from source in the same standalone layout (bin/, scripts/, share/, lib/plugin/).
# The file and its SHA-256 come from resolve.py (sha256sums.txt); in_container.sh checked it.
[ -n "${SOURCE_FILE:-}" ] && [ -f "$SOURCE_FILE" ] || { echo "[build] no MariaDB $VERSION file was resolved for $ARCH"; exit 3; }
cd "$SRC"
if [ "$ARCH" = x86_64 ]; then
  mkdir x; tar -xzf "$SOURCE_FILE" -C x --no-same-owner
  D="$(echo x/mariadb-*)"
  rm -rf "$D/mysql-test" "$D/mariadb-test" "$D/sql-bench" "$D/docs" "$D/man"
  find "$D" -name '*debug*' -prune -exec rm -rf {} +
  install -d "$DEST$PREFIX"
  cp -a "$D"/. "$DEST$PREFIX/"
else
  tar -xzf "$SOURCE_FILE" --no-same-owner
  S="$(echo "$SRC"/mariadb-"$VERSION")"
  # the ABI check compares preprocessed plugin headers with MariaDB's reference copies, a
  # check for MariaDB developers that fails on newer compilers; it does not change the build
  sed -i 's/SET(RUN_ABI_CHECK 1)/SET(RUN_ABI_CHECK 0)/' "$S/cmake/abi_check.cmake"
  mkdir build; cd build
  cmake "$S" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX="$PREFIX" -DINSTALL_LAYOUT=STANDALONE \
    -DWITH_SSL=system -DWITH_ZLIB=system -DWITH_PCRE=system -DWITH_SYSTEMD=yes -DWITH_LIBAIO=ON -DWITH_NUMA=ON \
    -DPLUGIN_COLUMNSTORE=NO -DPLUGIN_ROCKSDB=NO -DPLUGIN_MROONGA=NO -DPLUGIN_SPIDER=NO -DPLUGIN_TOKUDB=NO \
    -DPLUGIN_CONNECT=NO -DPLUGIN_OQGRAPH=NO -DPLUGIN_S3=NO -DWITH_UNIT_TESTS=OFF -DWITH_EMBEDDED_SERVER=OFF \
    -DCONC_WITH_UNIT_TESTS=OFF -DINSTALL_MYSQLTESTDIR= -DINSTALL_SQLBENCHDIR= -DWITH_DEBUG=OFF >/dev/null
  make -j"$JOBS"
  make install DESTDIR="$DEST" >/dev/null
  rm -rf "$DEST$PREFIX/mysql-test" "$DEST$PREFIX/mariadb-test" "$DEST$PREFIX/sql-bench" "$DEST$PREFIX/man" "$DEST$PREFIX/docs"
  find "$DEST$PREFIX" -type f \( -perm -u+x -o -name '*.so*' \) -print0 | while IFS= read -r -d '' f; do
    file -b "$f" | grep -q 'ELF.*not stripped' && strip --strip-unneeded "$f" 2>/dev/null || true
  done
fi
for b in mariadbd mariadb mariadb-install-db; do
  [ -e "$DEST$PREFIX/bin/$b" ] || [ -e "$DEST$PREFIX/scripts/$b" ] || { echo "[build] $b is missing from the build"; exit 3; }
done
"$DEST$PREFIX/bin/mariadbd" --version 2>/dev/null || true
