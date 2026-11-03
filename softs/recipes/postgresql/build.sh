# PostgreSQL from source, checked against the published .sha256, with the server's
# usual extensions (contrib). The default socket folder is /run/postgresql (as in the
# distribution packages), so psql and the panel find the server without options.
cd "$SRC"
curl -fsSL --retry 4 --retry-delay 3 -o sum.txt "https://ftp.postgresql.org/pub/source/v$VERSION/postgresql-$VERSION.tar.bz2.sha256"
want="$(awk '{print $1}' sum.txt)"; got="$(sha256sum "$SOURCE_FILE" | awk '{print $1}')"
[ -n "$want" ] && [ "$want" = "$got" ] || { echo "[build] PostgreSQL checksum mismatch"; exit 3; }
tar -xjf "$SOURCE_FILE" --no-same-owner; cd "postgresql-$VERSION"
sed -i 's|#define DEFAULT_PGSOCKET_DIR  *"/tmp"|#define DEFAULT_PGSOCKET_DIR "/run/postgresql"|' src/include/pg_config_manual.h
grep -q 'DEFAULT_PGSOCKET_DIR "/run/postgresql"' src/include/pg_config_manual.h || { echo "[build] socket folder patch failed"; exit 3; }
OPTS="--prefix=$PREFIX --with-openssl --with-icu --with-libxml --with-libxslt --with-lz4 --with-zstd --with-systemd
      --with-uuid=e2fs --with-readline --with-ldap --with-pam"
# shellcheck disable=SC2086
./configure $OPTS CFLAGS="-O2 -g0" >/dev/null 2>&1 || ./configure $OPTS CFLAGS="-O2 -g0" | tail -40
make -j"$JOBS" world-bin >/dev/null
make install-world-bin DESTDIR="$DEST" >/dev/null
find "$DEST$PREFIX" -type f \( -perm -u+x -o -name '*.so*' \) -exec sh -c 'file -b "$1" | grep -q "ELF.*not stripped" && strip --strip-unneeded "$1"' _ {} \; 2>/dev/null || true
"$DEST$PREFIX/bin/postgres" --version
