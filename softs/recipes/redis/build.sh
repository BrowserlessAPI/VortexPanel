cd "$SRC"; tar -xzf "$SOURCE_FILE"; cd redis-"$VERSION"
make -j"$JOBS" BUILD_TLS=yes USE_SYSTEMD=yes MALLOC=jemalloc
make install PREFIX="$DEST$PREFIX"
install -d "$DEST$PREFIX/share"; cp redis.conf "$DEST$PREFIX/share/redis.conf"
