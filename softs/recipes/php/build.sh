# PHP X.Y in the Debian layout the panel manages (/etc/php/X.Y, phpX.Y-fpm,
# /run/php/phpX.Y-fpm.sock), side by side with other versions. Optional extensions
# are built shared and switched on with mods-available / conf.d like Debian.
cd "$SRC"
tar -xf "$SOURCE_FILE"
cd php-"$VERSION"
ETC=/etc/php/$TRACK
MAJ=${VERSION%%.*}

# options that exist only in some PHP versions
opt() { ./configure --help | grep -q -- "$1" && echo "$2"; }
# Debian/Ubuntu keep libraries in lib/<multiarch> (e.g. lib/x86_64-linux-gnu)
LIBDIR=lib
if [ "$FAMILY" = rpm ]; then LIBDIR=lib64
elif MA="$(gcc -print-multiarch 2>/dev/null)" && [ -n "$MA" ]; then LIBDIR="lib/$MA"; fi
EXTRA="$(opt '--with-password-argon2' '--with-password-argon2')"
# AVIF images only where this system offers libavif 0.8.2+ (Debian/Ubuntu; EPEL where it has it)
pkg-config --exists 'libavif >= 0.8.2' 2>/dev/null && EXTRA="$EXTRA $(opt '--with-avif' '--with-avif')"
FREETYPE=--with-freetype
SYSTEMD=""; [ -e /usr/include/systemd/sd-daemon.h ] && SYSTEMD=--with-fpm-systemd

# EL8's linker (binutils 2.30) cannot link mbstring's CPU-specific functions (IFUNC) into
# a non-PIE program ("recompile with -fPIE and relink with -pie"): build PIE there
if [ "$TARGET" = el8 ]; then export CFLAGS="${CFLAGS:-} -O2 -g -fPIE" LDFLAGS="${LDFLAGS:-} -pie"; fi
./configure \
  --prefix="$PREFIX" \
  --with-config-file-path="$ETC/fpm" \
  --with-config-file-scan-dir="$ETC/fpm/conf.d" \
  --enable-fpm --with-fpm-user=www-data --with-fpm-group=www-data \
  $SYSTEMD \
  --enable-opcache --enable-mbstring --enable-bcmath=shared --enable-calendar=shared \
  --enable-exif=shared --enable-ftp=shared --enable-intl=shared --enable-pcntl --enable-shmop=shared \
  --enable-soap=shared --enable-sockets=shared --enable-sysvmsg=shared --enable-sysvsem=shared --enable-sysvshm=shared \
  --enable-gd=shared --with-jpeg --with-webp $FREETYPE \
  --with-curl=shared --with-openssl --with-zlib --with-bz2=shared --with-gmp=shared \
  --with-mysqli=shared,mysqlnd --with-pdo-mysql=shared,mysqlnd --enable-mysqlnd \
  --with-pgsql=shared --with-pdo-pgsql=shared --with-pdo-sqlite --with-sqlite3 \
  --with-sodium=shared --with-xsl=shared --with-zip=shared --with-ldap=shared --with-libdir=$LIBDIR \
  --with-ffi=shared --with-tidy=shared --with-readline \
  $EXTRA

make -j"$JOBS"
make install INSTALL_ROOT="$DEST"

# popular PECL extensions, built against this PHP (installed switched off; the
# panel's PHP extensions page turns them on). One that does not build is skipped.
PHPIZE="$DEST$PREFIX/bin/phpize"; PCONF="$DEST$PREFIX/bin/php-config"
sed -i "s|^prefix=.*|prefix=\"$DEST$PREFIX\"|" "$PCONF" "$PHPIZE"
EXT_DIR="$(ls -d "$DEST$PREFIX"/lib/php/extensions/*/ | head -1)"
# pinned PECL releases (checked here; newer ones are taken by changing these lines)
declare -A PECL=([igbinary]=3.2.16 [apcu]=5.1.24 [redis]=6.2.0 [imagick]=3.8.0 [memcached]=3.3.0)
for pe in igbinary apcu redis imagick memcached; do
  ( set -e
    cd "$SRC"; rm -rf "pecl-$pe"; mkdir "pecl-$pe"; cd "pecl-$pe"
    curl -fsSL --retry 3 "https://pecl.php.net/get/$pe-${PECL[$pe]}.tgz" -o "$pe.tgz"
    tar -xzf "$pe.tgz"; cd "$(find . -maxdepth 1 -type d -name "$pe-*" | head -1)"
    "$PHPIZE" >/dev/null
    ./configure --with-php-config="$PCONF" >/dev/null
    make -j"$JOBS" >/dev/null
    install -m 0755 modules/"$pe".so "$EXT_DIR/$pe.so"
  ) && say "PECL $pe built" || say "PECL $pe skipped (does not build for PHP $VERSION here)"
done
sed -i "s|^prefix=.*|prefix=\"$PREFIX\"|" "$PCONF" "$PHPIZE"
install -d "$DEST$PREFIX/share/conf"
cp php.ini-production "$DEST$PREFIX/share/conf/php.ini-production"
cp php.ini-development "$DEST$PREFIX/share/conf/php.ini-development"
# shared extensions that load by default (the rest are installed but off)
ls "$DEST$PREFIX"/lib/php/extensions/*/ > "$DEST$PREFIX/share/conf/extensions.txt"
[ -n "$SYSTEMD" ] && touch "$DEST$PREFIX/share/conf/systemd-notify"
rm -rf "$DEST$PREFIX/php/man" "$DEST$PREFIX/php/php/fpm" 2>/dev/null || true
