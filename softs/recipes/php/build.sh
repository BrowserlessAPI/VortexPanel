# PHP X.Y in the Debian layout the panel manages (/etc/php/X.Y, phpX.Y-fpm,
# /run/php/phpX.Y-fpm.sock), side by side with other versions. Optional extensions
# are built shared and switched on with mods-available / conf.d like Debian.
cd "$SRC"
tar -xf "$SOURCE_FILE"
# VERSION is the published build (8.1.34.1 for a security rebuild); UPSTREAM is the php.net
# release it is built from (8.1.34). Install paths use VERSION, the source tree UPSTREAM.
UPSTREAM="${VP_UPSTREAM:-$VERSION}"
cd php-"$UPSTREAM"
# Security patches published by the PHP project for releases that get no new tarball
# (e.g. PHP's official PHP2Shell backport for the end-of-life 8.1 branch). Each must
# apply exactly (no fuzz); the applied names are recorded so the panel can tell.
PATCHED=""
if [ -d "$RECIPE/patches/$UPSTREAM" ]; then
  for p in "$RECIPE/patches/$UPSTREAM"/*.patch; do
    [ -e "$p" ] || continue
    patch -p1 --fuzz=0 --forward --batch < "$p" >/dev/null || { echo "[build] patch does not apply: $(basename "$p")"; exit 3; }
    say "applied $(basename "$p")"
    PATCHED="$PATCHED $(basename "$p" .patch)"
  done
fi
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
# pinned PECL releases, each checked against its SHA-256 (newer ones are taken by changing
# the version and the checksum together): used for PHP 8.1 to 8.5.
declare -A PECL=([igbinary]=3.2.16 [apcu]=5.1.28 [redis]=6.3.0 [imagick]=3.8.1 [memcached]=3.4.0)
declare -A PECL_SHA=(
  [igbinary]=8bf25d465abc7973d9e2c9a3039a5f8eea635b23bc1477017ff3999ff95836da
  [apcu]=ca9c1820810a168786f8048a4c3f8c9e3fd941407ad1553259fb2e30b5f057bf
  [redis]=0d5141f634bd1db6c1ddcda053d25ecf2c4fc1c395430d534fd3f8d51dd7f0b5
  [imagick]=3a3587c0a524c17d0dad9673a160b90cd776e836838474e173b549ed864352ee
  [memcached]=c163434eb0da97c8f45c7ad41d979d381f8b81c49402b1b90b063987fb37972e)
# PHP 8.6 changed the extension API (php_verror(), XtOffsetOf(), ext/standard/php_smart_string.h):
# none of the releases above builds on it, and no release with the fixes is out yet. For PHP 8.6
# and newer each one is built from an exact upstream commit that carries the PHP 8.6 support
# (fetched with git, checked by its commit id): "repository commit version-reported".
# When releases with PHP 8.6 support are published, move these to PECL/PECL_SHA above.
declare -A PECL_GIT=(
  [igbinary]="https://github.com/igbinary/igbinary fe33bf9ec03e97e2290a090abc72326e6910f5c1 3.2.18-dev"
  [apcu]="https://github.com/krakjoe/apcu fb2c942552a3f5dab7f4dea4afb5cf0831222c57 5.1.29-dev"
  [redis]="https://github.com/phpredis/phpredis adf5196a9f1e601c4976a41a3657f533da7d69a4 6.4.0-dev"
  [imagick]="https://github.com/Imagick/imagick 55ed2e9fda264395636a2e27e51f31673f5566ab 3.8.2-dev"
  [memcached]="https://github.com/php-memcached-dev/php-memcached 0b52d3657140750fa0eddd20cdbfc6edc8fbdadd 3.4.1-dev")
TNUM=$(( ${TRACK%%.*} * 100 + ${TRACK#*.} ))          # 8.6 -> 806
# extensions without outside libraries: a PHP build without them is not published
PECL_REQUIRED="igbinary apcu redis"
PECL_OK=""
for pe in igbinary apcu redis imagick memcached; do
  LOGF="$SRC/pecl-$pe.log"
  if [ "$TNUM" -ge 806 ]; then
    read -r G_URL G_COMMIT G_VER <<< "${PECL_GIT[$pe]}"; SRCNOTE="$G_VER+${G_COMMIT:0:12}"
  else
    SRCNOTE="${PECL[$pe]}"
  fi
  ( set -e
    cd "$SRC"; rm -rf "pecl-$pe"; mkdir "pecl-$pe"; cd "pecl-$pe"
    if [ "$TNUM" -ge 806 ]; then
      git init -q src
      git -C src fetch -q --depth 1 "$G_URL" "$G_COMMIT"
      git -C src checkout -q FETCH_HEAD
      [ "$(git -C src rev-parse HEAD)" = "$G_COMMIT" ] || { echo "[build] $pe: not the pinned commit"; exit 1; }
      cd src
      # release tarballs fill in the version; a git checkout has the placeholder
      grep -rl --include='*.h' --include='*.c' '@PACKAGE_VERSION@' . | xargs -r sed -i "s/@PACKAGE_VERSION@/$G_VER/g"
    else
      curl -fsSL --retry 3 "https://pecl.php.net/get/$pe-${PECL[$pe]}.tgz" -o "$pe.tgz"
      echo "${PECL_SHA[$pe]}  $pe.tgz" | sha256sum -c - >/dev/null || { echo "[build] checksum mismatch: $pe-${PECL[$pe]}.tgz"; exit 1; }
      tar -xzf "$pe.tgz"; cd "$(find . -maxdepth 1 -type d -name "$pe-*" | head -1)"
    fi
    "$PHPIZE"
    ./configure --with-php-config="$PCONF"
    make -j"$JOBS"
    install -m 0755 modules/"$pe".so "$EXT_DIR/$pe.so"
  ) > "$LOGF" 2>&1 && { say "PECL $pe $SRCNOTE built"; PECL_OK="$PECL_OK $pe=$SRCNOTE"; } \
    || { say "PECL $pe $SRCNOTE did not build for PHP $VERSION here:"; grep -iE ' error|fatal|not found|checksum|pinned' "$LOGF" | head -8 >&2 || tail -8 "$LOGF" >&2
         case " $PECL_REQUIRED " in *" $pe "*) echo "[build] $pe is required for every PHP build"; exit 3;; esac; }
done
sed -i "s|^prefix=.*|prefix=\"$PREFIX\"|" "$PCONF" "$PHPIZE"
install -d "$DEST$PREFIX/share/conf"
cp php.ini-production "$DEST$PREFIX/share/conf/php.ini-production"
cp php.ini-development "$DEST$PREFIX/share/conf/php.ini-development"
# shared extensions that load by default (the rest are installed but off)
ls "$DEST$PREFIX"/lib/php/extensions/*/ > "$DEST$PREFIX/share/conf/extensions.txt"
[ -n "$SYSTEMD" ] && touch "$DEST$PREFIX/share/conf/systemd-notify"
# what this build carries beyond the php.net release: read by the panel (PHP2Shell status)
printf '%s\n' $PATCHED > "$DEST$PREFIX/share/conf/vp-patches.txt"
printf '%s\n' $PECL_OK > "$DEST$PREFIX/share/conf/pecl.txt"
rm -rf "$DEST$PREFIX/php/man" "$DEST$PREFIX/php/php/fpm" 2>/dev/null || true
