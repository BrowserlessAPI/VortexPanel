# Cisco Talos' own Linux release package (its libraries bundled, needs glibc 2.30+), or on
# EL8 (glibc 2.28) the same release compiled from source into the same layout. The programs
# are reached through small wrappers that point them at this version's libraries (RAR
# support is loaded from LD_LIBRARY_PATH), its signing certificates, the server's
# configuration files and the signature folder /var/lib/clamav.
[ -n "${SOURCE_FILE:-}" ] || { echo "no release file for $TARGET-$ARCH"; exit 3; }
cd "$SRC"; P="$DEST$PREFIX"
install -d "$P" "$P/etc"
if [ "$TARGET" = linux ]; then
  mkdir x; dpkg-deb -x "$SOURCE_FILE" x
  L=x/usr/local
  cp -a "$L/bin" "$L/sbin" "$L/lib" "$P/"
  [ ! -d "$L/etc/certs" ] || cp -a "$L/etc/certs" "$P/etc/certs"   # 1.5 and newer
  cp "$L/etc/clamd.conf.sample" "$L/etc/freshclam.conf.sample" "$P/etc/" 2>/dev/null || true
else
  tar -xzf "$SOURCE_FILE" --no-same-owner
  S="$SRC/clamav-$VERSION"; mkdir build; cd build
  cmake "$S" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib \
    -DAPP_CONFIG_DIRECTORY=/etc/clamav -DDATABASE_DIRECTORY=/var/lib/clamav \
    -DENABLE_TESTS=OFF -DENABLE_MILTER=OFF -DENABLE_SYSTEMD=OFF -DENABLE_MAN_PAGES=OFF -DENABLE_DOXYGEN=OFF \
    -DENABLE_JSON_SHARED=ON >/dev/null
  cmake --build . -j "$JOBS"
  DESTDIR="$DEST" cmake --install . >/dev/null
  cd "$SRC"
  [ ! -d "$S/certs" ] || cp -a "$S/certs" "$P/etc/certs"
  [ -d "$P/lib64" ] && { cp -a "$P/lib64/." "$P/lib/"; rm -rf "$P/lib64"; }
  mv "$P/etc/clamav/"*.sample "$P/etc/" 2>/dev/null || true; rm -rf "$P/etc/clamav" "$P/share/man" "$P/include"
fi
rm -rf "$P/lib/pkgconfig" "$P/lib"/*.a "$P/bin/clamav-config"
install -d "$P/vp-bin"
for b in "$P"/bin/* "$P"/sbin/*; do
  n="$(basename "$b")"; d="$(basename "$(dirname "$b")")"
  cat > "$P/vp-bin/$n" <<WRAP
#!/bin/sh
# VortexPanel build of ClamAV: this version's libraries, certificates and the server's config
D="\$(dirname "\$(dirname "\$(readlink -f "\$0")")")"
export LD_LIBRARY_PATH="\$D/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}" CVD_CERTS_DIR="\${CVD_CERTS_DIR:-\$D/etc/certs}"  # read by 1.5+ only
CF=""
case "$n" in
  clamd|clamdscan|clamdtop) for f in /etc/clamav/clamd.conf /etc/clamd.d/scan.conf; do [ -f "\$f" ] && { CF="\$f"; break; }; done ;;
  freshclam) for f in /etc/clamav/freshclam.conf /etc/freshclam.conf; do [ -f "\$f" ] && { CF="\$f"; break; }; done ;;
esac
case "$n" in
  clamscan)
    case " \$* " in *" -d"*|*" --database"*|*" --help "*|*" -h "*|*" --version "*|*" -V "*) ;;
      *) [ -d /var/lib/clamav ] && set -- "--database=/var/lib/clamav" "\$@" ;; esac ;;
esac
if [ -n "\$CF" ]; then
  case " \$* " in *" --config-file"*|*" -c "*|*" --help "*|*" -h "*|*" --version "*|*" -V "*) ;; *) set -- "--config-file=\$CF" "\$@" ;; esac
fi
exec "\$D/$d/$n" "\$@"
WRAP
  chmod 0755 "$P/vp-bin/$n"
done
"$P/vp-bin/clamscan" --version | grep -q "ClamAV $VERSION" || { echo "clamscan reports the wrong version"; exit 3; }
