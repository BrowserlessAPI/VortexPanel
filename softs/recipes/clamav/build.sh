# Cisco Talos' own Linux release package (built for old glibc, its libraries bundled).
# It is made for /usr/local: the programs are reached through small wrappers that point
# them at this version's libraries (RAR support is loaded from LD_LIBRARY_PATH), its
# signing certificates and the server's configuration files.
[ -n "${SOURCE_FILE:-}" ] || { echo "no release package for $ARCH"; exit 3; }
cd "$SRC"; mkdir x; dpkg-deb -x "$SOURCE_FILE" x
L=x/usr/local; P="$DEST$PREFIX"
install -d "$P"
cp -a "$L/bin" "$L/sbin" "$L/lib" "$P/"
install -d "$P/etc"; [ ! -d "$L/etc/certs" ] || cp -a "$L/etc/certs" "$P/etc/certs"   # 1.5 and newer
cp "$L/etc/clamd.conf.sample" "$L/etc/freshclam.conf.sample" "$P/etc/" 2>/dev/null || true
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
if [ -n "\$CF" ]; then
  case " \$* " in *" --config-file"*|*" -c "*|*" --help "*|*" -h "*|*" --version "*|*" -V "*) ;; *) set -- "--config-file=\$CF" "\$@" ;; esac
fi
exec "\$D/$d/$n" "\$@"
WRAP
  chmod 0755 "$P/vp-bin/$n"
done
"$P/vp-bin/clamscan" --version | grep -q "ClamAV $VERSION" || { echo "clamscan reports the wrong version"; exit 3; }
