# Pure Python: the package runs on the system python3 of every supported OS (3.6 to 3.13;
# 1.1 carries its own asyncore/asynchat for Python 3.12+). No setup.py install: the
# code, the programs and the stock configuration are copied into the version folder.
cd "$SRC"; tar -xzf "$SOURCE_FILE" --no-same-owner; cd fail2ban-"$VERSION"
python3 -c "import sys; sys.path.insert(0,'.'); from fail2ban.version import version; assert version.split('.dev')[0] == '$VERSION', version"
P="$DEST$PREFIX"
install -d "$P/lib" "$P/libexec" "$P/bin" "$P/share"
cp -a fail2ban "$P/lib/fail2ban"
rm -rf "$P/lib/fail2ban/tests"
find "$P/lib" -name '__pycache__' -type d -prune -exec rm -rf {} +
for b in fail2ban-client fail2ban-server fail2ban-regex; do
  install -m 0755 "bin/$b" "$P/libexec/$b"
  cat > "$P/bin/$b" <<WRAP
#!/bin/sh
# VortexPanel build of Fail2ban: run on the system python3 with the bundled package
D="\$(dirname "\$(dirname "\$(readlink -f "\$0")")")"
export PYTHONPATH="\$D/lib\${PYTHONPATH:+:\$PYTHONPATH}" PYTHONNOUSERSITE=1
exec /usr/bin/python3 "\$D/libexec/$b" "\$@"
WRAP
  chmod 0755 "$P/bin/$b"
done
cp -a config "$P/share/config"
find "$P/share/config" -name '*.local' -delete
cp files/fail2ban-logrotate "$P/share/fail2ban-logrotate" 2>/dev/null || true
cp files/fail2ban-tmpfiles.conf "$P/share/fail2ban-tmpfiles.conf" 2>/dev/null || true
