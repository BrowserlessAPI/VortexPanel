# ddclient is one Perl program. Built with its own autotools setup; the configuration
# file is chosen at start time (see vp-ddclient-start), so one build serves every OS.
cd "$SRC"; tar -xzf "$SOURCE_FILE" --no-same-owner; cd ddclient-"$VERSION"
./autogen
./configure --prefix="$PREFIX" --sysconfdir=/etc --localstatedir=/var --runstatedir=/run \
            --with-curl=/usr/bin/curl PERL=/usr/bin/perl
make
P="$DEST$PREFIX"
install -D -m 0755 ddclient "$P/sbin/ddclient"
install -D -m 0644 ddclient.conf "$P/share/ddclient.conf.sample"
v="$(/usr/bin/perl "$P/sbin/ddclient" --version=short)"
[ "$v" = "$VERSION" ] || { echo "ddclient reports '$v', expected $VERSION"; exit 3; }
cat > "$P/sbin/vp-ddclient-start" <<'WRAP'
#!/bin/sh
# Start ddclient with the server's own configuration file:
# /etc/ddclient.conf (Debian/Ubuntu) or /etc/ddclient/ddclient.conf (RHEL family).
D="$(dirname "$(readlink -f "$0")")"
CONF=/etc/ddclient.conf
[ -f "$CONF" ] || CONF=/etc/ddclient/ddclient.conf
set -- --file "$CONF" --cache /var/cache/ddclient/ddclient.cache --foreground "$@"
# run as a service even when the file sets no "daemon=" interval
grep -qE '^[[:space:]]*daemon[[:space:]]*=' "$CONF" 2>/dev/null || set -- "$@" --daemon 300
exec "$D/ddclient" "$@"
WRAP
chmod 0755 "$P/sbin/vp-ddclient-start"
