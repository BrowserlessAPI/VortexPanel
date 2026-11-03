# Caddy + caddy-waf, built with xcaddy and the official Go toolchain (go.dev, checked
# against the published SHA-256). Pure Go, static: runs on every supported system.
cd "$SRC"
GOARCH=amd64; [ "$ARCH" = aarch64 ] && GOARCH=arm64
GOV="$(curl -fsSL 'https://go.dev/dl/?mode=json' | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["version"])')"
GOSUM="$(curl -fsSL 'https://go.dev/dl/?mode=json' | python3 -c "
import json,sys
for f in json.load(sys.stdin)[0]['files']:
    if f['os']=='linux' and f['arch']=='$GOARCH' and f['kind']=='archive': print(f['sha256'])")"
curl -fsSL --retry 4 -o go.tgz "https://go.dev/dl/$GOV.linux-$GOARCH.tar.gz"
echo "$GOSUM  go.tgz" | sha256sum -c - >/dev/null || { echo "[build] Go checksum mismatch"; exit 3; }
tar -xzf go.tgz --no-same-owner
export GOROOT="$SRC/go" GOPATH="$SRC/gopath" GOCACHE="$SRC/gocache" GOFLAGS=-trimpath CGO_ENABLED=0
export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"
# newest caddy-waf release (tag) and its commit
WAF_TAG="$(git ls-remote --tags --refs https://github.com/fabriziosalmi/caddy-waf.git | sed 's|.*refs/tags/||' \
           | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1)"
[ -n "$WAF_TAG" ] || { echo "[build] cannot find a caddy-waf release"; exit 3; }
WAF_COMMIT="$(git ls-remote https://github.com/fabriziosalmi/caddy-waf.git "refs/tags/$WAF_TAG^{}" "refs/tags/$WAF_TAG" | head -1 | cut -f1)"
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build "v$VERSION" --with "github.com/fabriziosalmi/caddy-waf@$WAF_TAG" --output ./caddy
./caddy list-modules | grep -q '^http.handlers.waf' || { echo "[build] the waf module is missing from the build"; exit 3; }
install -D -m 0755 caddy "$DEST$PREFIX/bin/caddy"
install -d "$DEST$PREFIX/share"
# the module's starter rule set and lists from the same release (installed only where missing)
install -d "$DEST$PREFIX/share/waf"
for f in rules.json ip_blacklist.txt dns_blacklist.txt; do
  curl -fsSL --retry 4 -o "$DEST$PREFIX/share/waf/$f" "https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/$WAF_COMMIT/$f" \
    || { [ "$f" = rules.json ] && echo '[]' > "$DEST$PREFIX/share/waf/$f" || : > "$DEST$PREFIX/share/waf/$f"; }
done
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$DEST$PREFIX/share/waf/rules.json" || echo '[]' > "$DEST$PREFIX/share/waf/rules.json"
printf 'caddy %s\ncaddy-waf %s (%s)\ngo %s\n' "$VERSION" "$WAF_TAG" "$WAF_COMMIT" "$GOV" > "$DEST$PREFIX/share/BUILDINFO"
cat "$DEST$PREFIX/share/BUILDINFO"
