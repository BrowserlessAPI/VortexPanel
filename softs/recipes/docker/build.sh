# Docker Engine: the official static binaries (dockerd, docker, containerd, runc, ...)
# plus the Compose and Buildx CLI plugins from their GitHub releases (checked against
# the releases' checksum files).
cd "$SRC"
GOARCH=amd64; [ "$ARCH" = aarch64 ] && GOARCH=arm64
curl -fsSL --retry 4 -o docker.tgz "https://download.docker.com/linux/static/stable/$ARCH/docker-$VERSION.tgz"
mkdir x; tar -xzf docker.tgz -C x --no-same-owner
install -d "$DEST$PREFIX/bin" "$DEST$PREFIX/libexec/docker/cli-plugins" "$DEST$PREFIX/share"
install -m 0755 x/docker/* "$DEST$PREFIX/bin/"

latest_tag() {   # newest release tag without the GitHub API (no rate limit): the /latest redirect
  curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$1/releases/latest" | sed 's|.*/tag/||'
}
check_sum() {    # check_sum FILE NAME SUMSFILE
  local want got
  want="$(awk -v n="$2" '{f=$2; sub(/^\*/,"",f)} f==n{print $1}' "$3")"
  got="$(sha256sum "$1" | awk '{print $1}')"
  [ -n "$want" ] && [ "$want" = "$got" ] || { echo "[build] checksum mismatch: $2"; exit 3; }
}
CT="$(latest_tag docker/compose)"; [ -n "$CT" ] || { echo "[build] cannot find the Compose release"; exit 3; }
CN="docker-compose-linux-$ARCH"
curl -fsSL --retry 4 -o "$CN" "https://github.com/docker/compose/releases/download/$CT/$CN"
curl -fsSL --retry 4 -o compose.sums "https://github.com/docker/compose/releases/download/$CT/checksums.txt"
check_sum "$CN" "$CN" compose.sums
install -m 0755 "$CN" "$DEST$PREFIX/libexec/docker/cli-plugins/docker-compose"

BT="$(latest_tag docker/buildx)"; [ -n "$BT" ] || { echo "[build] cannot find the Buildx release"; exit 3; }
BN="buildx-$BT.linux-$GOARCH"
curl -fsSL --retry 4 -o "$BN" "https://github.com/docker/buildx/releases/download/$BT/$BN"
curl -fsSL --retry 4 -o buildx.sums "https://github.com/docker/buildx/releases/download/$BT/checksums.txt"
check_sum "$BN" "$BN" buildx.sums
install -m 0755 "$BN" "$DEST$PREFIX/libexec/docker/cli-plugins/docker-buildx"

printf 'docker %s\ncompose %s\nbuildx %s\n' "$VERSION" "$CT" "$BT" > "$DEST$PREFIX/share/BUILDINFO"
"$DEST$PREFIX/bin/docker" --version
