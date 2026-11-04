#!/bin/bash
# Runs INSIDE a clean container of the target OS (see targets.json).
# Installs the recipe's build dependencies, downloads the upstream source and runs
# the recipe's build.sh, which installs into $DEST$PREFIX.
#
# Environment (set by build.py): APP VERSION TRACK PREFIX DEST TARGET ARCH FAMILY JOBS
# plus VP_* values from the plan (VP_URL, VP_SHA256, VP_TAG, VP_ASSET_x86_64, ...).
set -euo pipefail
SOFTS_ROOT="${SOFTS_ROOT:-/softs}"
WORK="${WORK:-/work}"
OUT="${OUT:-/out}"
R=$SOFTS_ROOT/recipes/$APP
export SRC=$WORK/src RECIPE=$R
mkdir -p "$SRC" "$DEST"
cd "$WORK"

say() { echo "[build] $*" >&2; }   # stderr: fetch() output is captured

json() { python3 -c "import json,sys; d=json.load(open('$R/recipe.json')); v=d
for k in sys.argv[1].split('.'):
    v = v.get(k, {}) if isinstance(v, dict) else {}
print(' '.join(v) if isinstance(v, list) else (v if isinstance(v, str) else ''))" "$1"; }

# --- base tools + python3 (needed to read recipe.json) -------------------------
# package mirrors fail now and then (broken index, timeout): retry with a fresh index
try3() { local i; for i in 1 2 3; do "$@" && return 0; echo "[build] attempt $i failed, retrying" >&2; dnf clean metadata >/dev/null 2>&1 || apt-get update -qq >/dev/null 2>&1 || true; sleep 10; done; return 1; }
if [ "$FAMILY" = deb ]; then
  export DEBIAN_FRONTEND=noninteractive
  try3 apt-get update -qq
  try3 apt-get install -y -qq --no-install-recommends python3 ca-certificates curl xz-utils tar gzip bzip2 file \
      build-essential pkg-config >/dev/null
else
  # --allowerasing: EL9/10 images ship curl-minimal, which conflicts with the full curl
  try3 dnf -y -q install --allowerasing python3 ca-certificates curl xz tar gzip bzip2 file gcc gcc-c++ make \
      pkgconf-pkg-config dnf-plugins-core findutils which >/dev/null
  if [ -n "$(json rpm_repos)" ]; then
    dnf -y -q install epel-release >/dev/null || true
    dnf config-manager --set-enabled crb >/dev/null 2>&1 || dnf config-manager --set-enabled powertools >/dev/null 2>&1 || true
  fi
fi

# --- build dependencies ----------------------------------------------------------
PKGS="$(json deps.build.$FAMILY)"
TPKGS="$(json deps.build_$TARGET)"           # per-target extras, e.g. deps.build_el8
if [ -n "$PKGS$TPKGS" ]; then
  say "build dependencies: $PKGS $TPKGS"
  if [ "$FAMILY" = deb ]; then
    # one missing optional package must not stop the build: install what exists
    for p in $PKGS $TPKGS; do apt-get install -y -qq --no-install-recommends "$p" >/dev/null 2>&1 || say "  (not available here: $p)"; done
  else
    for p in $PKGS $TPKGS; do dnf -y -q install --allowerasing "$p" >/dev/null 2>&1 || say "  (not available here: $p)"; done
  fi
fi

# --- source ----------------------------------------------------------------------
fetch() {   # fetch URL [sha256]
  local url="$1" sum="${2:-}" out
  out="$SRC/$(basename "${url%%\?*}")"
  say "download $url"
  curl -fsSL --retry 4 --retry-delay 3 -o "$out" "$url"
  if [ -n "$sum" ]; then echo "$sum  $out" | sha256sum -c - >/dev/null || { echo "[build] checksum mismatch: $url"; exit 3; }; fi
  echo "$out"
}
export -f fetch say

SOURCE_TPL="$(json source)"
if [ -n "${VP_SOURCE_FILE:-}" ]; then          # local tests: a source archive already on disk
  export SOURCE_FILE="$VP_SOURCE_FILE"
elif [ -n "${VP_URL:-}" ]; then
  export SOURCE_FILE="$(fetch "$VP_URL" "${VP_SHA256:-}")"
elif [ -n "$SOURCE_TPL" ]; then
  U="${SOURCE_TPL//\{version\}/$VERSION}"; U="${U//\{track\}/$TRACK}"; U="${U//\{tag\}/${VP_TAG:-}}"
  U="${U//\{arch\}/$ARCH}"; U="${U//\{under\}/${VERSION//./_}}"
  export SOURCE_FILE="$(fetch "$U")"
fi

# --- build -------------------------------------------------------------------------
say "building $APP $VERSION for $TARGET-$ARCH into $PREFIX"
bash -euo pipefail "$R/build.sh"

# runtime packages: every shared library the built programs load, mapped to the
# package that provides it on this OS. The zip installs exactly these on the server.
: > "$OUT/run-deps.txt"
find "$DEST$PREFIX" -type f \( -perm -u+x -o -name '*.so*' \) -print0 2>/dev/null | while IFS= read -r -d '' f; do
  file -b "$f" | grep -q '^ELF' || continue
  ldd "$f" 2>/dev/null | awk '/=> \//{print $3}'
done | sort -u | while read -r lib; do
  case "$lib" in "$DEST"*) continue ;; esac
  real="$(readlink -f "$lib")"
  if [ "$FAMILY" = deb ]; then
    dpkg -S "$lib" 2>/dev/null || dpkg -S "$real" 2>/dev/null
  else
    rpm -qf --qf '%{NAME}\n' "$lib" 2>/dev/null || rpm -qf --qf '%{NAME}\n' "$real" 2>/dev/null
  fi
done | sed 's/:.*//' | grep -v '^libc6$\|^glibc$\|not owned' | sort -u >> "$OUT/run-deps.txt" || true
say "runtime packages: $(tr '\n' ' ' < "$OUT/run-deps.txt")"

# record what the binaries link against (shown in the panel's build details)
( find "$DEST$PREFIX" -type f -perm -u+x -exec file {} + 2>/dev/null | grep -q ELF ) && \
  ldd --version 2>&1 | head -1 > "$OUT/glibc.txt" || true
say "done"
