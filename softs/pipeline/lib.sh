# Shared helpers for the scripts inside every VortexPanel software zip.
# Sourced by install.sh / activate.sh / check.sh / uninstall.sh:   . "$(dirname "$0")/lib.sh"
#
# Environment set by the panel engine (panel/softs.py):
#   VP_APP VP_VERSION VP_TRACK   what is being installed
#   VP_PREFIX    /usr/local/vortex/<app>/<version>   (this version's files)
#   VP_CURRENT   /usr/local/vortex/<app>/current     (or .../<track> for side-by-side apps)
#                -> always point units and links at VP_CURRENT, never at VP_PREFIX,
#                   so switching or rolling back a version is one symlink change
#   VP_PREV      previous version's prefix ('' on a first install)
#   VP_ACTION    install | update | rollback | uninstall | migrate | abort
#                (abort = uninstall.sh after a failed first install or switch: put back
#                 any configuration the switch changed)
#   VP_INIT      systemd | none   (none = container tests: start daemons directly)
#   VP_FAMILY    deb | rpm
set -u

say()  { echo "[$VP_APP] $*"; }
fail() { echo "[$VP_APP] ERROR: $*" >&2; exit 1; }
# refuse() in uninstall.sh: the removal is not safe now; the panel stops and changes nothing
refuse() { echo "[$VP_APP] REFUSED: $*" >&2; exit 3; }

has_systemd() { [ "${VP_INIT:-systemd}" = systemd ] && [ -d /run/systemd/system ]; }

# write_unit NAME  (unit text on stdin) -> /etc/systemd/system/NAME, daemon-reload when it changed
write_unit() {
  local f="/etc/systemd/system/$1" tmp
  tmp="$(mktemp)"; cat > "$tmp"
  if ! cmp -s "$tmp" "$f" 2>/dev/null; then
    install -m 0644 "$tmp" "$f"
    has_systemd && systemctl daemon-reload
  fi
  rm -f "$tmp"
}

svc_enable()  { has_systemd && systemctl enable "$1" >/dev/null 2>&1 || true; }
svc_active()  { has_systemd && systemctl is-active --quiet "$1"; }

# svc_restart NAME [fallback command to start without systemd]
svc_restart() {
  local name="$1"; shift
  if has_systemd; then
    systemctl restart "$name"
  elif [ $# -gt 0 ]; then
    "$@"
  fi
}

svc_reload_or_restart() {
  local name="$1"; shift
  if has_systemd; then
    if systemctl is-active --quiet "$name"; then systemctl reload-or-restart "$name"; else systemctl restart "$name"; fi
  elif [ $# -gt 0 ]; then
    "$@"
  fi
}

svc_stop() { has_systemd && systemctl stop "$1" 2>/dev/null || true; }

# link SRC DST  -> DST is a symlink to SRC (replaces an older link, never a real file)
link() {
  if [ -e "$2" ] && [ ! -L "$2" ]; then
    mv -f "$2" "$2.vortex-replaced" 2>/dev/null || true
  fi
  ln -sfn "$1" "$2"
}

# unlink DST  (only when it is our link)
unlink_ours() {
  if [ -L "$1" ] && readlink "$1" | grep -q '^/usr/local/vortex/'; then rm -f "$1"; fi
  if [ -e "$1.vortex-replaced" ] && [ ! -e "$1" ]; then mv -f "$1.vortex-replaced" "$1"; fi
}

ensure_user() {   # ensure_user NAME HOME [shell]
  getent group "$1" >/dev/null || groupadd -r "$1"
  getent passwd "$1" >/dev/null || useradd -r -g "$1" -d "$2" -s "${3:-/usr/sbin/nologin}" "$1" 2>/dev/null \
    || useradd -r -g "$1" -d "$2" -s /sbin/nologin "$1"
}

# wait_port PORT [seconds]
wait_port() {
  local i
  for i in $(seq 1 "${2:-20}"); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
    sleep 1
  done
  return 1
}

# data_backup DIR SERVICE  -> stop SERVICE, copy DIR to DIR.vortex-before-<version>. Only the newest
# copy is kept (older ones are deleted first, so they never count against the free space). Fails when
# there is not enough free space: an update without a copy is refused. The copy is marked with this
# run's id (VP_RUN_ID), and data_restore only ever puts back a copy made by the same run.
data_backup() {
  local dir="$1" svc="$2" need avail bak="$1.vortex-before-$VP_VERSION"
  [ -d "$dir" ] || return 0
  [ -n "${VP_RUN_ID:-}" ] || fail "no run id from the panel; refusing to make a data copy that could not be matched later"
  rm -rf "$dir".vortex-before-* "$dir".vortex-copying
  need=$(( $(du -sk "$dir" | cut -f1) * 11 / 10 + 102400 ))
  avail=$(df -Pk "$(dirname "$dir")" | awk 'NR==2{print $4}')
  [ "$avail" -gt "$need" ] || fail "not enough free disk space to back up $dir before the update (need $((need/1024)) MB)"
  svc_stop "$svc"
  # copy under a temporary name: a half-finished copy is never taken for a backup
  cp -a "$dir" "$dir.vortex-copying" || { rm -rf "$dir.vortex-copying"; fail "copying $dir failed"; }
  mv "$dir.vortex-copying" "$bak"
  printf '%s\n' "$VP_RUN_ID" > "$bak.run"
  say "data backed up to $bak"
}

# data_restore DIR SERVICE -> stop SERVICE and put back the copy data_backup made IN THIS RUN.
# A copy left over from an earlier attempt is never restored. The copy is renamed into place
# (no second copy that could run out of disk space halfway); the data the failed version may
# have changed is kept as DIR.vortex-failed-<time> for inspection (only the newest one).
data_restore() {
  local dir="$1" svc="$2" bak="$1.vortex-before-$VP_VERSION" failed
  [ -d "$bak" ] && [ -n "${VP_RUN_ID:-}" ] && [ "$(cat "$bak.run" 2>/dev/null)" = "$VP_RUN_ID" ] || {
    say "no data copy from this run to put back; the data was not changed by this run's backup step"
    return 0
  }
  svc_stop "$svc"
  rm -rf "$dir".vortex-failed-*
  failed="$dir.vortex-failed-$(date +%Y%m%d%H%M%S)"
  if [ -e "$dir" ]; then mv "$dir" "$failed" || fail "could not move $dir aside; the copy is still in $bak"; fi
  mv "$bak" "$dir" || { [ -e "$failed" ] && mv "$failed" "$dir"; fail "could not put $bak back"; }
  rm -f "$bak.run"
  say "data restored from the copy made before the update (the changed data is kept in $failed)"
}
