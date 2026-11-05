#!/bin/bash
# Run this version's upstream installer from a scratch copy: a first install creates
# /usr/local/lsws; an update (or a rollback to an older version) replaces the program
# files and keeps conf/, admin/conf/, the virtual hosts and lsphp.
. "$(dirname "$0")/lib.sh"
set -e
L=/usr/local/lsws
W="$(mktemp -d /tmp/vp-ols.XXXXXX)"
KEEP=/var/lib/vortex-ols-keep       # outside /usr/local/lsws; kept if anything below fails
trap 'rm -rf "$W"; [ -n "${DONE:-}" ] && rm -rf "$KEEP"' EXIT
cp -a "$VP_CURRENT/dist/." "$W/"
U=nobody; G=nobody
if [ -f "$L/conf/httpd_config.conf" ]; then
  U="$(awk '$1=="user"{print $2; exit}' "$L/conf/httpd_config.conf")"; U="${U:-nobody}"
  G="$(awk '$1=="group"{print $2; exit}' "$L/conf/httpd_config.conf")"; G="${G:-nobody}"
fi
{ echo "OPENLSWS_USER=$U"; echo "OPENLSWS_GROUP=$G"; echo "USE_LSPHP7=no"; } > "$W/ols.conf"
# the server's configuration and WebAdmin login stay exactly as they are: copied before the
# upstream installer runs and put back after it (also if it took this for a fresh install)
if [ -d "$KEEP" ]; then
  # an earlier run stopped after the installer: its copy is the last good configuration
  for d in conf admin/conf; do
    [ -d "$KEEP/$d" ] || continue
    rm -rf "$L/$d.vortex-new"; cp -a "$KEEP/$d" "$L/$d.vortex-new" || fail "could not put $L/$d back from $KEEP"
    rm -rf "$L/$d"; mv "$L/$d.vortex-new" "$L/$d"
  done
  [ ! -f "$KEEP/adminpasswd" ] || cp -a "$KEEP/adminpasswd" "$L/adminpasswd"
  say "configuration put back from the copy an earlier run left in $KEEP"
fi
rm -rf "$KEEP"; mkdir -p -m 0700 "$KEEP"
for d in conf admin/conf; do
  [ -d "$L/$d" ] && { mkdir -p "$KEEP/$(dirname "$d")"; cp -a "$L/$d" "$KEEP/$d"; }
done
[ -f "$L/adminpasswd" ] && cp -a "$L/adminpasswd" "$KEEP/adminpasswd"
# upstream prints the generated WebAdmin password; it is kept in /usr/local/lsws/adminpasswd
# no input, a time limit, and downloads that give up instead of retrying for hours
mkdir -p "$W/.vp-bin"
# the installer finds its download tool with `which`, missing on minimal systems
command -v which >/dev/null 2>&1 || { printf '#!/bin/sh\ncommand -v "$1"\n' > "$W/.vp-bin/which"; chmod 0755 "$W/.vp-bin/which"; }
for t in wget curl; do
  real="$(command -v $t || true)"; [ -n "$real" ] || continue
  if [ $t = wget ]; then printf '#!/bin/sh\nexec %s --timeout=30 --tries=3 "$@"\n' "$real" > "$W/.vp-bin/wget"
  else printf '#!/bin/sh\nexec %s --connect-timeout 20 --max-time 120 --retry 2 "$@"\n' "$real" > "$W/.vp-bin/curl"; fi
  chmod 0755 "$W/.vp-bin/$t"
done
# output to a file, not a pipe: the installer starts the server in the background, and a
# server holding a pipe open would keep this script waiting forever
( cd "$W" && PATH="$W/.vp-bin:$PATH" timeout 1200 sh ./install.sh </dev/null >"$W/install.log" 2>&1 ) || true
grep -viE 'passw' "$W/install.log" | tail -40 || true
for d in conf admin/conf; do
  [ -d "$KEEP/$d" ] || continue
  rm -rf "$L/$d.vortex-new"
  cp -a "$KEEP/$d" "$L/$d.vortex-new" || fail "could not put $L/$d back; the copy is in $KEEP/$d"
  rm -rf "$L/$d.vortex-installer"; [ -e "$L/$d" ] && mv "$L/$d" "$L/$d.vortex-installer"
  mv "$L/$d.vortex-new" "$L/$d"
  rm -rf "$L/$d.vortex-installer"
done
[ ! -f "$KEEP/adminpasswd" ] || cp -a "$KEEP/adminpasswd" "$L/adminpasswd"
[ -x "$L/bin/openlitespeed" ] || fail "the OpenLiteSpeed installer did not complete"
v="$("$L/bin/openlitespeed" -v 2>&1 | sed -n 's|.*LiteSpeed/\([0-9.]*\).*|\1|p' | head -1)"
[ "$v" = "$VP_VERSION" ] || fail "the installer left OpenLiteSpeed '$v' in place, expected $VP_VERSION"
[ -s "$L/adminpasswd" ] && chmod 600 "$L/adminpasswd"
if has_systemd; then
  systemctl daemon-reload
  systemctl enable lshttpd >/dev/null 2>&1 || true
  systemctl restart lsws
else
  "$L/bin/lswsctrl" stop >/dev/null 2>&1 </dev/null || true; sleep 1
  "$L/bin/lswsctrl" start >/dev/null 2>&1 </dev/null
fi
DONE=1
