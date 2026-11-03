#!/bin/bash
# System integration for Fail2ban (idempotent; runs before the version switch).
# /etc/fail2ban: the stock files (*.conf in the top folder, filter.d, action.d) follow the
# new version; anything the admin changed or created (*.local, jail.d, edited stock files)
# is kept. An edited stock file gets the new version next to it as <file>.vortex-new.
. "$(dirname "$0")/lib.sh"
set -e
ETC=/etc/fail2ban
STOCK="$VP_PREFIX/share/config"
REC="$ETC/.vortex-stock.sha256"
install -d -m 0755 "$ETC" "$ETC/jail.d" "$ETC/fail2ban.d" /var/lib/fail2ban
touch "$REC"
if [ "$VP_FAMILY" = rpm ]; then PATHS=paths-fedora.conf; else PATHS=paths-debian.conf; fi
# md5 of the distro's untouched copies (Debian keeps them listed after "apt-get remove")
DPKG_SUMS="$(dpkg-query -W -f='${Conffiles}\n' fail2ban 2>/dev/null || true)"
[ "$VP_ACTION" = migrate ] || rm -rf "$ETC/.vortex-before-switch"
tmp="$(mktemp -d)"; newrec="$tmp/rec"; : > "$newrec"; kept=0
cd "$STOCK"
while IFS= read -r -d '' rel; do
  rel="${rel#./}"; src="$STOCK/$rel"; dst="$ETC/$rel"
  case "$rel" in jail.d/*|fail2ban.d/*|*.local) continue ;; esac
  if [ "$rel" = jail.conf ]; then
    sed -E "s/^before = paths-[a-z]+\.conf/before = $PATHS/" "$src" > "$tmp/jail.conf"; src="$tmp/jail.conf"
  fi
  want="$(sha256sum "$src" | cut -d' ' -f1)"
  if [ -e "$dst" ] && ! cmp -s "$src" "$dst"; then
    have="$(sha256sum "$dst" | cut -d' ' -f1)"
    ours="$(awk -v r="$rel" '$2==r{print $1}' "$REC")"
    distro="$(echo "$DPKG_SUMS" | awk -v f="$dst" '$1==f{print $2}')"
    if [ "$have" != "$ours" ] && { [ -z "$distro" ] || [ "$(md5sum "$dst" | cut -d' ' -f1)" != "$distro" ]; }; then
      install -m 0644 "$src" "$dst.vortex-new"; kept=$((kept+1))
      continue
    fi
  fi
  # switching from the distro package: keep its copy so a failed switch can put it back
  if [ "$VP_ACTION" = migrate ] && [ -e "$dst" ] && [ ! -e "$ETC/.vortex-before-switch/$rel" ]; then
    install -D -m 0644 "$dst" "$ETC/.vortex-before-switch/$rel"
  fi
  install -D -m 0644 "$src" "$dst"
  echo "$want  $rel" >> "$newrec"
done < <(find . -type f -print0)
cd /
install -m 0600 "$newrec" "$REC"
rm -rf "$tmp"
[ "$kept" -gt 0 ] && say "$kept edited stock file(s) kept; the new versions are next to them as .vortex-new"

# fresh server: the ban action that matches this firewall (same file the panel manages)
F2B_LOCAL="$ETC/jail.d/00-vortexpanel.local"
if [ ! -e "$F2B_LOCAL" ]; then
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then BA=firewallcmd-rich-rules; BAA=firewallcmd-allports
  elif command -v nft >/dev/null 2>&1 && ! command -v iptables >/dev/null 2>&1; then BA=nftables-multiport; BAA=nftables-allports
  else BA=iptables-multiport; BAA=iptables-allports; fi
  { echo "# Managed by VortexPanel (ban action for this server's firewall). Delete this line to keep your own edits."
    echo "[DEFAULT]"; echo "banaction = $BA"; echo "banaction_allports = $BAA"; } > "$F2B_LOCAL"
fi
# fresh server: protect SSH when there is a log to read (like the Debian package)
if [ -z "$(ls -A "$ETC/jail.d" | grep -v '^00-vortexpanel.local$')" ] && [ ! -e "$ETC/jail.local" ]; then
  if [ -f /var/log/auth.log ] || [ -f /var/log/secure ]; then
    printf '[sshd]\nenabled = true\n' > "$ETC/jail.d/defaults-vortex.conf"
  elif [ -d /run/systemd/system ] && /usr/bin/python3 -c "import systemd.journal" >/dev/null 2>&1; then
    printf '[sshd]\nenabled = true\nbackend = systemd\n' > "$ETC/jail.d/defaults-vortex.conf"
  fi
fi
for b in fail2ban-client fail2ban-server fail2ban-regex; do link "$VP_CURRENT/bin/$b" "/usr/bin/$b"; done
[ -d /etc/logrotate.d ] && [ ! -e /etc/logrotate.d/fail2ban ] && cp "$VP_PREFIX/share/fail2ban-logrotate" /etc/logrotate.d/fail2ban 2>/dev/null || true
write_unit fail2ban.service <<UNIT
[Unit]
Description=Fail2Ban Service (VortexPanel build)
Documentation=man:fail2ban(1)
After=network.target iptables.service firewalld.service ip6tables.service ipset.service nftables.service
PartOf=iptables.service firewalld.service ip6tables.service ipset.service nftables.service

[Service]
Type=simple
Environment="PYTHONNOUSERSITE=1"
ExecStartPre=/bin/mkdir -p /run/fail2ban
ExecStart=$VP_CURRENT/bin/fail2ban-server -xf start
ExecStop=$VP_CURRENT/bin/fail2ban-client stop
ExecReload=$VP_CURRENT/bin/fail2ban-client reload
PIDFile=/run/fail2ban/fail2ban.pid
Restart=on-failure
RestartPreventExitStatus=0 255

[Install]
WantedBy=multi-user.target
UNIT
svc_enable fail2ban
