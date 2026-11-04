# Shared by the Caddy and Caddy WAF scripts (sourced after lib.sh): the server's sites
# answer the same after an update as before it.
#   sites_snapshot FILE  -> "host code" for every site host in /etc/caddy/Caddyfile
#   sites_compare FILE   -> fail when a site that answered before (1xx-4xx) now gives 5xx
#                           or no answer
SITES_MAX=60
_caddy_bin() { if [ -x "$VP_CURRENT/bin/caddy" ]; then echo "$VP_CURRENT/bin/caddy"; else command -v caddy; fi; }
site_hosts() {
  [ -f /etc/caddy/Caddyfile ] || return 0
  "$(_caddy_bin)" adapt --config /etc/caddy/Caddyfile 2>/dev/null | python3 -c '
import json, sys
try:
    cfg = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
hosts = []
for srv in ((cfg.get("apps") or {}).get("http") or {}).get("servers", {}).values():
    for route in srv.get("routes") or []:
        for m in route.get("match") or []:
            for h in m.get("host") or []:
                if "*" not in h and h not in hosts:
                    hosts.append(h)
print("\n".join(hosts))' | head -n "$SITES_MAX"
}
site_code() {   # site_code HOST -> HTTP status over this server (https first, then http); 000 = no answer
  local c
  c="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 --resolve "$1:443:127.0.0.1" "https://$1/" 2>/dev/null)"
  case "$c" in 000|"") c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 --resolve "$1:80:127.0.0.1" "http://$1/" 2>/dev/null)" ;; esac
  echo "${c:-000}"
}
sites_snapshot() {
  : > "$1"
  local h
  for h in $(site_hosts); do echo "$h $(site_code "$h")" >> "$1"; done
  say "recorded how $(wc -l < "$1") site(s) answer before the update"
}
sites_compare() {
  [ -s "$1" ] || return 0
  local h before now bad="" i
  while read -r h before; do
    case "$before" in 1??|2??|3??|4??) ;; *) continue ;; esac   # broken before: not this update's doing
    for i in 1 2 3 4 5; do
      now="$(site_code "$h")"
      case "$now" in 1??|2??|3??|4??) break ;; esac
      sleep 2
    done
    case "$now" in 1??|2??|3??|4??) ;; *) bad="$bad $h($before->$now)" ;; esac
  done < "$1"
  [ -z "$bad" ] || fail "these sites stopped working with this version:$bad"
  say "every site answers as before the update"
}
