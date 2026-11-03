#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$("$VP_CURRENT/bin/httpd" -v | sed -n 's|.*Apache/\([0-9.]*\).*|\1|p')"
[ "$v" = "$VP_VERSION" ] || fail "expected Apache $VP_VERSION, found '$v'"
if [ "$VP_FAMILY" = deb ]; then PID=/run/apache2/apache2.pid; else PID=/run/httpd/httpd.pid; fi
up=""
for i in $(seq 1 15); do
  [ -s "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null && { up=1; break; }
  sleep 1
done
[ -n "$up" ] || fail "Apache is not running"
say "Apache $v is running"
# right after a switch from mod_php: every website whose PHP settings were converted must
# still answer without a server error (otherwise the switch is rolled back)
if [ "$VP_ACTION" = migrate ]; then
  python3 "$(dirname "$0")/php_fpm_switch.py" sites | while read -r host port scheme; do
    code="$(curl -sk -o /dev/null -m 20 -w '%{http_code}' --resolve "$host:$port:127.0.0.1" "$scheme://$host:$port/")"
    case "$code" in
      5*) fail "$host answers HTTP $code after its PHP settings moved to PHP-FPM" ;;
      *)  say "$host: HTTP $code" ;;
    esac
  done || exit 1
fi
