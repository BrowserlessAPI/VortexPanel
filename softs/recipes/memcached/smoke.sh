#!/bin/bash
set -e
exec 3<>/dev/tcp/127.0.0.1/11211
printf 'set vp-smoke 0 60 2\r\nok\r\nget vp-smoke\r\nquit\r\n' >&3
out="$(timeout 5 cat <&3)"
echo "$out" | grep -q '^VALUE vp-smoke' && echo "Memcached smoke test passed"
