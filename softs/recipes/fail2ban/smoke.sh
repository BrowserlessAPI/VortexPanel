#!/bin/bash
set -e
fail2ban-client -t >/dev/null
for i in $(seq 1 15); do
  fail2ban-client ping 2>/dev/null | grep -q pong && { echo "Fail2ban smoke test passed"; exit 0; }
  sleep 1
done
echo "fail2ban-server does not answer"; exit 1
