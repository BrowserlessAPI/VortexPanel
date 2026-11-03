#!/bin/bash
set -e
for i in $(seq 1 20); do
  rndc status 2>/dev/null | grep -q 'server is up and running' && { echo "BIND9 smoke test passed"; exit 0; }
  sleep 1
done
echo "rndc status does not report a running server"; exit 1
