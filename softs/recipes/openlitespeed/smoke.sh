#!/bin/bash
set -e
/usr/local/lsws/bin/openlitespeed -v 2>&1 | grep -q "$VP_VERSION"
for i in $(seq 1 15); do curl -fsS -o /dev/null http://127.0.0.1:8088/ && break; sleep 1; done
curl -fsS -o /dev/null http://127.0.0.1:8088/ || { echo "OpenLiteSpeed does not answer on port 8088"; exit 1; }
echo "OpenLiteSpeed smoke test passed"
