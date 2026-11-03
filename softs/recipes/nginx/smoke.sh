#!/bin/bash
# Container test after install: serve a page, test the config with modules.
set -e
curl -fsS -o /dev/null http://127.0.0.1/ || { echo "nginx does not answer on port 80"; exit 1; }
nginx -V 2>&1 | grep -q -- '--with-http_v3_module' || { echo "http_v3 missing"; exit 1; }
nginx -V 2>&1 | grep -q -- '--with-stream' || { echo "stream missing"; exit 1; }
echo "nginx smoke test passed"
