#!/bin/bash
set -e
caddy list-modules | grep -q '^http.handlers.waf'
curl -fsS -o /dev/null http://127.0.0.1/
echo "Caddy WAF smoke test passed"
