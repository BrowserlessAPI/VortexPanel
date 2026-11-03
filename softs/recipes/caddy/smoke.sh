#!/bin/bash
set -e
curl -fsS -o /dev/null http://127.0.0.1/ && echo "Caddy smoke test passed"
