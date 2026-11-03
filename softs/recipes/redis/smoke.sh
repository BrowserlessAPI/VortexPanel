#!/bin/bash
set -e
redis-cli set vp-smoke ok >/dev/null && [ "$(redis-cli get vp-smoke)" = ok ] && echo "Redis smoke test passed"
