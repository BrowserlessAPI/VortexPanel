#!/bin/bash
set -e
ddclient --version=short
for i in $(seq 1 10); do pgrep -f 'ddclient' >/dev/null && { echo "ddclient smoke test passed"; exit 0; }; sleep 1; done
echo "ddclient is not running"; exit 1
