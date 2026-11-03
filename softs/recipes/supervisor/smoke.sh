#!/bin/bash
set -e
for i in $(seq 1 10); do
  p="$(supervisorctl pid 2>/dev/null || true)"
  [[ "$p" =~ ^[0-9]+$ ]] && { echo "Supervisor smoke test passed (pid $p)"; exit 0; }
  sleep 1
done
echo "supervisorctl cannot reach supervisord"; exit 1
