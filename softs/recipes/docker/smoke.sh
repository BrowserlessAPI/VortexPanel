#!/bin/bash
# Container tests have no systemd and no privileges for dockerd: the programs must run.
set -e
docker --version | grep -q "$VP_VERSION"
dockerd --version | grep -q "$VP_VERSION"
docker compose version >/dev/null
docker buildx version >/dev/null
containerd --version >/dev/null && runc --version >/dev/null
echo "Docker smoke test passed"
