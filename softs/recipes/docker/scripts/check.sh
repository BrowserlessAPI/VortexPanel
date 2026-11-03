#!/bin/bash
. "$(dirname "$0")/lib.sh"
v="$("$VP_CURRENT/bin/dockerd" --version | sed -n 's/^Docker version \([0-9.]*\).*/\1/p')"
[ "$v" = "$VP_VERSION" ] || fail "expected Docker $VP_VERSION, found '$v'"
"$VP_CURRENT/libexec/docker/cli-plugins/docker-compose" version >/dev/null 2>&1 || fail "docker compose does not run"
if has_systemd; then
  for i in $(seq 1 30); do
    "$VP_CURRENT/bin/docker" info >/dev/null 2>&1 && { say "Docker $v is running"; exit 0; }
    sleep 1
  done
  fail "the Docker daemon does not answer (journalctl -u docker)"
fi
say "Docker $v installed"
