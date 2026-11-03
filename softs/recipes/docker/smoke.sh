#!/bin/bash
# Container tests have no systemd and no privileges for dockerd: the programs must run.
# Every check says what it found, so a failure is clear in the CI log.
ok=1
chk() {   # chk "description" command...
  local out
  if out="$("${@:2}" 2>&1)"; then echo "ok    $1: $(echo "$out" | head -1)"
  else echo "FAIL  $1: $(echo "$out" | head -3)"; ok=0; fi
}
chk "docker CLI"      docker --version
chk "dockerd"         dockerd --version
chk "compose plugin"  docker compose version
chk "buildx plugin"   docker buildx version
chk "containerd"      containerd --version
chk "runc"            runc --version
v="$(docker --version 2>/dev/null)"
case "$v" in *"$VP_VERSION"*) echo "ok    docker CLI is $VP_VERSION" ;; *) echo "FAIL  docker CLI reports '$v', expected $VP_VERSION"; ok=0 ;; esac
[ "$ok" = 1 ] || exit 1
echo "Docker smoke test passed"
