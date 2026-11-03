#!/bin/bash
# Restart containerd and Docker on the new version. Containers with a restart policy
# come back by themselves; /etc/docker/daemon.json "live-restore": true keeps them running.
. "$(dirname "$0")/lib.sh"
if has_systemd; then
  systemctl restart containerd
  systemctl restart docker.socket docker
else
  say "no systemd: the Docker daemon is not started (container test)"
fi
