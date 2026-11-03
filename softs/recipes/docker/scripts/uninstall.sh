#!/bin/bash
# Remove the programs; images, containers and volumes (/var/lib/docker) and
# /etc/docker are kept.
. "$(dirname "$0")/lib.sh"
svc_stop docker; svc_stop docker.socket; svc_stop containerd
if has_systemd; then systemctl disable docker docker.socket containerd >/dev/null 2>&1 || true; fi
rm -f /etc/systemd/system/docker.service /etc/systemd/system/docker.socket /etc/systemd/system/containerd.service
has_systemd && systemctl daemon-reload || true
for b in docker dockerd docker-init docker-proxy containerd containerd-shim-runc-v2 ctr runc; do unlink_ours "/usr/bin/$b"; done
for p in docker-compose docker-buildx; do unlink_ours "/usr/libexec/docker/cli-plugins/$p"; done
true
