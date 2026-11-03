#!/bin/bash
# System integration for Docker Engine. /var/lib/docker (images, containers, volumes),
# /etc/docker/daemon.json and /etc/containerd are never touched.
. "$(dirname "$0")/lib.sh"
set -e
BINS="docker dockerd docker-init docker-proxy containerd containerd-shim-runc-v2 ctr runc"
for b in $BINS; do
  [ -e "$VP_PREFIX/bin/$b" ] && link "$VP_CURRENT/bin/$b" "/usr/bin/$b"
done
# CLI plugins: the path the docker CLI searches on every distribution
install -d /usr/libexec/docker/cli-plugins
for p in docker-compose docker-buildx; do
  link "$VP_CURRENT/libexec/docker/cli-plugins/$p" "/usr/libexec/docker/cli-plugins/$p"
done
getent group docker >/dev/null || groupadd -r docker
install -d -m 0755 /etc/docker
install -d -m 0711 /var/lib/docker

write_unit containerd.service <<UNIT
[Unit]
Description=containerd container runtime (VortexPanel build)
Documentation=https://containerd.io
After=network.target local-fs.target

[Service]
ExecStartPre=-/sbin/modprobe overlay
ExecStart=$VP_CURRENT/bin/containerd
Type=notify
Delegate=yes
KillMode=process
Restart=always
RestartSec=5
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
OOMScoreAdjust=-999

[Install]
WantedBy=multi-user.target
UNIT
write_unit docker.socket <<UNIT
[Unit]
Description=Docker Socket for the API

[Socket]
ListenStream=/run/docker.sock
SocketMode=0660
SocketUser=root
SocketGroup=docker

[Install]
WantedBy=sockets.target
UNIT
write_unit docker.service <<UNIT
[Unit]
Description=Docker Application Container Engine (VortexPanel build)
Documentation=https://docs.docker.com
After=network-online.target nss-lookup.target docker.socket firewalld.service containerd.service time-set.target
Wants=network-online.target containerd.service
Requires=docker.socket

[Service]
Type=notify
Environment=PATH=$VP_CURRENT/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$VP_CURRENT/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
ExecReload=/bin/kill -s HUP \$MAINPID
TimeoutStartSec=0
RestartSec=2
Restart=always
StartLimitBurst=3
StartLimitInterval=60s
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
Delegate=yes
KillMode=process
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
UNIT
svc_enable containerd; svc_enable docker.socket; svc_enable docker
