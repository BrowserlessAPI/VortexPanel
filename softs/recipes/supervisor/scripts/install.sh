#!/bin/bash
# System integration for Supervisor (idempotent; runs before the version switch).
# Debian/Ubuntu layout: /etc/supervisor/supervisord.conf + conf.d/*.conf, service "supervisor".
# RHEL layout:          /etc/supervisord.conf + supervisord.d/*.ini, service "supervisord".
. "$(dirname "$0")/lib.sh"
set -e
if [ -e /etc/supervisor/supervisord.conf ]; then CONF=/etc/supervisor/supervisord.conf
elif [ -e /etc/supervisord.conf ]; then CONF=/etc/supervisord.conf
elif [ "$VP_FAMILY" = deb ]; then
  CONF=/etc/supervisor/supervisord.conf
  install -d /etc/supervisor/conf.d /var/log/supervisor
  cat > "$CONF" <<'C'
; supervisor config file (VortexPanel)

[unix_http_server]
file=/var/run/supervisor.sock
chmod=0700

[supervisord]
logfile=/var/log/supervisor/supervisord.log
pidfile=/var/run/supervisord.pid
childlogdir=/var/log/supervisor

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[supervisorctl]
serverurl=unix:///var/run/supervisor.sock

[include]
files = /etc/supervisor/conf.d/*.conf
C
else
  CONF=/etc/supervisord.conf
  install -d /etc/supervisord.d /var/log/supervisor /run/supervisor
  cat > "$CONF" <<'C'
; supervisor config file (VortexPanel)

[unix_http_server]
file=/run/supervisor/supervisor.sock
chmod=0700

[supervisord]
logfile=/var/log/supervisor/supervisord.log
pidfile=/run/supervisord.pid
childlogdir=/var/log/supervisor

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[supervisorctl]
serverurl=unix:///run/supervisor/supervisor.sock

[include]
files = supervisord.d/*.ini
C
fi
install -d /var/log/supervisor
for b in supervisord supervisorctl echo_supervisord_conf pidproxy; do
  [ -e "$VP_PREFIX/bin/$b" ] && link "$VP_CURRENT/bin/$b" "/usr/bin/$b"
done
# the panel calls the service by the name this layout uses; the other name is an alias
if [ "$CONF" = /etc/supervisord.conf ]; then NAME=supervisord; ALIAS=supervisor; else NAME=supervisor; ALIAS=supervisord; fi
rm -f "/etc/systemd/system/$ALIAS.service"
write_unit "$NAME.service" <<UNIT
[Unit]
Description=Supervisor process control system (VortexPanel build)
After=network.target

[Service]
Type=simple
ExecStart=$VP_CURRENT/bin/supervisord -n -c $CONF
ExecStop=$VP_CURRENT/bin/supervisorctl -c $CONF shutdown
ExecReload=$VP_CURRENT/bin/supervisorctl -c $CONF reload
KillMode=process
Restart=on-failure
RestartSec=5s
RuntimeDirectory=supervisor
RuntimeDirectoryPreserve=yes

[Install]
WantedBy=multi-user.target
Alias=$ALIAS.service
UNIT
if has_systemd; then systemctl reenable "$NAME" >/dev/null 2>&1 || systemctl enable "$NAME" >/dev/null 2>&1 || true; fi
