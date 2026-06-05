#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

VP_DIR="/opt/vortexpanel"
VP_CONF="/etc/vortexpanel"
VP_PORT="${VP_PORT:-8888}"

log()     { echo -e "${GREEN}[✓]${NC} $*"; }
info()    { echo -e "${CYAN}[→]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
section() { echo -e "\n${CYAN}${BOLD}--- $* ---${NC}"; }

[ "$(id -u)" -ne 0 ] && echo "Run as root" && exit 1

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

banner() {
    echo -e "${CYAN}"
    cat << 'BANNER'
  ╦  ╦╔═╗╦═╗╔╦╗╔═╗═╗ ╦╔═╗╔═╗╔╗╔╔═╗╦
  ╚╗╔╝║ ║╠╦╝ ║ ║╣ ╔╩╦╝╠═╝╠═╣║║║║╣ ║
   ╚╝ ╚═╝╩╚═ ╩ ╚═╝╩ ╚═╩  ╩ ╩╝╚╝╚═╝╩═╝
BANNER
    echo -e "${NC}  Python · FastAPI · Alpine.js\n"
}

check_existing() {
    if systemctl is-active --quiet vortexpanel 2>/dev/null; then
        warn "VortexPanel is already running."
        warn "To reinstall: systemctl stop vortexpanel && rm -rf $VP_DIR $VP_CONF"
        warn "Then run this installer again."
        exit 0
    fi
}

install_packages() {
    section "Installing system packages"
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    apt-get update -qq
    apt-get install -y -qq \
        python3 python3-pip python3-venv python3-dev \
        nginx curl wget git openssl \
        build-essential libssl-dev 2>/dev/null || true
    log "System packages installed"
}

setup_python() {
    section "Setting up Python environment"
    rm -rf "$VP_DIR/venv"
    python3 -m venv "$VP_DIR/venv"
    "$VP_DIR/venv/bin/pip" install --upgrade pip --quiet
    "$VP_DIR/venv/bin/pip" install -r "$SRC/requirements.txt" --quiet
    log "Python venv ready ($(wc -l < "$SRC/requirements.txt") packages)"
}

copy_files() {
    section "Installing panel files"
    mkdir -p "$VP_DIR" "$VP_CONF"
    cp -r "$SRC/panel"            "$VP_DIR/"
    cp -r "$SRC/web"              "$VP_DIR/"
    cp    "$SRC/run.py"           "$VP_DIR/"
    cp    "$SRC/init.py"          "$VP_DIR/"
    cp    "$SRC/requirements.txt" "$VP_DIR/"
    log "Files installed to $VP_DIR"
}

generate_secrets() {
    section "Generating secrets"
    mkdir -p "$VP_CONF"
    chmod 750 "$VP_CONF"

    openssl rand -hex 32 > "$VP_CONF/.jwt_secret"
    chmod 600 "$VP_CONF/.jwt_secret"

    local hex num pass
    hex=$(openssl rand -hex 4 | tr '[:lower:]' '[:upper:]')
    num=$(( (RANDOM % 90) + 10 ))
    pass="VP${hex}${num}!"
    echo "$pass" > "$VP_CONF/.admin_password"
    chmod 600 "$VP_CONF/.admin_password"

    log "Secrets generated"
    echo "$pass"
}

seed_admin() {
    local pass="$1"
    section "Creating admin account"

    set +e
    VP_DATA_DIR="$VP_CONF" \
    VP_JWT_SECRET="$(cat "$VP_CONF/.jwt_secret")" \
        "$VP_DIR/venv/bin/python" "$VP_DIR/init.py" \
        --username admin \
        --password "$pass" \
        --email "admin@vortexpanel.local" 2>&1
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        log "Admin account created"
    else
        warn "Seed failed (exit $rc) — check logs above"
    fi
}

setup_nginx() {
    section "Configuring Nginx"
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    rm -f /etc/nginx/conf.d/default.conf   2>/dev/null || true

    cat > /etc/nginx/conf.d/vortexpanel.conf << NGINX
server {
    listen ${VP_PORT};
    listen [::]:${VP_PORT};
    server_name _;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;

    location /static/ {
        alias ${VP_DIR}/web/static/;
        expires 30d;
        access_log off;
    }

    location / {
        proxy_pass http://127.0.0.1:8889;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 300s;
    }

    client_max_body_size 512m;
}
NGINX

    nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || systemctl restart nginx
    log "Nginx on port $VP_PORT"
}

setup_service() {
    section "Setting up systemd service"

    cat > /etc/systemd/system/vortexpanel.service << UNIT
[Unit]
Description=VortexPanel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${VP_DIR}
Environment=VP_DATA_DIR=${VP_CONF}
Environment=VP_JWT_SECRET_FILE=${VP_CONF}/.jwt_secret
ExecStart=${VP_DIR}/venv/bin/python run.py --host 127.0.0.1 --port 8889
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vortexpanel

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable vortexpanel --quiet
    systemctl start vortexpanel || true
    sleep 3

    if systemctl is-active --quiet vortexpanel; then
        log "Service started"
    else
        warn "Service failed — check: journalctl -u vortexpanel -n 20 --no-pager"
        journalctl -u vortexpanel -n 10 --no-pager 2>/dev/null || true
    fi
}

install_cli() {
    cat > /usr/local/bin/vortexpanel << 'CLI'
#!/usr/bin/env bash
case "${1:-help}" in
  start)          systemctl start vortexpanel ;;
  stop)           systemctl stop  vortexpanel ;;
  restart)        systemctl restart vortexpanel ;;
  status)         systemctl status vortexpanel --no-pager ;;
  logs)           journalctl -u vortexpanel -f --no-pager ;;
  reset-password)
    echo -n "New password: "; read -rs pass; echo
    VP_DATA_DIR=/etc/vortexpanel \
    VP_JWT_SECRET="$(cat /etc/vortexpanel/.jwt_secret)" \
      /opt/vortexpanel/venv/bin/python /opt/vortexpanel/init.py \
      --username admin --password "$pass" \
      --email admin@vortexpanel.local
    systemctl restart vortexpanel
    ;;
  *)
    echo "Usage: vortexpanel {start|stop|restart|status|logs|reset-password}"
    ;;
esac
CLI
    chmod +x /usr/local/bin/vortexpanel
    log "CLI installed"
}

print_summary() {
    local pass ip
    pass=$(cat "$VP_CONF/.admin_password" 2>/dev/null || echo "unknown")
    ip=$(curl -fsSL --max-time 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   VortexPanel installed successfully!    ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}YOUR LOGIN CREDENTIALS${NC}"
    echo -e "  URL:       ${CYAN}http://${ip}:${VP_PORT}${NC}"
    echo -e "  Username:  ${CYAN}admin${NC}"
    echo -e "  Password:  ${CYAN}${pass}${NC}"
    echo -e "  Email:     ${CYAN}admin@vortexpanel.local${NC}"
    echo ""
    echo -e "  ${YELLOW}⚠ Save these credentials — password shown once!${NC}"
    echo ""
    echo -e "  CLI: ${CYAN}vortexpanel status | restart | logs | reset-password${NC}"
    echo ""
}

main() {
    trap 'echo -e "\n${RED}Install interrupted${NC}"' ERR
    banner
    check_existing
    install_packages
    mkdir -p "$VP_DIR"
    copy_files
    setup_python
    local pass
    pass=$(generate_secrets)
    seed_admin "$pass"
    setup_nginx
    setup_service
    install_cli
    print_summary
}

main
