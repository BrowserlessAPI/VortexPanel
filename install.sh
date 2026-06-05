#!/usr/bin/env bash
# VortexPanel Installer
# Supports: Ubuntu 22.04, 24.04 | Debian 11, 12
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

VP_DIR="/opt/vortexpanel"
VP_CONF="/etc/vortexpanel"
VP_LOG="/var/log/vortexpanel"
VP_PORT="${VP_PORT:-8888}"
PYTHON="python3"

log()  { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "${CYAN}[→]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }
section() { echo -e "\n${CYAN}${BOLD}--- $* ---${NC}"; }

[ "$(id -u)" -ne 0 ] && die "Run as root: sudo bash install.sh"

# ── Source directory ───────────────────────────────────────
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

banner() {
    echo -e "${CYAN}"
    echo "  ╦  ╦╔═╗╦═╗╔╦╗╔═╗═╗ ╦╔═╗╔═╗╔╗╔╔═╗╦"
    echo "  ╚╗╔╝║ ║╠╦╝ ║ ║╣ ╔╩╦╝╠═╝╠═╣║║║║╣ ║"
    echo "   ╚╝ ╚═╝╩╚═ ╩ ╚═╝╩ ╚═╩  ╩ ╩╝╚╝╚═╝╩═╝"
    echo -e "${NC}"
    echo -e "  Server Control Panel — v1.0\n"
}

check_os() {
    section "Checking system"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VER="$VERSION_ID"
        log "OS: $PRETTY_NAME"
    else
        die "Cannot detect OS"
    fi

    case "$OS_ID" in
        ubuntu|debian) true ;;
        *) die "Unsupported OS: $OS_ID (Ubuntu/Debian required)" ;;
    esac

    local mem
    mem=$(free -m | awk '/^Mem:/{print $2}')
    [ "$mem" -lt 384 ] && warn "Low memory: ${mem}MB (512MB+ recommended)"
    log "Memory: ${mem}MB"
}

install_deps() {
    section "Installing dependencies"

    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a

    apt-get update -qq
    apt-get install -y -qq \
        python3 python3-pip python3-venv python3-dev \
        nginx curl wget git \
        build-essential libssl-dev libffi-dev \
        net-tools lsof ufw 2>/dev/null || true

    log "System packages installed"

    # Python virtualenv
    info "Setting up Python virtual environment…"
    python3 -m venv "$VP_DIR/venv"
    "$VP_DIR/venv/bin/pip" install --upgrade pip -q
    "$VP_DIR/venv/bin/pip" install -r "$SRC/requirements.txt" -q
    log "Python dependencies installed ($(wc -l < "$SRC/requirements.txt") packages)"
}

setup_dirs() {
    section "Setting up directories"
    mkdir -p "$VP_DIR" "$VP_CONF" "$VP_LOG"
    mkdir -p "$VP_DIR/venv"
    chmod 750 "$VP_CONF"
    log "Directories created"
}

copy_files() {
    section "Installing panel files"

    # copy panel source
    cp -r "$SRC/panel"        "$VP_DIR/"
    cp -r "$SRC/web"          "$VP_DIR/"
    cp    "$SRC/run.py"       "$VP_DIR/"
    cp    "$SRC/init.py"      "$VP_DIR/"
    cp    "$SRC/requirements.txt" "$VP_DIR/"

    log "Panel files installed: $VP_DIR"
}

generate_secrets() {
    section "Generating secrets"

    local jwt_secret
    jwt_secret=$(openssl rand -hex 32)
    echo "$jwt_secret" > "$VP_CONF/.jwt_secret"
    chmod 600 "$VP_CONF/.jwt_secret"

    # generate admin password
    local hex num pass
    hex=$(openssl rand -hex 4 | tr '[:lower:]' '[:upper:]')
    num=$(( (RANDOM % 90) + 10 ))
    pass="VP${hex}${num}!"

    echo "$pass" > "$VP_CONF/.admin_password"
    chmod 600 "$VP_CONF/.admin_password"

    log "Secrets generated"
    echo "$pass"
}

seed_database() {
    local password="$1"
    section "Creating admin account"

    VP_DATA_DIR="$VP_CONF" \
    VP_JWT_SECRET="$(cat "$VP_CONF/.jwt_secret")" \
        "$VP_DIR/venv/bin/python" "$VP_DIR/init.py" \
        --username admin \
        --password "$password" \
        --email "admin@vortexpanel.local"

    log "Admin account created"
}

setup_nginx() {
    section "Configuring Nginx"

    # disable default site
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
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 300s;
        proxy_buffering off;
    }

    client_max_body_size 512m;
}
NGINX

    nginx -t 2>/dev/null && systemctl reload nginx || systemctl restart nginx
    log "Nginx configured on port $VP_PORT"
}

setup_service() {
    section "Setting up systemd service"

    cat > /etc/systemd/system/vortexpanel.service << UNIT
[Unit]
Description=VortexPanel Control Panel
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
    systemctl enable vortexpanel
    systemctl start vortexpanel || true
    sleep 2

    if systemctl is-active --quiet vortexpanel; then
        log "VortexPanel service started"
    else
        warn "Service may still be starting — check: journalctl -u vortexpanel -f"
    fi
}

install_cli() {
    cat > /usr/local/bin/vortexpanel << 'CLI'
#!/usr/bin/env bash
case "${1:-help}" in
  start)   systemctl start  vortexpanel ;;
  stop)    systemctl stop   vortexpanel ;;
  restart) systemctl restart vortexpanel ;;
  status)  systemctl status vortexpanel --no-pager ;;
  logs)    journalctl -u vortexpanel -f ;;
  reset-password)
    read -rp "New password: " pass
    VP_DATA_DIR=/etc/vortexpanel \
      /opt/vortexpanel/venv/bin/python /opt/vortexpanel/init.py \
      --username admin --password "$pass" --email admin@vortexpanel.local
    ;;
  *)
    echo "Usage: vortexpanel {start|stop|restart|status|logs|reset-password}"
    ;;
esac
CLI
    chmod +x /usr/local/bin/vortexpanel
    log "CLI installed: /usr/local/bin/vortexpanel"
}

print_summary() {
    local pass
    pass=$(cat "$VP_CONF/.admin_password" 2>/dev/null || echo "check /etc/vortexpanel/.admin_password")

    local ip
    ip=$(curl -fsSL --max-time 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   VortexPanel installed successfully!    ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}  YOUR LOGIN CREDENTIALS${NC}"
    echo -e "  URL:       ${CYAN}http://${ip}:${VP_PORT}${NC}"
    echo -e "  Username:  ${CYAN}admin${NC}"
    echo -e "  Password:  ${CYAN}${pass}${NC}"
    echo -e "  Email:     ${CYAN}admin@vortexpanel.local${NC}"
    echo ""
    echo -e "${YELLOW}  ⚠ Save these credentials — password shown once!${NC}"
    echo ""
    echo -e "  CLI tools: ${CYAN}vortexpanel status | restart | logs | reset-password${NC}"
    echo ""
}

main() {
    trap 'print_summary 2>/dev/null || true' EXIT
    banner
    check_os
    setup_dirs
    install_deps
    copy_files
    local pass
    pass=$(generate_secrets)
    seed_database "$pass"
    setup_nginx
    setup_service
    install_cli
}

main
