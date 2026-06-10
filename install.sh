#!/bin/bash
# VortexPanel Universal Installer
# Supports: Ubuntu 20.04+, Debian 11+, Fedora 38+, RHEL/AlmaLinux/Rocky 8+

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[VortexPanel]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID,,}"
    OS_VER="${VERSION_ID}"
    OS_FAMILY="unknown"
    PKG_MGR="apt"
    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop) OS_FAMILY="debian"; PKG_MGR="apt" ;;
        fedora) OS_FAMILY="fedora"; PKG_MGR="dnf" ;;
        rhel|centos|almalinux|rocky|ol) OS_FAMILY="rhel"; PKG_MGR="dnf" ;;
        *) warn "Unknown OS: $OS_ID, assuming Debian-like" ; OS_FAMILY="debian"; PKG_MGR="apt" ;;
    esac
else
    err "Cannot detect OS"
fi

log "Detected: $NAME $VERSION_ID ($OS_FAMILY/$PKG_MGR)"

# Install dependencies
log "Installing dependencies..."
if [ "$PKG_MGR" = "apt" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y python3 python3-pip python3-venv curl git wget unzip sudo
elif [ "$PKG_MGR" = "dnf" ]; then
    dnf install -y python3 python3-pip curl git wget unzip sudo
    # Enable EPEL for extra packages
    if [[ "$OS_ID" =~ ^(rhel|almalinux|rocky|ol|centos)$ ]]; then
        dnf install -y epel-release 2>/dev/null || true
    fi
fi

# Install VortexPanel
INSTALL_DIR="/opt/vortexpanel"
log "Installing VortexPanel to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Clone or copy
if [ -d "/root/Vortexpanel/.git" ]; then
    cp -r /root/Vortexpanel/panel /root/Vortexpanel/web /root/Vortexpanel/app.py "$INSTALL_DIR/"
else
    git clone https://github.com/BrowserlessAPI/VortexPanel.git /tmp/vortexpanel_src
    cp -r /tmp/vortexpanel_src/panel /tmp/vortexpanel_src/web /tmp/vortexpanel_src/app.py "$INSTALL_DIR/"
fi

# Create virtualenv
log "Setting up Python environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
"$INSTALL_DIR/venv/bin/pip" install flask flask-session requests -q

# Create directories
mkdir -p /opt/vortexpanel/{backups,logs}
mkdir -p /etc/nginx/vortex 2>/dev/null || true

# Create credentials
if [ ! -f "$INSTALL_DIR/credentials.json" ]; then
    PASS=$(openssl rand -base64 12)
    HASH=$(python3 -c "import hashlib; print(hashlib.sha256('$PASS'.encode()).hexdigest())")
    cat > "$INSTALL_DIR/credentials.json" << EOF
{
  "username": "admin",
  "password_hash": "$HASH",
  "email": "admin@vortexpanel.local"
}
EOF
    log "Generated admin password: $PASS"
    echo "$PASS" > "$INSTALL_DIR/admin_password.txt"
fi

# Create systemd service
cat > /etc/systemd/system/vortexpanel.service << EOF
[Unit]
Description=VortexPanel Control Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/app.py
Restart=always
RestartSec=3
Environment=PORT=8888

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vortexpanel
systemctl restart vortexpanel

# Firewall rules
if command -v ufw &>/dev/null; then
    ufw allow 8888/tcp 2>/dev/null || true
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port=8888/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
fi

IP=$(curl -s https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
log "============================================"
log "VortexPanel installed successfully!"
log "URL: http://$IP:8888"
log "Username: admin"
log "Password: $(cat $INSTALL_DIR/admin_password.txt 2>/dev/null || echo 'See credentials.json')"
log "============================================"
