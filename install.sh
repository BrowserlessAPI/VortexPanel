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
        rhel|centos|almalinux|rocky|ol|cloudlinux) OS_FAMILY="rhel"; PKG_MGR="dnf" ;;
        *) warn "Unknown OS: $OS_ID, assuming Debian-like" ; OS_FAMILY="debian"; PKG_MGR="apt" ;;
    esac
else
    err "Cannot detect OS"
fi

log "Detected: $NAME $VERSION_ID ($OS_FAMILY/$PKG_MGR)"

# Install dependencies
log "Installing dependencies..."
PYTHON_BIN="python3"
if [ "$PKG_MGR" = "apt" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || true
    apt-get install -y python3 python3-pip python3-venv curl git wget unzip sudo
elif [ "$PKG_MGR" = "dnf" ]; then
    dnf install -y python3 python3-pip curl git wget unzip sudo
    # Enable EPEL for extra packages
    if [[ "$OS_ID" =~ ^(rhel|almalinux|rocky|ol|centos|cloudlinux)$ ]]; then
        dnf install -y epel-release 2>/dev/null || true
    fi
    # RHEL8-family ships Python 3.6 by default, which is too old for
    # Flask 3.x / boto3 / flask-sock. Use python3.11 if available.
    PYMAJOR=$(python3 -c 'import sys; print(sys.version_info[0])' 2>/dev/null || echo 0)
    PYMINOR=$(python3 -c 'import sys; print(sys.version_info[1])' 2>/dev/null || echo 0)
    if [ "$PYMAJOR" -lt 3 ] || { [ "$PYMAJOR" -eq 3 ] && [ "$PYMINOR" -lt 8 ]; }; then
        warn "System python3 is $PYMAJOR.$PYMINOR (too old), installing python3.11"
        dnf install -y python3.11 2>/dev/null || dnf install -y python3.11 python3.11-pip
    fi
fi

# Use python3.11 for the venv if the system default is too old (RHEL8-family)
if command -v python3.11 &>/dev/null; then
    V=$(python3 -c 'import sys; print(sys.version_info[1])' 2>/dev/null || echo 0)
    if [ "$V" -lt 8 ] 2>/dev/null; then PYTHON_BIN="python3.11"; fi
fi

# Install VortexPanel
INSTALL_DIR="/opt/vortexpanel"
log "Installing VortexPanel to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Clone or copy — always end up with a PERMANENT, git-connected source at
# /root/Vortexpanel, never a /tmp path (which gets wiped on reboot and silently
# breaks future `git pull` + deploy.sh workflows with no way to trace it back).
SRC_DIR="/root/Vortexpanel"
if [ -d "$SRC_DIR/.git" ]; then
    log "Using existing git checkout at $SRC_DIR"
elif [ -e "$SRC_DIR" ]; then
    # Something is there but it's not a valid git repo (e.g. leftover files
    # from a previous manual copy) — move it aside rather than fail or silently
    # clone into a messy directory.
    warn "$SRC_DIR exists but isn't a git repo — moving it to ${SRC_DIR}.bak"
    mv "$SRC_DIR" "${SRC_DIR}.bak.$(date +%s)"
    git clone https://github.com/BrowserlessAPI/VortexPanel.git "$SRC_DIR"
else
    git clone https://github.com/BrowserlessAPI/VortexPanel.git "$SRC_DIR"
fi
cp -r "$SRC_DIR/panel" "$SRC_DIR/web" "$SRC_DIR/app.py" "$INSTALL_DIR/"

# Create virtualenv
log "Setting up Python environment..."
"$PYTHON_BIN" -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
if [ -f "$SRC_DIR/requirements.txt" ]; then
    "$INSTALL_DIR/venv/bin/pip" install -r "$SRC_DIR/requirements.txt" -q
else
    "$INSTALL_DIR/venv/bin/pip" install flask flask-session flask-sock requests gunicorn boto3 -q
fi

# Create directories
mkdir -p /opt/vortexpanel/{backups,logs,sessions}
mkdir -p /var/log/vortexpanel
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
ExecStart=$INSTALL_DIR/venv/bin/gunicorn --workers 4 --threads 4 --worker-class gthread --bind 0.0.0.0:8888 --timeout 120 --access-logfile /var/log/vortexpanel/access.log --error-logfile /var/log/vortexpanel/error.log app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vortexpanel
systemctl restart vortexpanel

# Generate deploy.sh — always points at the SAME $SRC_DIR resolved above,
# so it can never drift out of sync with wherever the source actually lives.
# Auto-backs up the current code + configs before every deploy, so a bad
# update can always be undone with rollback.sh — the code+config themselves
# are never at risk from a normal deploy (they live outside panel/web/app.py
# entirely), but this gives genuine recovery if the NEW code itself is bad.
cat > /root/deploy.sh << EOF
#!/bin/bash
BACKUP_ROOT="$INSTALL_DIR/update_backups"
BACKUP_DIR="\$BACKUP_ROOT/\$(date +%Y%m%d-%H%M%S)"
mkdir -p "\$BACKUP_DIR"
echo "📦 Backing up current install to \$BACKUP_DIR ..."
for item in panel web app.py; do
    if [ -e "$INSTALL_DIR/\$item" ]; then
        cp -r "$INSTALL_DIR/\$item" "\$BACKUP_DIR/" 2>/dev/null
    fi
done
for f in config.json credentials.json admin_password.txt ai_config.json cdn_config.json secret.key; do
    if [ -f "$INSTALL_DIR/\$f" ]; then
        cp "$INSTALL_DIR/\$f" "\$BACKUP_DIR/" 2>/dev/null
    fi
done
echo "\$BACKUP_DIR" > "$INSTALL_DIR/.last_backup"
ls -1dt "\$BACKUP_ROOT"/*/ 2>/dev/null | tail -n +6 | xargs -r rm -rf
cp -r $SRC_DIR/panel/ $SRC_DIR/web/ $INSTALL_DIR/
cp $SRC_DIR/app.py $INSTALL_DIR/
find $INSTALL_DIR -name "__pycache__" -exec rm -rf {} + 2>/dev/null
systemctl restart vortexpanel && sleep 2
curl -s -o /dev/null -w "Panel: %{http_code}\n" http://127.0.0.1:8888/
echo "✓ Deployed (backup saved: \$BACKUP_DIR — run 'bash /root/rollback.sh' to undo)"
EOF
chmod +x /root/deploy.sh
log "Created /root/deploy.sh (source: $SRC_DIR -> install: $INSTALL_DIR)"

# Generate rollback.sh — restores code + configs from the most recent (or a
# specific) deploy.sh backup snapshot. A backup nobody can easily restore
# from isn't worth much, so this ships alongside deploy.sh automatically.
cat > /root/rollback.sh << EOF
#!/bin/bash
# Usage: rollback.sh [backup_timestamp]
#   No argument   -> restores the most recent backup
#   With argument -> restores that specific one, e.g. rollback.sh 20260712-073135
INSTALL_DIR="$INSTALL_DIR"
BACKUP_ROOT="\$INSTALL_DIR/update_backups"
if [ -n "\$1" ]; then
    BACKUP_DIR="\$BACKUP_ROOT/\$1"
else
    if [ -f "\$INSTALL_DIR/.last_backup" ]; then
        BACKUP_DIR=\$(cat "\$INSTALL_DIR/.last_backup")
    else
        BACKUP_DIR=\$(ls -1dt "\$BACKUP_ROOT"/*/ 2>/dev/null | head -1)
    fi
fi
if [ -z "\$BACKUP_DIR" ] || [ ! -d "\$BACKUP_DIR" ]; then
    echo "✗ No backup found\${1:+ for timestamp \$1}."
    echo "Available backups:"
    ls -1 "\$BACKUP_ROOT" 2>/dev/null || echo "  (none)"
    exit 1
fi
echo "⏪ Rolling back to: \$BACKUP_DIR"
echo "This will restore panel/, web/, app.py, and config files from that snapshot."
read -p "Continue? [y/N] " confirm
if [ "\$confirm" != "y" ] && [ "\$confirm" != "Y" ]; then
    echo "Cancelled."
    exit 0
fi
for item in panel web app.py; do
    if [ -e "\$BACKUP_DIR/\$item" ]; then
        rm -rf "\$INSTALL_DIR/\$item"
        cp -r "\$BACKUP_DIR/\$item" "\$INSTALL_DIR/"
        echo "✓ Restored \$item"
    fi
done
for f in config.json credentials.json admin_password.txt ai_config.json cdn_config.json secret.key; do
    if [ -f "\$BACKUP_DIR/\$f" ]; then
        cp "\$BACKUP_DIR/\$f" "\$INSTALL_DIR/"
        echo "✓ Restored \$f"
    fi
done
find "\$INSTALL_DIR" -name "__pycache__" -exec rm -rf {} + 2>/dev/null
systemctl restart vortexpanel 2>/dev/null && sleep 2
curl -s -o /dev/null -w "Panel: %{http_code}\n" http://127.0.0.1:8888/ 2>/dev/null
echo "✓ Rollback complete"
EOF
chmod +x /root/rollback.sh
log "Created /root/rollback.sh"

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
