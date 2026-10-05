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
        *)
            # Derivatives (Amazon Linux, EuroLinux, Raspbian, ...): go by
            # ID_LIKE / the package manager that exists, never assume apt.
            case " ${ID_LIKE,,} " in
                *" rhel "*|*" centos "*|*" fedora "*) OS_FAMILY="rhel"; PKG_MGR="dnf" ;;
                *" debian "*|*" ubuntu "*) OS_FAMILY="debian"; PKG_MGR="apt" ;;
                *) if command -v dnf >/dev/null 2>&1; then OS_FAMILY="rhel"; PKG_MGR="dnf";
                   else warn "Unknown OS: $OS_ID, assuming Debian-like"; OS_FAMILY="debian"; PKG_MGR="apt"; fi ;;
            esac ;;
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
    # cron: minimal/cloud images lack it (panel cron jobs, CRS/cert renewals);
    # zip: File Manager archives.
    apt-get install -y python3 python3-pip python3-venv curl git wget unzip zip cron sudo ca-certificates
    systemctl enable --now cron 2>/dev/null || true
elif [ "$PKG_MGR" = "dnf" ]; then
    # RHEL/Alma/Rocky 9+ and Fedora cloud images ship curl-minimal, which
    # conflicts with the full curl package: asking for "curl" there aborted
    # the whole installer (set -e). Only install curl when it is missing.
    DNF_PKGS="python3 python3-pip git wget unzip zip cronie sudo"
    command -v curl >/dev/null 2>&1 || DNF_PKGS="$DNF_PKGS curl"
    # semanage (SELinux port/file labels for sites, phpMyAdmin, FTP)
    if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" != "Disabled" ]; then
        DNF_PKGS="$DNF_PKGS policycoreutils-python-utils"
    fi
    dnf install -y $DNF_PKGS
    systemctl enable --now crond 2>/dev/null || true
    # EPEL (fail2ban, pure-ftpd, certbot, ...): epel-release only exists on
    # Alma/Rocky/CentOS/CloudLinux; Oracle Linux has oracle-epel-release-elN;
    # RHEL needs the upstream RPM plus CodeReady Builder. Never on Fedora.
    if [ "$OS_FAMILY" = "rhel" ] && [ -z "$(rpm -E '%{?fedora}' 2>/dev/null)" ] && ! rpm -q epel-release >/dev/null 2>&1; then
        if ! dnf install -y epel-release 2>/dev/null; then
            EL=$(rpm -E '%{?rhel}' 2>/dev/null); EL=${EL:-9}
            if [ "$OS_ID" = "ol" ]; then
                dnf install -y "oracle-epel-release-el$EL" || warn "Could not enable EPEL"
            elif dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$EL.noarch.rpm"; then
                subscription-manager repos --enable "codeready-builder-for-rhel-$EL-$(arch)-rpms" 2>/dev/null \
                    || dnf config-manager --set-enabled crb 2>/dev/null || true
            else
                warn "Could not enable EPEL"
            fi
        fi
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
cp "$SRC_DIR/requirements.txt" "$INSTALL_DIR/" 2>/dev/null || true
if [ -f "$SRC_DIR/VERSION" ]; then
    cp "$SRC_DIR/VERSION" "$INSTALL_DIR/"
    echo "v$(tr -d ' \n' < "$SRC_DIR/VERSION" | sed 's/^v//')" > "$INSTALL_DIR/version.txt"
fi

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
# Web root for every site the panel creates (never the distro default
# docroot /var/www/html or /usr/share/nginx/html -- see os_utils.get_webroot).
mkdir -p /www/wwwroot
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" != "Disabled" ]; then
    if command -v semanage >/dev/null 2>&1; then
        semanage fcontext -a -t httpd_sys_rw_content_t "/www/wwwroot(/.*)?" 2>/dev/null \
            || semanage fcontext -m -t httpd_sys_rw_content_t "/www/wwwroot(/.*)?" 2>/dev/null || true
        restorecon -R /www/wwwroot 2>/dev/null || true
    else
        chcon -R -t httpd_sys_rw_content_t /www/wwwroot 2>/dev/null || true
    fi
fi

# Create credentials. Hashed with Argon2id (bcrypt fallback) from the venv,
# the same scheme auth.py uses, instead of unsalted SHA-256. Files are 0600:
# the default umask left the hash and the plaintext password world-readable.
if [ ! -f "$INSTALL_DIR/credentials.json" ]; then
    PASS=$("$INSTALL_DIR/venv/bin/python" -c 'import secrets,string; a=string.ascii_letters+string.digits; print("".join(secrets.choice(a) for _ in range(16)))')
    ( umask 077
      VP_PASS="$PASS" "$INSTALL_DIR/venv/bin/python" - "$INSTALL_DIR/credentials.json" << 'PYEOF'
import json, os, sys, hashlib
pw = os.environ['VP_PASS']
try:
    from argon2 import PasswordHasher
    h = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1).hash(pw)
except Exception:
    try:
        import bcrypt
        h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()
    except Exception:
        h = hashlib.sha256(pw.encode()).hexdigest()
with open(sys.argv[1], 'w') as f:
    json.dump({'username': 'admin', 'password_hash': h, 'email': 'admin@vortexpanel.local'}, f, indent=2)
PYEOF
      echo "$PASS" > "$INSTALL_DIR/admin_password.txt" )
    chmod 600 "$INSTALL_DIR/credentials.json" "$INSTALL_DIR/admin_password.txt"
    log "Generated admin password: $PASS"
fi

# Session-signing key, created once here so the 4 gunicorn workers never
# race to create different ones on first start.
if [ ! -s "$INSTALL_DIR/secret.key" ]; then
    ( umask 077; head -c 64 /dev/urandom > "$INSTALL_DIR/secret.key" )
fi
chmod 600 "$INSTALL_DIR/secret.key" 2>/dev/null || true

# Re-running the installer must not reset a port / HTTPS setup made in
# Settings: keep the existing unit's --bind and certificate arguments.
# Dual-stack when the kernel has IPv6 and [::] also accepts IPv4
# (net.ipv6.bindv6only=0, the Linux default); IPv4-only otherwise.
PANEL_BIND="0.0.0.0:8888"
if [ -f /proc/net/if_inet6 ] && [ "$(cat /proc/sys/net/ipv6/bindv6only 2>/dev/null)" = "0" ]; then
    PANEL_BIND="[::]:8888"
fi
PANEL_TLS=""
UNIT_FILE=/etc/systemd/system/vortexpanel.service
if [ -f "$UNIT_FILE" ]; then
    OLD_BIND=$(grep -o -- '--bind [^ ]*' "$UNIT_FILE" | head -1 | awk '{print $2}')
    [ -n "$OLD_BIND" ] && PANEL_BIND="$OLD_BIND"
    PANEL_TLS=$(grep -o -- '--certfile [^ ]* --keyfile [^ ]*' "$UNIT_FILE" | head -1)
fi
PANEL_PORT="${PANEL_BIND##*:}"
PANEL_SCHEME=http
[ -n "$PANEL_TLS" ] && PANEL_SCHEME=https

# Create systemd service
cat > /etc/systemd/system/vortexpanel.service << EOF
[Unit]
Description=VortexPanel Control Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/gunicorn --workers 4 --threads 4 --worker-class gthread --bind $PANEL_BIND $PANEL_TLS --timeout 120 --access-logfile /var/log/vortexpanel/access.log --error-logfile /var/log/vortexpanel/error.log app:app
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
echo "Backing up current install to \$BACKUP_DIR ..."
for item in panel web app.py requirements.txt VERSION version.txt; do
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
# New Python dependencies first: a release that adds one otherwise restarts
# straight into an ImportError.
if [ -f $SRC_DIR/requirements.txt ]; then
    $INSTALL_DIR/venv/bin/pip install -q --disable-pip-version-check -r $SRC_DIR/requirements.txt || { echo "ERROR: pip install failed - nothing deployed"; exit 1; }
    cp $SRC_DIR/requirements.txt $INSTALL_DIR/
fi
cp -r $SRC_DIR/panel/ $SRC_DIR/web/ $INSTALL_DIR/
cp $SRC_DIR/app.py $INSTALL_DIR/
# Keep the displayed version in step with what was deployed (version.txt
# takes precedence over the repo VERSION file in the panel).
if [ -f $SRC_DIR/VERSION ]; then
    cp $SRC_DIR/VERSION $INSTALL_DIR/
    echo "v\$(tr -d ' \n' < $SRC_DIR/VERSION | sed 's/^v//')" > $INSTALL_DIR/version.txt
fi
find $INSTALL_DIR -name "__pycache__" -exec rm -rf {} + 2>/dev/null
systemctl restart vortexpanel && sleep 3
UNIT=/etc/systemd/system/vortexpanel.service
PORT=\$(grep -o -- '--bind [^ ]*' \$UNIT | head -1 | sed 's/.*://')
SCHEME=http; grep -q -- '--certfile' \$UNIT && SCHEME=https
curl -sk -o /dev/null -w "Panel: %{http_code}\n" "\$SCHEME://127.0.0.1:\${PORT:-8888}/"
echo "Deployed (backup saved: \$BACKUP_DIR - run 'bash /root/rollback.sh' to undo)"
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
    echo "ERROR: No backup found\${1:+ for timestamp \$1}."
    echo "Available backups:"
    ls -1 "\$BACKUP_ROOT" 2>/dev/null || echo "  (none)"
    exit 1
fi
echo "Rolling back to: \$BACKUP_DIR"
echo "This will restore panel/, web/, app.py, and config files from that snapshot."
read -p "Continue? [y/N] " confirm
if [ "\$confirm" != "y" ] && [ "\$confirm" != "Y" ]; then
    echo "Cancelled."
    exit 0
fi
for item in panel web app.py requirements.txt VERSION version.txt; do
    if [ -e "\$BACKUP_DIR/\$item" ]; then
        rm -rf "\$INSTALL_DIR/\$item"
        cp -r "\$BACKUP_DIR/\$item" "\$INSTALL_DIR/"
        echo "Restored \$item"
    fi
done
for f in config.json credentials.json admin_password.txt ai_config.json cdn_config.json secret.key; do
    if [ -f "\$BACKUP_DIR/\$f" ]; then
        cp "\$BACKUP_DIR/\$f" "\$INSTALL_DIR/"
        echo "Restored \$f"
    fi
done
find "\$INSTALL_DIR" -name "__pycache__" -exec rm -rf {} + 2>/dev/null
systemctl restart vortexpanel 2>/dev/null && sleep 3
UNIT=/etc/systemd/system/vortexpanel.service
PORT=\$(grep -o -- '--bind [^ ]*' \$UNIT | head -1 | sed 's/.*://')
SCHEME=http; grep -q -- '--certfile' \$UNIT && SCHEME=https
curl -sk -o /dev/null -w "Panel: %{http_code}\n" "\$SCHEME://127.0.0.1:\${PORT:-8888}/" 2>/dev/null
echo "Rollback complete"
EOF
chmod +x /root/rollback.sh
log "Created /root/rollback.sh"

# Firewall rules
if command -v ufw &>/dev/null; then
    ufw allow "$PANEL_PORT"/tcp 2>/dev/null || true
fi
# firewalld is checked independently of ufw (both can be installed) and
# only when it is actually running.
if command -v firewall-cmd &>/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$PANEL_PORT"/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
fi

IP=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
log "============================================"
log "VortexPanel installed successfully!"
log "URL: $PANEL_SCHEME://$IP:$PANEL_PORT"
log "Username: admin"
log "Password: $(cat $INSTALL_DIR/admin_password.txt 2>/dev/null || echo 'See credentials.json')"
log "============================================"
