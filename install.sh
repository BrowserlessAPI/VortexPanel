#!/bin/bash
# VortexPanel installer
# Supports: Ubuntu 20.04+, Debian 11+, Fedora 38+, RHEL/AlmaLinux/Rocky 8+
#
#   curl -fsSL https://raw.githubusercontent.com/BrowserlessAPI/VortexPanel/main/install.sh | sudo bash
#
# A new install gets a random port, a random login path, a random admin
# username and password, and HTTPS with a self-signed certificate.
# Options for a new install (also as environment variables):
#   --port N          VP_PORT     fixed port instead of a random one
#   --path P|off      VP_PATH     login path, "off" for none
#   --user NAME       VP_USER     administrator username
#   --http            VP_HTTP=1   no HTTPS (only behind a VPN / SSH tunnel)
#   --version vX.Y.Z  VP_VERSION  install this release instead of the latest
# Running it again on an installed server repairs/updates the code and keeps
# every setting, account and password.

set -e
while [ $# -gt 0 ]; do
    case "$1" in
        --port) VP_PORT="$2"; shift 2 ;;
        --path) VP_PATH="$2"; shift 2 ;;
        --user) VP_USER="$2"; shift 2 ;;
        --http) VP_HTTP=1; shift ;;
        --version) VP_VERSION="$2"; shift 2 ;;
        -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done
[ "$(id -u)" = "0" ] || { echo "Run the installer as root (sudo bash install.sh)"; exit 1; }
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
    apt-get install -y python3 python3-pip python3-venv curl git wget unzip zip cron sudo ca-certificates openssl openssh-client iproute2
    # ufw: the panel's Firewall page manages it. Installed with rules for SSH
    # and the panel port but NOT switched on - that stays the admin's choice.
    command -v ufw >/dev/null 2>&1 || command -v firewall-cmd >/dev/null 2>&1 || apt-get install -y ufw || true
    systemctl enable --now cron 2>/dev/null || true
elif [ "$PKG_MGR" = "dnf" ]; then
    # RHEL/Alma/Rocky 9+ and Fedora cloud images ship curl-minimal, which
    # conflicts with the full curl package: asking for "curl" there aborted
    # the whole installer (set -e). Only install curl when it is missing.
    DNF_PKGS="python3 python3-pip git wget unzip zip cronie sudo openssl openssh-clients iproute"
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
FRESH=1
[ -f "$INSTALL_DIR/credentials.json" ] && FRESH=0
log "Installing VortexPanel to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR"

# Where the code comes from:
#  - /root/Vortexpanel (a git clone you work in): used as is, and
#    /root/deploy.sh + /root/rollback.sh are created for that workflow.
#  - otherwise the newest signed release tag from GitHub (never the
#    unreleased main branch), unpacked from a bare mirror in
#    $INSTALL_DIR/src.git that the panel's updater keeps using.
REPO_URL="${VP_REPO_URL:-https://github.com/BrowserlessAPI/VortexPanel.git}"
DEV_DIR="/root/Vortexpanel"
TRUST_KEY='support@browserlessapi.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPCUgoALgv3KxwOQUM65hIcfGkXv6cS3/LwQE1ijGT3'
DEV_MODE=0
if [ -d "$DEV_DIR/.git" ]; then
    DEV_MODE=1
    SRC_DIR="$DEV_DIR"
    log "Using your git checkout at $SRC_DIR"
else
    MIRROR="$INSTALL_DIR/src.git"
    if [ -d "$MIRROR" ]; then
        git -C "$MIRROR" fetch --tags --force --prune origin -q
    else
        git clone --bare -q "$REPO_URL" "$MIRROR"
    fi
    chmod 700 "$MIRROR"
    TAG="${VP_VERSION:-$(git -C "$MIRROR" tag -l 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1)}"
    case "$TAG" in v*|"") ;; *) TAG="v$TAG" ;; esac
    SRC_DIR="$INSTALL_DIR/data/install_src"
    rm -rf "$SRC_DIR"; mkdir -p "$SRC_DIR"; chmod 700 "$INSTALL_DIR/data"
    if [ -n "$TAG" ] && git -C "$MIRROR" rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
        SIGNERS=$(mktemp); echo "$TRUST_KEY" > "$SIGNERS"
        if git -C "$MIRROR" -c gpg.ssh.allowedSignersFile="$SIGNERS" verify-tag "$TAG" >/dev/null 2>&1; then
            log "Release $TAG: signature verified"
        else
            warn "Release $TAG is not signed with the VortexPanel release key - installing it anyway"
        fi
        rm -f "$SIGNERS"
        git -C "$MIRROR" archive --format=tar "$TAG" | tar -x -C "$SRC_DIR"
    else
        [ -n "$VP_VERSION" ] && err "Release $VP_VERSION does not exist"
        warn "No release tag found - installing the main branch"
        git -C "$MIRROR" archive --format=tar main | tar -x -C "$SRC_DIR"
    fi
fi
[ -f "$SRC_DIR/app.py" ] || err "The downloaded code is incomplete ($SRC_DIR/app.py missing)"

for item in panel web; do
    rm -rf "$INSTALL_DIR/$item.new"; cp -r "$SRC_DIR/$item" "$INSTALL_DIR/$item.new"
    rm -rf "$INSTALL_DIR/$item"; mv "$INSTALL_DIR/$item.new" "$INSTALL_DIR/$item"
done
for item in app.py requirements.txt install.sh VERSION; do
    if [ -f "$SRC_DIR/$item" ]; then cp "$SRC_DIR/$item" "$INSTALL_DIR/"; fi
done
find "$INSTALL_DIR/panel" "$INSTALL_DIR/web" -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
if [ -f "$SRC_DIR/VERSION" ]; then
    echo "v$(tr -d ' \n' < "$SRC_DIR/VERSION" | sed 's/^v//')" > "$INSTALL_DIR/version.txt"
fi
[ "$DEV_MODE" = "1" ] || rm -rf "$SRC_DIR"

# Create virtualenv
log "Setting up Python environment..."
[ -x "$INSTALL_DIR/venv/bin/python" ] || "$PYTHON_BIN" -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q --disable-pip-version-check
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q --disable-pip-version-check

# Create directories (data/ holds jobs, temp downloads and state: root only)
mkdir -p "$INSTALL_DIR"/{backups,logs,sessions,data,ssl}
chmod 700 "$INSTALL_DIR"/{sessions,data,ssl}
mkdir -p /var/log/vortexpanel
chmod 750 /var/log/vortexpanel
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

randstr() { "$INSTALL_DIR/venv/bin/python" -c "import secrets,sys; a=sys.argv[2]; print(''.join(secrets.choice(a) for _ in range(int(sys.argv[1]))))" "$1" "$2"; }
LOWER='abcdefghijkmnpqrstuvwxyz23456789'
ALNUM='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'
port_in_use() { ss -Hltn "( sport = :$1 )" 2>/dev/null | grep -q . ; }

# Credentials (new install only). Hashed with Argon2id (bcrypt fallback),
# the same scheme the panel uses. The plaintext copy in admin_password.txt
# is deleted by the panel after the first successful sign-in.
if [ "$FRESH" = "1" ]; then
    ADMIN_USER="${VP_USER:-$(randstr 8 "$LOWER")}"
    PASS=$(randstr 16 "$ALNUM")
    ( umask 077
      VP_PASS="$PASS" VP_NAME="$ADMIN_USER" "$INSTALL_DIR/venv/bin/python" - "$INSTALL_DIR/credentials.json" << 'PYEOF'
import json, os, sys, secrets
pw = os.environ['VP_PASS']
try:
    from argon2 import PasswordHasher
    h = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1).hash(pw)
except Exception:
    import bcrypt
    h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()
with open(sys.argv[1], 'w') as f:
    json.dump({'username': os.environ['VP_NAME'], 'password_hash': h,
               'session_version': secrets.token_hex(8)}, f, indent=2)
PYEOF
      echo "$PASS" > "$INSTALL_DIR/admin_password.txt" )
    chmod 600 "$INSTALL_DIR/credentials.json" "$INSTALL_DIR/admin_password.txt"
fi

# Session-signing key, created once here so the 4 gunicorn workers never
# race to create different ones on first start.
if [ ! -s "$INSTALL_DIR/secret.key" ]; then
    ( umask 077; head -c 64 /dev/urandom > "$INSTALL_DIR/secret.key" )
fi
chmod 600 "$INSTALL_DIR/secret.key" 2>/dev/null || true

# Listening address. Dual-stack when the kernel has IPv6 and [::] also
# accepts IPv4 (net.ipv6.bindv6only=0, the Linux default); IPv4 otherwise.
BIND_HOST="0.0.0.0"
if [ -f /proc/net/if_inet6 ] && [ "$(cat /proc/sys/net/ipv6/bindv6only 2>/dev/null)" = "0" ]; then
    BIND_HOST="[::]"
fi
UNIT_FILE=/etc/systemd/system/vortexpanel.service
PANEL_TLS=""
if [ -f "$UNIT_FILE" ] && grep -q -- '--bind' "$UNIT_FILE"; then
    # Re-run: keep the port and HTTPS setup made in Settings.
    PANEL_BIND=$(grep -o -- '--bind [^ ]*' "$UNIT_FILE" | head -1 | awk '{print $2}')
    PANEL_TLS=$(grep -o -- '--certfile [^ ]* --keyfile [^ ]*' "$UNIT_FILE" | head -1)
else
    if [ -n "$VP_PORT" ]; then
        PANEL_PORT="$VP_PORT"
    else
        for _ in $(seq 1 50); do
            PANEL_PORT=$(( 10000 + $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 50000 ))
            port_in_use "$PANEL_PORT" || break
        done
    fi
    PANEL_BIND="$BIND_HOST:$PANEL_PORT"
    if [ -z "$VP_HTTP" ]; then
        # Self-signed certificate for the server's address. Replace it with a
        # Let's Encrypt one in Settings > Panel SSL once a domain points here.
        IP4=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
        SAN="DNS:localhost"; [ -n "$IP4" ] && SAN="IP:$IP4,DNS:localhost"
        if openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "$INSTALL_DIR/ssl/panel.key" -out "$INSTALL_DIR/ssl/panel.crt" \
            -subj "/CN=${IP4:-localhost}/O=VortexPanel/OU=Panel" -addext "subjectAltName=$SAN" >/dev/null 2>&1; then
            chmod 600 "$INSTALL_DIR/ssl/panel.key"
            PANEL_TLS="--certfile $INSTALL_DIR/ssl/panel.crt --keyfile $INSTALL_DIR/ssl/panel.key"
        else
            warn "Could not create a certificate - the panel will use plain HTTP"
        fi
    fi
fi
PANEL_PORT="${PANEL_BIND##*:}"
PANEL_SCHEME=http
[ -n "$PANEL_TLS" ] && PANEL_SCHEME=https

# Panel settings for a new install: port, HTTPS and a random login path.
if [ "$FRESH" = "1" ] || [ ! -f "$INSTALL_DIR/config.json" ]; then
    case "${VP_PATH:-random}" in
        off|none) SEC_PATH="" ;;
        random) SEC_PATH=$(randstr 8 "$LOWER") ;;
        *) SEC_PATH="$VP_PATH" ;;
    esac
    [ -f "$INSTALL_DIR/config.json" ] || ( umask 077; echo '{}' > "$INSTALL_DIR/config.json" )
    VP_SP="$SEC_PATH" VP_PT="$PANEL_PORT" VP_SSL="$PANEL_TLS" "$INSTALL_DIR/venv/bin/python" - "$INSTALL_DIR/config.json" << 'PYEOF'
import json, os, sys
p = sys.argv[1]
try:
    cfg = json.load(open(p))
except Exception:
    cfg = {}
cfg.setdefault('panel_name', 'VortexPanel')
cfg['port'] = int(os.environ['VP_PT'])
cfg['ssl_enabled'] = bool(os.environ.get('VP_SSL'))
if not cfg.get('security_path'):
    cfg['security_path'] = os.environ.get('VP_SP', '')
cfg.setdefault('session_hours', 12)
json.dump(cfg, open(p, 'w'), indent=2)
PYEOF
    chmod 600 "$INSTALL_DIR/config.json"
fi

# Create systemd service
cat > /etc/systemd/system/vortexpanel.service << UNITEOF
[Unit]
Description=VortexPanel Control Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
UMask=0077
ExecStart=$INSTALL_DIR/venv/bin/gunicorn --workers 4 --threads 4 --worker-class gthread --bind $PANEL_BIND $PANEL_TLS --timeout 120 --access-logfile /var/log/vortexpanel/access.log --error-logfile /var/log/vortexpanel/error.log app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNITEOF

# Command-line tool: vortexpanel (info, reset-password, port, path, ...)
cat > /usr/local/bin/vortexpanel << CLIEOF
#!/bin/sh
cd $INSTALL_DIR && VP_NO_INIT=1 exec $INSTALL_DIR/venv/bin/python -m panel.cli "\$@"
CLIEOF
chmod 755 /usr/local/bin/vortexpanel

systemctl daemon-reload
systemctl enable vortexpanel >/dev/null 2>&1
systemctl restart vortexpanel

if [ "$DEV_MODE" = "1" ]; then
# Developer workflow: /root/deploy.sh copies $SRC_DIR into the install after
# a snapshot (same format the panel's updater uses); /root/rollback.sh puts
# the newest snapshot back.
cat > /root/deploy.sh << DEPLOYEOF
#!/bin/bash
set -e
cd $INSTALL_DIR
BDIR=\$(VP_NO_INIT=1 $INSTALL_DIR/venv/bin/python -c "from panel import updater; print(updater.snapshot('deploy'))")
echo "Snapshot: \$BDIR"
$INSTALL_DIR/venv/bin/pip install -q --disable-pip-version-check -r $SRC_DIR/requirements.txt || { echo "pip install failed - nothing deployed"; exit 1; }
for item in panel web; do rm -rf $INSTALL_DIR/\$item; cp -r $SRC_DIR/\$item $INSTALL_DIR/; done
for item in app.py requirements.txt install.sh VERSION; do cp $SRC_DIR/\$item $INSTALL_DIR/ 2>/dev/null || true; done
echo "v\$(tr -d ' \n' < $SRC_DIR/VERSION | sed 's/^v//')" > $INSTALL_DIR/version.txt
find $INSTALL_DIR/panel $INSTALL_DIR/web -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
if VP_NO_INIT=1 $INSTALL_DIR/venv/bin/python -c "from panel import updater; import sys; sys.exit(updater.schedule_restart(None, '\$BDIR', wait=True))"; then
    echo "Deployed. Undo with: bash /root/rollback.sh"
else
    echo "The new code did not start - the snapshot was restored."; exit 1
fi
DEPLOYEOF
cat > /root/rollback.sh << 'ROLLEOF'
#!/bin/bash
exec /usr/local/bin/vortexpanel rollback
ROLLEOF
chmod 700 /root/deploy.sh /root/rollback.sh
log "Developer scripts: /root/deploy.sh and /root/rollback.sh"
fi

# Firewall: open the panel port (and keep SSH open) wherever a firewall exists.
SSH_PORT=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')
SSH_PORT=${SSH_PORT:-22}
if command -v ufw >/dev/null 2>&1; then
    ufw allow "$SSH_PORT"/tcp >/dev/null 2>&1 || true
    ufw allow "$PANEL_PORT"/tcp >/dev/null 2>&1 || true
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$PANEL_PORT"/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
fi

# Wait until the panel answers.
UP=0
for _ in $(seq 1 60); do
    if curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' "$PANEL_SCHEME://127.0.0.1:$PANEL_PORT/api/health" 2>/dev/null | grep -q 200; then UP=1; break; fi
    sleep 1
done
[ "$UP" = "1" ] || warn "The panel is not answering yet - check: vortexpanel logs"

log "============================================"
if [ "$FRESH" = "1" ]; then
    log "VortexPanel installed."
else
    log "VortexPanel updated - settings, accounts and passwords were kept."
fi
/usr/local/bin/vortexpanel info || true
if [ "$FRESH" = "1" ]; then
    log "Save these details now. Run 'vortexpanel' to see them again; the password"
    log "is removed from the server after your first sign-in."
    [ "$PANEL_SCHEME" = "https" ] && log "Your browser warns about the self-signed certificate once: that is expected."
    if command -v ufw >/dev/null 2>&1 && ! ufw status 2>/dev/null | grep -q "Status: active"; then
        log "The ufw firewall is installed but off (rules for SSH port $SSH_PORT and the panel are ready)."
        log "Turn it on in Security > Firewall or with: ufw enable"
    fi
fi
log "============================================"
