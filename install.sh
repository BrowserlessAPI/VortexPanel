#!/bin/bash
set -e
PANEL_DIR="/opt/vortexpanel"
SERVICE_FILE="/etc/systemd/system/vortexpanel.service"
CLI_FILE="/usr/local/bin/vortexpanel"
PORT=8888
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'; BOLD='\033[1m'

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  VortexPanel v3.0 Installer${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── 1. Python deps ───────────────────────────────────────────────────────────
echo -e "[1/5] Installing Python dependencies..."
apt-get install -y python3-venv python3-full -qq 2>/dev/null || true
python3 -m venv "$PANEL_DIR/venv" --system-site-packages 2>/dev/null || python3 -m venv "$PANEL_DIR/venv"
"$PANEL_DIR/venv/bin/pip" install flask -q

# ── 2. Copy files ────────────────────────────────────────────────────────────
echo -e "[2/5] Copying panel files..."
mkdir -p "$PANEL_DIR/backups"
cp -r . "$PANEL_DIR/"
chmod -R 755 "$PANEL_DIR"

# ── 3. Generate credentials ──────────────────────────────────────────────────
echo -e "[3/5] Setting up credentials..."
mkdir -p "$PANEL_DIR"

# Generate random password
RAND_PW=$("$PANEL_DIR/venv/bin/python3" -c "import secrets,string; print('VP'+''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(10))+'!')")
PW_HASH=$("$PANEL_DIR/venv/bin/python3" -c "import hashlib; print(hashlib.sha256('${RAND_PW}'.encode()).hexdigest())")

# Write credentials.json in the exact format our auth.py reads
cat > "${PANEL_DIR}/credentials.json" << JSONEOF
{
  "username": "admin",
  "password_hash": "${PW_HASH}",
  "email": "admin@vortexpanel.local"
}
JSONEOF
chmod 600 "${PANEL_DIR}/credentials.json"

# ── 4. Systemd service ───────────────────────────────────────────────────────
echo -e "[4/5] Creating systemd service..."
cat > "$SERVICE_FILE" << SVCEOF
[Unit]
Description=VortexPanel Web Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=${PANEL_DIR}
ExecStart=${PANEL_DIR}/venv/bin/python3 ${PANEL_DIR}/app.py
Restart=always
RestartSec=5
Environment=PORT=${PORT}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable vortexpanel --quiet
systemctl restart vortexpanel

# ── 5. CLI tool ──────────────────────────────────────────────────────────────
echo -e "[5/5] Installing CLI..."
cat > "$CLI_FILE" << 'CLIEOF'
#!/bin/bash
PANEL_DIR="/opt/vortexpanel"
case "$1" in
  status)   systemctl status vortexpanel --no-pager ;;
  restart)  systemctl restart vortexpanel && echo "Restarted" ;;
  stop)     systemctl stop vortexpanel && echo "Stopped" ;;
  start)    systemctl start vortexpanel && echo "Started" ;;
  logs)     journalctl -u vortexpanel -f ;;
  reset-password)
    NEW_PW=$(${PANEL_DIR}/venv/bin/python3 -c "import secrets,string; print('VP'+''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(10))+'!')")
    PW_HASH=$(${PANEL_DIR}/venv/bin/python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$NEW_PW")
    python3 -c "
import json, os
f = '$PANEL_DIR/credentials.json'
creds = json.load(open(f)) if os.path.exists(f) else {'username':'admin','email':'admin@vortexpanel.local'}
creds['password_hash'] = '$PW_HASH'
json.dump(creds, open(f,'w'), indent=2)
"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Password reset successfully!"
    echo "  Username: admin"
    echo "  Password: $NEW_PW"
    echo "  (Save this — shown once!)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    systemctl restart vortexpanel
    ;;
  set-password)
    if [ -z "$2" ]; then echo "Usage: vortexpanel set-password <newpassword>"; exit 1; fi
    PW_HASH=$(python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$2")
    python3 -c "
import json, os
f = '$PANEL_DIR/credentials.json'
creds = json.load(open(f)) if os.path.exists(f) else {'username':'admin'}
creds['password_hash'] = '$PW_HASH'
json.dump(creds, open(f,'w'), indent=2)
"
    systemctl restart vortexpanel
    echo "✓ Password updated. Login with: admin / $2"
    ;;
  *)
    echo "VortexPanel CLI"
    echo "Usage: vortexpanel [status|start|stop|restart|logs|reset-password|set-password <pw>]"
    ;;
esac
CLIEOF
chmod +x "$CLI_FILE"

# ── Done ─────────────────────────────────────────────────────────────────────
SERVER_IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  VortexPanel installed successfully!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}YOUR LOGIN CREDENTIALS${NC}"
echo -e "  URL:      ${CYAN}http://${SERVER_IP}:${PORT}${NC}"
echo -e "  Username: ${CYAN}admin${NC}"
echo -e "  Password: ${YELLOW}${RAND_PW}${NC}"
echo -e "  Email:    ${CYAN}admin@vortexpanel.local${NC}"
echo ""
echo -e "  ${RED}✓ Save these credentials — password shown once!${NC}"
echo ""
echo -e "  CLI: ${CYAN}vortexpanel status | restart | logs | reset-password${NC}"
echo ""
