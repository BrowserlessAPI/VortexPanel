#!/bin/bash
set -e

PANEL_DIR="/opt/vortexpanel"
SERVICE_FILE="/etc/systemd/system/vortexpanel.service"
PORT=8888

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  VortexPanel v3.0 Installer"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Install Python deps
echo "[1/4] Installing Python dependencies..."
pip3 install flask --break-system-packages -q 2>/dev/null || pip3 install flask -q

# Copy files
echo "[2/4] Copying panel files..."
mkdir -p "$PANEL_DIR"
cp -r . "$PANEL_DIR/"
mkdir -p "$PANEL_DIR/backups"

# Create systemd service
echo "[3/4] Creating systemd service..."
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=VortexPanel Web Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$PANEL_DIR
ExecStart=/usr/bin/python3 $PANEL_DIR/app.py
Restart=always
RestartSec=5
Environment=PORT=$PORT
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vortexpanel
systemctl restart vortexpanel

echo "[4/4] Done!"
echo ""
echo "  ✓ VortexPanel is running on port $PORT"
echo "  ✓ URL: http://$(hostname -I | awk '{print $1}'):$PORT"
echo "  ✓ Default login: admin / admin123"
echo ""
echo "  To view logs: journalctl -u vortexpanel -f"
