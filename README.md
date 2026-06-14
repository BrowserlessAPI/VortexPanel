<div align="center">
  <img src="https://img.shields.io/badge/VortexPanel-v3.0-6c7fff?style=for-the-badge&logo=lightning&logoColor=white" alt="VortexPanel">
  <img src="https://img.shields.io/badge/Python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask">
  <img src="https://img.shields.io/badge/Alpine.js-3.14-8bc0d0?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge">

  <h1>⚡ VortexPanel</h1>
  <p><strong>Open-source server management panel built for developers.</strong><br>
  A modern alternative to aaPanel / HestiaCP — built with Python/Flask + Alpine.js.</p>
</div>

---

## ✨ Features

| Category | Features |
|---|---|
| **Web Servers** | Nginx, Apache2, OpenLiteSpeed, Caddy — install, configure, SSL |
| **PHP** | Multi-version (7.4 → 8.4), extensions, php.ini editor, FPM control |
| **Databases** | MySQL, MariaDB, PostgreSQL, MongoDB — create DBs, users, backup |
| **File Manager** | Full-featured: editor, chmod, compress/extract, search, drag-upload |
| **Docker** | Container management, 40+ pre-configured images catalog |
| **CDN** | Cloudflare, BunnyCDN, Akamai, CloudFront, KeyCDN — full API |
| **Security** | Firewall (UFW), Fail2ban, ModSecurity WAF, SSH hardening |
| **Cron Jobs** | Visual scheduler, run-now, logs, 10 task types |
| **Monitoring** | Real-time CPU/RAM/Disk, process list, bandwidth tracking |
| **Backups** | Website + database backups, restore, upload |
| **DNS** | BIND9 zone management, DDNS |
| **Mail** | Postfix + Dovecot, domains, accounts |
| **AI Assistant** | Built-in NeonCodex AI for server help (requires API key) |

---

## 🚀 Quick Install

```bash
# One-line install (Ubuntu, Debian, Fedora, AlmaLinux, Rocky, RHEL, Oracle Linux, CentOS)
wget -O install.sh https://raw.githubusercontent.com/BrowserlessAPI/Vortexpanel/main/install.sh && bash install.sh
```

Access the panel at: `http://YOUR-SERVER-IP:8888`

The installer auto-detects your OS and package manager (`apt` or `dnf`), and on
RHEL 8-family systems (AlmaLinux 8 / Rocky 8, where the default Python is 3.6)
it automatically installs and uses Python 3.11 for the panel's virtual environment.

---

## 📋 Requirements

- **OS**: Ubuntu 20.04 / 22.04 / 24.04, Debian 11 / 12, Fedora 38+, AlmaLinux 8 / 9 / 10, Rocky Linux 8 / 9 / 10, RHEL 8 / 9 / 10, Oracle Linux 8 / 9, CentOS Stream
- **RAM**: 512 MB minimum (1 GB recommended)
- **Disk**: 2 GB free
- **Python**: 3.8+ (the installer handles this automatically on older RHEL 8-family systems)

---

## 🔧 Manual Setup

```bash
git clone https://github.com/BrowserlessAPI/Vortexpanel.git
cd Vortexpanel
pip install -r requirements.txt
python3 app.py
```

---

## 🛠 Stack

- **Backend**: Python 3 + Flask
- **Frontend**: Alpine.js 3.14 + Vanilla CSS (no framework)
- **Database**: File-based config (no external DB required for panel itself)
- **Auth**: Session-based with SHA-256 hashed passwords

---

## 🤝 Contributing

Pull requests welcome! Please open an issue first to discuss changes.

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

<div align="center">
  Made with ⚡ by <a href="https://github.com/BrowserlessAPI">BrowserlessAPI</a>
</div>
