<div align="center">

<img src="https://img.shields.io/badge/VortexPanel-v3.1-6c7fff?style=for-the-badge&logo=lightning&logoColor=white" alt="VortexPanel v3.1">
<img src="https://img.shields.io/badge/Python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white">
<img src="https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask">
<img src="https://img.shields.io/badge/Alpine.js-3.14-8bc0d0?style=for-the-badge">
<img src="https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge">
<img src="https://img.shields.io/github/stars/BrowserlessAPI/VortexPanel?style=for-the-badge&color=f59e0b">
<img src="https://img.shields.io/github/last-commit/BrowserlessAPI/VortexPanel?style=for-the-badge&color=6c7fff">

<br><br>

<h1>⚡ VortexPanel</h1>

<p><strong>Free, open-source server control panel.</strong><br>
Everything aaPanel locks behind a paid Pro tier — WAF, Fail2Ban, Load Balancer, WP Toolkit — built in and free.<br>
Built with Python/Flask + Alpine.js. No Node.js build step. No bloat. 2-minute install.</p>

<a href="#-quick-install"><img src="https://img.shields.io/badge/Quick_Install-1_command-6c7fff?style=for-the-badge" /></a>
<a href="https://github.com/BrowserlessAPI/VortexPanel/releases"><img src="https://img.shields.io/badge/Releases-Changelog-22c55e?style=for-the-badge" /></a>
<a href="https://github.com/BrowserlessAPI/VortexPanel/issues"><img src="https://img.shields.io/badge/Issues-Report_a_bug-ef4444?style=for-the-badge" /></a>

</div>

---

## 🆚 Why VortexPanel over aaPanel / HestiaCP / cPanel?

| Feature | cPanel | aaPanel Free | aaPanel Pro | HestiaCP | **VortexPanel** |
|---|---|---|---|---|---|
| **Price** | $30–$65/mo | Free | Paid add-on | Free | **Free (MIT)** |
| **ModSecurity WAF** | Paid ext. | ❌ | ✅ paid | Manual | **✅ Built-in** |
| **Fail2Ban** | Paid ext. | ❌ | ✅ paid | ✅ | **✅ Built-in** |
| **Load Balancer** | ❌ | ❌ | ✅ paid | ❌ | **✅ Built-in** |
| **WP Toolkit** | ❌ | ❌ | ❌ | ❌ | **✅ Built-in** |
| **Firewall (UFW + firewalld)** | ❌ | UFW only | UFW only | UFW only | **✅ Both** |
| **Cloud Backup (S3)** | Paid | ❌ | ✅ paid | Manual | **✅ Built-in** |
| **Docker UI** | ❌ | ✅ | ✅ | ❌ | **✅ Built-in** |
| **RHEL/AlmaLinux/Rocky** | ✅ | Partial | Partial | ❌ | **✅ 9 distros** |
| **Web Terminal** | ✅ | ✅ | ✅ | ❌ | **✅ Built-in** |
| **Open source** | ❌ | Partial | ❌ | ✅ | **✅ MIT** |

---

## ✨ Features

### 🌐 Website Management
- **Nginx, Apache2, OpenLiteSpeed, Caddy** — install and manage from the same panel
- **One-click SSL** via Let's Encrypt — auto-detects Cloudflare DNS-01 vs HTTP-01
- Reverse proxy, custom directives, PHP version per site, Composer integration
- One-click WordPress/Laravel/Symfony deploy

### 🔷 WP Toolkit *(new in v3.1)*
- **Full WordPress install** — downloads WP, creates DB, writes wp-config.php, creates vhost, configures SSL — all in one click
- **PHP 7.4–8.5**, **Nginx / Apache / OpenLiteSpeed / Caddy**, **MariaDB / MySQL**
- Plugin & theme management, one-click admin login, bulk updates
- **Security scanner** — 9 checks with one-click auto-fix buttons
- **Staging clone** — full site clone with DB, push/pull between staging and live
- Backup/restore, maintenance mode, system cron, debug mode toggle
- Powered by wp-cli (auto-installed if missing)

### 🔒 Security *(free — no "Pro" tier)*
- **Firewall** — UFW (Debian/Ubuntu) **and** firewalld (Fedora/RHEL/AlmaLinux/Rocky/Oracle/CentOS/CloudLinux) from the same UI
- **Fail2ban** — intrusion prevention, brute-force protection
- **ModSecurity WAF** — Nginx web application firewall, one-click install + toggle
- **Security Score** — at-a-glance audit with actionable fix buttons
- SSH hardening, login-attempt monitoring, open port scanner

### 🗄 Databases
- MySQL, MariaDB, PostgreSQL, MongoDB — multi-engine
- phpMyAdmin integration (auto-configured on its own port, separate PHP version)

### 📦 App Store
- 25+ one-click installs: Nginx, Apache, OpenLiteSpeed, Caddy, PHP (multi-version), MySQL, MariaDB, PostgreSQL, MongoDB, Redis, Docker, Node.js, Python, Composer, Fail2ban, ClamAV, ModSecurity, Roundcube, Supervisor, Pure-FTPd, BIND9 DNS, and more
- Automatic conflict detection, RHEL-family package manager support

### ⚡ Performance
- Dashboard stats from `/proc` (not `top -bn1`) — **10× faster** response
- Response caching for expensive endpoints
- **Gzip compression** — `app.js` 150KB → ~40KB, `index.html` 350KB → ~70KB

### 🔧 Everything else
- **Docker** — container management, 45+ pre-configured image catalog
- **DNS** — BIND9 zone management + Cloudflare DDNS (no ddclient)
- **Mail** — Postfix + Dovecot, domains, accounts, Roundcube webmail
- **CDN** — Cloudflare, BunnyCDN, Akamai, CloudFront, KeyCDN
- **Monitoring** — real-time CPU/RAM/Disk/Network, process list, bandwidth
- **File Manager** — code editor, chmod, AES-encrypted zip support, ClamAV scan
- **Web Terminal** — full PTY shell in browser over WebSocket
- **Backups** — website + database, restore, S3-compatible cloud backup
- **Cron Jobs** — visual scheduler, 10 task types, run-now, logs
- **AI Assistant** — configurable OpenAI-compatible API (NeonCodex, OpenAI, etc.)

---

## 🚀 Quick Install

```bash
wget -O install.sh https://raw.githubusercontent.com/BrowserlessAPI/VortexPanel/main/install.sh && bash install.sh
```

Access the panel at: **`http://YOUR-SERVER-IP:8888`**

The installer auto-detects your OS and package manager. On RHEL 8-family systems (AlmaLinux 8 / Rocky 8, where default Python is 3.6) it automatically installs Python 3.11.

---

## 📋 Supported Operating Systems

| Distro | Versions |
|---|---|
| **Ubuntu** | 20.04, 22.04, 24.04 |
| **Debian** | 11, 12 |
| **AlmaLinux** | 8, 9, 10 |
| **Rocky Linux** | 8, 9, 10 |
| **RHEL** | 8, 9, 10 |
| **Oracle Linux** | 8, 9 |
| **CentOS Stream** | 8, 9 |
| **CloudLinux** | 8, 9, 10 |
| **Fedora** | 38+ |

**Minimum requirements:** 512 MB RAM (1 GB recommended) · 2 GB free disk

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.8+ · Flask 3.x · Gunicorn (4 workers × 4 threads) |
| **Frontend** | Alpine.js 3.14 · Vanilla CSS (no build step, no npm) |
| **Auth** | Session-based · SHA-256 hashed passwords |
| **Panel config** | JSON files (no external database required) |
| **Service** | systemd · auto-start on boot |

---

## 🤝 Contributing

Contributions are welcome — bug reports, feature requests, and pull requests all help.

**Before you start:**
1. Check [open issues](https://github.com/BrowserlessAPI/VortexPanel/issues) to avoid duplicates
2. For new features, open an issue to discuss before coding
3. Read [CONTRIBUTING.md](CONTRIBUTING.md) for code style and PR process

```bash
git clone https://github.com/BrowserlessAPI/VortexPanel.git
cd VortexPanel
pip install -r requirements.txt
python3 app.py   # runs on :8888
```

---

## 🗺 Roadmap

- [ ] Per-site website analytics (traffic, top URIs, status codes, bot detection)
- [ ] Alerting — CPU/RAM/SSL-expiry push to Telegram/Discord/email/webhook
- [ ] Disk usage analyzer (visual tree, delete from panel)
- [ ] Multi-user / RBAC
- [ ] PHP webshell scanner (pattern-based, integrates with File Manager)
- [ ] LB node health monitoring + TCP/stream load balancing

---

## 📄 License

MIT License — free to use, modify, and distribute, including commercially.

---

<div align="center">
  Made with ⚡ by <a href="https://github.com/BrowserlessAPI">BrowserlessAPI</a> · <a href="https://github.com/BrowserlessAPI/VortexPanel/releases">Releases</a> · <a href="https://github.com/BrowserlessAPI/VortexPanel/issues">Issues</a> · <a href="CONTRIBUTING.md">Contributing</a>
</div>
