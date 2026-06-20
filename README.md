<div align="center">

<img src="https://img.shields.io/badge/VortexPanel-v3.2-6c7fff?style=for-the-badge&logo=lightning&logoColor=white" alt="VortexPanel v3.2">
<img src="https://img.shields.io/badge/Python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white">
<img src="https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask">
<img src="https://img.shields.io/badge/Alpine.js-3.14-8bc0d0?style=for-the-badge">
<img src="https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge">
<img src="https://img.shields.io/github/stars/BrowserlessAPI/VortexPanel?style=for-the-badge&color=f59e0b">
<img src="https://img.shields.io/github/last-commit/BrowserlessAPI/VortexPanel?style=for-the-badge&color=6c7fff">

<br><br>

<h1>⚡ VortexPanel</h1>

<p><strong>Free, open-source server control panel for Linux.</strong><br>
A self-hosted alternative to cPanel, Plesk, and aaPanel — WAF, Fail2Ban, Load Balancer, WP Toolkit, 2FA, and HTTPS for the panel itself, all built in and free, with no paid Pro tier.<br>
Built with Python/Flask + Alpine.js. No Node.js build step. No bloat. 2-minute install.</p>

<a href="#-quick-install"><img src="https://img.shields.io/badge/Quick_Install-1_command-6c7fff?style=for-the-badge" /></a>
<a href="https://github.com/BrowserlessAPI/VortexPanel/releases"><img src="https://img.shields.io/badge/Releases-Changelog-22c55e?style=for-the-badge" /></a>
<a href="https://github.com/BrowserlessAPI/VortexPanel/issues"><img src="https://img.shields.io/badge/Issues-Report_a_bug-ef4444?style=for-the-badge" /></a>

</div>

---

## 🆚 Why VortexPanel over cPanel / Plesk / aaPanel / HestiaCP?

| Feature | cPanel | Plesk | aaPanel Free | aaPanel Pro | HestiaCP | **VortexPanel** |
|---|---|---|---|---|---|---|
| **Price** | $30–$65/mo | $16–$46/mo | Free | Paid add-on | Free | **Free (MIT)** |
| **ModSecurity WAF** | Paid ext. | Paid ext. | ❌ | ✅ paid | Manual | **✅ Built-in, OWASP CRS v4** |
| **Fail2Ban** | Paid ext. | Built-in | ❌ | ✅ paid | ✅ | **✅ Built-in** |
| **Load Balancer** | ❌ | ❌ | ❌ | ✅ paid | ❌ | **✅ Built-in** |
| **WP Toolkit** | ❌ | Paid (Deluxe+) | ❌ | ❌ | ❌ | **✅ Built-in, free** |
| **Firewall (UFW + firewalld)** | ❌ | via ext. | UFW only | UFW only | UFW only | **✅ Both, native** |
| **Panel 2FA (TOTP)** | ✅ | ✅ | ✅ | ✅ | ❌ | **✅ Built-in** |
| **Panel HTTPS (self-hosted)** | ✅ | ✅ | ✅ | ✅ | ✅ | **✅ Custom port, never 443** |
| **Password hashing** | Unknown | Unknown | Unknown | Unknown | Unknown | **Argon2id (OWASP #1)** |
| **PHP Webshell Scanner** | ❌ | ❌ | ❌ | ❌ | ❌ | **✅ Built-in** |
| **Cloud Backup (S3)** | Paid | Paid ext. | ❌ | ✅ paid | Manual | **✅ Built-in** |
| **Docker UI** | ❌ | ❌ | ✅ | ✅ | ❌ | **✅ Built-in** |
| **RHEL/AlmaLinux/Rocky** | ✅ | ✅ | Partial | Partial | ❌ | **✅ 9 distros** |
| **Web Terminal** | ✅ | ✅ | ✅ | ✅ | ❌ | **✅ Built-in** |
| **Open source** | ❌ | ❌ | Partial | ❌ | ✅ | **✅ MIT** |

---

## ✨ Features

### 🌐 Website Management
- **Nginx, Apache2, OpenLiteSpeed, Caddy** — install and manage from the same panel
- **One-click SSL** via Let's Encrypt — auto-detects Cloudflare DNS-01 vs HTTP-01
- Reverse proxy, custom directives, PHP version per site, Composer integration
- One-click WordPress/Laravel/Symfony deploy
- PHP webshell scanner integrated with the File Manager

### 🔷 WP Toolkit
Full WordPress lifecycle management — install, manage, secure, stage, back up — no separate plugin or paid add-on:
- **Full install** in one click: downloads WP, creates DB, writes `wp-config.php`, runs the installer, creates the vhost, configures SSL — done
- **PHP 7.4 → 8.5**, **Nginx / Apache / OpenLiteSpeed / Caddy**, **MariaDB / MySQL** — pick any combination
- Plugin & theme management, one-click admin login (no password needed), bulk updates
- **Security scanner** — 9 checks with one-click auto-fix buttons
- **Staging clone** — full site clone with DB, push/pull between staging and live, auto-backup before push
- Backup/restore, maintenance mode, system cron, debug mode toggle
- Auto-generates non-default admin username + randomised table prefix on install (security by default)

### 🔒 Server Security
- **Firewall** — UFW (Debian/Ubuntu) **and** firewalld (Fedora/RHEL/AlmaLinux/Rocky/Oracle/CentOS/CloudLinux) from the same UI
- **Fail2ban** — intrusion prevention, brute-force protection
- **ModSecurity WAF** — OWASP CRS v4, 3-state engine (Blocking/Detection/Off), paranoia level 1–4, custom rule editor, audit log viewer, per-site override, weekly auto-update cron
- **SSH Hardening** — create sudo users, add SSH keys, disable root login, disable password auth, change port — all with built-in safety checks that block you from locking yourself out
- **Security Score** dashboard — SSH config, firewall (UFW or firewalld), Fail2ban, auto-updates, panel password strength, 2FA status, secret key — all in one glance

### 🛡 Panel Security *(hardened to OWASP standards)*
- **Argon2id password hashing** (OWASP's #1 recommendation) with transparent migration from legacy SHA-256/bcrypt — existing users never notice
- **2FA / TOTP** — QR-code setup with any authenticator app (Google Authenticator, Authy, 1Password), required on every login once enabled
- **Brute-force lockout** — 5 failed attempts → 15-minute lockout, persists across panel restarts
- **Panel HTTPS** — self-signed or Let's Encrypt, served on your **custom port** (never the well-known 443), so enabling HTTPS never makes the panel newly discoverable by a generic port scan
- **IP allowlist**, session timeout, login audit log, auto-generated 64-byte secret key, security headers (CSP, X-Frame-Options, HSTS-ready) on every response

### 🗄 Databases
- MySQL, MariaDB, PostgreSQL, MongoDB — multi-engine
- phpMyAdmin integration (auto-configured on its own port, separate PHP version)

### 📦 App Store
- 25+ one-click installs: Nginx, Apache, OpenLiteSpeed, Caddy, PHP (multi-version), MySQL, MariaDB, PostgreSQL, MongoDB, Redis, Docker, Node.js, Python, Composer, Fail2ban, ClamAV, ModSecurity, Roundcube, Supervisor, Pure-FTPd, BIND9 DNS, and more
- Automatic conflict detection, RHEL-family package manager support

### ⚙ Settings — redesigned card-based control center
- **Network & Access** — panel port (auto-updates firewall), custom domain, webroot
- **Panel SSL** — one-click self-signed or Let's Encrypt, validity countdown, automatic safe cutover (no downtime race conditions)
- **Authentication & Security** — 2FA, password, IP allowlist, session timeout, all at a glance
- **PHP Webshell Scanner** — pick a path, scan, get severity-coded results with file/line/snippet
- **Panel Settings** — auto-update, timezone, NTP sync, hostname, OS package updates
- **System Information** — OS, kernel, IP, uptime, version, all in one card

### ⚡ Performance
- Dashboard stats from `/proc` (not `top -bn1`) — **10× faster**
- Response caching for expensive endpoints, gzip compression on all responses
- `app.js` 150KB → ~40KB, `index.html` 350KB → ~70KB over the wire

### 🔧 Everything else
- **Docker** — container management, 45+ pre-configured image catalog
- **DNS** — BIND9 zone management + Cloudflare DDNS
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

**First things to do after install:** change the default password, enable 2FA, and enable Panel SSL — all from Settings.

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
| **Auth** | Session-based · Argon2id password hashing · TOTP 2FA |
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

- [ ] Disk usage analyzer (visual tree, delete from panel)
- [ ] Per-site website analytics (traffic, top URIs, status codes, bot detection)
- [ ] Alerting — CPU/RAM/SSL-expiry push to Telegram/Discord/email/webhook
- [ ] Multi-user / role-based access control
- [ ] Let's Encrypt auto-renewal cron
- [ ] Load balancer node health checks + TCP/stream load balancing

---

## 📄 License

MIT License — free to use, modify, and distribute, including commercially.

---

<div align="center">
  Made with ⚡ by <a href="https://github.com/BrowserlessAPI">BrowserlessAPI</a> · <a href="https://github.com/BrowserlessAPI/VortexPanel/releases">Releases</a> · <a href="https://github.com/BrowserlessAPI/VortexPanel/issues">Issues</a> · <a href="CONTRIBUTING.md">Contributing</a>
</div>
