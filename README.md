<div align="center">

<img src="https://img.shields.io/badge/VortexPanel-v3.9.0-6c7fff?style=for-the-badge&logo=lightning&logoColor=white" alt="VortexPanel v3.9.0">
<img src="https://img.shields.io/badge/Python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white">
<img src="https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask">
<img src="https://img.shields.io/badge/Alpine.js-3.15-8bc0d0?style=for-the-badge">
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
| **Panel 2FA (TOTP)** | ✅ | ✅ | ✅ | ✅ | ❌ | **✅ Built-in, with backup codes** |
| **Multi-user with roles** | ✅ | ✅ | ❌ | ✅ paid | ✅ | **✅ Admin / Site manager / Viewer** |
| **API keys** | ✅ | ✅ | ✅ | ✅ | ✅ | **✅ Role + IP allowlist** |
| **Alerts (email, Telegram, webhook)** | ✅ | ✅ | ✅ | ✅ | ❌ | **✅ Built-in** |
| **Signed, verified updates** | ✅ | ✅ | ❌ | ❌ | ❌ | **✅ git verify-tag + auto rollback** |
| **Panel HTTPS (self-hosted)** | ✅ | ✅ | ✅ | ✅ | ✅ | **✅ Custom port, never 443** |
| **Password hashing** | Unknown | Unknown | Unknown | Unknown | Unknown | **Argon2id (OWASP #1)** |
| **PHP Webshell Scanner** | ❌ | ❌ | ❌ | ❌ | ❌ | **✅ Built-in** |
| **Cloud Backup** | Paid | Paid ext. | ❌ | ✅ paid | Manual | **✅ S3, FTP, Google Drive, OneDrive, Dropbox, SFTP** |
| **Docker UI** | ❌ | ❌ | ✅ | ✅ | ❌ | **✅ Built-in** |
| **RHEL/AlmaLinux/Rocky** | ✅ | ✅ | Partial | Partial | ❌ | **✅ 9 distros** |
| **Web Terminal** | ✅ | ✅ | ✅ | ✅ | ❌ | **✅ Built-in** |
| **Go/Node.js app hosting** | ❌ | ❌ | ❌ | ❌ | ❌ | **✅ Built-in, one-click** |
| **Import from cPanel/aaPanel/Hestia** | ❌ | ❌ | ❌ | ❌ | ❌ | **✅ Built-in wizard** |
| **Open source** | ❌ | ❌ | Partial | ❌ | ✅ | **✅ MIT** |

---

## ✨ Features

### 🌐 Website Management
- **Nginx, Apache2, OpenLiteSpeed, Caddy** — install and manage from the same panel
- **One-click SSL** via Let's Encrypt — auto-detects Cloudflare DNS-01 vs HTTP-01
- **SSL through DNS-provider APIs** (DNS-01) for 17 providers and this server's own DNS, including **wildcard** certificates
- **Maintenance mode for all websites** with one switch and an IP allow list
- Reverse proxy, custom directives, PHP version per site, Composer integration
- One-click WordPress/Laravel/Symfony deploy
- PHP webshell scanner integrated with the File Manager
- **Per-site disk usage** (lazy-loaded, won't slow down servers with many/large sites)
- **Site statistics** — page views, unique visitors, bots, top pages, referrers, browsers and status codes per site, from the access logs
- **Git deploy** per site — deploy key, branch, signed GitHub/GitLab webhook, post-deploy command run as the site owner; the repository is kept outside the web root
- **Site clone** — copy a site (files, database, WordPress URLs) to a new domain in one step
- **Global SSL expiry alerts** on the Dashboard, aggregated across every site

### 🔵 Go, Node.js and Python Projects
Deploy compiled Go binaries and Node.js apps with the same one-click simplicity as WordPress — a capability none of cPanel, Plesk, aaPanel, or HestiaCP offer out of the box:
- **Go**: binary-only deployment, Go SDK manager (multiple versions side by side), GOPROXY config, systemd auto-restart, resource limits (`MemoryMax`/`CPUQuota`), on-demand TCP health checks, binary version history with one-click rollback
- **Node.js**: PM2 or systemd per project, nvm-based version switching, current LTS reality (v24 Active, v22 Maintenance, v18/v20 correctly blocked as EOL)
- **Python**: virtualenv per project, Gunicorn / Uvicorn / custom command, runs as a normal user under systemd, Git clone and pull, Python versions from the App Store
- All: reverse proxy on all 4 webservers with **WebSocket support**, Let's Encrypt SSL per domain, firewall integration, all 9 supported distros

### 📥 Website Import Wizard
Migrate a site off cPanel, aaPanel, HestiaCP or CyberPanel by uploading its backup archive — no SSH pull required:
- **Detect → confirm → import** flow — every auto-detected field (domain, PHP version, document root, database) is editable before anything executes
- Imported sites use the exact same code path as "New Website", so they're indistinguishable from natively-created ones
- Fresh random database password generated on import (originals are never in a backup dump)
- **Files, databases, SSL certificate, cron jobs and mailboxes** — the certificate is installed only when its key matches and it has not expired, cron jobs run as the web user with old account paths pointed at the new site, and mailboxes keep their passwords where the backup has the hash
- HestiaCP `.tar.zst` backups are supported when `zstd` is installed

### Server-to-Server Migration
- Move websites, MySQL/MariaDB and PostgreSQL databases (users and passwords included), SSL certificates and cron jobs to another VortexPanel server with a one-time migration key
- The old server keeps serving during the copy; "Sync again" refreshes the copy right before the DNS change; encrypted end to end, also over plain HTTP

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
- **Malware scan** — webshell signatures, PHP in upload folders and ClamAV; quarantine with restore, "not a threat" list, daily or weekly schedule
- **SSH sign-ins** — accepted and failed logins, top attacking addresses with one-click block, alert on a new sign-in
- **Bot protection (Anubis)** — per-website browser check against AI scrapers and bad bots; search engines (verified by their published addresses), sitemaps, feeds and ads.txt are never checked; separate switches for AI training and AI search crawlers; nightly search engine test and a watchdog that fails open; available to hosting customers per package
- **Security Score** dashboard — SSH config, firewall (UFW or firewalld), Fail2ban, auto-updates, panel password strength, 2FA status, secret key — all in one glance

### 🛡 Panel Security *(hardened to OWASP standards)*
- **Secure from the first minute**: a new install gets a random port, a random login path (every other address answers 404), a random admin username and password, and HTTPS
- **Argon2id password hashing** (OWASP's #1 recommendation) with transparent migration from legacy SHA-256/bcrypt — existing users never notice
- **2FA / TOTP** with single-use codes and 10 backup codes, QR code drawn in the browser
- **Brute-force lockout** per address and per account, persists across panel restarts
- **Accounts with roles** (Administrator, Site manager limited to assigned websites, Viewer) and **API keys** with role, IP allowlist and expiry
- **Signed updates**: releases are verified with `git verify-tag` before they are installed; code and Python packages are snapshotted and restored automatically if the new version does not start
- **Panel HTTPS** — self-signed or Let's Encrypt (domain or **IP address**) on your **custom port**; correct Secure cookie and HSTS behind a TLS reverse proxy
- **IP allowlist**, panel domain binding, session timeout, login audit log, security headers (CSP, HSTS, X-Frame-Options) on every response
- **`vortexpanel` command** for recovery: reset password, disable 2FA, change port or login path, clear the IP allowlist, unlock, update, rollback

### 🗄 Databases
- MySQL, MariaDB, PostgreSQL, MongoDB — multi-engine
- **Recycle bin** — a deleted database is kept as a dump for 7 days and can be restored
- phpMyAdmin integration (auto-configured on its own port, separate PHP version)

### 📦 App Store
- **27** one-click installs: Nginx, Apache, OpenLiteSpeed, Caddy, PHP (multi-version), MySQL, MariaDB, PostgreSQL, MongoDB, Redis, **Memcached**, **FFmpeg** (multi-version, side by side), Docker, Node.js, Python, Composer, Fail2ban, ClamAV, ModSecurity, Roundcube, Supervisor, Pure-FTPd, BIND9 DNS, and more
- **Live installation terminal** — every install, uninstall, and version switch streams real-time output line-by-line (like aaPanel's task terminal)
- Automatic conflict detection, RHEL-family package manager support — **all 5 previously-broken RHEL install paths (nginx, MySQL, Caddy, MongoDB, PostgreSQL) fixed**, tested on both x86_64 and arm64
- **Safe database version policy** — databases (MariaDB/MySQL/PostgreSQL/MongoDB) require uninstall-first to prevent data corruption; version switching kept for non-data modules

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
- **Docker** — container management, 45+ pre-configured image catalog, **domain assignment + automatic SSL** (reuses the same reverse-proxy code as Go/Node.js Projects, no Traefik needed)
- **DNS** — BIND9 zone management + Cloudflare DDNS
- **Mail** — Postfix + Dovecot, domains, accounts, Roundcube webmail
- **CDN** — Cloudflare, BunnyCDN, Akamai, CloudFront, KeyCDN
- **Monitoring & Dashboard** — realtime CPU/RAM/Network charts, **history from 1 hour to 90 days**, process list, bandwidth, login audit log viewer
- **Alerts** — email, Telegram or webhook (Slack, Discord) for high CPU/memory/disk, stopped services, websites that are down, expiring SSL, failed backups and sign-in attacks
- **File Manager** — code editor with edit history, recycle bin, owner and permission changes, download from URL, AES-encrypted zip support, ClamAV scan
- **Web Terminal** — full PTY shell in browser over WebSocket
- **Website Backups** — each site's files and databases in one archive, one-click restore, per-site schedules (every few hours / daily / weekly / monthly) with retention, copies to S3, FTP/FTPS or (with rclone) Google Drive, OneDrive, Dropbox, SFTP
- **Panel backup** — accounts, settings and keys in one archive, daily schedule, restore on a reinstalled server
- **Website Security & Limits** — force HTTPS, HSTS, HTTP/2, blocked paths, speed and connection limits, site expiry date
- **Language packs** — English, Simplified Chinese, Spanish, Portuguese (Brazil), German, French, Russian
- **Bandwidth** — per-website traffic history (24 hours / 7 / 30 days / 12 months) from the access logs, plus live interface traffic
- **Disk Usage analyzer** — scan a disk, drill into folders, see the largest files, open them in the File Manager or delete them (system and database folders are protected)
- **Dark mode** (Light / Dark / follow the system) and a **mobile layout** with a slide-in menu
- **Setup guide** — first-run wizard for the web stack, security basics and the first website
- **Cron Jobs** — visual scheduler, 10 task types, run-now, logs
- **AI Assistant** — configurable OpenAI-compatible API (NeonCodex, OpenAI, etc.)
- **Global search** (Ctrl+K) — pages, websites, apps and projects
- **Hosting Module** (paid add-on) — cPanel-style shared hosting: customer accounts with packages and limits, a separate customer portal, per-account PHP-FPM pools and private nameservers. Buy it on the panel's Hosting Module page; the licence is activated and the module installed by itself
- **Plugins** — add-ons such as the Hosting Module live in `/opt/vortexpanel/plugins`, never replace panel files and are skipped (not fatal) when they fail to load; `vortexpanel plugins` and a safe mode for recovery

---

## 🚀 Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/BrowserlessAPI/VortexPanel/main/install.sh -o install.sh && sudo bash install.sh
```
(or `wget -O install.sh https://raw.githubusercontent.com/BrowserlessAPI/VortexPanel/main/install.sh && sudo bash install.sh`)

The installer installs the newest signed release and prints everything you need, for example:

```
VortexPanel v3.7.0  (active)
  Address:   https://203.0.113.10:23817/k4m9q2xd
  Username:  hq7tmc2e
  Password:  ...
```

The port, the login path at the end of the address and the username are random, and the panel uses HTTPS with a self-signed certificate (your browser warns once; add a domain and a Let's Encrypt certificate in Settings > Panel SSL to remove the warning). Choose your own with `--port 8888`, `--path off`, `--user admin`, `--http` or install a specific release with `--version v3.7.0`.

Lost the address or the password? On the server, run `vortexpanel` (shows the address and username) or `vortexpanel reset-password`. `vortexpanel --help` lists every command.

The installer auto-detects your OS and package manager. On RHEL 8-family systems (AlmaLinux 8 / Rocky 8, where default Python is 3.6) it automatically installs Python 3.11.

**First things to do after install:** the setup guide opens on first login (web stack, firewall, fail2ban, first website). Then enable 2FA (Settings > Security) and set up Alerts.

### Updating

Use Settings > Panel Update (or `vortexpanel update`). Only signed release tags are installed; the previous version is restored automatically if the new one does not start, and `vortexpanel rollback` goes back by hand.

### API

Create a key in Users & API and send it as a bearer token:

```bash
curl -k -H "Authorization: Bearer vp_xxxxxxxx_..." https://YOUR-SERVER:PORT/api/dashboard/stats
```

Viewer keys can read monitoring and status; administrator keys can call every `/api/` endpoint the panel itself uses.

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
| **Frontend** | Alpine.js 3.15 · Vanilla CSS (no build step, no npm) · all JS deps self-hosted (no third-party CDNs) |
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
python3 app.py   # development server on :8888
```

---

## 🗺 Roadmap

**v3.4 — shipped:**
- [x] Go Projects — binary deployment, Go SDK manager, WebSocket proxy, Let's Encrypt per-domain, resource limits, health checks, version rollback
- [x] Node.js Projects — PM2 + systemd, nvm version switching
- [x] Website Import wizard — cPanel, aaPanel, HestiaCP backup upload (files + database)
- [x] FFmpeg Manager — multi-version side-by-side install (7.1/8.1/nightly), x86_64 + arm64
- [x] Memcached — full Service/Config/Switch Version/Load Status/Optimization management
- [x] Docker container domain assignment + automatic SSL (no Traefik)
- [x] Dashboard realtime CPU/RAM/Network charts, global SSL expiry alerts
- [x] Settings → Login audit log viewer
- [x] Per-site disk usage
- [x] RHEL-family install fixes — nginx, MySQL, Caddy, MongoDB, PostgreSQL now install correctly on RHEL/CentOS/Fedora/AlmaLinux/Rocky
- [x] arm64 fixes — MongoDB and PostgreSQL RHEL install paths
- [x] Modal/layout system overhaul — centering, horizontal scrollbar, cross-component scoping bugs

**v3.4.5 — reliability & security hardening:** full functional test pass of Mail, DNS, Cron, Fail2ban, ModSecurity, UFW and Docker; honest WP Toolkit install checks; self-hosted frontend dependencies; tighter Content-Security-Policy.

**v3.5.x — shipped:**
- [x] App Store install/uninstall reliability (package-lock waiting, visible errors, no stuck job windows)
- [x] Websites on every web server (Nginx, Apache, OpenLiteSpeed, Caddy), WAF 2.0 screen, multi-distro and SELinux support
- [x] Full audit of every route, page and App Store app (v3.5.3)
- [x] PHP Webshell Scanner

**v3.6.0:** bandwidth monitor, website backups with schedules and cloud upload, dark mode, setup guide, mobile layout, disk usage analyzer, import of SSL/cron/email, Mail Server in the App Store.

**v3.7.0:**
- [x] Secure install defaults (random port, login path, username; HTTPS) and the `vortexpanel` command
- [x] Signed release updates with package snapshots and automatic rollback
- [x] 2FA backup codes, single-use codes, per-account lockout
- [x] Multi-user accounts with roles, API keys
- [x] Alerts (email, Telegram, webhook) and monitoring history
- [x] Backup destinations: FTP/FTPS, Google Drive, OneDrive, Dropbox, SFTP (rclone); panel backup
- [x] Website Security & Limits (force HTTPS, HSTS, HTTP/2, blocked paths, rate and connection limits, expiry)
- [x] File manager recycle bin, edit history, owner change, download from URL; FTP disable, quota, log
- [x] Live App Store version data and distribution-package fallbacks
- [x] Language packs

**v3.9.0 (current):**
- [x] Mail: Rspamd spam filter with Junk folder, autoresponders, daily sending limits, SPF/DKIM/DMARC records for new mail domains
- [x] One-click Deploy installs WordPress, Drupal, Joomla, OpenCart and Laravel completely
- [x] ionCube Loader; API key role for WHMCS provisioning (Hosting Module 3.2)

**v3.8.1:** update fix for panels on 3.6.0 and older; Hosting Module pages appear right after buying

**v3.8.0:**
- [x] Python projects, Git deploy per site, site clone, site statistics
- [x] Malware scan with quarantine, SSH sign-in log and alerts, database recycle bin, global search
- [x] Plugin system (Hosting Module 3 is a plugin), private nameservers for new DNS zones
- [x] Layout fixes across the panel (Alpine 3.15 bindings, phone tables, settings windows)

**Next:**
- [ ] Coraza WAF installer for Caddy
- [ ] Site manager access to their own databases
- [ ] Two-way file sync between servers

---

## 📄 License

MIT License — free to use, modify, and distribute, including commercially.

---

<div align="center">
  Made with ⚡ by <a href="https://github.com/BrowserlessAPI">BrowserlessAPI</a> · <a href="https://github.com/BrowserlessAPI/VortexPanel/releases">Releases</a> · <a href="https://github.com/BrowserlessAPI/VortexPanel/issues">Issues</a> · <a href="CONTRIBUTING.md">Contributing</a>
</div>
