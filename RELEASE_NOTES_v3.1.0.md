# VortexPanel v3.1.0 — WP Toolkit, firewalld, Performance

**Release date:** June 2026

This is a large release. The headline addition is the **WP Toolkit** — a full WordPress management module with a better UI than aaPanel's, built entirely free with no Pro tier required. There are also critical bug fixes that affected every fresh install via `install.sh`.

---

## 🔷 New: WP Toolkit

Full WordPress lifecycle management — install, manage, secure, stage, back up — without needing a separate plugin or paid add-on.

### Install
- One-command WordPress install: downloads core, creates DB, writes `wp-config.php`, runs the installer, creates the vhost, sets file ownership, configures SSL, and enables system cron — all in one click
- **PHP 7.4 → 8.5** support with automatic FPM socket detection across all distros
- **Nginx, Apache, OpenLiteSpeed, Caddy** — correct vhost template per webserver including permalink rewrite rules
- **MariaDB and MySQL** — auto-detected
- Auto-generates a non-default admin username and randomised table prefix (security defaults)
- Detects which webservers are actually installed — warns and blocks if you select one that isn't

### Manage
- Site cards grid: WP version, PHP badge, SSL status, plugin/theme counts, update count
- Slide-in drawer with 7 tabs: Overview, Plugins, Themes, Security, Staging, Backups, Settings
- One-click admin login (wp-cli `user session create` → auto-login URL, no password needed)
- Plugin management: list, activate, deactivate, update, delete, bulk update all
- Theme management: list, activate, update, delete
- Core update with database migration

### Security scanner
- 9-point scan: admin username strength, file permissions, WP version, SSL, debug mode, XML-RPC exposure, wp-config.php HTTP access, plugin versions, login URL exposure
- A/B/C grade with score (0–100)
- **One-click fix buttons** for every failed check

### Staging
- Full site clone (rsync files + DB export/import + URL search-replace)
- Creates a vhost for the staging domain automatically
- Push staging → live: auto-creates a backup of live first, then syncs files + DB + URL rewrite
- Pull live → staging

### More
- Backup/restore: `tar.gz` of files + DB dump
- Settings: site title, email, password reset, language, PHP version switch, debug mode, maintenance mode, search engine visibility, system cron
- wp-cli auto-installed if not present

---

## 🔥 New: firewalld support (Fedora / RHEL / AlmaLinux / Rocky / Oracle / CentOS / CloudLinux)

The Firewall module previously only supported UFW (Debian/Ubuntu). Every RHEL-family distro uses firewalld, so the Firewall page showed inactive/empty and all actions silently no-op'd on those systems.

Now fully supported on both:
- **UFW path** (Debian/Ubuntu): unchanged
- **firewalld path** (Fedora/RHEL-family): `--list-ports`, `--list-services`, `--list-rich-rules` merged into a unified numbered list; `--add-port` for simple allow rules, `--add-rich-rule` for deny/reject/source-restricted rules; presets (webserver, mailserver, database) via rich rules; toggle enable/disable via `systemctl`

Also fixed on **all distros**: the frontend sent `protocol` but the backend read `proto` — UDP rules silently became TCP. Now fixed in both UFW and firewalld paths.

---

## 🐛 Critical bug fixes

### `app.py` — gunicorn entrypoint crash-loop on every fresh install
`app = create_app()` was only defined inside `if __name__ == '__main__'`. The systemd service created by `install.sh` runs `gunicorn ... app:app`, which *imports* the module — that block never executed. Every fresh install via `install.sh` produced a crash-looping service that would never start. Fixed by defining `app = create_app()` at module level.

### Pages not loading after login (browser refresh required)
All page components (`x-data="websitesPage()"` etc.) were initialised by Alpine.js at page load time — before login — so every `init()` hit 401 and stored empty data, which was never re-fetched after login. Added `document.addEventListener('vortex-logged-in', ...)` to all 22 page component `init()` functions. `_onLoggedIn()` already dispatched this event; now every page listens for it.

### Dashboard Disk card showing blank / wrong bar width
`ramPct()` and `diskPct()` were called in the Dashboard template as methods but never defined in `dashboardPage()`. Alpine threw a silent ReferenceError, leaving the Disk card value empty and the bar fill defaulting to nearly-full regardless of actual usage.

### `dashboard/stats` — 10× performance improvement
Replaced `top -bn1` (800–1500ms per request, waits for a CPU measurement cycle) with `/proc/stat` 100ms sample. RAM, load, uptime, and network now read from `/proc` (instant). Services detection changed from 8 sequential `systemctl is-active` calls to one batch call. Added 1.5s TTL cache. Total dashboard stats response: ~103ms (was ~1000ms).

### `security.py` — two 500 Internal Server Errors
- `GET /api/security/modsecurity`: `sh()` returns a 3-tuple in this file but `rules_count` was assigned the whole tuple and passed to `int()` — TypeError
- `PUT /api/security/loadbalancer`: same issue — tuple assigned to variable then `.lower()` called on it — AttributeError

### Load Balancer config corruption bug
The server-parsing regex also matched the virtual host's `server {` block declaration, adding a phantom `{address:'{'}` upstream entry. On re-save this wrote `server { weight=1;` into the nginx config *before* testing it — if `nginx -t` failed, the broken config stayed on disk. A future server restart would break nginx (all sites down). Fixed regex + made saves atomic (backup existing config, write new, test, rollback on failure).

### phpMyAdmin `php_version` save always failing
phpMyAdmin's PHP-version dropdown checked `/usr/bin/php{v}` (CLI binary), but only `php{v}-fpm` may be installed — leaving the dropdown empty, `currentPhp=''`, and Save always failing with "Config not found or PHP version missing". Fixed to check `/run/php/php{v}-fpm.sock` instead.

### PHP 8.5 FPM socket permission denied (502 Bad Gateway)
`php_install_script()` in `os_utils.py` never aligned new PHP-FPM pool `listen.owner`/`listen.group` with nginx's actual worker user. Package defaults (`www-data` on Debian) didn't match a server running nginx as user `nginx`, causing 502 for every site on that PHP version. Fixed for both Debian and RHEL-family.

### phpMyAdmin link opening on localhost
Databases page button hardcoded `href="http://localhost:8082"` — clicking from a browser opened port 8082 on the user's own machine, not the VPS. Fixed to use `location.hostname`.

### `bandwidth.py` — vnstat install broken on RHEL-family
`/api/bandwidth/install-vnstat` hardcoded `apt-get install -y vnstat`, non-functional on all RHEL-family distros. Fixed to use `pkg_install()` + EPEL enablement.

### Roundcube PHP version switcher never worked
Frontend posted `{action:'set_php'}` but `save_module_settings()` had no `set_php` handler — always returned `Unknown action`. Added the missing handler.

### DDNS Manager Uninstall button
DDNS Manager's `check` command is `echo found` (it's a built-in feature). The Uninstall button ran `apt-get remove ddclient` (unrelated package) and the check still reported "found" — appearing as if uninstall silently failed. Added `builtin:True` flag, threaded through the API, hidden the Uninstall button for built-in modules.

### Websites refactor (`websites.py` 1266-line → 8 modules)
Split monolithic `websites.py` into 8 focused modules. Added `ensure_web_ownership()` in `websites_core.py` to fix wp-config.php write-permission failures on new site creation.

---

## ⚡ Performance & UX

- **Gzip compression** via Flask-Compress: `app.js` 150KB → ~40KB, `index.html` 350KB → ~70KB over the wire
- **`/api/modules` response cached** (30s TTL) — App Store page loads instantly on revisit; cache invalidated on install/uninstall
- **Modal positioning fixed** — WP Toolkit and other modals now use `.modal-overlay` CSS class instead of inline `position:fixed`, which was getting trapped by Alpine's stacking context
- **Dashboard services list expanded** — now includes all PHP-FPM versions, fail2ban, supervisor

---

## Upgrading

```bash
cd /your/vortexpanel/source
git pull
cp -r panel/ web/ app.py /opt/vortexpanel/
pip install -r requirements.txt  # adds flask-compress
systemctl restart vortexpanel
```

Or fresh install:
```bash
wget -O install.sh https://raw.githubusercontent.com/BrowserlessAPI/VortexPanel/main/install.sh && bash install.sh
```

---

## What's next (v3.2 roadmap)

- Per-site website analytics (nginx access log → traffic/top-URIs/status-codes dashboard)
- Alerting — CPU/RAM/SSL-expiry push notifications (Telegram/Discord/email/webhook)
- Disk usage analyzer
- Multi-user / RBAC
- LB node health checks
