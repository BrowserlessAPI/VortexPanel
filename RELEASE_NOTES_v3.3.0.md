# VortexPanel v3.3.0 — Visual Design, Multi-Webserver HTTP/3, Live Terminal, Mail & Bandwidth

**Release date:** June 2026

A broad quality-of-life release covering visual polish, long-standing bugs, and several features that were half-built in earlier versions and are now complete and properly tested.

---

## 🎨 Visual Design Overhaul

The dashboard and sidebar were reworked to feel intentional rather than generic.

- **Stat cards** — each of the four dashboard metric cards now has its own colour identity: CPU (blue), RAM (purple), Disk (amber), Uptime (green). Each card has a left accent bar, a tinted progress bar, a coloured metric value, and a ghost emoji icon. The old design used a single cyan colour across all four.
- **Sidebar icon pills** — every nav item now has a small coloured pill behind its icon (unique colour per section). Active item switches to blue with a filled pill, matching the style used by aaPanel and modern control panels.
- **Active nav colour** — changed from cyan (`#0e7490`) to blue (`#2563eb`) for stronger contrast.
- **Semantic stat colour variables** — `--stat-cpu`, `--stat-ram`, `--stat-disk`, `--stat-uptime` added to `theme.css` for consistent use across the panel.
- **App Store settings sidebar** — the floating settings window tabs now use the same coloured icon pill pattern as the main sidebar, replacing the previous plain text-only tabs.

---

## ⚡ HTTP/3 — Full Multi-Webserver Support

The previous HTTP/3 toggle only worked on nginx and showed a static "go install it yourself" warning for everything else. It now handles all four supported webservers correctly:

- **nginx (nginx.org official package, 1.25+):** Enable/Disable toggle. Writes `listen 443 quic reuseport` and `Alt-Svc` header. Automatically opens UDP 443 in UFW or firewalld.
- **nginx (distro package, 1.25+):** Detects that the package lacks `--with-http_v3_module`. Shows a one-click **"Upgrade to nginx.org Mainline"** button that installs the official package, preserving all existing vhost configs.
- **nginx (< 1.25):** Clear error message — too old, no upgrade path within the distro.
- **Caddy:** Shows "Always On" — Caddy enables HTTP/3 automatically when SSL is active. Panel checks and opens UDP 443 if needed.
- **OpenLiteSpeed:** Same as Caddy — HTTP/3 is default-on. Panel ensures UDP 443 is open.
- **Apache:** Clear "Not Supported" message explaining why and suggesting switching to nginx or Caddy.
- **UDP 443 firewall** — opening UDP 443 is now done automatically on enable for all supported webservers across UFW (Debian/Ubuntu) and firewalld (RHEL/Fedora/Alma/Rocky).

---

## 🔧 Bug Fixes — SyntaxWarnings in modules.py

Seven invalid escape sequences in `modules.py` that would break on strict Python builds (Python 3.12+ raises `SyntaxWarning`, future versions will error):

- Lines 368, 405, 421: `\.`, `\s`, `\K` in regular strings → raw strings (`r'''...'''`)
- Lines 1065, 1217, 1405: `\s`, `\K`, `\S` in f-strings → raw f-strings (`rf"..."`)

---

## 🔄 Session Persistence — Survives Restarts

**Root cause:** Flask's default client-side signed cookie sessions are invalidated when gunicorn restarts, because each worker independently generates a secret key if the file doesn't exist yet — causing a race condition where workers end up with different keys in memory.

**Fix:** Enabled `flask-session` (already in `requirements.txt` but never activated) with `SESSION_TYPE = 'filesystem'`. Session data is now stored as files in `/opt/vortexpanel/sessions/`. The session cookie holds only a signed session ID. Sessions survive gunicorn restarts, nginx reloads, and worker recycling. Sessions can be individually invalidated server-side on logout.

---

## 📊 Live Installation Terminal — All App Store Actions

The App Store previously showed no progress when switching versions — the button would appear to do nothing for several minutes, then either succeed or fail with no output.

**Root cause chain (three separate bugs):**
1. `switch_version` used blocking `sh()` calls with no output streaming
2. Jobs were stored in an in-memory dict (`_jobs = {}`), but gunicorn runs with `--workers 4` — each worker has its own memory space, so the SSE stream (potentially on worker 2) couldn't see jobs created on worker 1
3. The SSE stream opened before the job file was created, immediately got "Job not found", and closed silently — leaving the terminal blank forever

**Fix:** Full rewrite of the job system:
- All three actions (install, uninstall, switch version) now use the same SSE streaming pipeline
- Jobs stored as JSONL files in `/tmp/vortex_jobs/` — append-only, shared across all workers via the filesystem
- SSE stream waits up to 5 seconds for the job file to appear before giving up
- subprocess output streams line-by-line in real time via `Popen` with `bufsize=1`
- 8-minute process timeout kills hung operations (e.g. `apt-get update` waiting on a slow mirror)
- `apt-get` network timeout set to 30 seconds per mirror on all switch scripts

**Terminal colours:** All output lines now have explicit hex colours so they're readable on the black terminal background: regular apt output (`#d1fae5`), info lines (`#67e8f9` cyan), success (`#4ade80` green bold), warnings (`#fbbf24` amber bold).

---

## 🗄 MariaDB — Settings & Versions Fixed

- **Optimization tab was blank** — `save_module_settings()` never defined `mod`, causing a `NameError` in the `run_switch` closure. Added `mod = _get_mod(mod_id)` at the top of the handler.
- **MariaDB settings response missing fields** — the GET handler returned `status`, `version`, `conf_path`, `conf_content`, `logs`, `port` but was missing `optimization`, `current_status`, `slow_log`, `log_path`, `datadir`. All fields now match the MySQL handler.
- **`save_optimization` had no MariaDB handler** — nginx, Apache, and OLS had handlers; MySQL/MariaDB fell through silently. Now reads the correct `.cnf` path per distro, updates existing keys with regex, appends new keys under `[mysqld]` if missing, then restarts the service.
- **Versions updated:** Added MariaDB 12.3.2 (Latest), 11.8.8, keeping 11.4 LTS, 10.11 LTS, 10.6 LTS. Previous list was missing the entire 12.x series.

---

## 🔒 Database Version Switching — Removed (Uninstall-First Approach)

Following aaPanel's approach: switching a running database engine version in-place risks data corruption, especially on downgrades. The "Switch Version" tab has been removed from MariaDB, MySQL, PostgreSQL, and MongoDB settings modals.

The safe workflow is: **Uninstall → Install new version from App Store**. Version switching remains available for non-database modules (Redis, nginx, Apache, OLS, Caddy, Node.js, BIND9, pure-ftpd).

---

## 🌐 Two-Webserver Conflict Detection

If two webservers (e.g. nginx + apache2) are both `active` simultaneously — causing port 80/443 conflicts and unpredictable routing — the dashboard now shows a red warning banner with a "Fix Now →" button linking directly to Services. Detection runs in parallel with the existing CPU/disk/services poll on every dashboard stats request.

---

## 📧 Mail — Forwarding & Logs Completed

- **Forwarding tab** previously broke silently because `selDomain` was only set when the user clicked a domain in the Mailboxes tab. The Forwarding tab now has its own domain selector dropdown, independent of the Mailboxes tab.
- **Mail logs** now support: line count selector (100/300/500), log type filter (All/Postfix/Dovecot), real-time client-side search/filter, RHEL log path (`/var/log/maillog`) with `journalctl` fallback, configurable via `?lines=` query param.

---

## 🟢 Node.js — Versions Corrected, Switch Bug Fixed

- **EOL versions removed:** v18 (EOL Oct 2023) and v20 (EOL Apr 2026) removed from all version lists.
- **Default install updated:** Was `setup_20.x` (EOL). Now `setup_24.x` (Active LTS).
- **Active LTS labelled correctly:** v24 "Krypton" is Active LTS; v22 "Jod" is Maintenance LTS; v26 is Current (non-LTS until Oct 2026).
- **Switch version bug fixed:** Switching from v26 to v24 previously installed v26 again because the old nodesource repo was still active and apt resolved to v26. Fix: old nodesource repo, list, and GPG keys are removed before the new version's setup script runs.
- **`nodejs_install_script()` default** in `os_utils.py` updated from `'22'` → `'24'`.

---

## 🚀 nginx Install — UDP 443 + Stream Block

`nginx_install_script()` in `os_utils.py` now runs two post-install steps automatically:

- **`stream {}` block** added to `/etc/nginx/nginx.conf` if missing (required for TCP load balancing to work at all — was causing silent failure on fresh installs).
- **UDP 443** opened in UFW (Debian/Ubuntu) and firewalld (RHEL/Fedora/Alma/Rocky) — required for HTTP/3 QUIC. Idempotent; safe to run if firewall is not active.

---

## 🔌 nginx Stream Module — Auto-Install All 9 Distros

The TCP Load Balancer previously showed a static warning telling users to run `apt install libnginx-mod-stream` manually. It now installs automatically:

- **Debian/Ubuntu:** `apt install libnginx-mod-stream`, with retry after `apt update` if first attempt fails.
- **RHEL/Fedora/AlmaLinux/Rocky/CentOS:** Checks if `.so` already exists (nginx.org packages bundle it). Falls back to `dnf install nginx-mod-stream` if not found.
- After install: ensures `load_module` directive exists in `nginx.conf`, runs `nginx -t`, reloads nginx.
- Detects Debian's auto-created `modules-enabled/50-mod-stream.conf` symlink and skips manual injection when present.
- Compatible with nginx 1.24 through 1.31.x.

---

## Upgrading

```bash
cd /root/Vortexpanel
git pull
cp -r panel/ web/ app.py /opt/vortexpanel/
mkdir -p /opt/vortexpanel/sessions
systemctl restart vortexpanel
```

Or fresh install:
```bash
wget -O install.sh https://raw.githubusercontent.com/BrowserlessAPI/VortexPanel/main/install.sh && bash install.sh
```

---

## What's Next (v3.4 Roadmap)

- **Bandwidth Monitor** — per-domain traffic graphs (daily/weekly/monthly) with vnstat integration
- **Website-level Backup** — per-domain backup of files + database together in one click
- **Dark mode** — CSS variable system is ready; just needs a toggle and dark variable set
- **Onboarding wizard** — guided first-run flow for new installations
- **Mobile responsiveness** — sidebar and layout improvements for small screens
- **PHP Webshell Scanner** — scan web roots for obfuscated PHP shells
