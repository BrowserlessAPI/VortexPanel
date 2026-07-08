# VortexPanel v3.4.0 — Go/Node.js Project Manager, FFmpeg & Memcached, Website Import, Nine-Distro Reliability

**Release date:** July 2026

The biggest release since v3.2.0's security overhaul. Two entirely new deployment managers (Go and Node.js binary/app hosting — something none of cPanel, Plesk, aaPanel, or HestiaCP offer out of the box), a full Website Import wizard for migrating off other panels, two new App Store modules, and a broad reliability pass across all nine supported distros and both x86_64/arm64 architectures.

---

## 🚀 Go Projects & Node.js Projects — New Deployment Managers

VortexPanel can now host compiled Go binaries and Node.js applications directly, with the same one-click simplicity as a WordPress install.

### Go Projects
- **Binary-only deployment** — point at a compiled Go binary, VortexPanel handles the rest
- **Go SDK manager** — install/switch between multiple Go versions side by side, GOPROXY configuration (official/goproxy.io/goproxy.cn/direct)
- **systemd service** — auto-restart on crash, enable-on-boot, journal logging
- **Reverse proxy on all 4 webservers** — nginx, Apache, OpenLiteSpeed, and Caddy, auto-detected
- **WebSocket support** — proper `Upgrade`/`Connection` header handling on nginx and Apache (needed for `gorilla/websocket`, gRPC-Web, etc.) — the shared nginx `$connection_upgrade` map is written once and reused across every proxied project
- **Let's Encrypt SSL per domain** — nginx/Apache use certbot's native plugin, OpenLiteSpeed uses `certonly` + manual vhost wiring, Caddy is detected as already-automatic (no action needed)
- **Resource limits** — `MemoryMax` / `CPUQuota` in the systemd unit, so a runaway process gets capped instead of taking down the whole server
- **On-demand health checks** — real TCP connect to the app's port, catching the case `Restart=always` can't: a hung process still holding the port open
- **Binary version history + rollback** — every start/restart snapshots the binary (skipped if unchanged, via SHA-256 hash), keeps the last 5 versions, one-click revert
- Firewall integration (UFW + firewalld), all 9 supported distros

### Node.js Projects
- **PM2 + systemd** — choose either process manager per project
- **nvm-based version switching** — install and switch Node versions without affecting other projects
- Same reverse-proxy-on-all-4-webservers support as Go Projects
- Current LTS reality reflected: **v24 Active LTS** default, v22 Maintenance, v18/v20 correctly blocked as EOL

---

## 📥 Website Import Wizard — Migrate from cPanel, aaPanel, HestiaCP

A new "Import Website" flow on the Websites page, upload-based (no SSH pull required):

1. **Upload** the backup archive exported from your old panel
2. **Detect** — VortexPanel extracts it and makes a best-effort guess at the domain, PHP version, document root, and database dump
3. **Confirm** — every detected field is editable before anything happens; nothing is auto-executed blind
4. **Import** — creates the site + nginx vhost (the exact same code path as "New Website", so imported sites are indistinguishable from natively-created ones), copies files, creates the database and imports the dump, generates a fresh random DB password (originals are never in a backup dump, so there's nothing to recover)

Supports **cPanel** (`cpmove`/full-backup format, `userdata` YAML domain detection), **aaPanel** (domain-folder detection + `.sql`/`.sql.gz` filename matching), and **HestiaCP** (`v-backup-user`'s nested `web.tar`/`mysql.tar` format). Files + database only in this release — email, cron, and SSL migration are not yet included.

---

## 📦 App Store — 2 New Modules

- **FFmpeg Manager** — install multiple FFmpeg versions side by side (7.1, 8.1, and nightly master), each with its own command alias (`ffmpeg7`, `ffmpeg8`). Sourced from BtbN/FFmpeg-Builds — the provider ffmpeg.org's own download page links to for Linux static builds — with full x86_64 and arm64 support
- **Memcached** — full management UI: Service (start/stop/restart/reload), Config File editor, Switch Version, Load Status (live stats via Memcached's own `stats` protocol), and Optimization (bind IP/port/cache size/max connections)

App Store module count: **27** (up from 25).

---

## 🖥 Dashboard & Monitoring

- **Realtime charts** — CPU/RAM history and Network I/O, client-side rolling window, no backend polling changes needed
- **Global SSL expiry banner** — aggregates certificate expiry across every site, warns at 14 days with severity-graded colour coding (yellow → orange → red-for-expired)
- **Settings → Audit Log viewer** — last 200 login attempts (time/status/IP/user/note) — the backend already existed, it just had no UI until now
- **Per-site disk usage** — lazy-loaded (only fires when you open a site's Directory tab, so it doesn't slow down the Websites list on servers with many/large sites)

---

## 🐳 Docker — Domain Assignment Without Traefik

Containers can now be assigned a domain + automatic SSL directly from the Docker page, reusing the exact same reverse-proxy code already built for Go/Node.js Projects. No new moving parts, no Traefik dependency — just point a domain at a container's exposed port.

---

## 🛠 Reliability — RHEL-Family & arm64 Fixes

A full audit turned up (and fixed) install-time failures that were silently breaking on real-world server configurations:

- **RHEL/CentOS/Fedora/AlmaLinux/Rocky** — **nginx, MySQL, Caddy, MongoDB, and PostgreSQL** were previously **completely uninstallable** on any RHEL-family distro. The install scripts only had a Debian-specific GPG-keyring + `sources.list` code path; on RHEL this produced garbage commands (`dpkg -i` on a distro with no `dpkg`, Debian package names fed to `dnf`, etc.). All 5 now have proper distro-aware install paths — MySQL uses RHEL's built-in AppStream module stream (no external repo needed at all), PostgreSQL correctly disables the conflicting built-in module before installing PGDG's versioned packages.
- **arm64** — MongoDB and PostgreSQL RHEL install paths had hardcoded `x86_64` in the repo URLs, silently breaking on ARM servers. MongoDB now uses `dnf`'s auto-resolving `$basearch`; PostgreSQL detects the real architecture via `uname -m`.
- **A pre-existing Caddy bug** (not new — this predates the audit) was piping a fetched GPG key into `rm -f` instead of `gpg --dearmor`, producing an empty/invalid keyring on **Debian too**, not just RHEL. Fixed.
- All module install/uninstall cycles audited for safety on repeat runs — GPG keys and repo files are now properly cleaned up on uninstall, preventing reinstall failures.

---

## 🎨 UI System — Modal & Layout Fixes

A cluster of related frontend bugs, all traced to the same root causes and fixed together:

- **Modal centering** — the underlying issue was `position:fixed` breaking when nested inside a scrolling ancestor (`overflow-y:auto` containers). All modals are now rendered as direct children of `<body>` via a shared global portal pattern, using explicit `width:100vw;height:100vh` so they're immune to any ancestor's overflow settings.
- **Horizontal scrollbar shifting the entire panel** — a classic flexbox `min-width:auto` trap: `.main-area` and `.page-content` were `flex:1` with no `min-width:0`, so a single unconstrained `<select>` dropdown with long option text (App Store version pickers) could force the *whole layout* wider instead of scrolling internally. Fixed at the source, plus a body-level safety net.
- **Cross-component scoping bugs** — several modals had their interactive functions defined inside the wrong Alpine.js component (a page's own scope instead of the global scope the portal actually renders in), causing buttons to silently do nothing. Standardized on the same pattern used by `toast()`/`get()`/`post()`: plain global functions, reachable from any component.
- Eight pages (`dashboard`, `docker`, `settings`, `files`, `mail`, `bandwidth`, `security`, `caddy`) had dead method calls in their tab-refresh event listeners from an earlier bulk edit — switching to those tabs was silently failing. All fixed.

---

## 🔩 Smaller Fixes

- Self-hosted SVG brand logos for all App Store modules — zero CDN dependency for icons
- nginx version bump — Stable 1.30.3, Mainline 1.31.2 (security patch)
- Update-check false positive (was comparing git hash against semver)
- Databases page now auto-detects MongoDB/PostgreSQL correctly with engine-aware columns
- Install/uninstall hang fixes — proper timeouts (10min install, 5min uninstall, 8min switch), service-stop-before-remove ordering
- `install.sh` now clones to a permanent `/root/Vortexpanel` instead of `/tmp` (which gets wiped on reboot, silently orphaning git tracking) — and auto-generates a correctly-pathed `deploy.sh` during install

---

## Upgrade Notes

No breaking changes. Existing sites, databases, and App Store installs are unaffected. Simply re-run `deploy.sh` or pull the latest and restart the `vortexpanel` service.
