# VortexPanel v3.7.0

This release closes every finding of the v3.6.0 fresh-install audit and ships the whole roadmap: secure install defaults, signed updates, a command-line tool, multi-user accounts with roles, API keys, alerts, monitoring history, more backup destinations, site security options, file manager and FTP extras, and language packs.

## Install and update

- **Secure defaults on a new install.** The installer picks a random port (10000-60000), a random login path, a random administrator username and a 16-character password, and turns on HTTPS with a self-signed certificate. It prints the full address, for example `https://203.0.113.10:23817/k4m9q2xd`. Use `--port`, `--path`, `--user`, `--http` or `--version` (or `VP_PORT`, `VP_PATH`, `VP_USER`, `VP_HTTP`, `VP_VERSION`) to choose. Re-running the installer on an installed server keeps every setting, account and password.
- **Installs and updates use signed release tags only.** The installer and the updater install the newest `vX.Y.Z` tag, never the unreleased main branch, and check its signature with `git verify-tag` against the release key shipped in the panel. An unsigned or wrongly signed release is refused unless you turn on "Allow unsigned updates" (Update window) or run `vortexpanel update --allow-unsigned`.
- **Safer updates.** Before anything changes, the running code and the exact list of Python packages (`pip freeze`) are saved. A failed `pip install`, a failed import test or a panel that does not answer `/api/health` after the restart puts the code and the packages back automatically. Requirements are now pinned to tested major versions.
- **No developer clone on production servers.** The release is unpacked from a bare mirror in `/opt/vortexpanel/src.git`. `/root/deploy.sh` and `/root/rollback.sh` are only created when you work from your own `/root/Vortexpanel` git clone.
- The plaintext `admin_password.txt` is deleted after the first successful sign-in.
- ufw is installed on Debian/Ubuntu (not switched on) with rules for SSH and the panel port ready.

## Command line: `vortexpanel`

Run it as root on the server. Without arguments it shows the address, username and status. Recovery and admin commands: `reset-password`, `username`, `disable-2fa`, `port`, `path`, `domain off`, `ssl self|off`, `allow-ip list|add|clear`, `unlock`, `users`, `start|stop|restart|status`, `logs`, `update [--check]`, `rollback`, `backup`.

## Security

- **Login path ("security entrance") is enforced.** When it is set (new installs set one; Settings > Network & Access), every other address answers `404 Not Found` until the login path has been opened in the browser. Signed-in sessions, static files, `/api/health` and API keys are not affected.
- **Panel domain is enforced** once saved in 3.7.0 (the panel answers only on that name; loopback always works; `vortexpanel domain off` undoes it). It cannot be saved while you are not using that domain, so you cannot lock yourself out.
- **2FA backup codes**: ten single-use codes are shown when 2FA is turned on and can be regenerated with your password. A code from the authenticator app can be used only once (replays are refused). Turning 2FA on or off signs out the account's other sessions.
- **Lockout per account and per address**: 5 failed attempts from one address or 10 against one account in 15 minutes. Behind a reverse proxy that does not pass the client address, visitors are no longer all treated as 127.0.0.1 (which was always allowed and shared one counter). `Forwarded:` headers are understood.
- **Secure cookie and HSTS behind a TLS proxy**: when a local proxy reports `X-Forwarded-Proto: https`, the session cookie gets the Secure flag and HSTS is sent.
- Security headers: HSTS on HTTPS, CSP with `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`; the obsolete `X-XSS-Protection` header was removed.
- The login audit log stores names typed into failed sign-ins that match no account as a short hash (people paste passwords into the username box).
- Fonts are served by the panel (no requests to Google), favicon added, the TOTP secret is never sent to a QR service.
- Background job output moved from world-readable `/tmp` to `/opt/vortexpanel/data` (0700); downloads, repository keys and installer logs too.
- Security Score adds: panel uses HTTPS, login path set, initial password file removed.

## Users, roles and API keys (Users & API)

- **Accounts with roles**: Administrator (everything), Site manager (only the assigned websites: settings, SSL, backups, WordPress tools and their files, no terminal, cron, databases or App Store because those run as root), Viewer (read-only monitoring and status). The server enforces the role on every request; the menu only shows what the role can open. Each account has its own password, 2FA and backup codes.
- **API keys**: `Authorization: Bearer vp_...` on any `/api/` address. Viewer or administrator role, optional address allowlist and expiry, last use shown, disable or delete at any time. The key is shown once and stored hashed.

## Alerts and monitoring

- **Alerts**: email (SMTP), Telegram and webhooks (JSON, Slack, Discord) for CPU, memory or disk above a threshold, a stopped service, a website that does not answer, an SSL certificate about to expire, a failed scheduled backup and many failed panel sign-ins. Each alert repeats at a set interval while the problem lasts and sends a "resolved" message. Test buttons per channel and a history list.
- **Monitoring history**: one sample per minute (CPU, memory, disk, load, network and disk throughput), kept 3 days at full resolution and 120 days as 15-minute averages, with charts from 1 hour to 90 days. The dashboard history endpoint now returns real samples (it returned random numbers before).

## Backups

- **More destinations**: FTP/FTPS servers and, through rclone, Google Drive, OneDrive, Dropbox, SFTP and 40 more services, next to S3-compatible storage. rclone is downloaded from its GitHub release and checked against the published SHA-256. Every destination has a test button and a file browser with "copy to this server" and delete.
- Website backup schedules choose their destination.
- **Panel backup**: accounts, settings, API keys, alert and backup settings, the panel certificate and panel-made web server and cron files in one archive. Back up now or daily, keep N copies, copy to a destination, download, upload, and restore (settings only, or settings and accounts) with a snapshot taken first.

## Websites

- **Security & Limits** tab (nginx): force HTTPS on or off, HSTS (optionally with subdomains), HTTP/2, blocked paths (404, with a recommended list: .git, .env, backups, SQL dumps...), speed limit per connection, connections per visitor address, and an expiry date after which the site is stopped automatically. Every change is checked with `nginx -t` and rolled back on failure.
- Fixed: uploading a certificate (or renewing one) for a site that already had HTTPS added another copy of the HTTPS server block each time. Damaged vhosts are repaired the next time a certificate is installed.
- Batch Create works (one domain per line, PHP version and database for each); the unused "Site Type" field was removed; Visit links use https:// when the site has SSL.

## File manager and FTP

- **Recycle bin**: deleted files and folders can be restored for 30 days (configurable); empty or delete single items.
- **Edit history**: the editor keeps the last 20 versions of each file; view and restore them.
- **Owner**: change user and group, optionally recursive.
- **Download from URL** now has a button, a destination folder and progress.
- **FTP**: disable and enable accounts (password kept), per-account disk quota, FTP log viewer. Fixed: a home directory entered with a leading slash was stored as `//path`.

## App Store

- **Distribution packages when vendor repositories cannot be reached**: nginx falls back to the distribution package when nginx.org's key or repository is unreachable (not only when it lacks the codename); PHP installs the distribution's own version when neither the PPA nor packages.sury.org can be reached, and otherwise says which version the distribution ships.
- **IPv6-less servers**: the `listen [::]` lines of distro default sites are commented out so nginx starts.
- **Live version information** from endoflife.date (daily, cached; the static list is used offline): current patch versions, LTS, security-only and end-of-life labels, and new release tracks appear without a panel update (PostgreSQL 19, Python 3.15 are now listed; BIND 9.22 via ISC's PPA, 9.20 via the extended-support PPA). Labels no longer carry stale patch numbers.
- **Recommended versions**: the App Store and the setup guide pick the recommended track (an LTS where the app has one: MySQL 8.4 LTS, MariaDB 11.8 LTS, Node.js 24 LTS, PHP 8.4...) instead of the first entry (the setup guide used to install MySQL Innovation).
- **The chosen version is honoured** for Caddy, Redis, OpenLiteSpeed and Composer (2.x or 2.2 LTS), and every install now says so when the package source provided a different version than the one you chose.
- **Uninstall**: the confirmation lists what the removal affects on this server (websites using that PHP version, databases, FTP accounts, jails, Supervisor processes...) and the app's configuration is saved to `/opt/vortexpanel/backups/app-config/` before it is removed.
- **ModSecurity**: refuses to install without the web server it protects; never installs the old CRS v4.0.0 when the latest release cannot be looked up; uninstall removes only the lines the panel added (it deleted every line mentioning "modsecurity" before) and keeps a copy of nginx.conf if the test fails.
- **OpenLiteSpeed**: a clear message when LiteSpeed's repository cannot be reached, instead of "lsphp83 not found".
- **Composer**: the installer's SHA-384 signature is checked before it runs.
- **Firewall page**: installs ufw (or firewalld) when none is present, with SSH and the panel port allowed; the setup guide does the same before turning the firewall on.

## Interface

- One ModSecurity screen (the WAF page); the Security page shows the state and links to it. The Caddy WAF tab appears only when Caddy is installed.
- The "Live" indicator shows whether the server is answering. phpMyAdmin links use its real port.
- Sites served by Apache, OpenLiteSpeed or Caddy explain why nginx-only tabs are hidden.
- **Language packs**: Simplified Chinese, Spanish, Brazilian Portuguese, German, French and Russian, chosen per browser on the sign-in page or the top bar. Your own packs in `/opt/vortexpanel/data/i18n/<code>.json` survive updates.
- Symbol characters were removed from labels, badges and messages.

## Upgrading from 3.6.0

Your port, HTTPS setting, accounts and settings are kept. A login path is not added on upgrade; set one in Settings > Network & Access (or `vortexpanel path random`). The new background timer `vortexpanel-metrics.timer` starts with the panel.
