# VortexPanel v3.5.3

A full audit release. Every route of the panel (431 API endpoints), every
page and every App Store app was reviewed line by line for crashes, wrong
results, unsafe shell commands, missing validation and distro or kernel
assumptions. Fixes were then verified on real Ubuntu 24.04 and 22.04 systems
with systemd:

- **Feature tests:** 512 automated end-to-end tests (websites on nginx and
  Apache, SSL, databases, backups, cron, files, FTP, DNS, firewall, SSH,
  fail2ban, WAF, App Store settings, auth, settings).
- **App Store:** a full install and uninstall run of every app on both
  releases.
- **Fresh install:** `install.sh` run on a clean Ubuntu 22.04.
- **Browser:** every page and every App Store settings window opened in a
  real browser.

## Websites work on every web server (Debian 12 report)
- **Sites created under Apache, OpenLiteSpeed or Caddy** now appear in
  Websites and can be managed. Before, only nginx sites were listed.
- **Apache sites support:** Domain Manager, PHP version, Directory, Default
  Doc, stop/start, Let's Encrypt, uploaded certificates, Disable SSL and logs.
- **Every config save is tested** with the web server's own check and the
  previous file is restored if it fails.
- **New sites always go to `/www/wwwroot`.** On a server where that folder
  did not exist, sites were created inside the default site's folder
  (`/var/www/html`), where `wp-config.php` could be downloaded as plain text.
- **All per-site settings apply to HTTPS too:** proxy, redirect, hotlink,
  IP rules, maintenance and access limits now go into every server block.
  Before, they silently did nothing once SSL was on, or covered only HTTP.
- **Fixed (critical):** the Directory "Save" and Default Doc "Save" buttons
  overwrote the site's vhost with an empty file.
- **Fixed:** the rewrite template picker deleted `location /` (permalinks
  broke).
- **Fixed:** Limit Access ignored the form and protected every path with the
  password `changeme`.
- **Fixed:** the maintenance page showed nginx's default 503 page.
- **Fixed:** enabling the Node.js App Runner removed PHP handling for good.
- **Fixed:** removing a bound domain could delete unrelated text from the
  vhost.
- **SSL:**
  - Uploaded certificates are checked: valid PEM, key matches certificate,
    not expired.
  - Cloudflare DNS certificates now reload the web server when they renew.
  - Renewal is enabled on RHEL-family systems, where certbot's timer ships
    disabled.
  - Failed requests now show certbot's real error.

## App Store
- **Install and uninstall:** they wait for a busy package manager (the
  original Caddy uninstall report), show every error and restart a service
  that a failed removal stopped. The job window can no longer hang.
- **Python:** the system Python can never be removed.
- **Roundcube:** install fixed.
- **Memcached:** fixed on servers with IPv6 disabled.
- **Pure-FTPd:**
  - Panel FTP accounts can now actually log in. PureDB was never enabled,
    and the database file is now created on install.
  - It now has a passive port range, and the firewall is opened for FTP.
- **Settings windows:** many tabs never saved. These are now implemented:
  - PHP extensions and php.ini
  - PHP-FPM profile
  - Roundcube mail config
  - FTP users
  - fail2ban black and white lists
  - Redis optimisation and persistence

  Every config save is tested, reloaded and rolled back on failure, and the
  service is brought back if the old config has to be restored.
- **Switch Version:**
  - Scripts were rewritten.
  - A failed switch no longer quietly installs "latest" and reports success.
  - Unsupported switches are refused with a clear message.
  - The installed version must really match the one asked for.
- **phpMyAdmin:** works with any PHP layout and web server. It uses Apache's
  `conf.d` on RHEL, keeps its config on reinstall and generates a
  `blowfish_secret`.
- **Weekly CRS rule update:** uses the panel's own update logic. It never
  falls back to an old ruleset, swaps the rules in all at once and rolls
  back on a failed config test.

## WAF
- **WAF 2.0 is now usable.** Its backend crashed on every change because 11
  settings were never defined, and it had no screen at all. The WAF page now
  has:
  - Recent hits
  - Per-site Enforce / Detect / Off
  - Rule exceptions (with a rule picker)
  - Region blocking (with a GeoIP database installer)
  - Custom rules builder
  - Rate limits
  - List import and export
- **Fixed:** region and custom rules could never load (chained-rule
  actions), and the audit log was never read on nginx (ModSecurity v3
  format).
- **Repair and Update CRS:** they now work when files are missing and keep
  your tuning.

## Security
- **SSH settings:**
  - Port changes are validated with `sshd -t`, opened in the firewall and
    labelled for SELinux.
  - Ubuntu's `ssh.socket` is handled.
  - The panel checks sshd is listening on the new port and rolls back
    automatically if not.
  - Disabling root login or passwords is refused when it would lock you out.
- **Firewall:**
  - Enabling it on a fresh server keeps SSH and the panel port open.
  - The SSH and panel rules cannot be deleted by accident.
  - It works with ufw or firewalld on any distro, including kernels with
    IPv6 disabled.
- **fail2ban:**
  - The ban action matches the machine (nftables, iptables or firewalld).
  - Log paths are correct on every distro, with a journal fallback.
  - Website jails work for Apache, OpenLiteSpeed and Caddy.
- **Login and sessions:**
  - The brute-force lockout is shared by all panel workers and can no longer
    be bypassed with a forged `X-Forwarded-For` header.
  - The 2FA code step is rate-limited.
  - A password change logs out other sessions and requires the current
    password.
  - Credentials are written safely (never regenerated on a read error).
- **Cross-site request protection:** requests from other origins are
  blocked, including when the panel is reached through an SSH tunnel.
- **2FA QR code:** drawn locally. The TOTP secret is no longer sent to an
  external QR service.
- **Command injection:** user input could reach root shell commands in many
  places (databases, Docker, FTP, mail, DNS, cron, PHP, services, logs,
  hostname, Go/Node projects, WordPress). All of these are now validated or
  passed safely.
- **Secrets:** cloud backup, DDNS, CDN and AI keys and mail passwords are
  stored readable by root only.
- **Archives:** website import and backup restore can no longer write
  outside their folder (tar/zip path escapes).

## Data, files and system
- **Databases:**
  - MySQL/MariaDB login works with socket auth, `debian.cnf` and RHEL socket
    paths.
  - PostgreSQL works without sudo, and new users can create tables on
    PG15+.
  - MongoDB user management works.
  - `.sql.gz` import.
  - Large exports no longer time out.
- **Backups:**
  - A failed database dump is no longer reported as a success.
  - PostgreSQL databases are dumped with `pg_dump`.
  - Restores go back to the right place.
  - Uploaded backups are actually restored.
  - Job progress works with all panel workers.
- **Cron:** a `crontab` read error can no longer wipe all jobs. `%` in
  commands works, and cron is installed when it is missing.
- **File manager:** search, folder size and Properties work again. Deleting
  `/`, `/etc` or `/usr` is refused, binary files can't be opened in the
  editor, and zip works without the `zip` tool.
- **DNS:**
  - Records go to the right name, and deleting removes the right record.
  - Every change is checked with `named-checkzone` / `named-checkconf`.
  - On RHEL, zones answer publicly.
- **Panel port change:** checks the port is free first and opens it in the
  firewall. The old port's rule is removed only once the panel answers on
  the new port, and the change rolls back automatically if it doesn't.
- **Panel self-update:**
  - It refuses to overwrite local changes, installs requirements into the
    panel's own Python environment and backs up first.
  - It tests the new code before restarting and restores the backup if the
    panel doesn't come back.
- **Web terminal:** sessions no longer leave zombie or orphan processes.
- **Services page:** stopped services are listed and can be started, with
  correct names on RHEL.
- **Dashboard:** the "multiple web servers running" warning no longer shows
  on every server.
- **Node.js and Go projects:**
  - They run as the web user correctly. Node versions installed with nvm now
    live in `/opt/vortexpanel/nvm`.
  - SSL issuing for Go projects no longer fails with an error 500.
  - Installing a second Go version no longer corrupts the first.
- **Docker:** job progress works with all panel workers, and container stats
  load again.

## Other OSes and kernels
- **Debian, Ubuntu, Fedora and RHEL / AlmaLinux / Rocky / Oracle Linux:** OS
  detection and package names fixed for each. EPEL is enabled on every RHEL
  flavour, Remi PHP versions are supported, and EL10 / Fedora 41+ have no
  dnf modules.
- **SELinux:**
  - Site folders get the right labels.
  - Reverse proxies (Node, Go, Docker, proxy rules) are allowed.
  - Non-standard ports (phpMyAdmin 8082, Roundcube 8083) are allowed.
  - FTP can write into site folders.
- **cgroup v1** memory limits, **IPv6-disabled** kernels, **containers**
  (live patching is not offered where it can't work) and missing
  `lsb_release`, `which` or `crontab`.
- **Live patching:** has its own card in Settings with enable, check and
  disable.
- **`install.sh`:**
  - The admin password is stored as argon2 with mode 0600.
  - It works on RHEL 9 / Fedora cloud images (curl-minimal conflict).
  - It keeps a custom port or HTTPS when re-run.
  - It creates `/www/wwwroot`.
  - It binds dual-stack when IPv6 is available.

## Known limits (not changed in this release)
- No Coraza installer for Caddy yet. The WAF page says so.
- WordPress installs need wordpress.org to be reachable from the server.
- Mail server setup has no screen yet.
