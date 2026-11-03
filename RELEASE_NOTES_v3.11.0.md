# VortexPanel 3.11.0

All App Store software and all VortexPanel Apps now come from the VortexPanel
download server (Cloudflare R2): built, tested and signed by an automated
pipeline, installed and updated from one place, without a panel release.

## New: VortexPanel software builds

The App Store installs server software as VortexPanel builds when one exists for
the server's system, instead of using the operating system's package sources.

| Kind | Software |
|---|---|
| Web servers | Nginx (with the ModSecurity module), Apache2, OpenLiteSpeed, Caddy, Caddy WAF |
| Databases | MySQL, MariaDB, PostgreSQL, MongoDB, Redis, Memcached |
| Languages and tools | PHP 8.1 to 8.5, Node.js, Python, Composer, Docker (with Compose and Buildx), Supervisor |
| Security | Fail2ban, ClamAV, ModSecurity (v3 library for Nginx, mod_security2 in the Apache build) |
| DNS and FTP | BIND9, DDNS Manager (ddclient), Pure-FTPd |
| Mirrored release files | phpMyAdmin, Adminer, Roundcube, Anubis Bot Protection, ffmpeg, OWASP Core Rule Set (ModSecurity WAF rules) |

- **Automatic pipeline.** Every 24 hours a GitHub Actions workflow:
  - finds new upstream releases
  - has them reviewed by AI (security fixes, CVEs, breaking changes, release notes)
  - builds them for AlmaLinux / Rocky / RHEL / Oracle / CentOS Stream / CloudLinux
    8, 9 and 10, Ubuntu 22.04 and 24.04 and Debian 12 and 13, on x86_64 and ARM
  - installs each build on a fresh system with the panel's own engine and
    smoke-tests it
  - uploads the builds to R2 and signs the catalog
- **Mirrored tools.** Tools installed from a released file (phpMyAdmin, Adminer,
  Roundcube, Anubis, ffmpeg, OWASP CRS) are copied to R2, checked against the
  upstream checksum where one is published, and installed only from that copy
  with the checksum from the signed catalog.
- **Signed and checked.** Panels accept only a catalog signed with the VortexPanel
  key and never an older one, and check every download against its SHA-256.
- **Safe updates.**
  - The new version is installed next to the current one in
    `/usr/local/vortex/<app>/<version>`, started and health-checked. If it does not
    start, the previous version comes back automatically.
  - Databases: the data folder is copied before an update (the update is refused
    when there is not enough free space) and put back if the new version fails.
    Updates stay inside one release line (for example MySQL 8.4, PostgreSQL 17);
    a new major version is never installed automatically.
  - The previous version is kept for a one-click **Roll back**.
  - Configuration files (`/etc/nginx`, `/etc/php/X.Y`, `/etc/mysql`, ...) are never
    replaced.
- **Release channels.** Security releases go to everyone at once; other releases
  spend 24 hours on the beta channel first. Withdrawn releases show a
  "Withdrawn - roll back" button.
- **Software updates panel** (App Store): which system this server is, catalog
  status, channel (stable or beta), automatic updates (security only, all, or
  off), alerts, and recent activity. Panels check every 6 hours
  (`vortexpanel-softs.timer`).
- **Use VortexPanel build.** Software installed from the OS packages can be
  switched over on Debian and Ubuntu. The build is verified first; the OS
  packages are removed with their configuration and data kept, and they are
  reinstalled if the build does not start.
  - **Apache with mod_php** is moved to PHP-FPM during the switch (each PHP version
    it used must have PHP-FPM; the switch says which to install first).
  - **OpenLiteSpeed from the LiteSpeed repository**: its configuration and WebAdmin
    login are copied before the package is removed and put back exactly.
  - A switch is refused, with the reason and nothing changed, when it would remove
    unrelated packages or when the data belongs to another database (MySQL data
    under MariaDB, a PostgreSQL cluster of another major version).
- **Every system checked against upstream.** Before building, the pipeline reads
  upstream's own download index (MongoDB, MariaDB, MySQL, ClamAV) for the exact file
  and checksum per system. A system upstream publishes nothing for is marked "not
  offered" and keeps its OS packages; it is never a failed build.
- **MariaDB on ARM** is compiled from the release's source for every system.
- Until `panel/trust/softs.json` names the download server and key, everything
  works as before.

## New: VortexPanel Apps from the cloud

Website Statistics, PHP Security, System Hardening, Network Threat Detection and
Network Scan Detection are checked and published by the same pipeline whenever
their code changes. Panels show "Update to vX" and install the new version
without a panel release.

## Fixes

- **App Store versions** show only the version number (for example `8.4.13`),
  without descriptions or extra space.
- **Website Statistics 1.1.0** counts only requests for the website's own domain
  names. Other domains pointed at the server (for example an embedded player on
  another site) are listed separately under "Other domains" and no longer show up
  as your pages and visitors. New setting: close connections for host names no
  website on the server serves.
- **PHP Security 1.1.0** builds Snuffleupagus 0.14.0, which supports PHP 8.5
  (the older release failed on PHP 8.5 with `php_setcookie`). Servers with an
  older build see "older release - rebuild".
- **CDN Manager** has an on/off switch in the App Store. Off hides its page and
  closes its API; saved provider settings are kept.

## Upgrade

Upload `vortex_upgrade_3.11.0.py` to `/root/` and run `python3 /root/vortex_upgrade_3.11.0.py`.
It upgrades from 3.10.0. Setup of the build pipeline: `softs/README.md`.
