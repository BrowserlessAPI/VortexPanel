# VortexPanel 3.12.0

## VortexPanel Apps now come from VortexPanel's own Cloudflare R2

System Hardening, PHP Security, Website Statistics, Network Scan Detection and Network
Threat Detection are VortexPanel's own Apps. They stay free for every VortexPanel server,
but they are no longer part of the open-source panel repository:

- The App Store downloads them from VortexPanel's own Cloudflare R2 bucket
  (`panel/trust/softs.json` "apps_url"): a signed `index.json` plus the App packages. No
  account, key or payment is involved.
- The index is signed with the VortexPanel catalog key, and every App package must match the
  SHA-256 in it before it is installed, so R2 only stores the files and is never trusted.
- The Apps are **not** published to GitHub. The source is kept in a private repository.
- The Apps carry their own licence terms (`LICENSE.txt` in each App); the MIT licence of the
  panel core does not cover them. A `LICENSE` file for the core is now in the repository.
- New releases: Website Statistics 1.1.1, Network Scan Detection 1.0.1, Network Threat
  Detection 1.0.1 (licence terms added), System Hardening 1.2.2 (its PHP2Shell check knows
  PHP 8.6 and the patched PHP 8.1.34.1) and PHP Security 1.2.0 (PHP 8.6 support, below). They
  arrive on the beta channel first and on stable after 24 hours.
- Installed Apps keep working and keep their data. After the update, the App Store offers the
  new versions as an update. The System Hardening integrity check gets the reference copy of
  each installed App from R2.
- When R2 cannot be reached, the App Store uses the last App list it received (for up to 7
  days) and installs wait until it is back. Websites and installed Apps are not affected.

## Second download source for server software: GitHub

Every server software build (web servers, PHP, databases, ...) and the signed catalog are now
also published on GitHub Releases (BrowserlessAPI/vortexpanel-softs).

- When the VortexPanel download server (Cloudflare R2) cannot be reached, the panel downloads
  the catalog and the build from GitHub instead.
- **App Store > Software updates > Download source** chooses which one is tried first:
  the VortexPanel download server (default) or GitHub.
- Both hold the same files. Every download is checked against the signed catalog, so a file
  changed on either side is refused.
- VortexPanel's own Apps are never published to GitHub; only the open-source server software
  is mirrored there.

## Self-hosted mirrors, offline bundles and signed upload

For servers behind a slow link, a LAN of servers, or no internet at all. Everything below is
still checked against the signed catalog, so a mirror or an imported file can only carry exact
copies of what VortexPanel signed, never modified software or Apps.

- **Self-hosted mirrors** (App Store > Software updates > Mirrors & offline installs, or
  `vortexpanel mirror add <url>`): add your own HTTP mirror(s) for server software and for
  Apps. Mirrors are tried before the VortexPanel servers. Serve a mirror with the directory
  that `bundle.py --mirror-dir` writes.
- **Offline bundles**: on any machine with internet, build a bundle with
  `softs/pipeline/bundle.py` (dependency-free; it reads the public download URLs), carry it to
  the server, and import it (the same panel, or `vortexpanel offline import <file>`). It holds
  the signed catalog / App index and the packages you chose; import verifies every signature
  and checksum, so an offline install is exactly as trusted as an online one. Turn on **Offline
  mode** to use only mirrors and imported bundles and never the internet; an imported catalog
  is accepted past its weekly refresh date (with a note) so an air-gapped server keeps working.
- **Signed upload**: upload a single already-downloaded package (`.zip`); it is kept only if
  its checksum is in a catalog the panel already has.

## Fixed: dashboard CPU reading was inflated

The dashboard measured CPU over an 80 ms window taken inside the request. That is too short to
be accurate and it caught the panel's own polling work (reading stats, checking services), so an
idle server could show CPU "spiking" to 40-60% with nothing running. CPU is now measured as the
change in `/proc/stat` between one poll and the next, averaged over the real poll interval, so
the reading matches what `top` shows. No sleep in the request either.

## Fixed: ClamAV could peg a CPU core after a failed start

The ClamAV App's old service unit used `RuntimeDirectory=clamav`, which systemd recreates as
root on every start; `clamd` (running as the `clamav` user) then could not create its socket,
exited, and was restarted every few seconds, reloading the whole signature database at 100% CPU
each time. If you have a server sitting at high CPU with no sites, this was the cause.

- The service units no longer use `RuntimeDirectory`; they create `/run/clamav` owned by the
  `clamav` user, so `clamd` can bind its socket. (The current recipe already did this; the fix
  below is what gets it to servers already running the old build.)
- Both units now stop retrying after 5 failed starts in 5 minutes (`StartLimit`) and wait 30 s
  between restarts, so a broken `clamd` fails visibly instead of burning a core for days.
- **Delivering recipe fixes to existing installs:** until now a fix to how a package is built
  (like this unit change) could not reach servers already running it, because the version number
  didn't change. The build pipeline now ships such a fix as a build bump -- ClamAV 1.5.4 becomes
  **1.5.4.1**, built from the same upstream source -- which panels are offered as a normal update.
  After upgrading, run the software pipeline with `force: clamav=1.5.4,clamav=1.4.6`; every
  ClamAV server is then offered 1.5.4.1 / 1.4.6.1, and updating rewrites the unit and heals the
  socket permissions.

## Running-jobs indicator: reopen a hidden install/update

An App Store operation (install, update, remove, version switch) keeps running on the server after you
press **Hide (keeps running)** on its window. Until now there was no way to get that live window back,
and a page reload lost it entirely.

- The App Store header now shows a **running-jobs indicator** whenever an operation is in progress. It
  shows what is running (e.g. "Installing PHP 8.4") and reopens the live log when clicked.
- It is rebuilt from the server on every page load, so it comes back after a reload or on another tab,
  and reattaches to the same job -- the live output streams from the start and continues to completion.
- A finished operation stays reopenable as "View last operation" for a few minutes, so a job that
  completed while its window was hidden can still be opened to read the result.
- New endpoint `GET /api/modules/jobs` lists active and recently finished jobs; nothing about how jobs
  run changed.

## PHP 8.6

PHP 8.6.0 (released 19 November 2026) is in the App Store: VortexPanel builds for every
supported system, and the operating system packages (ondrej/sury, Remi) are recognised too.

- **Extensions:** igbinary, APCu, Redis, Imagick and Memcached are built for PHP 8.6 like for
  every other version. PHP 8.6 changed the extension API and no release of these extensions
  builds on it yet, so for PHP 8.6 each one is built from an exact upstream commit that adds
  PHP 8.6 support (checked by its commit id); PHP 8.1 to 8.5 keep the released versions. They
  move to the official releases as soon as those are out.
- PHP 8.6 shows up everywhere PHP versions are listed: the PHP page, websites, WordPress
  Toolkit, the dashboard services and PHP2Shell.
- **PHP Security App 1.2.0** builds its module for PHP 8.6 from Snuffleupagus' upstream PHP 8.6
  support (an exact, verified commit; 0.14.0 is not safe on PHP 8.6: it calls functions PHP 8.6 removed). PHP 7.4 to 8.5 are
  unchanged.

## PHP2Shell: patched PHP 8.1 and a dashboard warning

- **PHP 8.1.34.1:** the VortexPanel PHP 8.1 build now carries PHP's official PHP2Shell fix for
  8.1 (the PHP project published it as source only, for builds of the end-of-life 8.1). Servers
  on PHP 8.1 are offered 8.1.34.1 as a normal update; the PHP2Shell tab then shows PHP 8.1 as
  fixed. Moving the websites to PHP 8.2 or newer is still recommended (8.1 gets no other fixes).
- **Dashboard warning:** when any PHP on the server is affected or has no fixed release, the
  dashboard says so, with a button that opens the PHP2Shell tab.
- Fixed: the PHP2Shell tab failed to load on a server with PHP 8.6 (a VortexPanel or Remi build).
- PECL extension downloads in the PHP builds are now checked against pinned SHA-256 checksums.

## WordPress Toolkit: verified downloads and changed-file checks

- **wp-cli** is installed only when it matches the SHA-512 wp-cli publishes; a failed download
  no longer leaves an error page installed as `/usr/local/bin/wp`.
- The security scan checks **WordPress core files** and **wordpress.org plugins** against the
  official checksums. A changed core or plugin file, or a file that is not part of WordPress (a
  typical place for a web shell after an attack), is listed. **Fix** reinstalls the same
  version's official files; `wp-content` and `wp-config.php` are not touched, and files that are
  not part of WordPress are listed for you to review, never deleted automatically.
- Fixed: the security scan failed on every site whose `wp-config.php` defines `WP_DEBUG`.

## Scan & import: take over apps that already run on the server

**Node.js, Go and Python projects > Scan & import** lists apps that run on this server but are
not managed by the panel: PM2 apps, programs built with Go, and Python web apps (gunicorn,
uvicorn, hypercorn, `python app.py`). Programs from the operating system packages, containers
and the panel's own services are never listed.

- **PM2:** the app becomes a Node.js project and keeps running in PM2 untouched; removing the
  project later only removes it from the panel.
- **Go and Python:** the same command, folder, user and environment become a VortexPanel service.
  The original is stopped (its own systemd service is disabled but kept, so you can switch it
  back on), the new service is started and checked; if it does not start and listen, the
  original is started again. Python apps keep their own virtualenv and file owners.
- Only the administrator can scan and import, and only a process the scan itself found can be
  imported.

## All Projects

**All Projects** (in the sidebar, below Websites) lists every website and app on the server in one place:
PHP, static and WordPress sites, Node.js, Go and Python projects and Docker containers, with
their domain, folder, port and status, a filter per type, search, and a link to manage each.

## Disk usage by category

The dashboard shows what takes the disk space: websites and apps, databases, backups, logs,
Docker, mail, and the system and everything else. It is measured in the background at the lowest
priority, at most every 6 hours (or with **Measure now**); **Analyze** opens Disk Usage.

## Site names

A website can have its own name in **Websites** (the pencil next to the domain), for example
"Shop (production)". Only the label changes: the domain, folder, certificate and configuration
stay as they are. The copy button next to it copies the name (or the domain).

## SSH sign-in alerts read less from disk

On servers without the systemd journal, the SSH sign-in alert read the whole `auth.log` every
minute (hundreds of MB on a server under SSH brute force). It now reads the log backwards from
the end and stops at the last minute's lines: a few KB per check.

## Software builds

- A failed source download or checksum now stops a build at once (the error text was taken as
  the file name before, and the build failed later with a confusing message).
- A rebuild of a published version whose recipe changed is published as a build bump
  (1.5.4 -> 1.5.4.1); see ClamAV above and PHP 8.1.34.1. A build's health check now compares
  the version the program reports with the upstream release it is built from, so a build bump
  passes it on every panel version (it was compared with 1.5.4.1 and rolled back). Build bumps
  are made only for three-part versions: on PostgreSQL's two-part versions (17.6) a fourth
  number would read as a real release.

## Upgrade

Panels on 3.11.4: **Settings > Update**, then **App Store** to update the installed Apps.

After the panel update, run the software pipeline (Actions > Software builds) with
`force: clamav=1.5.4,clamav=1.4.6,php=8.1.34`: every ClamAV server is then offered 1.5.4.1 /
1.4.6.1 and every VortexPanel PHP 8.1 server 8.1.34.1. PHP 8.6.0 is built by the next daily run
on its own.
