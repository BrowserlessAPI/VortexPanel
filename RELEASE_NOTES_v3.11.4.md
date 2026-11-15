# VortexPanel 3.11.4

## Fixed: App Store installs under the panel's private umask (issue #36)

The panel service runs with `UMask=0077` so that its own files stay private. Since
3.11.0 the panel installs software itself, and the install scripts inherited that umask:
build folders and the configuration files the scripts wrote could only be read by root.

- **Redis, MySQL, MongoDB and BIND9 failed to install.** Redis reported `Permission
  denied` (status 203/EXEC) and MySQL "initializing the data folder failed". All of
  these now install.
- **Installs that succeeded were damaged.** PHP could not be run by `www-data` or site
  users, and `php.ini`, the module `.ini` files and the FPM pool were readable only by
  root, so PHP run as a site user (cron jobs, Composer, hosting accounts) silently ran
  without its settings. ClamAV, BIND9, OpenLiteSpeed and Fail2ban files were affected the
  same way.
- **MariaDB failed after a failed MySQL attempt.** MySQL's configuration and a half-made
  `/var/lib/mysql` were left behind, and MariaDB stopped at MySQL-only settings
  (`mysqlx-bind-address`) or refused the folder as "MySQL 8 data".

What changed:
- Install, update and removal scripts run with the usual 022 umask. Build folders get
  explicit modes; the panel's `.vortex` metadata stays root-only.
- **One-time repair at the first panel start after the update.** It reopens build folders
  and the configuration files that install scripts wrote. Only files that belong to root,
  have no group or other rights at all and were written after the first VortexPanel build
  was installed are changed; keys, passwords, certificates, logs and caches are never
  touched. The list of changes is kept in `data/softs/permissions-repaired-1.json`.
- Before a fresh MySQL or MariaDB install, when neither is installed, the other server's
  VortexPanel configuration and a data folder holding only a failed first start are moved
  aside (never deleted). Future MySQL and MariaDB builds also remove a data folder they
  created themselves when its initialization fails.

## Fixed: ClamAV scanner did not start under systemd

The two ClamAV services shared `/run/clamav` through systemd's `RuntimeDirectory=`, and
systemd handed the folder back to root each time either service started. `clamd` could not
create its socket and the install was rolled back ("failed its health check"). The units now
create the folder for the `clamav` user before each start. Fixed builds of ClamAV 1.5.4 and
1.4.6 follow through the build pipeline.

## Build pipeline: every build is tested like a real server

Builds are installed, smoke-tested, restarted and uninstalled in a container that runs systemd
as init, with the panel service's 0077 umask. Before, the test ran without systemd and with the
usual umask, which is how both bugs above passed. ClamAV's smoke test also starts the real
scanner service.

## Fixed: PHP settings could not be saved for VortexPanel PHP builds

The configuration test ran `php-fpm -t` without the service's configuration file, failed
for every VortexPanel PHP build, and every change on the PHP settings page was rolled
back. The test now uses the same files as the PHP-FPM service.

## Security: PHP2Shell (CVE-2026-109618, CVE-2026-109619)

Unauthenticated remote code execution in the PHP runtime, exploited since October 2026.
The VortexPanel PHP builds 8.5.12, 8.4.27, 8.3.36 and 8.2.35 (published 4 November as
security updates) carry the fix. PHP 8.1 has no official fix.

- **PHP > Settings > PHP2Shell** shows every PHP on the server (VortexPanel builds,
  operating system packages, Remi, LiteSpeed lsphp) and whether it has the fix.
- **Protection, on by default:** `session.upload_progress.enabled = Off` in every PHP
  version and every PHP-FPM pool (also Hosting Module accounts), set where websites cannot
  turn it back on, and for Apache mod_php. PHP recommends this while patching and after it,
  because CVE-2026-115560 has no fix yet. Only upload progress bars stop working.
  New PHP versions get it when they are installed.
- **System Hardening 1.2.0:** the Integrity check reports PHP versions without the fix
  and the published traces of the attack (log patterns, exploit markers, dropped files,
  SSH keys of the web user, a hidden sshd in web server log folders, the kernel modules
  used for the root exploit that follows).

## System Hardening 1.2.0: web server check

The Integrity check has a new **Web servers** section for Apache, nginx, OpenLiteSpeed and
Caddy:
- **VortexPanel builds** behind a security release, from the signed catalog and a table of
  minimum safe versions: Apache 2.4.71 (CVE-2026-119618, HTTP/2 remote code execution,
  critical when HTTP/2 is on), nginx 1.31.7 and 1.30.6 (October 2026 fixes). Versions whose
  track no longer gets fixes are reported too.
- **Operating system packages** with a security update waiting in the package manager. For
  Apache with HTTP/2 on, it explains the distribution backport and the `Protocols http/1.1`
  workaround.
- **Known flaws without a fix:** OpenLiteSpeed CVE-2026-119559 (all versions up to 1.9.4). A
  site that requires client certificates can be reached without one over HTTP/3; it is
  reported as high only when a site requires client certificates and HTTP/3 is on.
- Fixed: the software build check reported files that a package ships as hard links (BIND's
  `tsig-keygen`, `named-compilezone`) as "not part of" the build. References cached by
  1.1.0 are rebuilt.

## Upgrade

Panels on 3.11.3: **Settings > Update**, then **Apps > System Hardening > Update to 1.2.0**.
If an App Store install failed with "Permission denied" or "initializing the data folder
failed", install it again after the update.
