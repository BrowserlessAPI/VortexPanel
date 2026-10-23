# VortexPanel v3.9.0

Email gets a spam filter, autoresponders, daily sending limits and the DNS records new mail domains need. One-click Deploy now installs the apps completely. PHP gets the ionCube Loader. For the Hosting Module 3.2.0: website mail counting and an API key role for WHMCS.

## Email (Mail Server)

- **Spam filter (Rspamd)**, new tab **Spam & limits**: install with one button, then choose the score that files a message into Junk and the score that refuses it, optional greylisting, and allow and block lists (addresses or whole domains). Messages marked as spam go to the mailbox's Junk folder. On Dovecot 2.3, moving a message into or out of Junk teaches the filter (Redis is installed for this). Outgoing mail is signed with DKIM. The last 24 hours show scanned, spam, refused and greylisted counts.
- **Autoresponders / vacation replies** per mailbox: subject, message, optional start and end date, and how often the same sender gets a reply. Lists, bounces and no-reply senders never get one.
- **Daily sending limits** per mailbox and per domain (server defaults, a different number per mailbox). Messages over the limit are refused with a clear error, the mailbox list shows what each mailbox sent today, and a new alert rule tells you when a mailbox reaches its limit. Mail servers set up before this update keep sending without a limit until you set one.
- **SPF, DKIM and DMARC for new mail domains**: when the domain's DNS zone is on this server, the records (plus MX and the mail host) are added automatically. The tab **DKIM / SPF / DMARC** shows which records are found in public DNS, adds missing ones, creates a new DKIM key and changes the DMARC policy.

## Websites

- **One-click Deploy** installs WordPress, Drupal, Joomla, OpenCart and Laravel completely: the website, a new database with its own user, the app's installer, file ownership and an SSL certificate when the domain already points to this server. Pick the PHP version (only versions the app supports are offered), the site title and the admin user and email; the PHP extensions the app needs are installed when missing. The installer's progress is shown and the result lists the login and database details once. The newest versions are looked up (at most twice a day) with the tested version as a fallback. When something fails, the new website and database are removed again. One-click Deploy only installs into new or empty websites.

## PHP

- **ionCube Loader** in PHP > Extensions for every installed PHP version (the official loader; Remi PHP uses its package). The install is checked with `php -v` and undone when PHP does not start with it.
- Extensions and php.ini changes now also reach the PHP services of hosting accounts (Hosting Module 3.2).

## App Store

- **Current versions** (October 2026) in the version lists, with the patch number shown:
  - **PHP:** 8.5.12, 8.4.27, 8.3.36, 8.2.35. These are the 21 October security releases for two critical remote code execution flaws (CVE-2026-109618, CVE-2026-109619) in PHP-FPM, mod_php, php-cgi and LiteSpeed: update PHP on every server. 8.2 reaches end of life on 31 December 2026.
  - **nginx:** 1.30.6 stable, 1.31.8 mainline. The labels follow new releases by themselves (daily live check), and an "Update available" badge appears when the installed nginx is behind on its branch.
  - **Web servers:** Apache 2.4.69, OpenLiteSpeed 1.9.3, Caddy 2.11.7.
  - **Databases:** MySQL 8.4.13 / 9.7.4 LTS, MariaDB 11.8.9 / 11.4.13 / 10.11.19 / 12.3.3 LTS and 13.0.2. MongoDB 9.0 is added; 8.2 is removed (end of life). PostgreSQL 18.6 / 17.11 / 16.15 / 15.19. PostgreSQL 19 is a release candidate and appears automatically once it is released.
  - **Runtimes and tools:** Node.js 24.22.1 / 22.23.4 / 26.12.1, Python 3.15.1 to 3.10.22 (3.10 is end of life), Redis 8.10.2 / 8.8.3 / 7.4.11, Docker 29.9.2, Composer 2.10.3 and 2.2.30 LTS.
  - **Mail and admin tools:** Roundcube 1.7.5 and 1.6.20, Adminer 6.1.2 (checksums updated), BIND 9.20.30.
  - **FFmpeg:** 9.0 is added. 7.1 builds are no longer published, so it can only be removed.
- **Tested versions without a panel update.** New app versions (a new PHP or PostgreSQL release, a new Adminer, phpMyAdmin, Roundcube or Anubis release, security notices) now reach the App Store once the VortexPanel team has installed and tested them, without waiting for a new panel version. The panel fetches the list when the App Store is opened, at most once a day, and when you click **Update App List**. It is free for every server: no licence, key or account is needed, and nothing but the request is sent. The list is signed; a list that is not signed by VortexPanel, is older than the one in use or does not fit the rules for an app is ignored, and the panel keeps its previous list or its built-in versions. The list never contains commands: installs still run the panel's own install scripts, and downloads are only taken from github.com and phpmyadmin.net and checked against their SHA-256 checksum. The App Store header shows which list is in use; `vortexpanel app-versions status` and `vortexpanel app-versions refresh` do the same on the command line.
- Installing or switching to a version that is not in the App Store's list is refused with a clear message.

## API keys

- New role **Hosting provisioning (WHMCS)**: the key can only create, suspend, unsuspend, terminate and change the package or password of hosting accounts, sign customers in to the customer portal and read their usage. Creating such a key shows the steps to connect WHMCS and a download of the WHMCS module (needs the Hosting Module 3.2).

## Hosting Module 3.2.0 (separate update, licence server)

- **Resource limits per package**: CPU (% of a core), memory, disk read and write (MB/s), processes and PHP workers, applied at once to everything the account runs (websites, PHP, cron, SSH) without restarting its websites. Each account's PHP now runs in its own service inside the account's limits.
- **Usage history per account** (account window > Resources): CPU, memory, disk I/O and processes for the last 24 hours, 7 days or 30 days, and how often a limit was reached.
- **SSH for customers** (restricted shell, no port forwarding or tunnels for hosting accounts): per package, or on/off per account. The customer only sees their own home folder; git, composer, wp-cli, php, node and npm are available. **SFTP now works for every account** with the account password or SSH keys, in the same restricted view.
- **Email sending limits per package**: per mailbox and per account per day; mail the account's websites send with PHP `mail()` counts too.
- **Several users per database** in the portal (read only, read and write, all), counted against the package's database users.
- **PHP extensions customers turn on themselves**: the package lists which ones; others still go through PHP requests.
- **Portal email**: change a mailbox password, set an autoresponder, see what each mailbox sent today and the package's limits, and open webmail (when Roundcube is installed).
- **WHMCS module**: create, suspend, unsuspend, terminate, change package and password, single sign-on to the portal (client area and admin area, with quick links to Email, Databases, File Manager, WordPress and Backups), daily disk and bandwidth usage, client area with account and mail settings.

## Fixes

- **Database permissions are exact.** MySQL reads `_` in `GRANT ... ON \`name\`.*` as a wildcard, so a database user could also reach a database whose name differed only where the first one had an underscore. All grants the panel creates now name exactly one database. (Hosting Module 3.2.0 also corrects the grants of existing customer databases once.)
- The Redis password Rspamd uses is no longer readable by every local user.
- Laravel is only deployed into new websites (its web folder must be the project's public folder).

## Notes

- Spam filter install, ionCube and the app downloads need the server to reach rspamd.com (RHEL family), downloads.ioncube.com, wordpress.org, drupal.org, github.com and packagist.org.
- The restricted shell needs bubblewrap (installed automatically). On Ubuntu 24.04 an AppArmor profile for it is added.
