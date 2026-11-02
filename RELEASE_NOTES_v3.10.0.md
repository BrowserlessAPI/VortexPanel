# VortexPanel 3.10.0

Panel Apps: five new security and analytics modules installed from the App Store,
an isolated App framework, and fixes for 19 problems found in an audit of the
App Store and security features.

## New: Panel Apps

Apps are optional modules listed in the App Store next to server software (tagged
**APP**). Installing one adds its own page to the panel. Each App is isolated:

- its own data folder (`data/apps/<id>`), nftables table (`vp_<id>`), systemd units
  (`vortexpanel-app-<id>*`) and Python package (`vpapp_<id>`)
- installed, updated and removed by a separate job that checks the App loads,
  restarts the panel, waits for it to answer and puts everything back if any step fails
- removing an App removes its services, firewall table and locks; its settings and
  history are kept unless you choose to delete them
- panel updates never change an installed App; the App Store offers an Update when
  the panel ships a newer version of it

The five Apps:

| App | What it does |
|---|---|
| Website Statistics | Visitors, page views, IPs, traffic, spiders and AI crawlers, regions, pages, sources, status codes, clients, error log; hourly/daily trends with comparison; live requests per minute |
| Network Scan Detection | Counts probes to closed ports in the kernel and blocks scanners (sliding window + distinct ports), block records, real-time probe log, whitelist |
| Network Threat Detection | Threat-intelligence lists in monitor or block mode, outbound botnet (C&C) detection, IP lookup, optional Suricata IDS with Emerging Threats rules |
| System Hardening | Monitor or lock users, SSH, cron, services, start-up files, binaries and custom folders; maintenance pause; process guard; compliance score with fixes; sign-in/sudo audit |
| PHP Security | Snuffleupagus (pinned, commit-verified) built per PHP version; block / log-only / off per rule; trusted folders; events with script, line and visitor |

No App ever blocks an address an administrator signed in from in the last 7 days.

## App Store: one-click updates

- "Update available" is now a button. It opens a dialog that lists the packages
  and their versions, and installs the update in place on the same version
  track (configuration files kept, running services restarted once).
- The badge is shown only for updates this server can actually install: what
  its own package sources (apt / dnf) offer for that software's packages. The
  old badge compared with the newest upstream release, so Python showed
  "3.12.16" on Ubuntu, which only ships 3.12.3 builds, and nothing could
  install it. Distribution fixes with the same version number are shown as
  "Security update". Package lists refresh in the background every 6 hours.
- Works for Docker, Python, PHP (all installed versions), Nginx, Apache,
  OpenLiteSpeed, Caddy, MySQL, MariaDB, MongoDB, PostgreSQL, Redis, Node.js,
  Pure-FTPd, Fail2ban, Postfix, ClamAV, BIND, Supervisor and Memcached;
  Composer updates itself with `composer self-update`.
- PHP: the "Add version" list no longer offers versions that are already
  installed (those are updated with the badge), so a PHP row never shows
  "update" and "install 8.5" for the same version.
- Version lists show plain versions; the word "recommended" is gone. The
  suggested version is still pre-selected.
- Version pickers are only as wide as their text and sit on one line with the
  Install button; version badges no longer stretch across the status column.
- BIND9 shows real versions (from isc.org): 9.20.30 current stable and
  extended support (ISC PPA bind-esv), 9.21.27 development (ISC PPA bind-dev),
  9.18 end of life (distribution package). The old "Current stable" entry
  without a version is gone.

## Fixed

- **Python/PHP uninstall** could remove the system's own Python (`version: "3"`) or
  every PHP version (`version: "-common"`); the version must now be a real `X.Y`.
- **Uninstalling ModSecurity** left `modsecurity off;` in the panel's own site configs
  (`/etc/nginx/vortex`), so the next nginx reload failed.
- **ufw deny/reject rules** were appended below existing allow rules and never applied;
  they are now inserted first (`ufw prepend`, with fallbacks). Blocking an IPv6
  address from the SSH sign-ins page works on ufw.
- **firewalld**: rule changes used `--reload`, which silently dropped every fail2ban ban;
  changes are now applied permanently and at runtime without a reload. "Limit" on
  firewalld is a real rate limit instead of a plain allow.
- **App Store "Nginx Load Balancer"** entry removed: it could not install, showed as
  installed whenever Security > Load Balancer was configured, and its Uninstall deleted
  that live configuration.
- **Load balancer**: re-saving reset the domain, port and cookie name; a nameless
  balancer on port 80/443 captured every unmatched request (a domain is now required
  there); the health checker marked backends without a port, IPv6 backends and unix
  sockets as down; the TCP balancer accepted ports already in use; the health-check
  script is refreshed when it changes; saves and health rewrites no longer race.
- **Website Anti-CC jails** counted CSS, JS, images and fonts, banning ordinary visitors;
  static files are ignored and the default limit is 120 requests per 60 s.
- **Malware scan** was reported as stopped during long ClamAV runs and a second scan
  could start; the scan now keeps its heartbeat while it runs.
- **WAF**: deleting the last region rule disabled country conditions in custom rules;
  1,000+ blacklisted IPs collided with other rule IDs (IPs are grouped, lists capped);
  concurrent WAF and load-balancer saves no longer overwrite each other.
- **ModSecurity v2 on RHEL-family** servers is wired into Apache and detected as installed.
- **Viewer role** can no longer read server logs (auth, mail) through the Monitoring API.
- **App Store** showed MySQL as unavailable when PostgreSQL or MongoDB was installed;
  the page now uses the server's conflict rules (only MySQL and MariaDB exclude each other).
- **Plugins** can no longer shadow the panel's own Python modules or each other's, and
  a plugin's entry file must be inside its folder.
- **Plugin pages** (Hosting Accounts and Apps) were rebuilt every time another plugin page
  loaded, which reset what the admin was doing on them.

## Upgrade

Upload `vortex_upgrade_3.10.0.py` to `/root/` and run `python3 /root/vortex_upgrade_3.10.0.py`.
It upgrades from 3.9.3. Apps are not installed automatically: open App Store and install
the ones you want.
