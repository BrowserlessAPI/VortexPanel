# VortexPanel v3.6.0

A feature release. It completes the v3.5 roadmap: per-website backups with
schedules and cloud upload, per-website traffic history, a disk usage
analyzer, dark mode, a mobile layout, a first-run setup guide, and SSL, cron
and email migration in Website Import. Everything was tested on a real
Ubuntu 24.04 system with systemd. The 512 end-to-end tests from v3.5.3 still
pass, and every page was checked in light mode, dark mode and at phone width.

## Website backups (files + databases, schedules, cloud)
- **One-click website backup:** a site's folder and its databases go into
  one archive. Databases are found automatically from `wp-config.php` or
  `.env`, or by the name the panel gives a new site's database. You can
  also pick them by hand.
- **One-click restore:** files and databases go back where they came from.
  You can restore only the files or only the databases, or put the files in
  another folder. The old files stay in place until the restored ones are
  ready, so a failed restore changes nothing.
- **Schedules per website:** every 1-12 hours, daily, weekly or monthly.
  You choose how many copies to keep on the server and in cloud storage,
  and which folders to leave out (for example `wp-content/cache`).
- **Cloud upload:** each scheduled backup can be sent to the S3-compatible
  storage set up under Backups > Cloud Storage (AWS, Backblaze B2, Wasabi,
  DigitalOcean Spaces, MinIO and others). Old copies are removed there too.
- **Backups page:** a new **Website Backups** tab shows each site's
  databases, schedule, next run and the result of the last backup. The
  Website Backup card now includes the database.
- **Scheduler:** a systemd timer (`vortexpanel-backups.timer`) checks every
  5 minutes. A missed run (server off) runs once when the server is back.
  Results are logged to `/var/log/vortexpanel/site-backups.log`.

## Bandwidth: traffic per website
- **New Website Traffic chart:** data sent and requests per website, over
  24 hours, 7 days, 30 days or 12 months.
- **Top websites list and table:** each site's share of the traffic and a
  14-day trend line.
- **Data source:** each site's access log (Nginx, Apache, OpenLiteSpeed
  and Caddy), read every 5 minutes by `vortexpanel-bandwidth.timer`.
  Traffic is counted in the hour it happened, rotated and truncated logs
  are handled, and nothing is counted twice.

## Disk Usage (new page)
- **Disk overview:** every disk with its used and free space, plus a
  warning when inodes run low.
- **Scan:** see which folders use the space, drill down through them, and
  list the largest files.
- **Actions:** open any item in the File Manager, or delete it. Folders of
  the operating system, package databases, database servers, Docker and
  the panel itself cannot be deleted from here.

## Dark mode and mobile layout
- **Theme switch:** Light, Dark or System in the top bar. The choice is
  remembered per browser and applied before the page appears, so there is
  no white flash. Charts change colour with the theme.
- **Mobile layout:**
  - Below tablet width the sidebar becomes a slide-in menu.
  - Tables scroll sideways inside their card.
  - Forms and grids collapse to one column.
  - Dialogs open as full-width sheets.
  - Inputs no longer make iOS zoom in.

## Setup guide (first run)
- **When it opens:** on the first login to a server with no websites. It
  can be skipped, and reopened later from Settings > Panel Settings >
  Setup guide.
- **Steps:**
  - Install a web server, database, PHP versions and extras, with live
    progress.
  - Turn on the firewall and fail2ban, change the panel password and set
    up 2FA.
  - Create the first website, with an optional database.

## Website Import: SSL, cron and email
- **SSL certificate:** a certificate in the backup whose names cover the
  domain and whose private key matches is shown in the preview and
  installed. Expired certificates are not installed.
- **Cron jobs:** cPanel crontabs and HestiaCP/Vesta `cron.conf` entries
  are listed and can be edited before import. Paths of the old account
  (`/home/<user>/public_html` and similar) are pointed at the new site
  folder. Jobs run as the web server user, not root.
- **Mailboxes:** Maildir mailboxes are imported with all their folders.
  Users keep their passwords when the backup has the password hash (cPanel
  `shadow`, HestiaCP/Vesta account files). Otherwise a new password is set
  and shown once.
- **HestiaCP `.tar.zst` backups** can now be imported when `zstd` is
  installed.

## Mail Server
- **App Store:** a new **Mail Server** app installs Postfix and Dovecot.
- **Mail Server page:** a **Set up mail server** card finishes the
  configuration.
- **Fixed:** on kernels with IPv6 disabled, Dovecot did not start ("Address
  family not supported by protocol"), so mail setup always rolled back.

## Other fixes and changes
- **Fixed:** "Static (no PHP)" in Add Site still gave the site a PHP
  handler. Static sites are now really static on Nginx, Apache and Caddy,
  and can be switched to a PHP version later from the PHP tab.
- **Faster sign-in:** pages no longer send about 50 requests before you
  sign in. Those requests all failed with "Unauthorized", and some showed
  error toasts on the login screen.
- **Login page:** shows the real panel version (it said v3.4).
- **Phones:** stat cards show two per row instead of one.

## Upgrading
Run `python3 /root/vortex_upgrade_3.6.0.py` on the development server. It
updates /root/Vortexpanel, deploys to the running panel with a health check
and automatic rollback, then asks before it commits, pushes and tags v3.6.0.
The two background timers are installed automatically when the panel starts.
If commit signing is set up for git on the server, the commit and the tag
are signed.
