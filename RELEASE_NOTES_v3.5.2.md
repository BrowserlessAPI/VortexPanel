# VortexPanel v3.5.2

An App Store reliability release. Every App Store app was installed and then
uninstalled through the panel's own API on a real Ubuntu 24.04 system with
systemd. Every failure that was found is fixed here, including the
"cannot uninstall Caddy" report.

## Uninstall (and install) when the package manager is busy
- **Cause of the Caddy report:** uninstalling failed when another process held
  the apt/dpkg lock. That process can be the panel's Security Updates check,
  unattended-upgrades, or a second install. This was reproduced exactly.
  - `apt-get remove` failed in under a second.
  - Its error output was thrown away (`2>/dev/null`), so the window stayed
    empty.
  - The final result line was written after the job was marked finished, so
    it never reached the browser.
  - Caddy was left stopped and disabled, but still installed.
- **Uninstall now waits** (up to 10 minutes) until no other process holds the
  package lock, *before* it stops or changes anything. The window says which
  process is holding the lock.
- **If the lock never frees,** the job ends with "Nothing was changed" and the
  app keeps running.
- **Every App Store job runs with package-manager wrappers.** They:
  - wait for and retry on the apt/dpkg lock while streaming output live
  - show apt, dnf and yum errors even when the command discarded them
  - skip uninstall package names that aren't installed (a single unknown name
    used to abort the whole removal)
  - repair an interrupted dpkg ("run dpkg --configure -a") once,
    automatically
- **If a removal still fails,** a service that was running before is started
  again, and the window says so. A half-removed app is no longer left down.
- **The result message is always the last line,** and it is shown next to
  the Close button instead of "Check output above".

## Job window can no longer hang on "Working..."
- **The live output stream** no longer stops after 6 minutes. It sends
  keep-alives so proxies (nginx, Cloudflare) don't close it during long,
  silent steps.
- **If the stream drops,** the window switches to polling the job status and
  still shows the result. Reconnects continue from the last line instead of
  repeating it.
- **Unexpected errors** inside a job (for example a service that would not
  stop) now end the job with the error shown. Before, the job silently died.
- **A job orphaned by a panel restart** is reported as such.
- **Close button:** it can be used at any time. While a job is running it
  reads "Hide (keeps running)".
- **Timeouts:** jobs are now stopped by a real watchdog, even when the
  command has gone silent. The limits are 30 minutes for install and version
  switch, 20 for uninstall, and the ffmpeg download allows up to 20 minutes.

## Python Manager
- **Safety fix:** "Uninstall" without a version used to remove the operating
  system's own Python (3.12 on Ubuntu 24.04), together with python3, apt
  tooling, netplan, cloud-init, certbot and fail2ban. The server's Python can
  now never be removed from the panel. The uninstall picker lists only extra
  versions that are really installed.
- **Failed installs were reported as successful:** a trailing `|| true` hid
  every failure, and the check (`which python3`) is true on every server.
  - Installs now stop on the first error.
  - The requested `pythonX.Y` must exist afterwards.
  - Installing the server's own version sets up pip, venv and headers for it.
- **RHEL family:** the RHEL / AlmaLinux / Rocky install was a shell syntax
  error. Fixed.

## Roundcube
- **Install never worked:** a block of settings-page code had been pasted
  into the install route, so Install returned settings data instead of
  starting. That same paste is why the Roundcube Settings page had no data.
  Both are fixed.
- **Install uses PHP-FPM.** It no longer installs the `php` metapackage,
  which pulled in Apache next to nginx. An existing PHP-FPM version is reused.
- **nginx site:** Roundcube is served by nginx on port 8083 with config, temp
  and logs blocked, and the port is opened in ufw/firewalld. Uninstall removes
  the site and closes the port.
- Download and extract failures are reported clearly.

## Other App Store fixes
- **Memcached:** on servers with IPv6 disabled, memcached crash-looped while
  being reported as installed. It now listens on 127.0.0.1 only on such
  servers.
- **All apps:** "Installed" now warns when the app's service is not running,
  and shows the service's last log lines.
- **Redis:** falls back to the Ubuntu/Debian package when packages.redis.io
  cannot be reached. Before, only "no release for this codename" was handled.
- **PHP install on Ubuntu:**
  - falls back to packages.sury.org when Launchpad (ondrej/php) cannot be
    reached
  - installs `add-apt-repository` when it is missing
  - says clearly when neither source is reachable
- **PHP uninstall-all** now includes 8.0 and 8.5.
- **Apache, BIND9, Python on RHEL / AlmaLinux / Rocky:** the RHEL command
  translation commented out the rest of these one-line install scripts, so
  they failed with a shell syntax error. Fixed.
- **Fedora / RHEL repositories:** `%fedora` / `%rhel` macro detection fixed
  for nginx, MySQL, MongoDB, PostgreSQL, OpenLiteSpeed and the Remi repos
  (PHP, Redis). Fedora now gets the Fedora Remi repo.
- **Caddy WAF uninstall** no longer stops Caddy, and never leaves it stopped
  when there is no backup binary.
- **nginx install:**
  - a failed install could report success, because the final setup step
    hid the error
  - nginx-lb refuses to install without nginx, and removes its config if
    `nginx -t` rejects it
- **MariaDB uninstall** cleanup no longer stops early on RHEL-family systems.
- **Uninstall no longer runs `systemctl stop`** for apps that have no service.
- **Built-in apps** (CDN Manager) can't be uninstalled through the API.
- **Uninstall confirmation** now warns about what will be deleted for each
  app: databases, nginx/Caddy/OpenLiteSpeed configuration, DNS zones,
  Roundcube files.
- **Settings > Switch Version** lists now come from the App Store catalog.
  They had outdated lists, for example MySQL 9.3, MongoDB 6.0 and no
  PostgreSQL 18.
- **Job output:** dpkg's "Reading database ... 5%" progress spam is filtered
  out.
- **Job output endpoints** now require login.

## Upgrading
Run `python3 /root/vortex_upgrade_3.5.2.py` on the development server. It
updates /root/Vortexpanel, deploys to the running panel with a health check
and automatic rollback, then asks before it commits, pushes and tags v3.5.2.
Installed panels will then show "Update Available".
