# VortexPanel 3.11.3

## Security: protection against replaced programs and panel backdoors

In November 2026 researchers reported "CWPdoor": attackers who already had root on
servers running Control Web Panel (CWP) replaced the panel's own web server with a
backdoored copy. It ran any command sent in a secret header, kept those requests out
of the logs, and got its original timestamps back so `ls` and `stat` showed no change.
The same samples were found next to the Ebury SSH backdoor. VortexPanel already
refused unsigned updates; this release adds the checks that find such a replacement
after the fact. They are part of **System Hardening 1.1.0** (Apps).

**Disguised replacements are now detected.** The file monitor also records each
file's change time, which a program cannot set back, and hashes files of every size.
A program rewritten in place with the same size and the old date is reported. A
changed program or login library is checked against its package right away: a real
update or reinstall is reported as low, anything else as critical.

**New area: Login libraries.** PAM modules, libkeyutils, libpam, libcrypt,
/etc/pam.d and nsswitch.conf, where Ebury and PAM backdoors hide. System binaries
now also cover /usr/local/bin, /usr/local/sbin and the OpenSSH helpers.

**New: Integrity check** (System Hardening > Integrity, runs every day):
- **VortexPanel files** against the signed release tag the panel was installed from,
  including every compiled `__pycache__` file (a planted `.pyc` runs even when the
  `.py` next to it is clean). **Restore from the signed release** puts changed files
  back, moves foreign code to quarantine and restarts the panel.
- **Installed Apps** against the signed release or the published package.
- **Panel Python packages** (Flask, gunicorn, ...) against what pip installed, and
  `.pth` files that run code at every Python start.
- **VortexPanel software builds** against the exact package on the download server
  (signed catalog), or the file list recorded at install time.
- **System packages**: SSH, sudo, PAM, core tools and the package of every running
  program, against the package manager's checksums (dpkg / rpm).
- **Known backdoors**: CWPdoor (its socket and marker), Ebury (its library names,
  a libkeyutils that loads an extra library, libkeyutils in tls/ folders, fake dbus
  sockets), /etc/ld.so.preload and LD_PRELOAD in running programs.

New problems are sent through Settings > Alerts.

## Other changes

- VortexPanel software builds record the sha256 of every file from the verified
  package when they are installed (`.vortex/files.json`).

## Upgrade

Panels on 3.11.2: **Settings > Update**, then **Apps > System Hardening > Update to 1.1.0**.
