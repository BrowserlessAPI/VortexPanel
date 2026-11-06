# VortexPanel 3.11.4

## App Store

- **Install dialog.** Installing software opens a dialog with the version list and what
  will happen: downloaded from the VortexPanel download server and checked against its
  signed checksum, the previous setup restored if it does not start.
- **Software installed earlier from the OS packages is taken over** when you install
  the same version line (for example PHP 8.5 from Ubuntu): the OS packages are
  replaced, configuration files, websites and data are kept. Before, the install
  stopped with "PHP is installed from the operating system packages".
- **Faster App Store.** The list checks all apps at the same time instead of one
  after another.

## Fixes

- **No login screen flash.** While the panel is restarting or busy, the browser keeps
  checking the session for up to a minute instead of showing the login screen.
- **No dialogs flashing while the page loads** (Import Website, file picker and others
  showed for a moment before the panel had started).

## Upgrade

Upload `vortex_upgrade_3.11.4.py` to `/root/` and run `python3 /root/vortex_upgrade_3.11.4.py`.
It upgrades from 3.11.3.
