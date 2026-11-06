# VortexPanel 3.11.1

## Software builds switched on

The App Store now installs and updates server software, mirrored tools and
VortexPanel Apps from the VortexPanel download server (`https://dl.vortexpanel.dev`).

- The panel accepts only a catalog signed with the VortexPanel release key
  (`panel/trust/softs.json`) and checks every download against its SHA-256.
- Software already installed from the OS packages keeps running unchanged. It is moved
  to a VortexPanel build only when you choose **Use VortexPanel build**.
- A system upstream publishes nothing for, or one whose glibc is too old for a build,
  keeps installing from its OS package sources.
- Panels check for updates every 6 hours; settings are in App Store > Software updates.

## Upgrade

Upload `vortex_upgrade_3.11.1.py` to `/root/` and run `python3 /root/vortex_upgrade_3.11.1.py`.
It upgrades from 3.11.0.
