# VortexPanel 3.11.3

## App Store

- **One App Store, managed by VortexPanel.** Software is installed and updated from
  the VortexPanel download server without separate labels or buttons: the
  "VortexPanel build" tag and the "Use VortexPanel build" button are gone.
- **Software installed earlier from the OS packages** shows the normal
  **Update to vX** button when a newer version of the same line is available. The
  update moves it to the VortexPanel version; configuration, websites and data are
  kept, and the previous setup comes back if the new version does not start.

## Fixes

- **Anubis Bot Protection** installs from the VortexPanel download server. Before,
  the install stopped with "The download addresses for Anubis are not valid".

## Upgrade

Upload `vortex_upgrade_3.11.3.py` to `/root/` and run `python3 /root/vortex_upgrade_3.11.3.py`.
It upgrades from 3.11.2.
