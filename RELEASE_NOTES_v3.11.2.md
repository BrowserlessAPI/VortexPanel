# VortexPanel 3.11.2

## Fixes

- **App Store right after the upgrade to 3.11.1 or later:** the signed software catalog
  is fetched on the first App Store visit. Before, the App Store kept offering the OS
  package versions ("Distro-provided") until the 6-hourly check had run once.
- **ClamAV from the OS packages:** the first signature download no longer fails with
  "Failed to lock the log file" (the clamav-freshclam service is paused for it and
  started again right after).

## Upgrade

Upload `vortex_upgrade_3.11.2.py` to `/root/` and run `python3 /root/vortex_upgrade_3.11.2.py`.
It upgrades from 3.11.1.
