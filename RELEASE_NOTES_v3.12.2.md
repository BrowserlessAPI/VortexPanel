# VortexPanel 3.12.2

## VortexPanel Apps are signed with their own key

The App index (the list of VortexPanel's own Apps the App Store reads from
`https://apps.vortexpanel.dev`) is now signed with a separate Apps key instead of the
software catalog key.

- `panel/trust/softs.json` has a new list, "apps_keys". A key there is accepted for the
  App index only, online and in offline bundles, and never for the software catalog, so
  the software builds and the Apps are signed independently.
- The catalog keys ("keys") are still accepted for the App index, as before.
- Every App package is still checked against the signed SHA-256 in the index before it is
  installed, so the bucket only stores the files and is never trusted.
- Installed Apps keep working and keep their data. Panels need 3.12.2 to read the App
  index; after the update the App Store offers PHP Security 1.2.0, System Hardening 1.2.2,
  Website Statistics 1.1.1, Network Scan Detection 1.0.1 and Network Threat Detection
  1.0.1.

## Upgrade

Panels on 3.12.1 or 3.12.0: **Settings > Update**, then **App Store** to update the
installed Apps.
