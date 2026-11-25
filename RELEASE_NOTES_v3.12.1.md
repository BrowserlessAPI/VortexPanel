# VortexPanel 3.12.1

## VortexPanel Apps: download address set

3.12.0 moved VortexPanel's own Apps (System Hardening, PHP Security, Website Statistics,
Network Scan Detection, Network Threat Detection) to their own Cloudflare R2 bucket, but
shipped without its address, so the App Store could not list or update them.

- The App Store now downloads the Apps from `https://apps.vortexpanel.dev`
  (`panel/trust/softs.json` "apps_url").
- Nothing else changed: the App index is signed with the VortexPanel catalog key and every
  package is checked against the signed SHA-256 before it is installed, so the bucket only
  stores the files and is never trusted.
- Installed Apps keep working and keep their data; the App Store offers the new versions
  (PHP Security 1.2.0, System Hardening 1.2.2, Website Statistics 1.1.1, Network Scan
  Detection 1.0.1, Network Threat Detection 1.0.1) as updates.

## Software builds (pipeline)

- Fresh-system tests no longer fail on the container's login console (`getty`), which broke
  tests of software that had passed every check.
- A build's glibc requirement is capped at the build system's own glibc: RHEL 9 backports
  symbols tagged GLIBC_2.35 into its glibc 2.34, which made the EL9 PHP 8.6 build refuse EL9.
- A stalled test-image build is retried instead of failing the job.
- PHP 8.6 builds on EL8 (FreeType 2.9): the bundled GD now includes FreeType the supported way.

## Upgrade

Panels on 3.12.0: **Settings > Update**, then **App Store** to update the installed Apps.
