# VortexPanel 3.9.2

A fix for the Hosting Module licence status.

## Fixed

- A licence that was revoked, refunded, released or that reached the end of its paid
  period kept showing as active in the panel until the next scheduled check-in (up to
  12 hours later). Only **Check licence now** showed the real state.
  - Opening the Hosting Module page now checks in with the licence server when the last
    answer is more than 2 minutes old.
  - The background check-in runs at least every hour, and right after the paid period ends.
  - A Hosting Module admin action (new account, package change) checks in first when the
    last answer is more than 10 minutes old.
  - A prepaid licence counts as ended at its period end even if the last answer was older.
- Clear titles on the Hosting Module page: Licence revoked, Licence refunded, Licence
  expired, Licence no longer on this server (released, moved or deleted on the licence
  server), with what to do next.

When the licence server cannot be reached, nothing changes: the licence keeps working
for its offline grace period and the panel retries after 2 minutes on the page, or
15 minutes in the background.

## Upgrade

Upload `vortex_upgrade_3.9.2.py` to `/root/` and run `python3 /root/vortex_upgrade_3.9.2.py`.
It upgrades from 3.9.1.
