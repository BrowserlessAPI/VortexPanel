# VortexPanel 3.9.3

A hardening update for the Hosting Module licence gate.

## Changed

- When the Hosting Module is installed or updated, the panel now compiles the
  module's licence gate to a native library (`licence_gate*.so`) and removes the
  Python source, so the licence check cannot simply be opened and edited to run
  the module unlicensed.
  - It uses this panel's own venv Python, so the compiled library matches the
    Python that loads it.
  - It is best-effort: on a panel without a C compiler (or offline for the one-time
    Cython download), the gate is left as source and still enforces normally. The
    install is never blocked by this step.
  - Set `VP_NO_GATE_COMPILE=1` in the panel environment to skip it.

This needs Hosting Module 3.3.0 or newer (the release that ships the gate and the
compile helper). Existing customer sites, mail and the customer portal are not
affected; the gate only guards new hosting accounts and package changes.

## Upgrade

Upload `vortex_upgrade_3.9.3.py` to `/root/` and run `python3 /root/vortex_upgrade_3.9.3.py`.
It upgrades from 3.9.2.
