"""Install / upgrade / uninstall steps for System Hardening (run by panel/apps.py)."""
from panel import appkit

APP = 'sys-harden'


def install(log):
    if not appkit.have('chattr'):
        appkit.pkg_install(['e2fsprogs'], log)
    from vpapp_sys_harden import guard
    n = 0
    for aid in guard.all_areas():
        if guard.area_mode(aid, guard.config()) != 'off' and guard.load_baseline(aid) is None:
            snap = guard.snapshot(aid)
            guard.save_baseline(aid, snap)
            n += len(snap)
    log(f'Recorded the current state of {n} protected files (changes from now on are reported).')
    appkit.install_service(APP, 'vpapp_sys_harden.worker', description='System Hardening')
    state = appkit.service_state(appkit.unit_name(APP))
    log(f'Service {appkit.unit_name(APP)}: {state}')
    if state != 'active':
        raise RuntimeError('the protection service did not start: journalctl -u ' + appkit.unit_name(APP))


def upgrade(log, old_version):
    install(log)


def uninstall(log, purge):
    appkit.remove_units(APP)
    from vpapp_sys_harden import guard
    n, errs = guard.unlock_area(None)
    log(f'Protection stopped; {n} lock(s) this App had set were removed.' + (' Problems: ' + '; '.join(errs) if errs else ''))
