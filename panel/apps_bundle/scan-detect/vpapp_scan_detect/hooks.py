"""Install / upgrade / uninstall steps for Network Scan Detection (run by panel/apps.py)."""
from panel import appkit

APP = 'scan-detect'


def install(log):
    if not appkit.have('nft'):
        if not appkit.pkg_install(['nftables'], log) or not appkit.have('nft'):
            raise RuntimeError('nftables could not be installed')
    if not appkit.have('ss'):
        appkit.pkg_install(['iproute2'] if appkit.os_family() == 'debian' else ['iproute'], log)
    from vpapp_scan_detect import engine
    ok, err = engine.apply()
    if not ok:
        raise RuntimeError('this kernel/nftables rejected the detection table: ' + err[-300:])
    log('Detection table vp_scan_detect is active (separate from your firewall rules).')
    appkit.install_service(APP, 'vpapp_scan_detect.worker', description='Network Scan Detection')
    state = appkit.service_state(appkit.unit_name(APP))
    log(f'Service {appkit.unit_name(APP)}: {state}')
    if state != 'active':
        raise RuntimeError('the detection service did not start: journalctl -u ' + appkit.unit_name(APP))


def upgrade(log, old_version):
    install(log)


def uninstall(log, purge):
    appkit.remove_units(APP)
    appkit.nft_drop_table(APP)
    log('Detection service stopped and table vp_scan_detect removed; blocked addresses are released.')
