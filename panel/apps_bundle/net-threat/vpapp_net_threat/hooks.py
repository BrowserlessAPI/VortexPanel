"""Install / upgrade / uninstall steps for Network Threat Detection (run by panel/apps.py)."""
from panel import appkit

APP = 'net-threat'


def install(log):
    if not appkit.have('nft'):
        if not appkit.pkg_install(['nftables'], log) or not appkit.have('nft'):
            raise RuntimeError('nftables could not be installed')
    from vpapp_net_threat import engine as E
    for ok, m in E.update_all():
        log(m)
    ok, err = E.apply()
    if not ok:
        raise RuntimeError('the kernel rejected the threat table: ' + err[-300:])
    log('Threat lists loaded into table vp_net_threat (monitor mode; outbound botnet traffic is blocked).')
    appkit.install_service(APP, 'vpapp_net_threat.worker', description='Network Threat Detection')
    state = appkit.service_state(appkit.unit_name(APP))
    log(f'Service {appkit.unit_name(APP)}: {state}')
    if state != 'active':
        raise RuntimeError('the detection service did not start: journalctl -u ' + appkit.unit_name(APP))


def upgrade(log, old_version):
    install(log)


def uninstall(log, purge):
    appkit.remove_units(APP)
    appkit.nft_drop_table(APP)
    import os
    if os.path.exists('/etc/suricata/suricata.yaml') and appkit.service_state('suricata') == 'active':
        log('Suricata is left running (it may be used by something else); stop it with: systemctl disable --now suricata')
    log('Threat detection stopped and table vp_net_threat removed.')
