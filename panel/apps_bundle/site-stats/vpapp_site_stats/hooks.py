"""Install / upgrade / uninstall steps for Website Statistics (run by panel/apps.py)."""
from panel import appkit

APP = 'site-stats'


def install(log):
    # Optional: country lookups (the country database itself is downloaded from the App page)
    rc, _, err = appkit.run([appkit.venv_python(), '-c', 'import maxminddb'], timeout=30)
    if rc != 0:
        rc, _, err = appkit.run([appkit.venv_python(), '-m', 'pip', 'install', '--quiet', '--disable-pip-version-check',
                                 'maxminddb>=2.5,<3'], timeout=300)
        log('Country lookups enabled (maxminddb).' if rc == 0 else
            'maxminddb could not be installed (no internet?); everything works except the Regions view.')
    from vpapp_site_stats import collector, store
    store.connect().close()
    n = len(collector.log_sources())
    log(f'Found {n} website access log(s); the collector reads the last 64 MB of each to start with.')
    appkit.install_service(APP, 'vpapp_site_stats.collector', description='Website Statistics collector')
    state = appkit.service_state(appkit.unit_name(APP))
    log(f'Service {appkit.unit_name(APP)}: {state}')
    if state != 'active':
        raise RuntimeError('the collector did not start: journalctl -u ' + appkit.unit_name(APP))


def upgrade(log, old_version):
    install(log)


def uninstall(log, purge):
    appkit.remove_units(APP)
    log('Collector stopped. Your websites and their logs are not changed.')
