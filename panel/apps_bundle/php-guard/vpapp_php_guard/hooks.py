"""Install / upgrade / uninstall steps for PHP Security (run by panel/apps.py)."""
from panel import appkit

APP = 'php-guard'


def install(log):
    from vpapp_php_guard import engine, rules
    s = engine.settings()
    engine.write_rules(rules.build(s['modes'], s['trusted']))
    vers = [l['ver'] for l in engine.layouts()]
    log('PHP versions found: ' + (', '.join(vers) if vers else 'none (install PHP from the App Store first)'))
    log('Turn protection on per PHP version from the App page: the module is built for that version there '
        '(it takes a minute or two).')


def upgrade(log, old_version):
    from vpapp_php_guard import engine
    ok, err = engine.apply_rules()
    log('Rules refreshed.' if ok else 'Rules could not be refreshed: ' + err)


def uninstall(log, purge):
    from vpapp_php_guard import engine
    engine.disable_all()
    appkit.remove_units(APP)
    import os
    try:
        os.remove(engine.RULES_FILE)
    except OSError:
        pass
    log('PHP Security turned off for every PHP version (the module files stay in the PHP extension folders, unused).')
