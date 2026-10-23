"""Background tasks of the panel, run by systemd timers instead of the web
workers (gunicorn runs several processes, and none of them should own a
schedule):

    vortexpanel-bandwidth.timer  every 5 minutes  per-site traffic history
    vortexpanel-backups.timer    every 5 minutes  scheduled website and panel backups,
                                                  Hosting Module licence check-in (when due)
    vortexpanel-metrics.timer    every minute     monitoring history, alerts,
                                                  App Store version data (daily)

    python3 -m panel.tasks bandwidth
    python3 -m panel.tasks backups
    python3 -m panel.tasks metrics
    python3 -m panel.tasks install-timers
"""
import os, sys, subprocess

PANEL_DIR = '/opt/vortexpanel'
UNIT_DIR = '/etc/systemd/system'

_UNITS = {
    'vortexpanel-bandwidth': ('VortexPanel per-site traffic history', 'bandwidth', 'OnCalendar=*:0/5\nRandomizedDelaySec=30'),
    'vortexpanel-backups': ('VortexPanel scheduled website backups', 'backups', 'OnCalendar=*:0/5'),
    'vortexpanel-metrics': ('VortexPanel monitoring history and alerts', 'metrics', 'OnCalendar=*:*:00\nAccuracySec=5s'),
}


def _python():
    for p in (os.path.join(PANEL_DIR, 'venv/bin/python3'), sys.executable, '/usr/bin/python3'):
        if p and os.path.exists(p):
            return p
    return 'python3'


def _unit_texts(name, desc, cmd, cal):
    service = (f'[Unit]\nDescription={desc}\nAfter=network-online.target\n\n'
               f'[Service]\nType=oneshot\nWorkingDirectory={PANEL_DIR}\n'
               f'ExecStart={_python()} -m panel.tasks {cmd}\n'
               'Nice=10\nIOSchedulingClass=best-effort\nIOSchedulingPriority=7\n'
               'TimeoutStartSec=8h\n')
    timer = (f'[Unit]\nDescription={desc} (timer)\n\n'
             f'[Timer]\n{cal}\nPersistent=true\nUnit={name}.service\n\n'
             '[Install]\nWantedBy=timers.target\n')
    return service, timer


def install_timers():
    """Write the units if they changed and enable the timers. Safe to call on
    every panel start; returns a list of problems (empty when all is well)."""
    problems = []
    if not os.path.isdir('/run/systemd/system'):
        return ['systemd is not running - scheduled tasks are disabled']
    changed = False
    for name, (desc, cmd, cal) in _UNITS.items():
        service, timer = _unit_texts(name, desc, cmd, cal)
        for path, text in ((f'{UNIT_DIR}/{name}.service', service), (f'{UNIT_DIR}/{name}.timer', timer)):
            try:
                cur = open(path).read() if os.path.exists(path) else None
            except OSError:
                cur = None
            if cur != text:
                try:
                    tmp = path + '.tmp'
                    with open(tmp, 'w') as f:
                        f.write(text)
                    os.chmod(tmp, 0o644)
                    os.replace(tmp, path)
                    changed = True
                except OSError as e:
                    problems.append(f'{path}: {e}')
    try:
        if changed:
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, timeout=60)
        for name in _UNITS:
            r = subprocess.run(['systemctl', 'is-enabled', f'{name}.timer'], capture_output=True, text=True, timeout=30)
            a = subprocess.run(['systemctl', 'is-active', f'{name}.timer'], capture_output=True, text=True, timeout=30)
            if changed or r.stdout.strip() != 'enabled' or a.stdout.strip() != 'active':
                e = subprocess.run(['systemctl', 'enable', '--now', f'{name}.timer'], capture_output=True, text=True, timeout=60)
                if e.returncode != 0:
                    problems.append(f'{name}.timer: {e.stderr.strip()[:200]}')
    except Exception as e:
        problems.append(str(e))
    return problems


def timer_status():
    out = {}
    for name in _UNITS:
        try:
            r = subprocess.run(['systemctl', 'show', f'{name}.timer', '-p', 'ActiveState', '-p', 'NextElapseUSecRealtime',
                                '-p', 'LastTriggerUSec'], capture_output=True, text=True, timeout=15)
            d = dict(l.split('=', 1) for l in r.stdout.splitlines() if '=' in l)
            out[name] = {'active': d.get('ActiveState') == 'active', 'next': d.get('NextElapseUSecRealtime', ''),
                         'last': d.get('LastTriggerUSec', '')}
        except Exception:
            out[name] = {'active': False}
    return out


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ''
    if cmd == 'bandwidth':
        from panel import bwstats
        print(bwstats.collect())
        return 0
    if cmd == 'backups':
        from panel import sitebackup
        for domain, ok, msg in sitebackup.run_due():
            print(f'{domain}: {"ok" if ok else "FAILED"} - {msg}')
        try:
            from panel.routes.files import recycle_purge_old
            n = recycle_purge_old()
            if n:
                print(f'recycle bin: {n} old item(s) removed')
        except Exception as e:
            print(f'recycle bin: {e}')
        try:
            from panel.routes.websites_extras import run_expiry
            for domain, ok, err in run_expiry():
                print(f'{domain}: expired - {"stopped" if ok else "could not stop: " + str(err)}')
        except Exception as e:
            print(f'site expiry: {e}')
        try:
            from panel import panelbackup
            r = panelbackup.run_due()
            if r:
                print(r)
        except Exception as e:
            print(f'panel backup: {e}')
        try:
            from panel.routes.databases import recycle_purge
            recycle_purge()
        except Exception as e:
            print(f'database recycle bin: {e}')
        try:
            from panel import malware
            malware.run_due()
        except Exception as e:
            print(f'malware scan: {e}')
        try:
            from panel import mailx
            r = mailx.maintenance()
            if r:
                print(f'mail: {r}')
        except Exception as e:
            print(f'mail: {e}')
        try:
            from panel import licence
            r = licence.refresh_if_due()
            if r not in ('no licence', 'not due'):
                print(f'hosting module licence: {r}')
        except Exception as e:
            print(f'hosting module licence: {e}')
        return 0
    if cmd == 'malware-scan':
        from panel import malware
        path = sys.argv[2] if len(sys.argv) > 2 else '/www/wwwroot'
        ok, err = malware.start(path, (sys.argv[3] if len(sys.argv) > 3 else '1') == '1', trigger='schedule', wait=True)
        print('scan done' if ok else f'scan not started: {err}')
        return 0 if ok else 1
    if cmd == 'metrics':
        from panel import metrics, alerts
        s = metrics.collect()
        print(f'cpu {s["cpu"]}% mem {s["mem"]}% disk {s["disk"]}%')
        try:
            for m in alerts.evaluate():
                print('alert:', m)
        except Exception as e:
            print(f'alerts: {e}')
        try:
            from panel import versions
            versions.refresh()
        except Exception:
            pass
        return 0
    if cmd == 'install-timers':
        p = install_timers()
        print('\n'.join(p) if p else 'timers installed')
        return 1 if p else 0
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.path.insert(0, PANEL_DIR) if os.path.isdir(PANEL_DIR) else None
    sys.exit(main(sys.argv))
