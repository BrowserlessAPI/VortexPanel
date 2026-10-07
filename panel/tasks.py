"""Background tasks of the panel, run by systemd timers instead of the web
workers (gunicorn runs several processes, and none of them should own a
schedule):

    vortexpanel-bandwidth.timer  every 5 minutes  per-site traffic history
    vortexpanel-backups.timer    every 5 minutes  scheduled website backups

    python3 -m panel.tasks bandwidth
    python3 -m panel.tasks backups
    python3 -m panel.tasks install-timers
"""
import os, sys, subprocess

PANEL_DIR = '/opt/vortexpanel'
UNIT_DIR = '/etc/systemd/system'

_UNITS = {
    'vortexpanel-bandwidth': ('VortexPanel per-site traffic history', 'bandwidth', 'OnCalendar=*:0/5\nRandomizedDelaySec=30'),
    'vortexpanel-backups': ('VortexPanel scheduled website backups', 'backups', 'OnCalendar=*:0/5'),
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
