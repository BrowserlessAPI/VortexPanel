"""System Hardening service (vortexpanel-app-sys-harden).

  every 30 s   keep the locks in line with the settings (and re-lock after a pause)
  every 60 s   process guard
  every N min  compare each monitored area with its last snapshot; changes become events
"""
import os
import signal
import sys
import time

from panel import appkit
from vpapp_sys_harden import guard, procguard

APP = guard.APP
PKG_LOGS = ('/var/log/dpkg.log', '/var/log/dnf.rpm.log', '/var/log/yum.log', '/var/log/apt/history.log')


def event(area, severity, kind, path, detail='', notify=True, cfg=None):
    rec = {'t': int(time.time()), 'area': area, 'severity': severity, 'kind': kind, 'path': path[:500], 'detail': detail[:500]}
    appkit.append_jsonl(APP, 'events.jsonl', rec, 5000)
    cfg = cfg or guard.config()
    if notify and cfg['notify'] and severity in ('critical', 'high'):
        label = guard.AREAS.get(area, {}).get('label') or ('Process guard' if area == 'process' else area)
        appkit.notify(APP, 'Security change detected', f'[{severity}] {label}: {kind} {path} {detail}'.strip())
    return rec


def _package_activity(window):
    now = time.time()
    for p in PKG_LOGS:
        try:
            if now - os.path.getmtime(p) < window:
                return True
        except OSError:
            continue
    return False


def scan_areas(cfg):
    window = cfg['scan_minutes'] * 60 + 120
    pkg = _package_activity(window)
    st = appkit.read_json(APP, 'scan_state.json', {})
    for aid in guard.all_areas(cfg):
        if guard.area_mode(aid, cfg) == 'off':
            continue
        old = guard.load_baseline(aid)
        new = guard.snapshot(aid, old, cfg)
        if old is None:
            guard.save_baseline(aid, new)
            st[aid] = {'t': int(time.time()), 'files': len(new), 'changes': 0}
            continue
        changes = guard.diff(old, new)
        base = guard.AREAS.get(aid, {}).get('severity', 'high')
        for kind, path, detail in changes[:200]:
            sev = base
            if aid == 'env' and path == '/etc/ld.so.preload' and kind in ('added', 'modified'):
                sev = 'critical'
            elif kind == 'added' and aid in ('cron', 'services', 'ssh', 'users'):
                sev = 'high' if sev != 'critical' else sev
            note = detail
            if pkg and aid in ('binaries', 'services', 'env', 'users'):
                sev = 'low'
                note = (detail + '; ' if detail else '') + 'during a package install/update'
            event(aid, sev, kind, path, note, cfg=cfg)
        if len(changes) > 200:
            event(aid, base, 'many changes', aid, f'{len(changes)} changes in one scan; only the first 200 are listed', cfg=cfg)
        if changes:
            guard.save_baseline(aid, new)
        st[aid] = {'t': int(time.time()), 'files': len(new), 'changes': len(changes)}
    appkit.write_json(APP, 'scan_state.json', st)


def scan_processes(cfg, seen):
    found = procguard.scan(cfg['proc_whitelist'])
    appkit.write_json(APP, 'processes.json', {'t': int(time.time()), 'items': found})
    for p in found:
        key = (p['pid'], p['exe'])
        if key in seen:
            continue
        seen.add(key)
        detail = f"pid {p['pid']} user {p['user']}: {p['cmd'][:200]}"
        if cfg['auto_kill'] and p['severity'] == 'critical':
            ok, how = procguard.kill(p['pid'])
            event('process', 'critical', 'killed' if ok else 'detected', p['exe'], p['reason'] + '; ' + (how if ok else detail), cfg=cfg)
        else:
            event('process', p['severity'], 'detected', p['exe'], p['reason'] + '; ' + detail, cfg=cfg)
    if len(seen) > 5000:
        seen.clear()


def main():
    running = {'on': True}
    signal.signal(signal.SIGTERM, lambda *_: running.update(on=False))
    last_lock = last_proc = last_scan = 0
    seen = set()
    while running['on']:
        now = time.time()
        cfg = guard.config()
        try:
            if now - last_lock >= 30:
                last_lock = now
                guard.enforce_locks(cfg)
            if now - last_proc >= 60:
                last_proc = now
                scan_processes(cfg, seen)
            if now - last_scan >= cfg['scan_minutes'] * 60 or os.path.exists(os.path.join(appkit.data_dir(APP), '.scan-now')):
                last_scan = now
                try:
                    os.remove(os.path.join(appkit.data_dir(APP), '.scan-now'))
                except OSError:
                    pass
                scan_areas(cfg)
        except Exception as e:  # noqa: BLE001
            print(f'tick error: {type(e).__name__}: {e}', flush=True)
        for _ in range(10):
            if not running['on']:
                break
            time.sleep(0.5)
    return 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'scan':
        scan_areas(guard.config())
    else:
        sys.exit(main())
