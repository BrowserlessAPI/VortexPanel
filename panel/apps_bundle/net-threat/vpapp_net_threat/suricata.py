"""Optional deep packet inspection: Suricata IDS (passive, af-packet) with the free
Emerging Threats Open rules. Detection only - it never drops traffic, so a bad
signature can never take a website offline. Needs about 1 GB of free memory."""
import json
import os
import re
import sys
import time

from panel import appkit

APP = 'net-threat'
YAML = '/etc/suricata/suricata.yaml'
EVE = '/var/log/suricata/eve.json'
JOB_UNIT = appkit.unit_name(APP, 'ids-install')


def _svc():
    for u in ('suricata', 'suricata.service'):
        st = appkit.service_state(u)
        if st != 'unknown':
            return st
    return 'inactive'


def mem_mb():
    try:
        for line in open('/proc/meminfo'):
            if line.startswith('MemAvailable:'):
                return int(line.split()[1]) // 1024
    except OSError:
        pass
    return 0


def status():
    rules = 0
    for p in ('/var/lib/suricata/rules/suricata.rules', '/etc/suricata/rules/suricata.rules'):
        try:
            with open(p) as f:
                rules = sum(1 for ln in f if ln.startswith(('alert', 'drop')))
            break
        except OSError:
            continue
    ver = ''
    if appkit.have('suricata'):
        rc, out, _ = appkit.run(['suricata', '-V'], timeout=20)
        m = re.search(r'version ([\d.]+)', out or '')
        ver = m.group(1) if m else ''
    return {'installed': appkit.have('suricata'), 'version': ver, 'service': _svc() if appkit.have('suricata') else '',
            'rules': rules, 'mem_available_mb': mem_mb(), 'job': appkit.read_json(APP, 'ids-job.json', {}),
            'job_running': appkit.service_state(JOB_UNIT) in ('active', 'activating')}


def _iface():
    rc, out, _ = appkit.run(['ip', 'route', 'show', 'default'], timeout=10)
    m = re.search(r'\bdev (\S+)', out or '')
    return m.group(1) if m else 'eth0'


def _home_net():
    rc, out, _ = appkit.run(['ip', '-o', 'addr'], timeout=10)
    nets = []
    for m in re.finditer(r'inet6? ([0-9a-fA-F:.]+/\d+)', out or ''):
        a = m.group(1)
        if not a.startswith(('127.', '::1', 'fe80')):
            nets.append(a.split('/')[0] + ('/32' if ':' not in a else '/128'))
    return '[' + ','.join(nets) + ']' if nets else '[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]'


def configure(log):
    """Interface + HOME_NET in suricata.yaml (backup first)."""
    if not os.path.exists(YAML):
        raise RuntimeError('suricata.yaml not found')
    txt = open(YAML).read()
    bak = YAML + '.vortexpanel.bak'
    if not os.path.exists(bak):
        with open(bak, 'w') as f:
            f.write(txt)
    iface = _iface()
    txt = re.sub(r'(af-packet:\s*\n\s*-\s*interface:\s*)\S+', r'\g<1>' + iface, txt, count=1)
    txt = re.sub(r'(\n\s*HOME_NET:\s*)"[^"]*"', r'\g<1>"' + _home_net() + '"', txt, count=1)
    with open(YAML, 'w') as f:
        f.write(txt)
    if os.path.exists('/etc/default/suricata'):           # Debian start script
        d = open('/etc/default/suricata').read()
        d = re.sub(r'^IFACE=.*$', f'IFACE={iface}', d, flags=re.M)
        d = re.sub(r'^LISTENMODE=.*$', 'LISTENMODE=af-packet', d, flags=re.M)
        open('/etc/default/suricata', 'w').write(d)
    if os.path.exists('/etc/sysconfig/suricata'):         # RHEL
        d = open('/etc/sysconfig/suricata').read()
        d = re.sub(r'^OPTIONS=.*$', f'OPTIONS="--af-packet={iface} --user suricata"', d, flags=re.M)
        open('/etc/sysconfig/suricata', 'w').write(d)
    log(f'Listening on {iface}; home network {_home_net()}')


def install(log):
    if mem_mb() < 700:
        raise RuntimeError(f'only {mem_mb()} MB of memory is free; Suricata needs about 1 GB')
    pkgs = ['suricata'] if appkit.os_family() == 'rhel' else ['suricata', 'suricata-update']
    if appkit.os_family() == 'rhel':
        appkit.pkg_install(['epel-release'], log)
    if not appkit.pkg_install(pkgs, log) or not appkit.have('suricata'):
        raise RuntimeError('Suricata could not be installed from the system package sources')
    configure(log)
    log('Downloading the Emerging Threats Open rules...')
    rc, out, err = appkit.run(['suricata-update', '--no-test'], timeout=900)
    if rc != 0:
        log('suricata-update: ' + (err or out).strip()[-300:])
    rc, out, err = appkit.run(['suricata', '-T', '-c', YAML], timeout=300)
    if rc != 0:
        raise RuntimeError('Suricata rejected its configuration: ' + (err or out).strip()[-400:])
    appkit.run(['systemctl', 'enable', '--now', 'suricata'], timeout=120)
    appkit.run(['systemctl', 'restart', 'suricata'], timeout=120)
    # weekly rule refresh
    appkit.install_timer(APP, 'vpapp_net_threat.suricata', 'Sun *-*-* 04:17:00', suffix='ids-rules',
                         description='Suricata rule update', args='update-rules')
    log('Suricata is ' + _svc())


def update_rules():
    rc, out, err = appkit.run(['suricata-update', '--no-test'], timeout=900)
    if rc == 0:
        appkit.run(['systemctl', 'reload', 'suricata'], timeout=60)
    return rc == 0, (err or out).strip()[-300:]


def start_install():
    if appkit.service_state(JOB_UNIT) in ('active', 'activating'):
        return False, 'An installation is already running'
    plugin_dir = os.path.join(appkit.PANEL_DIR, 'plugins', APP)
    appkit.write_json(APP, 'ids-job.json', {'state': 'running', 'lines': ['Starting...'], 't': int(time.time())})
    rc, out, err = appkit.run(['systemd-run', '--unit', JOB_UNIT, '--collect', '--quiet', f'--working-directory={appkit.PANEL_DIR}',
                               f'--setenv=PYTHONPATH={plugin_dir}:{appkit.PANEL_DIR}', appkit.venv_python(), '-m',
                               'vpapp_net_threat.suricata', 'install'], timeout=30)
    return rc == 0, (err or out).strip()[-300:]


def alerts(limit=500, q=''):
    """Newest alerts from eve.json."""
    out = []
    try:
        with open(EVE, 'rb') as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 16 * 1024 * 1024))
            lines = f.read().decode('utf-8', 'replace').splitlines()
    except OSError:
        return out
    for ln in reversed(lines):
        if '"event_type":"alert"' not in ln:
            continue
        try:
            j = json.loads(ln)
        except ValueError:
            continue
        a = j.get('alert') or {}
        rec = {'t': j.get('timestamp', '')[:19].replace('T', ' '), 'src': j.get('src_ip', ''), 'sport': j.get('src_port'),
               'dest': j.get('dest_ip', ''), 'dport': j.get('dest_port'), 'proto': j.get('proto', ''),
               'signature': a.get('signature', ''), 'category': a.get('category', ''), 'severity': a.get('severity', 3),
               'sid': a.get('signature_id')}
        if q and q.lower() not in (rec['signature'] + ' ' + rec['src'] + ' ' + rec['category']).lower():
            continue
        out.append(rec)
        if len(out) >= limit:
            break
    return out


def remove(log=print):
    appkit.run(['systemctl', 'disable', '--now', 'suricata'], timeout=120)
    log('Suricata stopped and disabled (the package stays installed; remove it with your package manager if you like).')


def _job_main():
    st = {'state': 'running', 'lines': [], 't': int(time.time())}

    def log(m):
        print(m, flush=True)
        st['lines'] = (st['lines'] + [str(m)])[-200:]
        appkit.write_json(APP, 'ids-job.json', st)
    try:
        install(log)
        st.update(state='done', message='Deep inspection is running.')
    except Exception as e:  # noqa: BLE001
        st.update(state='failed', message=str(e))
    log(st['message'])
    appkit.oplog(APP, 'suricata install', st['message'], user='admin')
    return 0 if st['state'] == 'done' else 1


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'install':
        sys.exit(_job_main())
    if len(sys.argv) > 1 and sys.argv[1] == 'update-rules':
        ok, m = update_rules()
        print(m)
        sys.exit(0 if ok else 1)
    print('usage: python -m vpapp_net_threat.suricata install|update-rules')
    sys.exit(2)
