"""App Store test runner (for a TEST server only).

Installs the app versions waiting for approval on the licence server, checks
them, removes them again and reports the results, so the administrator sees
"tested: passed" next to each version before publishing it.

    vortexpanel app-test setup              mark this server as a test server (asks first)
    vortexpanel app-test run [--only APP]   test every untested version once
    vortexpanel app-test status

The licence server address comes from panel/trust/licence.json; the runner
token (Licence server admin > App versions > Test runner) is stored in
data/app_test.json (root only). Installs run as on a normal server: use a fresh
test VPS, never a server with websites. Apps already installed on this server
are not tested (they would be replaced); apps that conflict with an installed
one (MySQL / MariaDB, the web servers) are skipped with a note.
"""
import json
import os
import platform
import re
import subprocess
import sys
import time
import urllib.request

INSTALL_DIR = '/opt/vortexpanel'
CONF = os.path.join(INSTALL_DIR, 'data', 'app_test.json')
MARK = os.path.join(INSTALL_DIR, 'data', 'app_test_server')
LOGDIR = os.path.join(INSTALL_DIR, 'data', 'app_test_logs')


def _conf():
    try:
        with open(CONF) as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return {}


def _save_conf(c):
    os.makedirs(os.path.dirname(CONF), exist_ok=True)
    tmp = CONF + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(c, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONF)


def _server():
    from panel.licence import trust
    return os.environ.get('VP_APPTEST_SERVER') or trust()['server']


def _api(method, path, token, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(_server() + path, data=data, method=method, headers={
        'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Accept': 'application/json',
        'User-Agent': 'VortexPanel app-test'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def setup(token=None):
    print('This server will install and remove App Store apps to test them.')
    print('Use a fresh test server only: never one with websites, databases or mail.')
    if input('Type "test server" to continue: ').strip().lower() != 'test server':
        print('Cancelled.')
        return 1
    token = token or input('Runner token (licence server > App versions > Test runner): ').strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{30,80}', token):
        print('That does not look like a runner token.')
        return 1
    os.makedirs(os.path.dirname(MARK), exist_ok=True)
    with open(MARK, 'w') as f:
        f.write(f'marked as an App Store test server {time.strftime("%Y-%m-%d %H:%M")}\n')
    _save_conf({'token': token})
    try:
        r = _api('GET', '/api/v1/app-versions/candidates', token)
        print(f'Connected. {len(r.get("candidates") or [])} version(s) waiting for a test.')
    except Exception as e:  # noqa: BLE001
        print(f'Saved, but the licence server did not answer: {e}')
    return 0


def _sh(cmd, timeout):
    try:
        r = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'))
        return r.returncode, (r.stdout or '') + (r.stderr or '')
    except subprocess.TimeoutExpired as e:
        return 124, ((e.stdout or b'').decode(errors='replace') if isinstance(e.stdout, bytes) else (e.stdout or '')) + \
            f'\n[timed out after {timeout}s]'


def test_one(m, cand, log):
    """-> (result, installed_version, note). result: passed | failed | skipped"""
    from panel import appversions
    from panel.routes import modules as M
    # candidates are not signed: hold them to the same rules as the signed list
    # (value pattern, download hosts, full checksums) before anything runs
    ok = appversions.entries(m['id'], m.get('versions'),
                             {'apps': {m['id']: {'versions': [dict(cand, recommended=True)]}}})
    if not ok or ok[0]['value'] != str(cand.get('value') or ''):
        return 'failed', '', 'the candidate does not fit the App Store rules for this app'
    entry = ok[0]
    ver = entry['value']
    blocked = M._install_blocked(m['id'])
    if blocked:
        return 'skipped', '', blocked
    if M.is_installed(m['check']):
        return 'skipped', '', f'{m["name"]} is already installed on the test server'
    group, other = M.get_conflict(m['id'])
    if other:
        return 'skipped', '', f'{other} is installed on the test server ({group})'
    cmd, err = M.build_install_cmd(m, ver, entry)
    if err or not cmd:
        return 'failed', '', err or 'no install command'
    log(f'== installing {m["id"]} {ver} ({cand.get("version") or ""})')
    t0 = time.time()
    rc, out = _sh(M.translate_install_cmd(cmd), 1800)
    log(out[-20000:])
    note = []
    ok = rc == 0 and M.is_installed(m['check'])
    if rc != 0:
        note.append(f'install exited with {rc}')
    vtpl = m.get('verify_tpl', '')
    if ok and vtpl and not M.is_installed(vtpl.replace('{ver}', ver)):
        ok = False
        note.append('the version check failed')
    svc = M._resolve_svc(m.get('service', '')) if ok else ''
    if ok and svc:
        time.sleep(3)
        if not M._svc_active(svc):
            ok = False
            note.append(f'service {svc} is not running')
    installed = ''
    try:
        installed = M.get_version(m['id'], ver) if ok else ''
    except TypeError:
        installed = M.get_version(m['id']) if ok else ''
    except Exception:  # noqa: BLE001
        installed = ''
    want = str(cand.get('version') or '')
    if ok and want and installed:
        wt = re.findall(r'\d+', want)[:2]
        it = re.findall(r'\d+', installed)[:2]
        if wt and it and wt != it:
            ok = False
            note.append(f'installed {installed}, expected {want}')
        elif installed != want:
            note.append(f'the package source offers {installed} (listed {want})')
    note.append(f'{int(time.time() - t0)} s')
    # remove it again (the server stays clean for the next test)
    un = m.get('uninstall_tpl', '')
    un = un.replace('{ver}', ver) if un else m.get('uninstall', '')
    if un:
        urc, uout = _sh(M.translate_install_cmd(un), 900)
        log('== removing\n' + uout[-5000:])
        if urc != 0:
            note.append('removing it again failed - check the test server')
    return ('passed' if ok else 'failed'), installed, '; '.join(note)


def run(only=None):
    if not os.path.exists(MARK):
        print('This is not marked as a test server. Run "vortexpanel app-test setup" on a fresh test server first.')
        return 1
    token = _conf().get('token')
    if not token:
        print('No runner token: run "vortexpanel app-test setup".')
        return 1
    from panel.routes import modules as M
    r = _api('GET', '/api/v1/app-versions/candidates', token)
    cands = [c for c in (r.get('candidates') or []) if not only or c.get('app') == only]
    if not cands:
        print('Nothing to test.')
        return 0
    os.makedirs(LOGDIR, exist_ok=True)
    osname = ''
    try:
        osname = re.search(r'^PRETTY_NAME="?([^"\n]+)', open('/etc/os-release').read(), re.M).group(1)
    except Exception:  # noqa: BLE001
        osname = platform.platform()
    failed = 0
    for c in cands:
        m = next((x for x in M.MODULES if x['id'] == c.get('app')), None)
        if not m:
            continue
        lines = []
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', str(c.get('value') or ''))[:30].strip('.')
        path = os.path.join(LOGDIR, f'{m["id"]}-{safe}-{time.strftime("%Y%m%d-%H%M%S")}.log')

        def log(t):
            lines.append(t)
        try:
            result, installed, note = test_one(m, c, log)
        except Exception as e:  # noqa: BLE001
            result, installed, note = 'failed', '', f'test error: {e}'
        with open(path, 'w') as f:
            f.write('\n'.join(lines))
        print(f'{m["id"]:<12} {c.get("value"):<10} {result:<8} {note}')
        failed += result == 'failed'
        try:
            _api('POST', '/api/v1/app-versions/results', token, {
                'app': m['id'], 'value': c.get('value'), 'version': c.get('version') or '', 'key': c.get('key') or '',
                'result': result,
                'installed': installed, 'note': note[:500], 'os': osname[:80], 'log': '\n'.join(lines)[-30000:]})
        except Exception as e:  # noqa: BLE001
            print(f'  could not report the result: {e}')
    return 1 if failed else 0


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(prog='vortexpanel app-test')
    sp = ap.add_subparsers(dest='cmd')
    s = sp.add_parser('setup')
    s.add_argument('--token')
    r = sp.add_parser('run')
    r.add_argument('--only')
    sp.add_parser('status')
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        print('Run as root.')
        return 1
    if a.cmd == 'setup':
        return setup(a.token)
    if a.cmd == 'run':
        return run(a.only)
    print(json.dumps({'test_server': os.path.exists(MARK), 'token': bool(_conf().get('token')),
                      'server': _server()}, indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
