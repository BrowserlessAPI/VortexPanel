"""Install or update the Hosting Module from its signed package.

Started by the panel (Hosting Module page) as its own systemd unit, so restarting
the panel does not stop it:

    systemd-run --unit vortexpanel-module-install --collect python3 -m panel.licence install-module

Steps, with a full rollback when one fails:
  1. download the newest release from the licence server; check the Ed25519 signature and sha256
  2. unpack into plugins/hosting.new (regular files only, no links, no paths outside the folder)
  3. back up the module's data files and the portal service
  4. swap the folders (the previous version is kept in the backup)
  5. the module must load in this panel (separate process) before anything is restarted
  6. restart the panel, check /api/health; restart the customer portal when it is on

Progress is written to data/licence/install.json for the Hosting Module page.
"""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

PANEL_DIR = '/opt/vortexpanel'
PLUGIN_DIR = os.path.join(PANEL_DIR, 'plugins', 'hosting')
DATA_DIR = os.path.join(PANEL_DIR, 'data', 'plugins', 'hosting')
PROGRESS = os.path.join(PANEL_DIR, 'data', 'licence', 'install.json')
PORTAL_UNIT = '/etc/systemd/system/vortexpanel-portal.service'
UNIT = 'vortexpanel-module-install'
DATA_FILES = ['hosting_accounts.json', 'hosting_packages.json', 'account_security.json', 'ownership.json',
              'hosting_pw_audit.json', 'php_ext_requests.json', 'private_nameservers.json', 'portal_cdn.json']
MAX_FILES = 2000
MAX_BYTES = 50 * 1024 * 1024


class _Progress:
    def __init__(self):
        self.data = {'state': 'running', 'started': int(time.time()), 'lines': [], 'version': ''}
        self.save()

    def save(self):
        os.makedirs(os.path.dirname(PROGRESS), mode=0o700, exist_ok=True)
        tmp = PROGRESS + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(self.data, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, PROGRESS)

    def say(self, text):
        print(text, flush=True)
        self.data['lines'].append(text)
        self.save()

    def done(self, ok, message):
        self.data.update(state='done' if ok else 'failed', finished=int(time.time()), message=message)
        self.say(message)


def progress():
    try:
        with open(PROGRESS) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def running():
    r = subprocess.run(['systemctl', 'is-active', UNIT + '.service'], capture_output=True, text=True)
    return r.stdout.strip() in ('active', 'activating')


def start(version=None):
    """Start the install in its own unit. Returns (ok, message)."""
    if running():
        return False, 'An install is already running.'
    py = os.path.join(PANEL_DIR, 'venv', 'bin', 'python3')
    py = py if os.path.exists(py) else sys.executable
    cmd = ['systemd-run', '--unit', UNIT, '--collect', '--quiet', f'--working-directory={PANEL_DIR}',
           py, '-m', 'panel.licence', 'install-module'] + ([version] if version else [])
    try:
        os.makedirs(os.path.dirname(PROGRESS), mode=0o700, exist_ok=True)
        with open(PROGRESS, 'w') as f:
            json.dump({'state': 'running', 'started': int(time.time()), 'lines': ['Starting...']}, f)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as e:  # noqa: BLE001
        return False, str(e)
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()[-300:] or 'systemd-run failed'
    return True, 'Install started.'


def _sh(argv, timeout=120):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


def _panel_url():
    try:
        unit = open('/etc/systemd/system/vortexpanel.service').read()
    except OSError:
        unit = ''
    m = re.search(r'--bind\s+\S+:(\d+)', unit)
    return ('https' if '--certfile' in unit else 'http') + '://127.0.0.1:' + (m.group(1) if m else '8888')


def _healthy(url, tries=30):
    import ssl
    import urllib.request
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for _ in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=5, context=ctx) as r:
                if r.status == 200:
                    return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(2)
    return False


def _plugin_loads():
    py = os.path.join(PANEL_DIR, 'venv', 'bin', 'python')
    py = py if os.path.exists(py) else sys.executable
    code = ('import sys,json; sys.path.insert(0,"/opt/vortexpanel"); import flask; from panel import plugins;'
            'app=flask.Flask("x"); plugins.load_all(app); e=plugins.REGISTRY.get("hosting",{});'
            'print("VPH-STATUS "+json.dumps([e.get("status"), e.get("error")]))')
    rc, out = _sh(['env', 'VP_NO_INIT=1', py, '-c', code], timeout=120)
    for line in out.splitlines():
        if line.startswith('VPH-STATUS '):
            st, err = json.loads(line[11:])
            return st == 'loaded', err or st
    return False, out[-500:]


def _unpack(path, dest):
    """Safe extraction: regular files and folders inside dest only."""
    total = 0
    with tarfile.open(path, 'r:gz') as tar:
        members = tar.getmembers()
        if len(members) > MAX_FILES:
            raise ValueError('the package has too many files')
        for m in members:
            name = m.name.lstrip('./')
            if not name:
                continue
            if name.startswith('/') or '..' in name.split('/') or not (m.isfile() or m.isdir()):
                raise ValueError(f'unsafe entry in the package: {m.name}')
            total += m.size
            if total > MAX_BYTES:
                raise ValueError('the package is too large')
        for m in members:
            name = m.name.lstrip('./')
            if not name:
                continue
            target = os.path.join(dest, name)
            if m.isdir():
                os.makedirs(target, mode=0o755, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
            with tar.extractfile(m) as src, open(target, 'wb') as out:
                shutil.copyfileobj(src, out)
            os.chmod(target, 0o644)
    man = json.load(open(os.path.join(dest, 'plugin.json')))
    if man.get('id') != 'hosting':
        raise ValueError('the package is not the Hosting Module')
    return man


def run(version=None):
    from panel import licence
    p = _Progress()
    if os.geteuid() != 0:
        p.done(False, 'Must run as root.')
        return 1
    work = tempfile.mkdtemp(prefix='vp-module-')
    prev = None
    bdir = None
    try:
        p.say('Downloading the Hosting Module from the licence server...')
        try:
            pkg, meta = licence.download_module(work, version)
        except licence.LicenceError as e:
            p.done(False, f'Download failed: {e}')
            return 1
        p.data['version'] = meta['version']
        p.say(f'Downloaded version {meta["version"]}; signature and checksum verified.')
        from panel.plugins import core_version, _vtuple
        if meta.get('min_core') and _vtuple(core_version()) < _vtuple(meta['min_core']):
            p.done(False, f'This module version needs VortexPanel {meta["min_core"]} or newer '
                          f'(this panel is {core_version()}). Update the panel first.')
            return 1

        new = PLUGIN_DIR + '.new'
        shutil.rmtree(new, ignore_errors=True)
        os.makedirs(new, mode=0o755)
        try:
            man = _unpack(pkg, new)
        except (ValueError, tarfile.TarError, OSError, KeyError) as e:
            shutil.rmtree(new, ignore_errors=True)
            p.done(False, f'The package could not be unpacked: {e}')
            return 1
        _sh(['chown', '-R', 'root:root', new])

        ts = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        bdir = os.path.join(DATA_DIR, 'install-backups', ts)
        os.makedirs(bdir, mode=0o700, exist_ok=True)
        n = 0
        for name in DATA_FILES:
            src = os.path.join(PANEL_DIR, name)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(bdir, name))
                n += 1
        if os.path.exists(PORTAL_UNIT):
            shutil.copy2(PORTAL_UNIT, os.path.join(bdir, 'vortexpanel-portal.service'))
        p.say(f'Backed up {n} data file(s) to {bdir}.')

        if os.path.isdir(PLUGIN_DIR):
            prev = os.path.join(bdir, 'plugin-previous')
            shutil.move(PLUGIN_DIR, prev)
        os.makedirs(os.path.dirname(PLUGIN_DIR), exist_ok=True)
        os.rename(new, PLUGIN_DIR)
        p.say(f'Installed version {man.get("version")} files.')

        def rollback(reason):
            p.say('Rolling back: ' + reason)
            shutil.rmtree(PLUGIN_DIR, ignore_errors=True)
            if prev and os.path.isdir(prev):
                shutil.move(prev, PLUGIN_DIR)
            if bdir and os.path.exists(os.path.join(bdir, 'vortexpanel-portal.service')):
                shutil.copy2(os.path.join(bdir, 'vortexpanel-portal.service'), PORTAL_UNIT)
                _sh(['systemctl', 'daemon-reload'])
            _sh(['systemctl', 'restart', 'vortexpanel'], timeout=180)
            ok = _healthy(_panel_url() + '/api/health')
            p.done(False, reason + (' The previous state was restored.' if ok else
                                    ' The previous files were restored but the panel is not answering: '
                                    'journalctl -u vortexpanel -n 50'))
            return 1

        ok, err = _plugin_loads()
        if not ok:
            return rollback(f'the module does not load in this panel: {err}')
        p.say('The module loads in this panel.')

        _sh(['systemctl', 'restart', 'vortexpanel'], timeout=180)
        if not _healthy(_panel_url() + '/api/health'):
            return rollback('the panel did not come back after the restart')
        p.say('Panel restarted and healthy.')

        try:
            cfg = json.load(open(os.path.join(PANEL_DIR, 'config.json')))
        except (OSError, ValueError):
            cfg = {}
        if cfg.get('portal_enabled'):
            time.sleep(3)
            _sh(['systemctl', 'daemon-reload'])
            _sh(['systemctl', 'restart', 'vortexpanel-portal'], timeout=120)
            port = int(cfg.get('portal_port') or 2087)
            https = '--certfile' in (open(PORTAL_UNIT).read() if os.path.exists(PORTAL_UNIT) else '')
            url = ('https' if https else 'http') + f'://127.0.0.1:{port}/api/account-auth/check'
            if not _healthy(url, 20):
                return rollback('the customer portal did not start')
            p.say(f'Customer portal restarted (port {port}).')
        p.done(True, f'Hosting Module {man.get("version")} is installed.')
        return 0
    except Exception as e:  # noqa: BLE001
        if prev and not os.path.isdir(PLUGIN_DIR):
            shutil.move(prev, PLUGIN_DIR)
        p.done(False, f'Install failed: {type(e).__name__}: {e}')
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)
