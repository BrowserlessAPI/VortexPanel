"""VortexPanel Apps: first-party add-on modules that ship with the panel and are
installed on demand from the App Store (like aaPanel's App Store plugins).

Source (shipped with the panel, updated with it):  panel/apps_bundle/<id>/
Installed copy (what the panel loads):             /opt/vortexpanel/plugins/<id>/
Data (survives update and uninstall):              /opt/vortexpanel/data/apps/<id>/

An App is an ordinary plugin (panel/plugins.py loads it) whose plugin.json has
"kind": "app". Panel updates never touch plugins/, so an installed App only
changes when the admin clicks Update in the App Store (offered when the bundled
copy is newer).

Install, update and uninstall run in their own systemd unit
(`python -m panel.apps <action> <id>`), because they end by restarting the
panel. Every step can be rolled back:

  1. checks: compatible with this panel, no conflicting App, nothing else running
  2. copy the bundle to plugins/<id>.new (regular files only)
  3. the App must import and register in a separate Python process
  4. swap folders (previous copy kept in data/apps/_backups)
  5. run the App's hooks.install() (packages, services, firewall tables)
  6. restart the panel and wait for /api/health; on failure restore everything
"""
import datetime
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

PANEL_DIR = '/opt/vortexpanel'
HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE_DIR = os.environ.get('VP_APPS_BUNDLE', os.path.join(HERE, 'apps_bundle'))
PLUGINS_DIR = os.environ.get('VP_PLUGINS_DIR', os.path.join(PANEL_DIR, 'plugins'))
APPS_DATA = os.environ.get('VP_APPS_DATA', os.path.join(PANEL_DIR, 'data', 'apps'))
JOB_FILE = os.path.join(APPS_DATA, '_job.json')
BACKUPS = os.path.join(APPS_DATA, '_backups')
UNIT = 'vortexpanel-apps-job'
ID_RE = re.compile(r'^[a-z][a-z0-9-]{1,30}$')
MAX_FILES = 800
MAX_BYTES = 30 * 1024 * 1024


# ----------------------------------------------------------------------- manifests

def _manifest(d):
    try:
        with open(os.path.join(d, 'plugin.json')) as f:
            m = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(m, dict) or m.get('kind') != 'app' or m.get('id') != os.path.basename(d.rstrip('/')):
        return None
    if not ID_RE.match(m['id']):
        return None
    return m


def bundled():
    out = {}
    try:
        names = sorted(os.listdir(BUNDLE_DIR))
    except OSError:
        return out
    for n in names:
        m = _manifest(os.path.join(BUNDLE_DIR, n))
        if m:
            out[n] = m
    return out


def installed():
    out = {}
    try:
        names = sorted(os.listdir(PLUGINS_DIR))
    except OSError:
        return out
    for n in names:
        if n.endswith(('.new', '.old')):
            continue
        m = _manifest(os.path.join(PLUGINS_DIR, n))
        if m:
            out[n] = m
    return out


def _vt(v):
    from panel.plugins import _vtuple
    return _vtuple(v)


def catalog():
    """Everything the App Store needs, one entry per bundled or installed App."""
    from panel import plugins
    b, i = bundled(), installed()
    core = plugins.core_version()
    out = []
    for aid in sorted(set(b) | set(i), key=lambda k: (b.get(k) or i.get(k)).get('order', 100)):
        m = b.get(aid) or i.get(aid)
        inst = i.get(aid)
        reg = plugins.REGISTRY.get(aid) or {}
        compatible = plugins.version_matches(core, m.get('requires_core', ''))
        out.append({
            'id': aid, 'name': m.get('name') or aid, 'category': m.get('category') or 'Apps',
            'summary': m.get('summary') or '', 'description': m.get('description') or '',
            'icon': m.get('icon') or 'puzzle', 'color': m.get('color') or '#0e7490',
            'features': m.get('features') or [], 'engines': m.get('engines') or [],
            'version': (b.get(aid) or {}).get('version') or '',
            'installed': bool(inst), 'installed_version': (inst or {}).get('version') or '',
            'has_update': bool(inst and b.get(aid) and _vt(b[aid].get('version')) > _vt(inst.get('version'))),
            'status': reg.get('status') or ('pending-restart' if inst else ''),
            'error': reg.get('error') or '',
            'page': ((inst or m).get('pages') or [{}])[0].get('id', ''),
            'compatible': compatible, 'requires_core': m.get('requires_core', ''),
            'conflicts': m.get('conflicts') or [],
            'bundled': aid in b,
        })
    return out


# ---------------------------------------------------------------------------- job

class Job:
    def __init__(self, action, aid):
        self.d = {'state': 'running', 'action': action, 'id': aid, 'started': int(time.time()), 'lines': []}
        self.save()

    def save(self):
        os.makedirs(APPS_DATA, mode=0o700, exist_ok=True)
        tmp = JOB_FILE + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(self.d, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, JOB_FILE)

    def say(self, text):
        print(text, flush=True)
        self.d['lines'] = (self.d['lines'] + [str(text)])[-400:]
        self.save()

    def done(self, ok, message):
        self.d.update(state='done' if ok else 'failed', finished=int(time.time()), message=message)
        self.say(message)
        return 0 if ok else 1


def job():
    try:
        with open(JOB_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def job_running():
    r = subprocess.run(['systemctl', 'is-active', UNIT + '.service'], capture_output=True, text=True)
    return r.stdout.strip() in ('active', 'activating')


def start(action, aid, purge=False):
    """Start install/update/uninstall in its own unit. (ok, message)."""
    if action not in ('install', 'update', 'uninstall'):
        return False, 'Unknown action'
    if not ID_RE.match(aid or ''):
        return False, 'Unknown App'
    if action in ('install', 'update') and aid not in bundled():
        return False, 'This App is not available in this panel version.'
    if action in ('update', 'uninstall') and aid not in installed():
        return False, 'This App is not installed.'
    if action == 'install':
        ok, why = precheck(aid)
        if not ok:
            return False, why
    if job_running():
        return False, 'Another App install, update or removal is running. Wait for it to finish.'
    from panel.module_install import running as hosting_running
    try:
        if hosting_running():
            return False, 'The Hosting Module is being installed. Wait for it to finish.'
    except Exception:  # noqa: BLE001
        pass
    py = os.path.join(PANEL_DIR, 'venv', 'bin', 'python3')
    py = py if os.path.exists(py) else sys.executable
    argv = ['systemd-run', '--unit', UNIT, '--collect', '--quiet', f'--working-directory={PANEL_DIR}',
            py, '-m', 'panel.apps', action, aid] + (['--purge'] if purge else [])
    os.makedirs(APPS_DATA, mode=0o700, exist_ok=True)
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except Exception as e:  # noqa: BLE001
        return False, str(e)
    if r.returncode != 0:
        # a job that lost the race must not overwrite the running job's log
        return False, (r.stderr or r.stdout).strip()[-300:] or 'systemd-run failed'
    return True, 'Started'


def precheck(aid):
    from panel import plugins
    m = bundled().get(aid)
    if not m:
        return False, 'This App is not available in this panel version.'
    if not plugins.version_matches(plugins.core_version(), m.get('requires_core', '')):
        return False, f'{m["name"]} needs VortexPanel {m.get("requires_core")}; update the panel first.'
    inst = installed()
    for other in m.get('conflicts') or []:
        if other in inst:
            return False, f'{m["name"]} cannot run together with {inst[other].get("name", other)}. Uninstall that first.'
    for other_id, om in inst.items():
        if aid in (om.get('conflicts') or []):
            return False, f'{om.get("name", other_id)} cannot run together with {m["name"]}.'
    # a non-App plugin already using this folder name (e.g. a manual plugin)
    d = os.path.join(PLUGINS_DIR, aid)
    if os.path.isdir(d) and aid not in inst:
        return False, f'plugins/{aid} already exists and is not a VortexPanel App; move it away first.'
    return True, ''


def _prune_backups(aid, keep=3):
    try:
        mine = sorted((n for n in os.listdir(BACKUPS) if re.match(re.escape(aid) + r'-\d', n)),
                      key=lambda n: os.path.getmtime(os.path.join(BACKUPS, n)))   # oldest first, by time
    except OSError:
        return
    for n in mine[:-keep]:
        shutil.rmtree(os.path.join(BACKUPS, n), ignore_errors=True)


# ------------------------------------------------------------------------ helpers

def _sh(argv, timeout=120):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


def _copy_bundle(src, dest):
    """Regular files and folders only (no links, devices); size/count limits."""
    shutil.rmtree(dest, ignore_errors=True)
    n = size = 0
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d != '__pycache__' and not os.path.islink(os.path.join(root, d))]
        rel = os.path.relpath(root, src)
        out = os.path.join(dest, rel) if rel != '.' else dest
        os.makedirs(out, mode=0o755, exist_ok=True)
        for fn in files:
            p = os.path.join(root, fn)
            if os.path.islink(p) or not os.path.isfile(p) or fn.endswith('.pyc'):
                continue
            n += 1
            size += os.path.getsize(p)
            if n > MAX_FILES or size > MAX_BYTES:
                raise ValueError('App bundle is too large')
            shutil.copyfile(p, os.path.join(out, fn))
            os.chmod(os.path.join(out, fn), 0o644)
    _sh(['chown', '-R', 'root:root', dest])


def _hooks(plugin_dir, man):
    """Import the App's hooks module fresh from plugin_dir (None when it has none)."""
    name = man.get('hooks')
    if not name:
        return None
    pkg = name.split('.')[0]
    for k in list(sys.modules):
        if k == pkg or k.startswith(pkg + '.'):
            del sys.modules[k]
    sys.path.insert(0, plugin_dir)
    try:
        return importlib.import_module(name)
    finally:
        try:
            sys.path.remove(plugin_dir)
        except ValueError:
            pass


def _loads(aid):
    """The App imports and registers in a fresh panel process. (ok, error)."""
    py = os.path.join(PANEL_DIR, 'venv', 'bin', 'python')
    py = py if os.path.exists(py) else sys.executable
    code = ('import sys,json; sys.path.insert(0,"/opt/vortexpanel"); import flask; from panel import plugins;'
            f'app=flask.Flask("x"); plugins.load_all(app); e=plugins.REGISTRY.get({aid!r},{{}});'
            'print("VPA-STATUS "+json.dumps([e.get("status"), e.get("error")]))')
    rc, out = _sh(['env', 'VP_NO_INIT=1', py, '-c', code], timeout=120)
    for line in out.splitlines():
        if line.startswith('VPA-STATUS '):
            st, err = json.loads(line[11:])
            return st == 'loaded', err or st
    return False, out[-500:]


def _restart_panel(j):
    from panel.module_install import _healthy, _panel_url
    j.say('Restarting the panel to load the change...')
    _sh(['systemctl', 'restart', 'vortexpanel'], timeout=180)
    ok = _healthy(_panel_url() + '/api/health')
    j.say('Panel restarted and healthy.' if ok else 'The panel did not answer after the restart.')
    return ok


# --------------------------------------------------------------------- operations

def run_install(aid, update=False):
    j = Job('update' if update else 'install', aid)
    if os.geteuid() != 0:
        return j.done(False, 'Must run as root.')
    man = bundled().get(aid)
    if not man:
        return j.done(False, 'This App is not in this panel version.')
    if not update:
        ok, why = precheck(aid)
        if not ok:
            return j.done(False, why)
    final = os.path.join(PLUGINS_DIR, aid)
    new = final + '.new'
    prev_man = installed().get(aid)
    ts = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    prev = None
    j.say(f'{"Updating" if update else "Installing"} {man["name"]} {man.get("version", "")}'
          + (f' (from {prev_man.get("version")})' if prev_man else '') + '...')
    try:
        os.makedirs(PLUGINS_DIR, exist_ok=True)
        _copy_bundle(os.path.join(BUNDLE_DIR, aid), new)
    except (OSError, ValueError) as e:
        shutil.rmtree(new, ignore_errors=True)
        return j.done(False, f'Could not copy the App files: {e}')

    if os.path.isdir(final):
        os.makedirs(BACKUPS, mode=0o700, exist_ok=True)
        prev = os.path.join(BACKUPS, f'{aid}-{(prev_man or {}).get("version", "x")}-{ts}')
        shutil.move(final, prev)
    os.rename(new, final)
    j.say('Files in place.')

    def rollback(reason):
        j.say('Rolling back: ' + reason)
        if not prev:
            try:
                h = _hooks(final, man)
                if h and hasattr(h, 'uninstall'):
                    h.uninstall(j.say, False)
            except Exception as e:  # noqa: BLE001
                j.say(f'cleanup: {e}')
        shutil.rmtree(final, ignore_errors=True)
        if prev and os.path.isdir(prev):
            shutil.move(prev, final)
            try:
                h = _hooks(final, prev_man or man)
                if h and hasattr(h, 'install'):
                    h.install(j.say)
            except Exception as e:  # noqa: BLE001
                j.say(f'restoring the previous version: {e}')
        ok = _restart_panel(j)
        return j.done(False, reason + (' Everything was put back as it was.' if ok else
                                       ' The files were restored but the panel is not answering: '
                                       'journalctl -u vortexpanel -n 50'))

    ok, err = _loads(aid)
    if not ok:
        return rollback(f'the App does not load in this panel: {err}')
    j.say('The App loads in this panel.')

    try:
        h = _hooks(final, man)
        if h:
            if update and hasattr(h, 'upgrade'):
                h.upgrade(j.say, (prev_man or {}).get('version', ''))
            elif hasattr(h, 'install'):
                h.install(j.say)
    except Exception as e:  # noqa: BLE001
        return rollback(f'setup failed: {e}')

    from panel import appkit
    appkit.oplog(aid, 'update' if update else 'install', f'version {man.get("version")}', user='admin')
    if not _restart_panel(j):
        return rollback('the panel did not come back after the restart')
    _prune_backups(aid)
    return j.done(True, f'{man["name"]} {man.get("version", "")} is {"updated" if update else "installed"}. '
                        'Reload the page to open it.')


def run_uninstall(aid, purge=False):
    j = Job('uninstall', aid)
    if os.geteuid() != 0:
        return j.done(False, 'Must run as root.')
    man = installed().get(aid)
    if not man:
        return j.done(False, 'This App is not installed.')
    final = os.path.join(PLUGINS_DIR, aid)
    j.say(f'Removing {man["name"]}...')
    try:
        h = _hooks(final, man)
        if h and hasattr(h, 'uninstall'):
            h.uninstall(j.say, purge)
    except Exception as e:  # noqa: BLE001
        j.say(f'Cleanup reported a problem (continuing): {e}')
    from panel import appkit
    appkit.remove_units(aid)
    appkit.nft_drop_table(aid)
    appkit.nginx_remove_all(aid)
    ts = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    os.makedirs(BACKUPS, mode=0o700, exist_ok=True)
    shutil.move(final, os.path.join(BACKUPS, f'{aid}-{man.get("version", "x")}-{ts}-removed'))
    if purge:
        shutil.rmtree(os.path.join(APPS_DATA, aid), ignore_errors=True)
        j.say('Settings and history deleted.')
    else:
        appkit.oplog(aid, 'uninstall', 'settings and history kept', user='admin')
        j.say('Settings and history kept (reinstalling restores them).')
    _restart_panel(j)
    return j.done(True, f'{man["name"]} was removed.')


def main(argv):
    if len(argv) < 2 or argv[0] not in ('install', 'update', 'uninstall') or not ID_RE.match(argv[1]):
        print('usage: python -m panel.apps install|update|uninstall <id> [--purge]')
        return 2
    action, aid = argv[0], argv[1]
    if action == 'uninstall':
        return run_uninstall(aid, '--purge' in argv)
    return run_install(aid, update=(action == 'update'))


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
