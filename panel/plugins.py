"""Plugins (add-on modules such as the Hosting Module).

A plugin lives in its own folder, outside the panel's code, so panel updates
never touch it and removing it is deleting the folder:

    /opt/vortexpanel/plugins/<id>/
        plugin.json     manifest (below)
        plugin.py       def register(ctx): ...   (Flask blueprints, timers)
        static/         served at /api/plugins/<id>/assets/... (signed-in admins)
        pages/          HTML fragments for admin pages

plugin.json:
    {
      "id": "hosting", "name": "Hosting Module", "version": "3.0.0",
      "requires_core": ">=3.8.0,<4.0.0",
      "entry": "plugin.py",
      "pages":   [{"id": "hosting-accounts", "label": "Hosting Accounts",
                   "icon": "users", "group": "Overview",
                   "fragment": "pages/accounts.html"}],
      "scripts": ["static/hosting.js"],
      "styles":  ["static/hosting.css"]
    }

Rules the loader enforces so a plugin can never take the panel down:
  - every plugin is imported and registered inside try/except; a failure is
    logged, shown on Settings > Plugins and `vortexpanel plugins`, and the
    panel starts without it
  - a plugin whose requires_core does not match this panel is not loaded
  - VP_SAFE_MODE=1 (or `vortexpanel plugins safe-mode on`) loads none
  - config.json "plugins_disabled": [ids] skips those
  - plugin routes are admin-only unless the plugin's own blueprint says
    otherwise (the central role check in app.py denies unknown paths for the
    site and viewer roles)
"""
import importlib.util
import json
import os
import re
import sys
import time
import traceback

PANEL_DIR = '/opt/vortexpanel'
PLUGINS_DIR = os.environ.get('VP_PLUGINS_DIR', os.path.join(PANEL_DIR, 'plugins'))
DATA_DIR = os.path.join(PANEL_DIR, 'data', 'plugins')
CONFIG_FILE = os.path.join(PANEL_DIR, 'config.json')
_ID_RE = re.compile(r'^[a-z][a-z0-9_-]{1,40}$')

# id -> {"manifest", "dir", "status": loaded|error|disabled|incompatible|safe-mode, "error", "loaded_at"}
REGISTRY = {}


def core_version():
    for p in (os.path.join(PANEL_DIR, 'VERSION'),
              os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'VERSION')):
        try:
            return open(p).read().strip()
        except OSError:
            continue
    return '0.0.0'


def _vtuple(v):
    parts = re.findall(r'\d+', str(v))[:3]
    return tuple(int(x) for x in (parts + ['0', '0', '0'])[:3])


def version_matches(version, spec):
    """'>=3.8.0,<4.0.0' style specs; empty spec matches everything."""
    v = _vtuple(version)
    for clause in (spec or '').split(','):
        clause = clause.strip()
        if not clause:
            continue
        m = re.match(r'^(>=|<=|==|>|<|!=)?\s*([\d.]+)$', clause)
        if not m:
            return False
        op, ref = m.group(1) or '==', _vtuple(m.group(2))
        ok = {'>=': v >= ref, '<=': v <= ref, '==': v == ref, '>': v > ref,
              '<': v < ref, '!=': v != ref}[op]
        if not ok:
            return False
    return True


def _config():
    try:
        return json.load(open(CONFIG_FILE))
    except Exception:
        return {}


def disabled_ids():
    return set(_config().get('plugins_disabled') or [])


def safe_mode():
    return os.environ.get('VP_SAFE_MODE') == '1' or bool(_config().get('plugins_safe_mode'))


def discover():
    """[(id, dir, manifest or None, error)] for every folder in PLUGINS_DIR."""
    out = []
    try:
        names = sorted(os.listdir(PLUGINS_DIR))
    except OSError:
        return out
    for name in names:
        d = os.path.join(PLUGINS_DIR, name)
        mf = os.path.join(d, 'plugin.json')
        if not os.path.isdir(d) or not os.path.isfile(mf):
            continue
        try:
            man = json.load(open(mf))
        except Exception as e:
            out.append((name, d, None, f'plugin.json is not valid JSON: {e}'))
            continue
        pid = str(man.get('id') or '')
        if pid != name or not _ID_RE.match(pid):
            out.append((name, d, None, 'plugin.json "id" must match the folder name (a-z, 0-9, - and _)'))
            continue
        out.append((pid, d, man, ''))
    return out


class PluginContext:
    """What register(ctx) receives."""

    def __init__(self, app, pid, plugin_dir, manifest):
        self.app = app
        self.id = pid
        self.dir = plugin_dir
        self.manifest = manifest
        self.core_version = core_version()
        self.data_dir = os.path.join(DATA_DIR, pid)
        os.makedirs(self.data_dir, mode=0o700, exist_ok=True)

    def register_blueprint(self, bp, **kw):
        self.app.register_blueprint(bp, **kw)

    def log(self, msg):
        print(f'[plugin {self.id}] {msg}', file=sys.stderr, flush=True)


def load_all(app):
    """Load every enabled, compatible plugin into the Flask app."""
    REGISTRY.clear()
    cv = core_version()
    sm = safe_mode()
    off = disabled_ids()
    for pid, d, man, err in discover():
        entry = {'id': pid, 'dir': d, 'manifest': man or {}, 'status': 'error', 'error': err, 'loaded_at': None}
        REGISTRY[pid] = entry
        if err:
            continue
        if sm:
            entry.update(status='safe-mode', error='Safe mode is on: no plugins are loaded')
            continue
        if pid in off:
            entry.update(status='disabled', error='')
            continue
        spec = man.get('requires_core', '')
        if not version_matches(cv, spec):
            entry.update(status='incompatible',
                         error=f'needs VortexPanel {spec}, this panel is {cv}. Update the plugin or the panel.')
            continue
        src = os.path.join(d, man.get('entry') or 'plugin.py')
        try:
            if d not in sys.path:
                sys.path.insert(0, d)
            spec_ = importlib.util.spec_from_file_location(f'vp_plugin_{pid.replace("-", "_")}', src)
            mod = importlib.util.module_from_spec(spec_)
            sys.modules[spec_.name] = mod
            spec_.loader.exec_module(mod)
            if not hasattr(mod, 'register'):
                raise RuntimeError(f'{os.path.basename(src)} has no register(ctx) function')
            mod.register(PluginContext(app, pid, d, man))
            entry.update(status='loaded', error='', loaded_at=time.time())
        except Exception as e:
            tb = traceback.format_exc(limit=6)
            entry.update(status='error', error=f'{type(e).__name__}: {e}')
            print(f'[plugins] {pid} failed to load and was skipped:\n{tb}', file=sys.stderr, flush=True)
    return REGISTRY


def public_list():
    """For /api/plugins: what the admin UI needs (no file system paths)."""
    out = []
    for pid, e in sorted(REGISTRY.items()):
        m = e['manifest'] or {}
        loaded = e['status'] == 'loaded'
        out.append({
            'id': pid, 'name': m.get('name') or pid, 'version': m.get('version') or '',
            'description': m.get('description') or '', 'requires_core': m.get('requires_core') or '',
            'status': e['status'], 'error': e['error'],
            'pages': [{k: p.get(k) for k in ('id', 'label', 'icon', 'group')} for p in (m.get('pages') or [])
                      if loaded and isinstance(p, dict) and _ID_RE.match(str(p.get('id') or ''))],
            'scripts': [f'/api/plugins/{pid}/assets/' + s.split('static/', 1)[-1] for s in (m.get('scripts') or [])] if loaded else [],
            'styles': [f'/api/plugins/{pid}/assets/' + s.split('static/', 1)[-1] for s in (m.get('styles') or [])] if loaded else [],
        })
    return out


def fragment_path(pid, page_id):
    e = REGISTRY.get(pid)
    if not e or e['status'] != 'loaded':
        return None
    for p in (e['manifest'].get('pages') or []):
        if isinstance(p, dict) and p.get('id') == page_id and p.get('fragment'):
            path = os.path.realpath(os.path.join(e['dir'], p['fragment']))
            if path.startswith(os.path.realpath(e['dir']) + os.sep) and os.path.isfile(path):
                return path
    return None


def asset_dir(pid):
    e = REGISTRY.get(pid)
    if not e or e['status'] != 'loaded':
        return None
    d = os.path.join(e['dir'], 'static')
    return d if os.path.isdir(d) else None


def set_enabled(pid, enabled):
    cfg = _config()
    off = set(cfg.get('plugins_disabled') or [])
    (off.discard if enabled else off.add)(pid)
    cfg['plugins_disabled'] = sorted(off)
    tmp = CONFIG_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(cfg, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_FILE)


def set_safe_mode(on):
    cfg = _config()
    cfg['plugins_safe_mode'] = bool(on)
    tmp = CONFIG_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(cfg, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_FILE)
