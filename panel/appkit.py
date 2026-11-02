"""Shared toolkit for VortexPanel Apps (panel/apps_bundle/<id>, installed to plugins/<id>).

Every App uses these helpers instead of rolling its own, so they all follow the
same isolation rules and cannot step on each other or on the core panel:

  - data:      /opt/vortexpanel/data/apps/<id>/          (0700, JSON written atomically under a lock)
  - nftables:  its own table `inet vp_<id_>`              (never touches ufw/firewalld/other tables)
  - systemd:   units named vortexpanel-app-<id>[-<name>]  (removed on uninstall)
  - nginx:     /etc/nginx/conf.d/vp-app-<id>-*.conf       (nginx -t before reload, rolled back on failure)
  - routes:    /api/app/<id>/...                          (admin only; central auth + CSRF apply)
  - python:    one package per App named vpapp_<id_>      (the loader refuses name clashes)

Nothing here runs a shell: every command is an argv list.
"""
import fcntl
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager

PANEL_DIR = '/opt/vortexpanel'
APPS_DATA = os.environ.get('VP_APPS_DATA', os.path.join(PANEL_DIR, 'data', 'apps'))
ID_RE = re.compile(r'^[a-z][a-z0-9-]{1,30}$')


def py_name(app_id):
    """'scan-detect' -> 'scan_detect' (python/nft identifier form)."""
    return app_id.replace('-', '_')


def venv_python():
    p = os.path.join(PANEL_DIR, 'venv', 'bin', 'python3')
    return p if os.path.exists(p) else sys.executable


# --------------------------------------------------------------------------- data

def data_dir(app_id):
    d = os.path.join(APPS_DATA, app_id)
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


@contextmanager
def locked(app_id, name='state'):
    """Cross-process lock (gunicorn workers + the App's own service)."""
    path = os.path.join(data_dir(app_id), f'.{name}.lock')
    with open(path, 'a') as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def read_json(app_id, name, default=None):
    try:
        with open(os.path.join(data_dir(app_id), name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default if default is not None else {}


def write_json(app_id, name, data):
    path = os.path.join(data_dir(app_id), name)
    tmp = f'{path}.{os.getpid()}.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, separators=(',', ':'))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def update_json(app_id, name, fn, default=None):
    """Read-modify-write under the App's lock. fn(data) mutates or returns new data."""
    with locked(app_id, name):
        data = read_json(app_id, name, default if default is not None else {})
        out = fn(data)
        data = data if out is None else out
        write_json(app_id, name, data)
        return data


def append_jsonl(app_id, name, rec, max_lines=20000):
    """Append one record; trims to the newest max_lines when the file grows past it."""
    path = os.path.join(data_dir(app_id), name)
    line = json.dumps(rec, separators=(',', ':')) + '\n'
    with locked(app_id, name):
        with open(path, 'a') as f:
            f.write(line)
        try:
            if os.path.getsize(path) > max_lines * 260:
                with open(path) as f:
                    lines = f.readlines()
                if len(lines) > max_lines:
                    tmp = path + '.tmp'
                    with open(tmp, 'w') as f:
                        f.writelines(lines[-max_lines:])
                    os.replace(tmp, path)
        except OSError:
            pass
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def read_jsonl(app_id, name, limit=500, newest_first=True, match=None):
    path = os.path.join(data_dir(app_id), name)
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError:
        return []
    out = []
    for ln in (reversed(lines) if newest_first else lines):
        try:
            rec = json.loads(ln)
        except ValueError:
            continue
        if match and not match(rec):
            continue
        out.append(rec)
        if len(out) >= limit:
            break
    return out


def oplog(app_id, action, detail='', user=None):
    """Operation log shown on each App's 'Operation logs' tab."""
    if user is None:
        try:
            from flask import g, session
            u = g.get('vp_user') or {}
            user = u.get('username') or session.get('user') or 'admin'
        except Exception:  # noqa: BLE001 - outside a request (the App's service)
            user = 'system'
    append_jsonl(app_id, 'oplog.jsonl', {'t': int(time.time()), 'user': str(user)[:64],
                                         'action': str(action)[:80], 'detail': str(detail)[:500]}, 5000)


# ----------------------------------------------------------------------- commands

def run(argv, timeout=60, input_text=None):
    """(rc, stdout, stderr). Never raises."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input_text)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, '', f'{argv[0]}: not found'
    except subprocess.TimeoutExpired:
        return 124, '', f'{argv[0]}: timed out after {timeout}s'
    except Exception as e:  # noqa: BLE001
        return 1, '', str(e)


def have(binary):
    return shutil.which(binary) is not None


def os_family():
    try:
        txt = open('/etc/os-release').read().lower()
    except OSError:
        return 'debian'
    if re.search(r'^id(_like)?=.*(rhel|fedora|centos|rocky|alma)', txt, re.M):
        return 'rhel'
    return 'debian'


def pkg_install(packages, log=print, timeout=900):
    """Install distro packages (apt or dnf). Returns True when all succeeded."""
    packages = [p for p in packages if re.fullmatch(r'[A-Za-z0-9.+_-]+', p)]
    if not packages:
        return True
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
    if os_family() == 'rhel':
        argv = ['dnf', 'install', '-y'] + packages
    else:
        subprocess.run(['apt-get', 'update', '-qq'], capture_output=True, timeout=timeout, env=env)
        argv = ['apt-get', 'install', '-y', '-qq'] + packages
    log('Installing ' + ' '.join(packages) + ' ...')
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
    except Exception as e:  # noqa: BLE001
        log(f'Package install failed: {e}')
        return False
    if r.returncode != 0:
        log((r.stderr or r.stdout).strip()[-800:])
    return r.returncode == 0


# ------------------------------------------------------------------------ systemd

def unit_name(app_id, suffix=''):
    return f'vortexpanel-app-{app_id}' + (f'-{suffix}' if suffix else '')


def install_service(app_id, module, suffix='', description='', plugin_dir=None, extra=''):
    """Install + start a long-running service: `python -m <module>` with the App on PYTHONPATH."""
    plugin_dir = plugin_dir or os.path.join(PANEL_DIR, 'plugins', app_id)
    name = unit_name(app_id, suffix)
    unit = f"""[Unit]
Description=VortexPanel App {app_id}{(' - ' + description) if description else ''}
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={PANEL_DIR}
Environment=PYTHONPATH={plugin_dir}:{PANEL_DIR}
Environment=PYTHONUNBUFFERED=1
ExecStart={venv_python()} -m {module}
Restart=always
RestartSec=5
Nice=5
{extra}
[Install]
WantedBy=multi-user.target
"""
    path = f'/etc/systemd/system/{name}.service'
    with open(path, 'w') as f:
        f.write(unit)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', name])
    run(['systemctl', 'restart', name])
    return name


def install_timer(app_id, module, on_calendar, suffix='', description='', plugin_dir=None, args=''):
    """Install + start a oneshot service run by a timer (OnCalendar=...)."""
    plugin_dir = plugin_dir or os.path.join(PANEL_DIR, 'plugins', app_id)
    name = unit_name(app_id, suffix)
    svc = f"""[Unit]
Description=VortexPanel App {app_id}{(' - ' + description) if description else ''}

[Service]
Type=oneshot
WorkingDirectory={PANEL_DIR}
Environment=PYTHONPATH={plugin_dir}:{PANEL_DIR}
ExecStart={venv_python()} -m {module} {args}
Nice=10
"""
    tmr = f"""[Unit]
Description=VortexPanel App {app_id} timer{(' - ' + description) if description else ''}

[Timer]
OnCalendar={on_calendar}
Persistent=true
RandomizedDelaySec=30

[Install]
WantedBy=timers.target
"""
    with open(f'/etc/systemd/system/{name}.service', 'w') as f:
        f.write(svc)
    with open(f'/etc/systemd/system/{name}.timer', 'w') as f:
        f.write(tmr)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', f'{name}.timer'])
    return name


def _other_ids(app_id):
    """Other App ids that start with '<app_id>-' (e.g. 'site' vs 'site-stats'): their
    units and files share our prefix and must be left alone."""
    try:
        from panel import apps
        ids = set(apps.bundled()) | set(apps.installed())
    except Exception:  # noqa: BLE001
        ids = set()
    return [i for i in ids if i != app_id and i.startswith(app_id + '-')]


def remove_units(app_id):
    """Stop, disable and delete every unit this App installed."""
    prefix = unit_name(app_id)
    others = [unit_name(o) + '-' for o in _other_ids(app_id)] + [unit_name(o) + '.' for o in _other_ids(app_id)]
    removed = []
    for fn in sorted(os.listdir('/etc/systemd/system')) if os.path.isdir('/etc/systemd/system') else []:
        if not (fn == prefix + '.service' or fn.startswith(prefix + '-')) or \
                not fn.endswith(('.service', '.timer')) or fn.startswith(tuple(others)):
            continue
        run(['systemctl', 'disable', '--now', fn], timeout=60)
        try:
            os.remove(os.path.join('/etc/systemd/system', fn))
            removed.append(fn)
        except OSError:
            pass
    run(['systemctl', 'daemon-reload'])
    return removed


def service_state(name):
    rc, out, _ = run(['systemctl', 'is-active', name], timeout=10)
    return (out.strip().splitlines() or ['unknown'])[0]


def restart_service(name):
    rc, _, err = run(['systemctl', 'restart', name], timeout=60)
    return rc == 0, err.strip()


# ------------------------------------------------------------------------- nftables

def nft_table(app_id):
    return 'vp_' + py_name(app_id)


def nft(script, timeout=30):
    """Apply an nft script atomically (one transaction). (ok, error)."""
    rc, _, err = run(['nft', '-f', '-'], timeout=timeout, input_text=script)
    return rc == 0, err.strip()


def nft_json(*args, timeout=20):
    rc, out, _ = run(['nft', '-j'] + list(args), timeout=timeout)
    if rc != 0:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def nft_set_elements(table, set_name):
    """[{'val': '1.2.3.4' | ['1.2.3.4', 22], 'expires': seconds or None, 'packets': n}] for one set."""
    j = nft_json('list', 'set', 'inet', table, set_name)
    out = []
    if not j:
        return out
    for item in j.get('nftables', []):
        s = item.get('set')
        if not s:
            continue
        for el in s.get('elem') or []:
            rec = {'val': None, 'expires': None, 'packets': 0}
            e = el.get('elem') if isinstance(el, dict) and 'elem' in el else el
            if isinstance(e, dict):
                v = e.get('val')
                rec['expires'] = e.get('expires')
                ctr = e.get('counter') or {}
                rec['packets'] = ctr.get('packets', 0)
            else:
                v = e
            if isinstance(v, dict) and 'concat' in v:
                v = v['concat']
            elif isinstance(v, dict) and 'prefix' in v:
                v = f"{v['prefix']['addr']}/{v['prefix']['len']}"
            elif isinstance(v, dict) and 'range' in v:
                v = f"{v['range'][0]}-{v['range'][1]}"
            rec['val'] = v
            out.append(rec)
    return out


def nft_drop_table(app_id):
    return run(['nft', 'delete', 'table', 'inet', nft_table(app_id)])[0] == 0


# ---------------------------------------------------------------------------- nginx

def nginx_conf_dir():
    for d in ('/etc/nginx/conf.d', '/www/server/nginx/conf/conf.d'):
        if os.path.isdir(d):
            return d
    return None


def nginx_write(app_id, name, content):
    """Write /etc/nginx/conf.d/vp-app-<id>-<name>.conf, test, reload; restore on failure.
    content='' removes the file. (ok, error)."""
    d = nginx_conf_dir()
    if not d or not have('nginx'):
        return False, 'nginx is not installed'
    if not re.fullmatch(r'[a-z0-9-]{1,40}', name):
        return False, 'bad name'
    path = os.path.join(d, f'vp-app-{app_id}-{name}.conf')
    old = None
    if os.path.exists(path):
        with open(path) as f:
            old = f.read()
    if content:
        with open(path, 'w') as f:
            f.write(content)
    elif os.path.exists(path):
        os.remove(path)
    rc, _, err = run(['nginx', '-t'], timeout=30)
    if rc != 0:
        if old is None:
            if os.path.exists(path):
                os.remove(path)
        else:
            with open(path, 'w') as f:
                f.write(old)
        return False, err.strip()[-600:]
    run(['systemctl', 'reload', 'nginx'], timeout=30)
    return True, ''


def nginx_remove_all(app_id):
    d = nginx_conf_dir()
    if not d:
        return
    removed = False
    for fn in os.listdir(d):
        if fn.startswith(f'vp-app-{app_id}-') and fn.endswith('.conf') and \
                not fn.startswith(tuple(f'vp-app-{o}-' for o in _other_ids(app_id))):
            os.remove(os.path.join(d, fn))
            removed = True
    if removed and run(['nginx', '-t'])[0] == 0:
        run(['systemctl', 'reload', 'nginx'])


# ---------------------------------------------------------------------- validation

def parse_ip(text):
    """'1.2.3.4' | '2001:db8::1' | '10.0.0.0/8' -> normalized string, or None."""
    t = str(text or '').strip()
    if not t or len(t) > 64:
        return None
    try:
        if '/' in t:
            return str(ipaddress.ip_network(t, strict=False))
        return str(ipaddress.ip_address(t))
    except ValueError:
        return None


def ip_in(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in nets:
        try:
            if a in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def clamp_int(v, lo, hi, default):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def admin_ips():
    """IPs of currently signed-in admins (never auto-block those)."""
    out = set()
    try:
        from flask import request
        ip = (request.headers.get('X-Real-IP') or request.remote_addr or '').replace('::ffff:', '')
        if ip:
            out.add(ip)
    except Exception:  # noqa: BLE001
        pass
    try:
        for rec in json.load(open(os.path.join(APPS_DATA, 'admin_ips.json'))).get('ips', []):
            out.add(rec)
    except (OSError, ValueError, AttributeError):
        pass
    out |= ssh_session_ips()
    return out


_seen_here = {}


def remember_admin_ip(ip):
    """Called on each admin request by the core: Apps never block the admin's own address.
    Several gunicorn workers call this: the read-modify-write is under a file lock, and the
    in-process 'recently written' cache is set only after the write succeeded."""
    if not ip:
        return
    now = int(time.time())
    if now - _seen_here.get(ip, 0) < 600:      # in-process cache: no disk I/O per request
        return
    path = os.path.join(APPS_DATA, 'admin_ips.json')
    try:
        os.makedirs(APPS_DATA, mode=0o700, exist_ok=True)
        with open(path + '.lock', 'a') as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            try:
                d = json.load(open(path))
            except (OSError, ValueError):
                d = {}
            ips = d.get('seen') or {}
            ips[ip] = now
            ips = {k: v for k, v in ips.items() if now - v < 7 * 86400}
            d = {'seen': ips, 'ips': sorted(ips)}
            tmp = path + f'.{os.getpid()}.tmp'
            with open(tmp, 'w') as f:
                json.dump(d, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        _seen_here[ip] = now
    except OSError:
        pass


def ssh_session_ips():
    """Addresses with an open SSH session right now: an admin who only uses SSH (and has
    not opened the panel from this address yet) must never be auto-blocked either."""
    ports = {'22'}
    try:
        for line in open('/etc/ssh/sshd_config'):
            m = re.match(r'\s*Port\s+(\d+)', line)
            if m:
                ports.add(m.group(1))
    except OSError:
        pass
    rc, out, _ = run(['ss', '-Htn', 'state', 'established'], timeout=10)
    found = set()
    for line in (out or '').splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local, peer = parts[-2], parts[-1]
        if local.rsplit(':', 1)[-1] in ports:
            ip = peer.rsplit(':', 1)[0].strip('[]').replace('::ffff:', '')
            if parse_ip(ip):
                found.add(ip)
    return found


# ------------------------------------------------------------------------- flask

def blueprint(app_id, import_name):
    """Blueprint for an App with an admin-only guard and the /api/app/<id> prefix."""
    from flask import Blueprint, jsonify
    from panel.utils.authctx import is_admin
    bp = Blueprint('vpapp_' + py_name(app_id), import_name, url_prefix=f'/api/app/{app_id}')

    @bp.before_request
    def _admin_only():
        if not is_admin():
            return jsonify({'ok': False, 'error': 'Administrator only'}), 403
        return None
    return bp


def body():
    from flask import request
    d = request.get_json(silent=True)
    return d if isinstance(d, dict) else {}


# ---------------------------------------------------------------------- alerts

def notify(app_id, title, detail, min_gap=600):
    """Send through Settings > Alerts channels (when alerts are on), at most one
    message per App every min_gap seconds; skipped events are summarised next time."""
    st = read_json(app_id, 'notify_state.json', {})
    now = int(time.time())
    st['pending'] = (st.get('pending') or [])[-49:] + [f'{time.strftime("%H:%M", time.localtime(now))} {detail}']
    if now - int(st.get('last') or 0) < min_gap:
        write_json(app_id, 'notify_state.json', st)
        return False
    body = '\n'.join(st['pending'])
    st.update(last=now, pending=[])
    write_json(app_id, 'notify_state.json', st)
    try:
        from panel import alerts
        cfg = alerts.load()
        if not cfg.get('enabled'):
            return False
        host = alerts.server_name()
        subj = f'[{host}] {title}'
        res = alerts.send(subj, body, cfg, {'event': f'app:{app_id}', 'server': host})
        alerts._record({'time': now, 'key': f'app:{app_id}:{title}', 'title': subj, 'state': 'event', 'result': res})
        return True
    except Exception:  # noqa: BLE001
        return False
