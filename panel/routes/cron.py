from flask import Blueprint, jsonify, request, session
import subprocess, re, os, time, json, uuid, threading

cron_bp = Blueprint('cron', __name__)
def req(): return 'user' in session

CRON_META_FILE = '/opt/vortexpanel/cron_meta.json'

def sh(c, t=30):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e: return '', str(e), 1

def load_meta():
    if os.path.exists(CRON_META_FILE):
        try:
            with open(CRON_META_FILE) as f: return json.load(f)
        except: pass
    return {}

def save_meta(meta):
    os.makedirs(os.path.dirname(CRON_META_FILE), exist_ok=True)
    tmp = CRON_META_FILE + '.tmp'
    with open(tmp, 'w') as f: json.dump(meta, f, indent=2)
    os.replace(tmp, CRON_META_FILE)

class CrontabError(Exception):
    pass

def get_crontab():
    """Root's crontab. `crontab -l` exits 1 with "no crontab for root" when
    none exists yet - that is an empty crontab. Any other failure (crontab
    binary missing because cron/cronie is not installed, timeout) must abort
    the caller: treating it as empty made the next add/edit/delete overwrite
    the whole existing crontab with just the new line."""
    try:
        r = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        raise CrontabError('crontab command not found - install cron (Debian/Ubuntu) or cronie (RHEL/Fedora)')
    except subprocess.TimeoutExpired:
        raise CrontabError('crontab -l timed out')
    if r.returncode == 0:
        return r.stdout
    if 'no crontab' in (r.stderr or '').lower():
        return ''
    raise CrontabError((r.stderr or 'crontab -l failed').strip())

def set_crontab(content):
    try:
        r = subprocess.run(['crontab', '-'], input=content, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    if r.returncode != 0:
        return False, (r.stderr or 'crontab rejected the new table').strip()
    return True, None

def cron_daemon_active():
    out, _, _ = sh('systemctl is-active cron crond cronie 2>/dev/null', t=10)
    return any(l.strip() == 'active' for l in out.split('\n'))

def _cron_unit():
    """cron (Debian/Ubuntu) or crond (RHEL/Fedora cronie), whichever exists."""
    for u in ('cron', 'crond'):
        if subprocess.run(['systemctl', 'cat', u], capture_output=True, timeout=15).returncode == 0:
            return u
    return ''

def ensure_cron():
    """Make sure root's crontab can be written AND is executed: minimal and
    cloud images (Fedora cloud, Debian/Ubuntu minimal, containers) ship
    without cron/cronie, so 'crontab' did not exist and every job failed; a
    present but stopped daemon silently ran nothing. Installs cron (apt) or
    cronie (dnf/yum) when crontab is missing and enables the daemon.
    Returns (ok, message)."""
    import shutil
    msg = ''
    if not shutil.which('crontab'):
        if shutil.which('apt-get'):
            cmd = ['apt-get', 'install', '-y', '-o', 'DPkg::Lock::Timeout=120', 'cron']
        elif shutil.which('dnf') or shutil.which('yum'):
            cmd = [shutil.which('dnf') or shutil.which('yum'), 'install', '-y', 'cronie']
        else:
            return False, 'crontab command not found and no supported package manager to install cron'
        env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='a')
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
            if r.returncode != 0 and cmd[0] == 'apt-get':
                # minimal images often have empty package lists
                subprocess.run(['apt-get', 'update', '-qq'], capture_output=True, timeout=300, env=env)
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
        except subprocess.TimeoutExpired:
            return False, 'Installing cron timed out'
        if r.returncode != 0 or not shutil.which('crontab'):
            return False, 'cron is not installed and installing it failed: ' + ((r.stderr or r.stdout or '').strip()[-400:])
        msg = 'cron was not installed -- installed it. '
    unit = _cron_unit()
    if unit and not cron_daemon_active():
        try:
            r = subprocess.run(['systemctl', 'enable', '--now', unit], capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                msg += f'The {unit} service was not running -- started and enabled it. '
            else:
                msg += f'Warning: the {unit} service could not be started: {(r.stderr or "").strip()[-200:]} '
        except subprocess.TimeoutExpired:
            msg += f'Warning: starting {unit} timed out. '
    return True, msg.strip()

_VID_RE = re.compile(r'^[a-f0-9-]{1,36}$')
_FIELD_RE = re.compile(r'^[0-9*/,A-Za-z-]+$')

def _vid_re(vid):
    return re.compile(r'#\s*vp:' + re.escape(vid) + r'\s*$')

def _valid_schedule(schedule):
    parts = schedule.split()
    return len(parts) == 5 and all(_FIELD_RE.match(p) for p in parts)

def _escape_percent(cmd):
    """cron turns an unescaped '%' into a newline (the rest of the line becomes
    stdin), so `date +%F` silently breaks. Escape any '%' not already escaped."""
    return re.sub(r'(?<!\\)%', r'\%', cmd)

def _cron_to_shell(cmd):
    """Undo cron's %-processing for Run Now: the part before the first unescaped
    '%' is the command, the rest (with '%' -> newline) is stdin, '\\%' -> '%'."""
    m = re.search(r'(?<!\\)%', cmd)
    stdin = None
    if m:
        cmd, stdin = cmd[:m.start()], cmd[m.end():]
        stdin = re.sub(r'(?<!\\)%', '\n', stdin).replace('\\%', '%')
    return cmd.replace('\\%', '%'), stdin

def _validate_job(schedule, command, name):
    if not command: return 'Command required'
    if any(c in (command + schedule + (name or '')) for c in '\r\n'):
        return 'Command, schedule and name must be a single line'
    if not _valid_schedule(schedule):
        return 'Invalid cron schedule - must be 5 fields (min hour day month weekday)'
    return None

def parse_crontab(raw, meta):
    jobs = []
    for line in raw.split('\n'):
        s = line.strip()
        if not s: continue
        # Extract vp-id tag if present: # vp:uuid -- this MUST happen before
        # deciding whether to skip a comment line. cron's own convention for
        # disabling a job is prefixing the whole line with '#', so a disabled
        # VP job's line legitimately starts with '#' too. Skipping every
        # '#'-prefixed line here (as before) made disabled jobs disappear
        # from parse_crontab's results entirely -- confirmed via direct
        # testing against a real crontab -- with no way to re-enable them
        # through the UI since they no longer showed up in the job list at all.
        vid_m = re.search(r'#\s*vp:([a-f0-9-]+)', s)
        if not vid_m and s.startswith('#'):
            continue  # a genuine non-VP comment line, not a job at all
        is_enabled = not s.startswith('#')
        # Strip meta tag, then strip a leading disable '#' if present, before
        # parsing the schedule/command out of what remains.
        clean = re.sub(r'\s*#\s*vp:[a-f0-9-]+', '', s).strip()
        if not is_enabled:
            clean = clean.lstrip('#').strip()
        parts = clean.split(None, 5)
        if len(parts) < 6: continue
        schedule = ' '.join(parts[:5])
        command  = parts[5]
        vid = vid_m.group(1) if vid_m else None
        m = meta.get(vid, {}) if vid else {}
        jobs.append({
            'id':        vid or clean,
            'schedule':  schedule,
            'command':   command,
            'name':      m.get('name', ''),
            'type':      m.get('type', 'shell'),
            'user':      m.get('user', 'root'),
            'logs':      m.get('last_log', ''),
            'last_run':  m.get('last_run', ''),
            'last_exit': m.get('last_exit', ''),
            'enabled':   is_enabled,
            'raw_line':  s,
        })
    return jobs

def human_schedule(schedule):
    """Convert cron expression to human-readable string"""
    parts = schedule.split()
    if len(parts) != 5: return schedule
    mn, hr, dom, mon, dow = parts
    if schedule == '* * * * *':   return 'Every minute'
    if mn == '*/5' and hr == '*': return 'Every 5 minutes'
    if mn == '*/10':              return 'Every 10 minutes'
    if mn == '*/15':              return 'Every 15 minutes'
    if mn == '*/30':              return 'Every 30 minutes'
    if hr == '*' and mn != '*':   return f'Every hour at :{mn.zfill(2)}'
    if dom == '*' and mon == '*' and dow == '*':
        return f'Daily at {hr.zfill(2)}:{mn.zfill(2)}'
    if dow != '*':
        days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat']
        try:
            day_name = days[int(dow)]
            return f'Every {day_name} at {hr.zfill(2)}:{mn.zfill(2)}'
        except: pass
    if dom != '*':
        return f'Monthly on day {dom} at {hr.zfill(2)}:{mn.zfill(2)}'
    return schedule

# --- PRESETS --------------------------------------------------------------------
SCHEDULE_PRESETS = [
    {'label':'Every minute',      'value':'* * * * *'},
    {'label':'Every 5 minutes',   'value':'*/5 * * * *'},
    {'label':'Every 10 minutes',  'value':'*/10 * * * *'},
    {'label':'Every 15 minutes',  'value':'*/15 * * * *'},
    {'label':'Every 30 minutes',  'value':'*/30 * * * *'},
    {'label':'Every hour',        'value':'0 * * * *'},
    {'label':'Every 2 hours',     'value':'0 */2 * * *'},
    {'label':'Every 6 hours',     'value':'0 */6 * * *'},
    {'label':'Every 12 hours',    'value':'0 */12 * * *'},
    {'label':'Daily at midnight', 'value':'0 0 * * *'},
    {'label':'Daily at 1:00 AM',  'value':'0 1 * * *'},
    {'label':'Daily at 3:00 AM',  'value':'0 3 * * *'},
    {'label':'Every Sunday',      'value':'0 0 * * 0'},
    {'label':'Every Monday',      'value':'0 0 * * 1'},
    {'label':'First of month',    'value':'0 0 1 * *'},
    {'label':'Custom...',         'value':'custom'},
]

TASK_TEMPLATES = [
    {'id':'shell',      'label':'Shell Script',      'icon':'terminal',  'desc':'Run any shell command or script',
     'cmd':'','hint':'/usr/bin/bash /path/to/script.sh'},
    {'id':'php',        'label':'PHP Script',         'icon':'code', 'desc':'Execute a PHP file with php-cli',
     'cmd':'/usr/bin/php ','hint':'/www/wwwroot/site.com/cron.php'},
    {'id':'python',     'label':'Python Script',      'icon':'code', 'desc':'Run a Python script',
     'cmd':'/usr/bin/python3 ','hint':'/www/wwwroot/app/task.py'},
    {'id':'node',       'label':'Node.js Script',     'icon':'dot', 'desc':'Execute a Node.js script',
     'cmd':'/usr/bin/node ','hint':'/www/wwwroot/app/cron.js'},
    {'id':'url',        'label':'URL Request',        'icon':'globe', 'desc':'Fetch a URL (website cron trigger)',
     'cmd':'/usr/bin/curl -s ','hint':'https://example.com/cron?token=abc'},
    {'id':'backup',     'label':'Website Backup',     'icon':'hard-drive', 'desc':'Backup a website directory',
     'cmd':'tar -czf /opt/vortexpanel/backups/cron_backup_$(date +\\%Y\\%m\\%d).tar.gz ','hint':'/www/wwwroot/site.com'},
    {'id':'db_backup',  'label':'Database Backup',    'icon':'database', 'desc':'Dump a MySQL/MariaDB database',
     'cmd':'mysqldump -u root ','hint':'dbname | gzip > /opt/vortexpanel/backups/db_$(date +\\%Y\\%m\\%d).sql.gz'},
    {'id':'certbot',    'label':'SSL Certificate Renewal','icon':'lock','desc':'Renew Let\'s Encrypt certificates',
     'cmd':'/usr/bin/certbot renew --quiet','hint':''},
    {'id':'log_clear',  'label':'Clear Nginx Logs',   'icon':'trash', 'desc':'Rotate/clear Nginx access logs',
     'cmd':'> /var/log/nginx/access.log && systemctl reload nginx','hint':''},
    {'id':'cloud_sync', 'label':'Cloud Backup Sync',  'icon':'cloud',  'desc':'Upload any new local backups to cloud storage',
     'cmd':'cd /opt/vortexpanel && venv/bin/python3 -c "from panel.routes.cloud_backup import sync_all; sync_all()"','hint':''},
    {'id':'custom',     'label':'Custom Command',     'icon':'settings',  'desc':'Enter any custom command',
     'cmd':'','hint':'Enter your command...'},
]

@cron_bp.route('/api/cron/presets')
def get_presets():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, 'schedules':SCHEDULE_PRESETS, 'templates':TASK_TEMPLATES})

@cron_bp.route('/api/cron/jobs')
def list_jobs():
    if not req(): return jsonify({'ok':False}), 401
    try: raw = get_crontab()
    except CrontabError as e:
        # Listing never installs anything; the first job added does (ensure_cron).
        return jsonify({'ok':False,'error':str(e),'jobs':[],'cron_missing':'not found' in str(e),
                        'hint':'Adding a job installs and starts cron automatically.'})
    meta = load_meta()
    jobs = parse_crontab(raw, meta)
    # Add human-readable schedule
    for j in jobs:
        j['schedule_human'] = human_schedule(j['schedule'])
    return jsonify({'ok':True, 'jobs':jobs, 'count':len(jobs), 'daemon_active':cron_daemon_active()})

@cron_bp.route('/api/cron/jobs', methods=['POST'])
def add_job():
    if not req(): return jsonify({'ok':False}), 401
    d        = request.get_json() or {}
    schedule = ' '.join((d.get('schedule') or '0 * * * *').split())
    command  = (d.get('command') or '').strip()
    name     = (d.get('name') or '').strip()
    jtype    = d.get('type','shell')

    ok, res = add_cron_job(schedule, command, name, jtype)
    if not ok:
        return jsonify({'ok':False,'error':res[0]}), res[1]
    return jsonify({'ok':True, 'id':res['id'], 'schedule_human':human_schedule(schedule), 'notice':res['notice']})


def add_cron_job(schedule, command, name, jtype='shell'):
    """Append a job to root's crontab (also used by Website Import).
    Returns (True, {'id', 'notice'}) or (False, (error, http_status))."""
    schedule = ' '.join((schedule or '').split())
    err = _validate_job(schedule, command, name)
    if err: return False, (err, 400)

    vid  = str(uuid.uuid4())[:8]
    line = f'{schedule} {_escape_percent(command)} # vp:{vid}'

    ok, note = ensure_cron()
    if not ok: return False, (note, 500)
    try: raw = get_crontab()
    except CrontabError as e: return False, (str(e), 500)
    new  = (raw.rstrip() + '\n' + line + '\n') if raw.strip() else line + '\n'
    ok, err = set_crontab(new)
    if not ok:
        return False, ('Failed to update crontab: ' + err, 500)

    meta = load_meta()
    # Jobs always live in root's crontab (the panel has no per-user crontab support)
    meta[vid] = {'name':name, 'type':jtype, 'user':'root', 'created':time.strftime('%Y-%m-%d %H:%M:%S'), 'last_log':'', 'last_run':'', 'last_exit':''}
    save_meta(meta)
    return True, {'id': vid, 'notice': note}

@cron_bp.route('/api/cron/jobs/<vid>', methods=['PUT'])
def edit_job(vid):
    if not req(): return jsonify({'ok':False}), 401
    d        = request.get_json() or {}
    schedule = ' '.join((d.get('schedule') or '').split())
    command  = (d.get('command') or '').strip()
    name     = d.get('name','') or ''
    jtype    = d.get('type','shell')

    if not _VID_RE.match(vid): return jsonify({'ok':False,'error':'Job not found'}), 404
    err = _validate_job(schedule, command, name)
    if err: return jsonify({'ok':False,'error':err}), 400

    try: raw = get_crontab()
    except CrontabError as e: return jsonify({'ok':False,'error':str(e)}), 500
    rx = _vid_re(vid)
    new_lines = []
    found = False
    for line in raw.rstrip('\n').split('\n'):
        if rx.search(line):
            # keep a disabled job disabled
            prefix = '# ' if line.strip().startswith('#') else ''
            new_lines.append(f'{prefix}{schedule} {_escape_percent(command)} # vp:{vid}')
            found = True
        else:
            new_lines.append(line)
    if not found:
        return jsonify({'ok':False,'error':'Job not found'}), 404

    ok, err = set_crontab('\n'.join(new_lines) + '\n')
    if not ok: return jsonify({'ok':False,'error':'Failed to update crontab: ' + err}), 500
    meta = load_meta()
    if vid in meta:
        meta[vid].update({'name':name,'type':jtype})
        save_meta(meta)
    return jsonify({'ok':True,'schedule_human':human_schedule(schedule)})

@cron_bp.route('/api/cron/jobs/<vid>', methods=['DELETE'])
def delete_job(vid):
    if not req(): return jsonify({'ok':False}), 401
    if not _VID_RE.match(vid): return jsonify({'ok':False,'error':'Job not found'}), 404
    try: raw = get_crontab()
    except CrontabError as e: return jsonify({'ok':False,'error':str(e)}), 500
    rx = _vid_re(vid)
    lines = [l for l in raw.rstrip('\n').split('\n') if not rx.search(l)]
    ok, err = set_crontab('\n'.join(lines).strip('\n') + '\n' if any(l.strip() for l in lines) else '')
    if not ok: return jsonify({'ok':False,'error':'Failed to update crontab: ' + err}), 500
    meta = load_meta()
    meta.pop(vid, None)
    save_meta(meta)
    return jsonify({'ok':True})

@cron_bp.route('/api/cron/jobs/<vid>/toggle', methods=['POST'])
def toggle_job(vid):
    if not req(): return jsonify({'ok':False}), 401
    enable = bool((request.get_json() or {}).get('enable', True))
    if not _VID_RE.match(vid): return jsonify({'ok':False,'error':'Job not found'}), 404
    try: raw = get_crontab()
    except CrontabError as e: return jsonify({'ok':False,'error':str(e)}), 500
    rx = _vid_re(vid)
    new_lines = []
    found = False
    for line in raw.rstrip('\n').split('\n'):
        if rx.search(line):
            found = True
            s = line.strip()
            if enable:
                new_lines.append(re.sub(r'^#+\s*', '', s))
            else:
                new_lines.append('# ' + s if not s.startswith('#') else s)
        else:
            new_lines.append(line)
    if not found: return jsonify({'ok':False,'error':'Job not found'}), 404
    ok, err = set_crontab('\n'.join(new_lines) + '\n')
    if not ok: return jsonify({'ok':False,'error':'Failed to update crontab: ' + err}), 500
    return jsonify({'ok':True, 'enabled':enable})

@cron_bp.route('/api/cron/jobs/<vid>/run', methods=['POST'])
def run_now(vid):
    if not req(): return jsonify({'ok':False}), 401
    if not _VID_RE.match(vid): return jsonify({'ok':False,'error':'Job not found or disabled'}), 404
    try: raw = get_crontab()
    except CrontabError as e: return jsonify({'ok':False,'error':str(e)}), 500
    rx  = _vid_re(vid)
    cmd = ''
    for line in raw.split('\n'):
        if rx.search(line) and not line.strip().startswith('#'):
            parts = line.strip().split(None, 5)
            if len(parts) >= 6:
                cmd = rx.sub('', parts[5]).strip()
    if not cmd:
        return jsonify({'ok':False,'error':'Job not found or disabled'}), 404
    shell_cmd, stdin_data = _cron_to_shell(cmd)

    run_id = str(uuid.uuid4())[:8]
    # Run state goes through job_state (shared file): the poll for a run that
    # started in one gunicorn worker usually lands on another worker.
    from panel.routes.job_state import save_job
    state = {'lines':[], 'done':False, 'exit_code':None, 'start': time.time()}
    save_job('cronrun_' + run_id, state)

    def execute():
        start = time.time()
        last_save = [0.0]
        def flush(force=False):
            if force or time.time() - last_save[0] > 0.4:
                if len(state['lines']) > 2000:
                    state['lines'] = state['lines'][:2] + ['[VortexPanel] ... output truncated ...'] + state['lines'][-1900:]
                try: save_job('cronrun_' + run_id, state)
                except Exception: pass
                last_save[0] = time.time()
        state['lines'].append(f'[VortexPanel] Executing: {cmd}')
        state['lines'].append(f'[VortexPanel] Started: {time.strftime("%Y-%m-%d %H:%M:%S")}')
        flush(True)
        rc = None
        try:
            proc = subprocess.Popen(shell_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                                    text=True, bufsize=1, errors='replace')
            if stdin_data is not None:
                try:
                    proc.stdin.write(stdin_data); proc.stdin.close()
                except OSError: pass
            for line in proc.stdout:
                state['lines'].append(line.rstrip())
                flush()
            rc = proc.wait()
        except Exception as e:
            state['lines'].append(f'[VortexPanel] Failed to start: {e}')
            rc = 127
        elapsed = round(time.time() - start, 2)
        state.update({'done':True,'exit_code':rc})
        state['lines'].append(f'[VortexPanel] Finished in {elapsed}s - exit code: {rc}')
        flush(True)
        # Save to meta
        meta = load_meta()
        if vid in meta:
            log_str = '\n'.join(state['lines'])
            meta[vid].update({
                'last_run':  time.strftime('%Y-%m-%d %H:%M:%S'),
                'last_exit': str(rc),
                'last_log':  log_str[-2000:],
            })
            save_meta(meta)

    threading.Thread(target=execute, daemon=True).start()
    return jsonify({'ok':True, 'run_id':run_id})

@cron_bp.route('/api/cron/run/<run_id>')
def run_status(run_id):
    if not req(): return jsonify({'ok':False}), 401
    from panel.routes.job_state import load_job
    job = load_job('cronrun_' + run_id)
    if not job: return jsonify({'ok':False,'error':'Run not found'}), 404
    return jsonify(dict(job, ok=True))

@cron_bp.route('/api/cron/jobs/<vid>/logs')
def job_logs(vid):
    if not req(): return jsonify({'ok':False}), 401
    meta = load_meta()
    info = meta.get(vid, {})
    return jsonify({'ok':True,'log':info.get('last_log',''),'last_run':info.get('last_run',''),'last_exit':info.get('last_exit','')})
