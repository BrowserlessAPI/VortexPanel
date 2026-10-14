# panel/routes/job_state.py
#
# Background job status needs to survive being READ by a different
# process than the one that WROTE it -- VortexPanel runs under gunicorn
# with multiple worker processes (confirmed: install.sh uses
# --workers 4), each with its own independent memory. A plain in-memory
# dict for job status is invisible to three out of every four requests,
# since gunicorn load-balances across workers -- the job can genuinely
# be running to completion while the polling endpoint keeps reporting
# "not started" because it keeps landing on a worker that never touched
# it. Confirmed as the real cause of a live bug report: the Security
# Updates apply button appeared frozen on "Starting..." forever, even
# though the update was actually completing correctly in the background.
#
# A simple JSON file is visible to every worker process regardless of which
# one wrote it or which one is asked to read it -- no new dependency (like
# Redis) needed for something this small. Kept under the panel's data
# directory (mode 0700): job output can include paths, database names and
# command output that other local users must not read from /tmp.

import json, os, tempfile

JOBS_DIR = '/opt/vortexpanel/data/jobs/state'


def _job_path(job_id):
    safe_id = ''.join(c for c in job_id if c.isalnum() or c in ('_', '-'))
    return os.path.join(JOBS_DIR, f'{safe_id}.json')


def _ensure_dir():
    if not os.path.isdir(JOBS_DIR):
        os.makedirs(JOBS_DIR, mode=0o700, exist_ok=True)
        try:
            os.chmod(os.path.dirname(JOBS_DIR), 0o700)
            os.chmod(JOBS_DIR, 0o700)
        except OSError:
            pass


def save_job(job_id, state):
    _ensure_dir()
    path = _job_path(job_id)
    # Write to a temp file then rename -- atomic on the same filesystem,
    # so a worker reading the file never sees a half-written partial
    # JSON body even if a write is in progress at that exact moment.
    fd, tmp_path = tempfile.mkstemp(dir=JOBS_DIR)
    with os.fdopen(fd, 'w') as f:
        json.dump(state, f)
    os.replace(tmp_path, path)


def load_job(job_id, default=None):
    path = _job_path(job_id)
    if not os.path.exists(path):
        return default if default is not None else {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        # A read landed mid-write despite the atomic rename (e.g. the
        # file was mid-replace) -- treat as "no state yet" rather than
        # crashing the polling endpoint over a transient read.
        return default if default is not None else {}


def clear_job(job_id):
    path = _job_path(job_id)
    if os.path.exists(path):
        os.remove(path)
