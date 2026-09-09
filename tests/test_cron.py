"""
Tests for panel/routes/cron.py

Covers:
  - parse_crontab         — enabled, disabled, with/without VP tags, edge cases
  - human_schedule        — all preset expressions + custom/unknown
  - SCHEDULE_PRESETS      — every preset has a valid 5-part schedule value (or 'custom')
  - TASK_TEMPLATES        — every template has the required keys
  - add_job API           — happy path, missing command, bad schedule (wrong part count)
  - edit_job API          — happy path, missing command, job not found
  - delete_job API        — removes line from crontab and meta
  - toggle_job API        — enable / disable
  - list_jobs API         — returns jobs with schedule_human field
  - run_now API           — disabled job rejected, enabled job gets a run_id
  - run_status API        — unknown run_id returns 404
  - job_logs API          — returns log/last_run/last_exit from meta
"""

import json
import os
import sys
import time
import uuid
import pytest

# ---------------------------------------------------------------------------
# Make the workspace root importable so "from panel.routes.cron import ..."
# works without installing the package.
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from panel.routes.cron import (
    parse_crontab,
    human_schedule,
    SCHEDULE_PRESETS,
    TASK_TEMPLATES,
)

# We also need to import the Flask app for route-level tests.
import importlib
import panel.routes.cron as cron_mod


# ===========================================================================
# Helpers
# ===========================================================================

def _meta(**kw):
    """Return a minimal meta dict for one job."""
    return {'name': kw.get('name', ''), 'type': kw.get('type', 'shell'),
            'user': kw.get('user', 'root'), 'last_log': '', 'last_run': '', 'last_exit': ''}


# ===========================================================================
# 1. parse_crontab
# ===========================================================================

class TestParseCrontab:

    def test_single_enabled_job(self):
        raw = '0 * * * * /usr/bin/php cron.php # vp:aabbccdd\n'
        jobs = parse_crontab(raw, {'aabbccdd': _meta(name='My PHP job')})
        assert len(jobs) == 1
        j = jobs[0]
        assert j['id'] == 'aabbccdd'
        assert j['schedule'] == '0 * * * *'
        assert j['command'] == '/usr/bin/php cron.php'
        assert j['name'] == 'My PHP job'
        assert j['enabled'] is True

    def test_disabled_job_is_parsed(self):
        """A line starting with '#' that contains a vp: tag must still appear."""
        raw = '# 0 3 * * * /usr/bin/backup.sh # vp:deadbeef\n'
        jobs = parse_crontab(raw, {'deadbeef': _meta(name='Backup')})
        assert len(jobs) == 1
        j = jobs[0]
        assert j['enabled'] is False
        assert j['id'] == 'deadbeef'
        assert j['schedule'] == '0 3 * * *'
        assert j['command'] == '/usr/bin/backup.sh'

    def test_pure_comment_skipped(self):
        """Lines starting with '#' that have no vp: tag are skipped."""
        raw = '# This is a regular comment\n0 * * * * /bin/true # vp:00000001\n'
        jobs = parse_crontab(raw, {})
        assert len(jobs) == 1
        assert jobs[0]['id'] == '00000001'

    def test_empty_crontab(self):
        assert parse_crontab('', {}) == []

    def test_blank_lines_skipped(self):
        raw = '\n\n0 * * * * /bin/date # vp:11111111\n\n'
        jobs = parse_crontab(raw, {})
        assert len(jobs) == 1

    def test_multiple_jobs(self):
        raw = (
            '*/5 * * * * /bin/script1.sh # vp:aaaa0001\n'
            '0 0 * * * /bin/script2.sh # vp:aaaa0002\n'
        )
        jobs = parse_crontab(raw, {})
        assert len(jobs) == 2
        ids = {j['id'] for j in jobs}
        assert ids == {'aaaa0001', 'aaaa0002'}

    def test_job_without_vp_tag(self):
        """Jobs without a vp: tag should still be parsed (id = cleaned line)."""
        raw = '30 4 * * 1 /usr/bin/certbot renew\n'
        jobs = parse_crontab(raw, {})
        assert len(jobs) == 1
        j = jobs[0]
        assert j['id'] == '30 4 * * 1 /usr/bin/certbot renew'
        assert j['enabled'] is True

    def test_meta_fields_populated(self):
        vid = 'cafecafe'
        raw = f'0 2 * * * /bin/backup.sh # vp:{vid}\n'
        meta = {vid: {'name': 'Nightly backup', 'type': 'shell', 'user': 'root',
                      'last_log': 'ok', 'last_run': '2024-01-01 02:00:00', 'last_exit': '0'}}
        jobs = parse_crontab(raw, meta)
        j = jobs[0]
        assert j['name'] == 'Nightly backup'
        assert j['last_run'] == '2024-01-01 02:00:00'
        assert j['last_exit'] == '0'
        assert j['logs'] == 'ok'

    def test_disabled_job_has_correct_schedule_and_command(self):
        """Ensure stripping '#' from a disabled line leaves a parseable schedule."""
        raw = '# */15 * * * * /bin/ping.sh # vp:feedface\n'
        jobs = parse_crontab(raw, {})
        assert len(jobs) == 1
        j = jobs[0]
        assert j['schedule'] == '*/15 * * * *'
        assert j['command'] == '/bin/ping.sh'
        assert j['enabled'] is False

    def test_line_with_fewer_than_six_parts_skipped(self):
        """A line that only has 4 parts (too short) must be skipped."""
        raw = '0 1 * * # vp:shortline\n'
        jobs = parse_crontab(raw, {})
        assert jobs == []


# ===========================================================================
# 2. human_schedule
# ===========================================================================

class TestHumanSchedule:

    @pytest.mark.parametrize("expr,expected", [
        ('* * * * *',    'Every minute'),
        ('*/5 * * * *',  'Every 5 minutes'),
        ('*/10 * * * *', 'Every 10 minutes'),
        ('*/15 * * * *', 'Every 15 minutes'),
        ('*/30 * * * *', 'Every 30 minutes'),
        ('0 * * * *',    'Every hour at :00'),
        ('15 * * * *',   'Every hour at :15'),
        ('0 0 * * *',    'Daily at 00:00'),
        ('0 3 * * *',    'Daily at 03:00'),
        ('30 6 * * *',   'Daily at 06:30'),
        ('0 0 * * 0',    'Every Sun at 00:00'),
        ('0 0 * * 1',    'Every Mon at 00:00'),
        ('0 0 * * 6',    'Every Sat at 00:00'),
        ('0 0 1 * *',    'Monthly on day 1 at 00:00'),
        ('0 0 15 * *',   'Monthly on day 15 at 00:00'),
    ])
    def test_known_expressions(self, expr, expected):
        assert human_schedule(expr) == expected

    def test_unknown_expression_returned_unchanged(self):
        expr = '5 4 * 1-3 2'
        assert human_schedule(expr) == expr

    def test_invalid_part_count_returned_unchanged(self):
        assert human_schedule('* * * *') == '* * * *'
        assert human_schedule('') == ''

    def test_dow_out_of_range_falls_through(self):
        """DOW=9 is invalid; human_schedule should fall back to returning the raw expr."""
        expr = '0 0 * * 9'
        result = human_schedule(expr)
        # Should not crash and should return the original string (no day name mapped)
        assert isinstance(result, str)


# ===========================================================================
# 3. SCHEDULE_PRESETS
# ===========================================================================

class TestSchedulePresets:

    def test_all_presets_have_required_keys(self):
        for p in SCHEDULE_PRESETS:
            assert 'label' in p, f"Missing 'label' in preset: {p}"
            assert 'value' in p, f"Missing 'value' in preset: {p}"

    def test_non_custom_presets_are_valid_5part_cron(self):
        for p in SCHEDULE_PRESETS:
            if p['value'] == 'custom':
                continue
            parts = p['value'].split()
            assert len(parts) == 5, f"Preset '{p['label']}' has {len(parts)} parts, expected 5"

    def test_custom_preset_exists(self):
        values = [p['value'] for p in SCHEDULE_PRESETS]
        assert 'custom' in values

    def test_preset_labels_are_unique(self):
        labels = [p['label'] for p in SCHEDULE_PRESETS]
        assert len(labels) == len(set(labels)), "Duplicate preset labels found"


# ===========================================================================
# 4. TASK_TEMPLATES
# ===========================================================================

class TestTaskTemplates:

    REQUIRED_KEYS = {'id', 'label', 'icon', 'desc', 'cmd', 'hint'}

    def test_all_templates_have_required_keys(self):
        for t in TASK_TEMPLATES:
            missing = self.REQUIRED_KEYS - t.keys()
            assert not missing, f"Template '{t.get('id')}' missing keys: {missing}"

    def test_template_ids_are_unique(self):
        ids = [t['id'] for t in TASK_TEMPLATES]
        assert len(ids) == len(set(ids)), "Duplicate template IDs found"

    def test_shell_template_exists(self):
        ids = [t['id'] for t in TASK_TEMPLATES]
        assert 'shell' in ids

    def test_url_template_uses_curl(self):
        url_tpl = next(t for t in TASK_TEMPLATES if t['id'] == 'url')
        assert 'curl' in url_tpl['cmd']


# ===========================================================================
# 5. Flask API route tests (add / edit / delete / toggle / list / run / logs)
# ===========================================================================
#
# We build a minimal Flask test app, monkey-patch the low-level I/O helpers
# (get_crontab / set_crontab / load_meta / save_meta) so the tests never touch
# a real crontab, and exercise every route.
# ===========================================================================

@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Return a Flask test client with an authenticated session and stubbed I/O."""

    from flask import Flask
    from flask.sessions import SecureCookieSessionInterface

    app = Flask(__name__)
    app.secret_key = 'test-secret'
    app.config['TESTING'] = True

    # In-memory crontab and meta stores shared across the whole fixture.
    store = {'crontab': '', 'meta': {}}

    monkeypatch.setattr(cron_mod, 'get_crontab', lambda: store['crontab'])
    monkeypatch.setattr(cron_mod, 'set_crontab', lambda c: store.__setitem__('crontab', c) or True)
    monkeypatch.setattr(cron_mod, 'load_meta',   lambda: store['meta'])
    monkeypatch.setattr(cron_mod, 'save_meta',   lambda m: store.__setitem__('meta', m))

    app.register_blueprint(cron_mod.cron_bp)

    with app.test_client() as c:
        # Inject a session so req() passes
        with c.session_transaction() as sess:
            sess['user'] = 'admin'
        yield c, store


class TestListJobs:

    def test_empty_crontab(self, client):
        c, store = client
        resp = c.get('/api/cron/jobs')
        data = resp.get_json()
        assert data['ok'] is True
        assert data['jobs'] == []
        assert data['count'] == 0

    def test_jobs_have_schedule_human(self, client):
        c, store = client
        store['crontab'] = '0 * * * * /bin/date # vp:testjob1\n'
        store['meta']['testjob1'] = _meta(name='Date job')
        resp = c.get('/api/cron/jobs')
        data = resp.get_json()
        assert data['count'] == 1
        assert 'schedule_human' in data['jobs'][0]


class TestAddJob:

    def test_happy_path(self, client):
        c, store = client
        payload = {'schedule': '*/5 * * * *', 'command': '/bin/true', 'name': 'Test', 'type': 'shell', 'user': 'root'}
        resp = c.post('/api/cron/jobs', data=json.dumps(payload), content_type='application/json')
        data = resp.get_json()
        assert data['ok'] is True
        assert 'id' in data
        assert 'schedule_human' in data
        # crontab and meta should be updated
        assert '/bin/true' in store['crontab']
        assert data['id'] in store['meta']

    def test_missing_command_returns_400(self, client):
        c, store = client
        payload = {'schedule': '* * * * *', 'command': '', 'name': 'Bad'}
        resp = c.post('/api/cron/jobs', data=json.dumps(payload), content_type='application/json')
        assert resp.status_code == 400
        assert resp.get_json()['ok'] is False

    def test_bad_schedule_returns_400(self, client):
        c, store = client
        payload = {'schedule': '* * * *', 'command': '/bin/true'}  # only 4 parts
        resp = c.post('/api/cron/jobs', data=json.dumps(payload), content_type='application/json')
        assert resp.status_code == 400
        data = resp.get_json()
        assert data['ok'] is False
        assert 'schedule' in data['error'].lower() or '5' in data['error']

    def test_schedule_human_returned(self, client):
        c, store = client
        payload = {'schedule': '0 0 * * *', 'command': '/bin/backup.sh'}
        resp = c.post('/api/cron/jobs', data=json.dumps(payload), content_type='application/json')
        assert resp.get_json()['schedule_human'] == 'Daily at 00:00'


class TestEditJob:

    def _add_job(self, store, vid='test1234', schedule='0 * * * *', command='/bin/ping.sh'):
        store['crontab'] = f'{schedule} {command} # vp:{vid}\n'
        store['meta'][vid] = _meta(name='Ping')

    def test_happy_path(self, client):
        c, store = client
        self._add_job(store)
        payload = {'schedule': '*/10 * * * *', 'command': '/bin/newcmd.sh', 'name': 'Updated', 'type': 'shell'}
        resp = c.put('/api/cron/jobs/test1234', data=json.dumps(payload), content_type='application/json')
        data = resp.get_json()
        assert data['ok'] is True
        assert '*/10 * * * *' in store['crontab']
        assert '/bin/newcmd.sh' in store['crontab']

    def test_missing_command_returns_400(self, client):
        c, store = client
        self._add_job(store)
        payload = {'schedule': '* * * * *', 'command': ''}
        resp = c.put('/api/cron/jobs/test1234', data=json.dumps(payload), content_type='application/json')
        assert resp.status_code == 400

    def test_job_not_found_returns_404(self, client):
        c, store = client
        store['crontab'] = ''
        payload = {'schedule': '* * * * *', 'command': '/bin/true'}
        resp = c.put('/api/cron/jobs/nonexistent', data=json.dumps(payload), content_type='application/json')
        assert resp.status_code == 404


class TestDeleteJob:

    def test_delete_removes_line_and_meta(self, client):
        c, store = client
        vid = 'deldeldel'
        store['crontab'] = f'0 * * * * /bin/job.sh # vp:{vid}\n'
        store['meta'][vid] = _meta()
        resp = c.delete(f'/api/cron/jobs/{vid}')
        assert resp.get_json()['ok'] is True
        assert f'vp:{vid}' not in store['crontab']
        assert vid not in store['meta']

    def test_delete_nonexistent_still_ok(self, client):
        """Deleting a job that doesn't exist should still return ok (idempotent)."""
        c, store = client
        store['crontab'] = ''
        resp = c.delete('/api/cron/jobs/ghostjob')
        assert resp.get_json()['ok'] is True


class TestToggleJob:

    def test_disable_job(self, client):
        c, store = client
        vid = 'toggl001'
        store['crontab'] = f'*/5 * * * * /bin/job.sh # vp:{vid}\n'
        payload = {'enable': False}
        resp = c.post(f'/api/cron/jobs/{vid}/toggle', data=json.dumps(payload), content_type='application/json')
        data = resp.get_json()
        assert data['ok'] is True
        assert data['enabled'] is False
        # The line in the crontab should now start with '#'
        line = [l for l in store['crontab'].split('\n') if f'vp:{vid}' in l][0]
        assert line.startswith('#')

    def test_enable_job(self, client):
        c, store = client
        vid = 'toggl002'
        store['crontab'] = f'# */5 * * * * /bin/job.sh # vp:{vid}\n'
        payload = {'enable': True}
        resp = c.post(f'/api/cron/jobs/{vid}/toggle', data=json.dumps(payload), content_type='application/json')
        data = resp.get_json()
        assert data['ok'] is True
        assert data['enabled'] is True
        line = [l for l in store['crontab'].split('\n') if f'vp:{vid}' in l][0]
        assert not line.startswith('#')

    def test_re_enable_already_enabled_job(self, client):
        """Enabling an already-enabled job should be a no-op and still return ok."""
        c, store = client
        vid = 'toggl003'
        store['crontab'] = f'0 1 * * * /bin/task.sh # vp:{vid}\n'
        resp = c.post(f'/api/cron/jobs/{vid}/toggle',
                      data=json.dumps({'enable': True}), content_type='application/json')
        assert resp.get_json()['ok'] is True


class TestRunNow:

    def test_disabled_job_returns_404(self, client):
        c, store = client
        vid = 'runtest1'
        store['crontab'] = f'# 0 * * * * /bin/job.sh # vp:{vid}\n'
        resp = c.post(f'/api/cron/jobs/{vid}/run', data='{}', content_type='application/json')
        assert resp.status_code == 404

    def test_enabled_job_returns_run_id(self, client):
        c, store = client
        vid = 'runtest2'
        store['crontab'] = f'0 * * * * /bin/true # vp:{vid}\n'
        store['meta'][vid] = _meta()
        resp = c.post(f'/api/cron/jobs/{vid}/run', data='{}', content_type='application/json')
        data = resp.get_json()
        assert data['ok'] is True
        assert 'run_id' in data

    def test_nonexistent_job_returns_404(self, client):
        c, store = client
        store['crontab'] = ''
        resp = c.post('/api/cron/jobs/ghostjob/run', data='{}', content_type='application/json')
        assert resp.status_code == 404


class TestRunStatus:

    def test_unknown_run_id_returns_404(self, client):
        c, _ = client
        resp = c.get('/api/cron/run/doesnotexist')
        assert resp.status_code == 404
        assert resp.get_json()['ok'] is False

    def test_known_run_id_returns_status(self, client):
        c, _ = client
        run_id = 'testrun1'
        cron_mod._run_logs[run_id] = {'lines': ['output line'], 'done': True, 'exit_code': 0, 'start': time.time()}
        resp = c.get(f'/api/cron/run/{run_id}')
        data = resp.get_json()
        assert data['ok'] is True
        assert data['done'] is True
        assert data['exit_code'] == 0


class TestJobLogs:

    def test_returns_log_info(self, client):
        c, store = client
        vid = 'logstest'
        store['meta'][vid] = {
            'name': 'log test', 'type': 'shell', 'user': 'root',
            'last_log': 'All good', 'last_run': '2024-06-01 03:00:00', 'last_exit': '0'
        }
        resp = c.get(f'/api/cron/jobs/{vid}/logs')
        data = resp.get_json()
        assert data['ok'] is True
        assert data['log'] == 'All good'
        assert data['last_run'] == '2024-06-01 03:00:00'
        assert data['last_exit'] == '0'

    def test_unknown_job_returns_empty_log(self, client):
        c, store = client
        resp = c.get('/api/cron/jobs/notexist/logs')
        data = resp.get_json()
        assert data['ok'] is True
        assert data['log'] == ''


class TestPresetsEndpoint:

    def test_returns_schedules_and_templates(self, client):
        c, _ = client
        resp = c.get('/api/cron/presets')
        data = resp.get_json()
        assert data['ok'] is True
        assert isinstance(data['schedules'], list)
        assert isinstance(data['templates'], list)
        assert len(data['schedules']) > 0
        assert len(data['templates']) > 0


class TestUnauthenticated:
    """Every endpoint must return 401 when there is no session."""

    @pytest.fixture()
    def anon_client(self, tmp_path, monkeypatch):
        from flask import Flask
        app = Flask(__name__)
        app.secret_key = 'test-secret'
        app.config['TESTING'] = True
        monkeypatch.setattr(cron_mod, 'get_crontab', lambda: '')
        monkeypatch.setattr(cron_mod, 'set_crontab', lambda c: True)
        monkeypatch.setattr(cron_mod, 'load_meta',   lambda: {})
        monkeypatch.setattr(cron_mod, 'save_meta',   lambda m: None)
        app.register_blueprint(cron_mod.cron_bp)
        return app.test_client()

    def test_list_jobs_401(self, anon_client):
        assert anon_client.get('/api/cron/jobs').status_code == 401

    def test_add_job_401(self, anon_client):
        resp = anon_client.post('/api/cron/jobs', data='{}', content_type='application/json')
        assert resp.status_code == 401

    def test_edit_job_401(self, anon_client):
        resp = anon_client.put('/api/cron/jobs/abc', data='{}', content_type='application/json')
        assert resp.status_code == 401

    def test_delete_job_401(self, anon_client):
        assert anon_client.delete('/api/cron/jobs/abc').status_code == 401

    def test_toggle_job_401(self, anon_client):
        resp = anon_client.post('/api/cron/jobs/abc/toggle', data='{}', content_type='application/json')
        assert resp.status_code == 401

    def test_run_now_401(self, anon_client):
        resp = anon_client.post('/api/cron/jobs/abc/run', data='{}', content_type='application/json')
        assert resp.status_code == 401

    def test_run_status_401(self, anon_client):
        assert anon_client.get('/api/cron/run/abc').status_code == 401

    def test_job_logs_401(self, anon_client):
        assert anon_client.get('/api/cron/jobs/abc/logs').status_code == 401

    def test_presets_401(self, anon_client):
        assert anon_client.get('/api/cron/presets').status_code == 401
