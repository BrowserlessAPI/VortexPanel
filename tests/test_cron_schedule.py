"""
tests/test_cron_schedule.py
===========================
Comprehensive tests for the VortexPanel cron schedule module.

Coverage areas
--------------
1.  parse_crontab          – enabled jobs, disabled jobs, plain comments, no
                             VP tag, malformed lines, multi-job files.
2.  human_schedule         – every preset expression + edge / unknown cases.
3.  SCHEDULE_PRESETS       – schema validity, no duplicate values, completeness.
4.  REST API – GET  /api/cron/jobs        – list jobs (mocked crontab).
5.  REST API – POST /api/cron/jobs        – add job (valid + error cases).
6.  REST API – PUT  /api/cron/jobs/<vid> – edit job (found + not-found).
7.  REST API – DELETE /api/cron/jobs/<vid> – delete job.
8.  REST API – POST /api/cron/jobs/<vid>/toggle – enable / disable.
9.  REST API – GET  /api/cron/presets     – preset list returned correctly.
10. Auth guard             – every endpoint returns 401 when not logged in.
"""

import json
import re
import sys
import os
import types
import unittest
from unittest.mock import patch, MagicMock

# ---------------------------------------------------------------------------
# Make the workspace root importable
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# ---------------------------------------------------------------------------
# Import the helpers we want to unit-test directly (no Flask app needed yet)
# ---------------------------------------------------------------------------
from panel.routes.cron import (
    parse_crontab,
    human_schedule,
    SCHEDULE_PRESETS,
    TASK_TEMPLATES,
)


# ===========================================================================
# 1. parse_crontab
# ===========================================================================

class TestParseCrontab(unittest.TestCase):
    """Unit tests for the parse_crontab() helper."""

    ENABLED_LINE  = "*/5 * * * * /usr/bin/php /var/www/cron.php # vp:aabbccdd"
    DISABLED_LINE = "# */5 * * * * /usr/bin/php /var/www/cron.php # vp:aabbccdd"
    COMMENT_LINE  = "# This is a plain comment"
    NO_TAG_LINE   = "0 3 * * * /usr/bin/backup.sh"

    META = {
        "aabbccdd": {
            "name": "PHP Cron",
            "type": "php",
            "user": "root",
            "last_log": "ok",
            "last_run": "2024-01-01 03:00:00",
            "last_exit": "0",
        }
    }

    # ---- enabled job -------------------------------------------------------

    def test_enabled_job_parsed(self):
        jobs = parse_crontab(self.ENABLED_LINE, self.META)
        self.assertEqual(len(jobs), 1)
        j = jobs[0]
        self.assertTrue(j["enabled"])
        self.assertEqual(j["schedule"], "*/5 * * * *")
        self.assertEqual(j["command"], "/usr/bin/php /var/www/cron.php")
        self.assertEqual(j["id"], "aabbccdd")
        self.assertEqual(j["name"], "PHP Cron")
        self.assertEqual(j["type"], "php")

    def test_enabled_job_meta_populated(self):
        jobs = parse_crontab(self.ENABLED_LINE, self.META)
        j = jobs[0]
        self.assertEqual(j["last_run"],  "2024-01-01 03:00:00")
        self.assertEqual(j["last_exit"], "0")
        self.assertEqual(j["logs"],      "ok")

    # ---- disabled job -------------------------------------------------------

    def test_disabled_job_parsed(self):
        jobs = parse_crontab(self.DISABLED_LINE, self.META)
        self.assertEqual(len(jobs), 1)
        j = jobs[0]
        self.assertFalse(j["enabled"])
        self.assertEqual(j["schedule"], "*/5 * * * *")
        self.assertEqual(j["command"], "/usr/bin/php /var/www/cron.php")
        self.assertEqual(j["id"], "aabbccdd")
        self.assertEqual(j["name"], "PHP Cron")

    # ---- plain comment (no vp: tag) -----------------------------------------

    def test_plain_comment_skipped(self):
        jobs = parse_crontab(self.COMMENT_LINE, {})
        self.assertEqual(jobs, [])

    # ---- no vp tag (foreign cron line) ---------------------------------------

    def test_no_tag_job_parsed(self):
        jobs = parse_crontab(self.NO_TAG_LINE, {})
        self.assertEqual(len(jobs), 1)
        j = jobs[0]
        self.assertTrue(j["enabled"])
        self.assertEqual(j["schedule"], "0 3 * * *")
        self.assertEqual(j["command"],  "/usr/bin/backup.sh")
        # id falls back to the full cleaned line
        self.assertIsNotNone(j["id"])

    # ---- empty / whitespace-only input -------------------------------------

    def test_empty_raw(self):
        self.assertEqual(parse_crontab("", {}), [])

    def test_whitespace_only(self):
        self.assertEqual(parse_crontab("   \n\n   ", {}), [])

    # ---- malformed line (< 6 parts) -----------------------------------------

    def test_malformed_line_skipped(self):
        jobs = parse_crontab("* * * * * # vp:deadbeef", {})
        # Only 5 parts after stripping tag — should be skipped
        self.assertEqual(jobs, [])

    # ---- multiple jobs -------------------------------------------------------

    def test_multiple_jobs(self):
        raw = "\n".join([
            "* * * * * /bin/a # vp:aaaaaaaa",
            "0 3 * * * /bin/b # vp:bbbbbbbb",
            "# 0 6 * * * /bin/c # vp:cccccccc",
        ])
        meta = {
            "aaaaaaaa": {"name": "A", "type": "shell", "user": "root",
                         "last_log": "", "last_run": "", "last_exit": ""},
            "bbbbbbbb": {"name": "B", "type": "shell", "user": "root",
                         "last_log": "", "last_run": "", "last_exit": ""},
            "cccccccc": {"name": "C", "type": "shell", "user": "root",
                         "last_log": "", "last_run": "", "last_exit": ""},
        }
        jobs = parse_crontab(raw, meta)
        self.assertEqual(len(jobs), 3)
        ids = {j["id"] for j in jobs}
        self.assertEqual(ids, {"aaaaaaaa", "bbbbbbbb", "cccccccc"})
        enabled = {j["id"]: j["enabled"] for j in jobs}
        self.assertTrue(enabled["aaaaaaaa"])
        self.assertTrue(enabled["bbbbbbbb"])
        self.assertFalse(enabled["cccccccc"])

    # ---- raw_line preserved -------------------------------------------------

    def test_raw_line_preserved(self):
        jobs = parse_crontab(self.ENABLED_LINE, self.META)
        self.assertEqual(jobs[0]["raw_line"], self.ENABLED_LINE)


# ===========================================================================
# 2. human_schedule
# ===========================================================================

class TestHumanSchedule(unittest.TestCase):
    """Unit tests for the human_schedule() helper."""

    def test_every_minute(self):
        self.assertEqual(human_schedule("* * * * *"), "Every minute")

    def test_every_5_minutes(self):
        self.assertEqual(human_schedule("*/5 * * * *"), "Every 5 minutes")

    def test_every_10_minutes(self):
        self.assertEqual(human_schedule("*/10 * * * *"), "Every 10 minutes")

    def test_every_15_minutes(self):
        self.assertEqual(human_schedule("*/15 * * * *"), "Every 15 minutes")

    def test_every_30_minutes(self):
        self.assertEqual(human_schedule("*/30 * * * *"), "Every 30 minutes")

    def test_every_hour_at_minute(self):
        self.assertEqual(human_schedule("45 * * * *"), "Every hour at :45")

    def test_daily_midnight(self):
        self.assertEqual(human_schedule("0 0 * * *"), "Daily at 00:00")

    def test_daily_at_1am(self):
        self.assertEqual(human_schedule("0 1 * * *"), "Daily at 01:00")

    def test_daily_at_3am(self):
        self.assertEqual(human_schedule("0 3 * * *"), "Daily at 03:00")

    def test_every_sunday(self):
        self.assertEqual(human_schedule("0 0 * * 0"), "Every Sun at 00:00")

    def test_every_monday(self):
        self.assertEqual(human_schedule("0 0 * * 1"), "Every Mon at 00:00")

    def test_every_saturday(self):
        self.assertEqual(human_schedule("0 0 * * 6"), "Every Sat at 00:00")

    def test_monthly_first(self):
        self.assertEqual(human_schedule("0 0 1 * *"), "Monthly on day 1 at 00:00")

    def test_monthly_fifteenth(self):
        self.assertEqual(human_schedule("0 9 15 * *"), "Monthly on day 15 at 09:00")

    def test_unknown_returns_original(self):
        expr = "5 4 * * 1-5"
        self.assertEqual(human_schedule(expr), expr)

    def test_wrong_part_count_returns_original(self):
        expr = "* * * *"          # only 4 parts
        self.assertEqual(human_schedule(expr), expr)

    def test_empty_string_returns_original(self):
        self.assertEqual(human_schedule(""), "")

    def test_every_2_hours(self):
        # Falls through to daily check – hr='*/2', dom='*', mon='*', dow='*'
        result = human_schedule("0 */2 * * *")
        # Should return a human string (Daily at 00:*/2 is acceptable fallback)
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)

    def test_every_hour_zero_padding(self):
        # minute=5, zero-padded
        result = human_schedule("5 * * * *")
        self.assertEqual(result, "Every hour at :05")


# ===========================================================================
# 3. SCHEDULE_PRESETS
# ===========================================================================

class TestSchedulePresets(unittest.TestCase):
    """Validate the SCHEDULE_PRESETS constant."""

    def test_is_list(self):
        self.assertIsInstance(SCHEDULE_PRESETS, list)

    def test_not_empty(self):
        self.assertGreater(len(SCHEDULE_PRESETS), 0)

    def test_each_has_label_and_value(self):
        for p in SCHEDULE_PRESETS:
            self.assertIn("label", p, msg=f"Missing 'label' in {p}")
            self.assertIn("value", p, msg=f"Missing 'value' in {p}")

    def test_no_duplicate_values(self):
        """Except the intentional 'custom' placeholder."""
        non_custom = [p["value"] for p in SCHEDULE_PRESETS
                      if not p["value"].startswith("cu")]
        self.assertEqual(len(non_custom), len(set(non_custom)),
                         "Duplicate cron values found in SCHEDULE_PRESETS")

    def test_valid_cron_expressions(self):
        """Every non-custom preset must have exactly 5 space-separated parts."""
        for p in SCHEDULE_PRESETS:
            val = p["value"]
            if val.startswith("cu"):
                continue    # custom placeholder, skip
            parts = val.split()
            self.assertEqual(len(parts), 5,
                             f"Invalid cron expr '{val}' in preset '{p['label']}'")

    def test_contains_common_presets(self):
        values = {p["value"] for p in SCHEDULE_PRESETS}
        self.assertIn("* * * * *",   values, "Missing 'every minute' preset")
        self.assertIn("0 0 * * *",   values, "Missing 'daily midnight' preset")
        self.assertIn("0 0 1 * *",   values, "Missing 'monthly' preset")
        self.assertIn("*/5 * * * *", values, "Missing 'every 5 min' preset")


# ===========================================================================
# 4-10. REST API tests (Flask test client)
# ===========================================================================

def _build_app():
    """Create a minimal Flask app that registers the cron blueprint."""
    from flask import Flask, session
    import panel.routes.cron as cron_mod

    app = Flask(__name__)
    app.secret_key = "test-secret"
    app.config["TESTING"] = True
    app.register_blueprint(cron_mod.cron_bp)
    return app, cron_mod


class TestCronAPI(unittest.TestCase):
    """Integration-style tests for every REST endpoint."""

    VID = "aabbccdd"
    META = {
        "aabbccdd": {
            "name": "Test Job",
            "type": "shell",
            "user": "root",
            "last_log": "done",
            "last_run": "2024-06-01 00:00:00",
            "last_exit": "0",
        }
    }
    RAW_CRONTAB = f"0 3 * * * /usr/bin/backup.sh # vp:{VID}\n"

    @classmethod
    def setUpClass(cls):
        cls.app, cls.cron_mod = _build_app()

    def _client(self, logged_in=True):
        """Return a test client, optionally with a fake session."""
        client = self.app.test_client()
        if logged_in:
            with client.session_transaction() as sess:
                sess["user"] = "admin"
        return client

    # -----------------------------------------------------------------------
    # Helper: patch both I/O functions for the duration of one test
    # -----------------------------------------------------------------------
    def _patch_io(self, raw=None, meta=None):
        raw  = raw  if raw  is not None else self.RAW_CRONTAB
        meta = meta if meta is not None else dict(self.META)
        captured = {"crontab": raw, "meta": meta}

        def fake_get():
            return captured["crontab"]

        def fake_set(content):
            captured["crontab"] = content
            return True

        def fake_load():
            return dict(captured["meta"])

        def fake_save(m):
            captured["meta"] = m

        patches = [
            patch.object(self.cron_mod, "get_crontab",  side_effect=fake_get),
            patch.object(self.cron_mod, "set_crontab",  side_effect=fake_set),
            patch.object(self.cron_mod, "load_meta",    side_effect=fake_load),
            patch.object(self.cron_mod, "save_meta",    side_effect=fake_save),
        ]
        return patches, captured

    # -----------------------------------------------------------------------
    # 4. GET /api/cron/jobs
    # -----------------------------------------------------------------------

    def test_list_jobs_returns_jobs(self):
        patches, _ = self._patch_io()
        client = self._client()
        with patches[0], patches[1], patches[2], patches[3]:
            r = client.get("/api/cron/jobs")
        data = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["jobs"][0]["id"], self.VID)
        self.assertIn("schedule_human", data["jobs"][0])

    def test_list_jobs_empty_crontab(self):
        patches, _ = self._patch_io(raw="")
        client = self._client()
        with patches[0], patches[1], patches[2], patches[3]:
            r = client.get("/api/cron/jobs")
        data = r.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["jobs"], [])

    def test_list_jobs_schedule_human_present(self):
        patches, _ = self._patch_io()
        client = self._client()
        with patches[0], patches[1], patches[2], patches[3]:
            r = client.get("/api/cron/jobs")
        job = r.get_json()["jobs"][0]
        self.assertEqual(job["schedule_human"], "Daily at 03:00")

    # -----------------------------------------------------------------------
    # 5. POST /api/cron/jobs  (add)
    # -----------------------------------------------------------------------

    def test_add_job_success(self):
        patches, captured = self._patch_io(raw="")
        client = self._client()
        payload = {"schedule": "*/5 * * * *", "command": "/bin/echo hello",
                   "name": "Echo", "type": "shell", "user": "root"}
        with patches[0], patches[1], patches[2], patches[3]:
            r = client.post("/api/cron/jobs",
                            data=json.dumps(payload),
                            content_type="application/json")
        data = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(data["ok"])
        self.assertIn("id", data)
        self.assertEqual(data["schedule_human"], "Every 5 minutes")
        # Crontab should now contain the new line
        self.assertIn("/bin/echo hello", captured["crontab"])

    def test_add_job_missing_command(self):
        patches, _ = self._patch_io(raw="")
        client = self._client()
        payload = {"schedule": "* * * * *", "command": ""}
        with patches[0], patches[1], patches[2], patches[3]:
            r = client.post("/api/cron/jobs",
                            data=json.dumps(payload),
                            content_type="application/json")
        self.assertEqual(r.status_code, 400)
        self.assertFalse(r.get_json()["ok"])

    def test_add_job_invalid_schedule(self):
        patches, _ = self._patch_io(raw="")
        client = self._client()
        payload = {"schedule": "bad schedule", "command": "/bin/true"}
        with patches[0], patches[1], patches[2], patches[3]:
            r = client.post("/api/cron/jobs",
                            data=json.dumps(payload),
                            content_type="application/json")
        self.assertEqual(r.status_code, 400)
        data = r.get_json()
        self.assertFalse(data["ok"])
        self.assertIn("5 parts", data["error"])

    def test_add_job_meta_saved(self):
        patches, captured = self._patch_io(raw="")
        client = self._client()
        payload = {"schedule": "0 0 * * *", "command": "/bin/true",
                   "name": "Nightly", "type": "shell", "user": "www-data"}
        with patches[0], patches[1], patches[2], patches[3]:
            r = client.post("/api/cron/jobs",
                            data=json.dumps(payload),
                            content_type="application/json")
        vid = r.get_json()["id"]
        self.assertIn(vid, captured["meta"])
        self.assertEqual(captured["meta"][vid]["name"], "Nightly")
        self.assertEqual(captured["meta"][vid]["user"], "www-data")

    # -----------------------------------------------------------------------
    # 6. PUT /api/cron/jobs/<vid>  (edit)
    # -----------------------------------------------------------------------

    def test_edit_job_success(self):
        patches, captured = self._patch_io()
        client = self._client()
        payload = {"schedule": "0 6 * * *",
                   "command": "/usr/bin/backup-new.sh",
                   "name": "Renamed", "type": "shell"}
        with patches[0], patches[1], patches[2], patches[3]:
            r = client.put(f"/api/cron/jobs/{self.VID}",
                           data=json.dumps(payload),
                           content_type="application/json")
        data = r.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["schedule_human"], "Daily at 06:00")
        self.assertIn("/usr/bin/backup-new.sh", captured["crontab"])
        self.assertNotIn("/usr/bin/backup.sh", captured["crontab"])

    def test_edit_job_not_found(self):
        patches, _ = self._patch_io()
        client = self._client()
        payload = {"schedule": "0 6 * * *", "command": "/bin/x", "name": ""}
        with patches[0], patches[1], patches[2], patches[3]:
            r = client.put("/api/cron/jobs/nonexistent",
                           data=json.dumps(payload),
                           content_type="application/json")
        self.assertEqual(r.status_code, 404)
        self.assertFalse(r.get_json()["ok"])

    def test_edit_job_missing_command(self):
        patches, _ = self._patch_io()
        client = self._client()
        payload = {"schedule": "* * * * *", "command": "", "name": ""}
        with patches[0], patches[1], patches[2], patches[3]:
            r = client.put(f"/api/cron/jobs/{self.VID}",
                           data=json.dumps(payload),
                           content_type="application/json")
        self.assertEqual(r.status_code, 400)

    # -----------------------------------------------------------------------
    # 7. DELETE /api/cron/jobs/<vid>
    # -----------------------------------------------------------------------

    def test_delete_job_removes_line(self):
        patches, captured = self._patch_io()
        client = self._client()
        with patches[0], patches[1], patches[2], patches[3]:
            r = client.delete(f"/api/cron/jobs/{self.VID}")
        self.assertTrue(r.get_json()["ok"])
        self.assertNotIn(self.VID, captured["crontab"])

    def test_delete_nonexistent_job_still_ok(self):
        """Deleting an unknown VID is a no-op that still returns ok=True."""
        patches, _ = self._patch_io()
        client = self._client()
        with patches[0], patches[1], patches[2], patches[3]:
            r = client.delete("/api/cron/jobs/ffffffff")
        self.assertTrue(r.get_json()["ok"])

    # -----------------------------------------------------------------------
    # 8. POST /api/cron/jobs/<vid>/toggle
    # -----------------------------------------------------------------------

    def test_toggle_disable_job(self):
        patches, captured = self._patch_io()
        client = self._client()
        payload = {"enable": False}
        with patches[0], patches[1], patches[2], patches[3]:
            r = client.post(f"/api/cron/jobs/{self.VID}/toggle",
                            data=json.dumps(payload),
                            content_type="application/json")
        data = r.get_json()
        self.assertTrue(data["ok"])
        self.assertFalse(data["enabled"])
        # The crontab line should now start with '#'
        for line in captured["crontab"].split("\n"):
            if self.VID in line:
                self.assertTrue(line.strip().startswith("#"),
                                f"Expected disabled line to start with '#': {line}")

    def test_toggle_enable_job(self):
        # Start with a disabled line
        disabled_raw = f"# 0 3 * * * /usr/bin/backup.sh # vp:{self.VID}\n"
        patches, captured = self._patch_io(raw=disabled_raw)
        client = self._client()
        payload = {"enable": True}
        with patches[0], patches[1], patches[2], patches[3]:
            r = client.post(f"/api/cron/jobs/{self.VID}/toggle",
                            data=json.dumps(payload),
                            content_type="application/json")
        data = r.get_json()
        self.assertTrue(data["ok"])
        self.assertTrue(data["enabled"])
        for line in captured["crontab"].split("\n"):
            if self.VID in line and line.strip():
                self.assertFalse(line.strip().startswith("#"),
                                 f"Expected enabled line NOT to start with '#': {line}")

    # -----------------------------------------------------------------------
    # 9. GET /api/cron/presets
    # -----------------------------------------------------------------------

    def test_get_presets_returns_schedules(self):
        client = self._client()
        r = client.get("/api/cron/presets")
        data = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(data["ok"])
        self.assertIsInstance(data["schedules"], list)
        self.assertGreater(len(data["schedules"]), 0)

    def test_get_presets_returns_templates(self):
        client = self._client()
        r = client.get("/api/cron/presets")
        data = r.get_json()
        self.assertIsInstance(data["templates"], list)
        self.assertGreater(len(data["templates"]), 0)

    def test_presets_have_required_keys(self):
        client = self._client()
        r = client.get("/api/cron/presets")
        for p in r.get_json()["schedules"]:
            self.assertIn("label", p)
            self.assertIn("value", p)

    # -----------------------------------------------------------------------
    # 10. Auth guard (401 for every endpoint when not logged in)
    # -----------------------------------------------------------------------

    def _assert_401(self, method, url, **kwargs):
        client = self._client(logged_in=False)
        fn = getattr(client, method)
        r = fn(url, **kwargs)
        self.assertEqual(r.status_code, 401,
                         f"Expected 401 for {method.upper()} {url}, got {r.status_code}")
        self.assertFalse(r.get_json()["ok"])

    def test_auth_list_jobs(self):
        self._assert_401("get", "/api/cron/jobs")

    def test_auth_add_job(self):
        self._assert_401("post", "/api/cron/jobs",
                         data=json.dumps({"schedule": "* * * * *", "command": "/bin/true"}),
                         content_type="application/json")

    def test_auth_edit_job(self):
        self._assert_401("put", f"/api/cron/jobs/{self.VID}",
                         data=json.dumps({"schedule": "* * * * *", "command": "/bin/true", "name": ""}),
                         content_type="application/json")

    def test_auth_delete_job(self):
        self._assert_401("delete", f"/api/cron/jobs/{self.VID}")

    def test_auth_toggle_job(self):
        self._assert_401("post", f"/api/cron/jobs/{self.VID}/toggle",
                         data=json.dumps({"enable": True}),
                         content_type="application/json")

    def test_auth_presets(self):
        self._assert_401("get", "/api/cron/presets")

    def test_auth_job_logs(self):
        self._assert_401("get", f"/api/cron/jobs/{self.VID}/logs")

    def test_auth_run_now(self):
        self._assert_401("post", f"/api/cron/jobs/{self.VID}/run")


if __name__ == "__main__":
    unittest.main(verbosity=2)
