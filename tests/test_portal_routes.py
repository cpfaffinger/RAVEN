import base64
import json
import re
import sys
import threading
import time
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi.routing import APIRoute  # noqa: E402

from portal_harness import (  # noqa: E402
    AGENT_SCRIPT, PORTAL_MODULES, WORKER_THREADS, PortalTestCase, hours_ago, hours_ahead, portal_app as app,
    portal_auth as auth, portal_core as core, portal_workers as workers,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import backup_check  # noqa: E402


PUBLIC_PAGES = {"/livez", "/readyz", "/healthz", "/login"}
PAGES_FOR_EVERY_USER = {
    "/", "/manual", "/account", "/checker", "/policies", "/policies/{policy_id}", "/clients/{client_id}",
}
ADMIN_PAGES = (
    "/users", "/mirrors", "/processes", "/settings/smtp", "/settings/application",
    "/certificates", "/clients/new", "/explorer",
)
LOGIN_POSTS = {"/login", "/login/passkey/options", "/login/passkey"}
POSTS_FOR_EVERY_USER = {
    "/logout", "/account/passkeys/options", "/account/passkeys", "/account/passkeys/{credential_id}/delete",
}
# These take JSON from the passkey script, so the token travels in a header.
CSRF_HEADER_POSTS = {"/account/passkeys/options", "/account/passkeys"}
AGENT_POST_PREFIXES = ("/api/agent/", "/api/onboard/")
LATE_REPORT = "Agent hat sich seit 48 Stunden nicht gemeldet"


def routes(method):
    return [route for route in app.app.routes if isinstance(route, APIRoute) and method in route.methods]


def concrete_path(route):
    return re.sub(r"\{[^}]+\}", "1", route.path)


def required_query(route):
    return {field.name: "1" for field in route.dependant.query_params if field.field_info.is_required()}


def filled_form(route, **overrides):
    """Answer every form field; "1" passes as both a number and a string."""
    return {**{field.name: "1" for field in route.dependant.body_params}, **overrides}


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


class FrozenClock(datetime):
    """Stand in for the portal's datetime so a test can step from one schedule slot to the next."""

    current = None

    @classmethod
    def now(cls, tz=None):
        return cls.current.astimezone(tz)


class AnonymousAccessTests(PortalTestCase):
    def test_every_page_outside_the_public_ones_redirects_to_login(self):
        client = self.client()
        for route in routes("GET"):
            if route.path in PUBLIC_PAGES or route.path == "/bootstrap":
                continue
            with self.subTest(route.path):
                response = client.get(concrete_path(route), params=required_query(route))
                self.assertEqual(response.status_code, 303)
                self.assertEqual(response.headers["location"], "/login")

    def test_every_portal_post_redirects_to_login(self):
        client = self.client()
        for route in routes("POST"):
            if route.path in LOGIN_POSTS or route.path.startswith(AGENT_POST_PREFIXES):
                continue
            with self.subTest(route.path):
                response = client.post(concrete_path(route), data=filled_form(route))
                self.assertEqual(response.status_code, 303)
                self.assertEqual(response.headers["location"], "/login")

    def test_every_agent_route_needs_a_bearer_token(self):
        client = self.client()
        paths = [concrete_path(route) for route in routes("POST") if route.path.startswith(AGENT_POST_PREFIXES)]
        self.assertGreaterEqual(len(paths), 5)
        for path in paths:
            with self.subTest(path):
                self.assertEqual(client.post(path, json={}).status_code, 401)
                self.assertEqual(client.post(path, json={}, headers=bearer("wrong")).status_code, 401)
        self.assertEqual(client.get("/bootstrap").status_code, 401)

    def test_the_probes_answer_without_a_session(self):
        self.assertEqual(self.client().get("/livez").status_code, 200)

    def test_a_request_for_a_foreign_host_is_refused(self):
        response = self.client().get("/livez", headers={"Host": "evil.raven.test"})
        self.assertEqual(response.status_code, 400)


class RoleTests(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.agent = self.add_client("alpha")
        self.viewer = self.session("viewer")
        self.admin = self.session("admin")

    def test_a_viewer_reaches_the_pages_open_to_every_user(self):
        for path in ("/", "/manual", "/account", "/checker", "/policies",
                     f"/policies/{self.default_policy_id()}", f"/clients/{self.agent.id}"):
            with self.subTest(path):
                self.assertEqual(self.viewer.get(path).status_code, 200)

    def test_every_other_page_is_forbidden_for_a_viewer(self):
        for route in routes("GET"):
            if route.path in PAGES_FOR_EVERY_USER | PUBLIC_PAGES or route.path == "/bootstrap":
                continue
            with self.subTest(route.path):
                response = self.viewer.get(concrete_path(route), params=required_query(route))
                self.assertEqual(response.status_code, 403)

    def test_every_admin_post_is_forbidden_for_a_viewer_with_a_valid_token(self):
        for route in routes("POST"):
            if (
                route.path in LOGIN_POSTS | POSTS_FOR_EVERY_USER
                or route.path.startswith(AGENT_POST_PREFIXES)
            ):
                continue
            with self.subTest(route.path):
                response = self.viewer.post(
                    concrete_path(route), data=filled_form(route, csrf_token=self.viewer.csrf_token)
                )
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.json()["detail"], "Administratorrechte erforderlich")

    def test_a_viewer_cannot_create_a_user(self):
        response = self.viewer.submit(
            "/users", username="intruder", display_name="x", password="long enough password", role="admin"
        )
        self.assertEqual(response.status_code, 403)
        self.assertIsNone(self.row("SELECT id FROM users WHERE username='intruder'"))

    def test_an_admin_reaches_the_admin_pages(self):
        for path in ADMIN_PAGES:
            with self.subTest(path):
                self.assertEqual(self.admin.get(path).status_code, 200)

    def test_an_admin_reaches_the_detail_pages(self):
        target_id = self.add_mirror_target(next_run_at=hours_ahead(24))
        run_id = self.add_mirror_run(target_id, "success", output="fertig")
        for path in (f"/mirrors/{target_id}", f"/mirrors/runs/{run_id}", f"/mirrors/runs/{run_id}/output"):
            with self.subTest(path):
                self.assertEqual(self.admin.get(path).status_code, 200)

    def test_an_admin_creates_a_client_without_touching_the_system(self):
        response = self.admin.submit(
            "/clients/new", slug="bravo", source_hostname="bravo.raven.test", policy_id=self.default_policy_id()
        )
        self.assertEqual(response.status_code, 303)
        self.provisioned.assert_called_once_with("backup_bravo", core.HOME_ROOT / "backup_bravo")
        created = self.row("SELECT * FROM clients WHERE slug='bravo'")
        self.assertEqual(created["username"], "backup_bravo")
        self.assertEqual(self.subprocess_run.call_count, 0)


class CsrfTests(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.agent = self.add_client("alpha")
        self.admin = self.session("admin")

    def test_every_portal_post_rejects_an_invalid_token(self):
        checked = 0
        for route in routes("POST"):
            fields = filled_form(route)
            if "csrf_token" not in fields:
                continue
            checked += 1
            with self.subTest(route.path):
                response = self.admin.post(concrete_path(route), data=filled_form(route, csrf_token="wrong"))
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.json()["detail"], "Ungueltiges CSRF-Token")
        self.assertGreater(checked, 30)

    def test_every_portal_post_is_protected_by_a_token(self):
        unprotected = {
            route.path for route in routes("POST")
            if "csrf_token" not in filled_form(route)
            and route.path not in LOGIN_POSTS | CSRF_HEADER_POSTS
            and not route.path.startswith(AGENT_POST_PREFIXES)
        }
        self.assertEqual(unprotected, set())

    def test_the_passkey_routes_reject_an_invalid_header(self):
        for path in sorted(CSRF_HEADER_POSTS):
            with self.subTest(path):
                self.assertEqual(self.admin.post(path, headers={"X-CSRF-Token": "wrong"}).status_code, 403)
                self.assertEqual(self.admin.post(path).status_code, 403)

    def test_a_missing_token_is_refused(self):
        response = self.admin.post(f"/clients/{self.agent.id}/backup/trigger", data={})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.count("backup_commands"), 0)

    def test_the_token_of_another_session_is_refused(self):
        other = self.session("admin", username="other-admin")
        response = self.admin.submit(f"/clients/{self.agent.id}/backup/trigger", csrf_token=other.csrf_token)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.count("backup_commands"), 0)

    def test_a_rejected_post_changes_nothing(self):
        policy_id = self.add_policy("Unassigned")
        target_id = self.add_mirror_target()
        victim = self.add_user("victim", "viewer")
        for path in (
            f"/policies/{policy_id}/delete", f"/mirrors/{target_id}/delete", f"/mirrors/{target_id}/run",
            f"/users/{victim}/toggle", f"/clients/{self.agent.id}/delete",
            f"/clients/{self.agent.id}/backup/trigger", "/checker/run",
        ):
            with self.subTest(path):
                self.assertEqual(self.admin.submit(path, csrf_token="wrong", mode="normal").status_code, 403)
        self.assertEqual(self.count("backup_policies", "id=?", policy_id), 1)
        self.assertEqual(self.count("mirror_targets", "id=?", target_id), 1)
        self.assertEqual(self.count("mirror_runs"), 0)
        self.assertEqual(self.row("SELECT active FROM users WHERE id=?", victim)["active"], 1)
        self.assertEqual(self.count("clients", "id=?", self.agent.id), 1)
        self.assertEqual(self.count("backup_commands"), 0)
        self.assertEqual(self.count("checker_runs"), 0)

    def test_the_right_token_is_accepted(self):
        response = self.admin.submit(f"/clients/{self.agent.id}/backup/trigger", force="1")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.count("backup_commands", "client_id=?", self.agent.id), 1)


class SessionTests(PortalTestCase):
    PASSWORD = "correct horse battery"

    def setUp(self):
        super().setUp()
        self.add_user("operator", "admin", password=self.PASSWORD)

    def login(self, client, password=None):
        return client.post("/login", data={"username": "operator", "password": password or self.PASSWORD})

    def test_login_opens_a_session_and_logout_closes_it(self):
        client = self.client()
        response = self.login(client)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/")
        self.assertEqual(client.get("/").status_code, 200)
        session = self.row("SELECT csrf_token FROM sessions")

        response = client.post("/logout", data={"csrf_token": session["csrf_token"]})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")
        self.assertEqual(self.count("sessions"), 0)
        self.assertEqual(client.get("/").status_code, 303)

    def test_the_session_cookie_cannot_leave_https_or_reach_scripts(self):
        cookie = self.login(self.client()).headers["set-cookie"].lower()
        self.assertIn("secure", cookie)
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)

    def test_the_stored_session_does_not_contain_the_cookie_value(self):
        client = self.client()
        self.login(client)
        raw = client.cookies["backup_portal_session"]
        self.assertEqual(self.row("SELECT token_hash FROM sessions")["token_hash"], core.token_hash(raw))

    def test_a_wrong_password_opens_no_session(self):
        self.patch(time, "sleep")
        response = self.login(self.client(), "not the password")
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(self.count("sessions"), 0)

    def test_an_unknown_user_gets_the_same_answer_as_a_wrong_password(self):
        self.patch(time, "sleep")
        unknown = self.client().post("/login", data={"username": "nobody", "password": "whatever"})
        wrong = self.login(self.client(), "not the password")
        self.assertEqual(unknown.status_code, wrong.status_code)
        self.assertIn("Benutzername oder Passwort ist falsch", unknown.text)
        self.assertIn("Benutzername oder Passwort ist falsch", wrong.text)

    def test_too_many_failures_block_even_the_right_password(self):
        auth.LOGIN_FAILURES["testclient"] = [time.time()] * 8
        response = self.login(self.client())
        self.assertEqual(response.status_code, 429)
        self.assertEqual(self.count("sessions"), 0)

    def test_a_disabled_user_cannot_log_in(self):
        self.patch(time, "sleep")
        self.execute("UPDATE users SET active=0 WHERE username='operator'")
        self.assertEqual(self.login(self.client()).status_code, 401)

    def test_a_signed_in_user_is_sent_away_from_the_login_page(self):
        response = self.session("viewer").get("/login")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/")

    def test_an_expired_session_counts_as_anonymous(self):
        client = self.session("admin", expires_in=-10)
        self.assertEqual(client.get("/").status_code, 303)
        self.assertEqual(self.count("sessions"), 0)

    def test_a_disabled_user_loses_an_open_session(self):
        client = self.session("viewer")
        self.execute("UPDATE users SET active=0 WHERE id=?", client.user_id)
        self.assertEqual(client.get("/").status_code, 303)

    def test_logout_without_a_valid_token_keeps_the_session(self):
        client = self.session("viewer")
        self.assertEqual(client.post("/logout", data={"csrf_token": "wrong"}).status_code, 403)
        self.assertEqual(client.get("/").status_code, 200)


class AgentTestCase(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.http = self.client()
        self.agent = self.add_client("alpha")
        self.other = self.add_client("bravo")

    def poll(self, agent=None, **payload):
        agent = agent or self.agent
        body = {"hostname": agent.hostname, "config_version": 1, **payload}
        return self.http.post("/api/agent/poll", json=body, headers=agent.headers)

    def report(self, event, agent=None, **payload):
        agent = agent or self.agent
        return self.http.post("/api/agent/status", json={"event": event, "payload": payload}, headers=agent.headers)

    def set_command_state(self, command_id, agent=None, **body):
        agent = agent or self.agent
        return self.http.post(f"/api/agent/commands/{command_id}", json=body, headers=agent.headers)

    def command(self, command_id):
        return self.row("SELECT * FROM backup_commands WHERE id=?", command_id)

    def client_row(self, agent=None):
        return self.row("SELECT * FROM clients WHERE id=?", (agent or self.agent).id)

    def events(self, agent=None):
        return self.rows("SELECT * FROM status_events WHERE client_id=? ORDER BY id", (agent or self.agent).id)

    def commands_in(self, status, agent=None):
        return self.count("backup_commands", "client_id=? AND status=?", (agent or self.agent).id, status)


class AgentPollTests(AgentTestCase):
    def test_a_bad_token_is_refused(self):
        response = self.http.post("/api/agent/poll", json={}, headers=bearer("wrong"))
        self.assertEqual(response.status_code, 401)
        self.assertIsNone(self.client_row()["last_poll_at"])

    def test_a_missing_token_is_refused(self):
        self.assertEqual(self.http.post("/api/agent/poll", json={}).status_code, 401)

    def test_the_token_of_a_deactivated_client_is_refused(self):
        self.execute("UPDATE clients SET active=0 WHERE id=?", self.agent.id)
        self.assertEqual(self.poll().status_code, 401)

    def test_a_good_token_gets_an_empty_answer_with_the_schedule(self):
        response = self.poll()
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["action"], "none")
        self.assertEqual(body["schedule"]["hour"], 2)
        self.assertEqual(body["schedule"]["interval_hours"], 24)
        self.assertNotIn("config_update", body)
        self.assertIsNotNone(self.client_row()["last_poll_at"])

    def test_a_body_that_is_no_json_still_counts_as_a_poll(self):
        response = self.http.post("/api/agent/poll", content=b"nonsense", headers=self.agent.headers)
        self.assertEqual(response.status_code, 200)

    def test_a_hostname_mismatch_is_refused_and_remembered(self):
        response = self.poll(hostname="renamed.raven.test")
        self.assertEqual(response.status_code, 409)
        row = self.client_row()
        self.assertEqual(row["reported_hostname"], "renamed.raven.test")
        self.assertIsNone(row["last_poll_at"])

    def test_a_hostname_mismatch_claims_no_command(self):
        command_id = self.add_command(self.agent.id)
        self.assertEqual(self.poll(hostname="renamed.raven.test").status_code, 409)
        self.assertEqual(self.command(command_id)["status"], "queued")

    def test_a_hostname_mismatch_keeps_an_invalid_name_out_of_the_database(self):
        self.assertEqual(self.poll(hostname="not a host name").status_code, 409)
        self.assertIsNone(self.client_row()["reported_hostname"])

    def test_the_matching_hostname_clears_a_remembered_mismatch(self):
        self.poll(hostname="renamed.raven.test")
        self.assertEqual(self.poll().status_code, 200)
        self.assertIsNone(self.client_row()["reported_hostname"])

    def test_a_queued_command_is_claimed_and_returned(self):
        policy = {"id": 7, "name": "Snapshot", "paths": []}
        command_id = self.add_command(
            self.agent.id, force=1, reason="schedule", due_at="2026-10-31T02:00:00+00:00",
            policy_snapshot=json.dumps(policy),
        )
        body = self.poll().json()
        self.assertEqual(body["action"], "backup")
        self.assertEqual(body["command_id"], command_id)
        self.assertEqual(body["reason"], "schedule")
        self.assertIs(body["force"], True)
        self.assertEqual(body["due_at"], "2026-10-31T02:00:00+00:00")
        self.assertEqual(body["policy"], policy)
        row = self.command(command_id)
        self.assertEqual(row["status"], "claimed")
        self.assertIsNotNone(row["claimed_at"])

    def test_a_claimed_command_is_not_handed_out_twice(self):
        self.add_command(self.agent.id)
        self.assertEqual(self.poll().json()["action"], "backup")
        self.assertEqual(self.poll().json()["action"], "none")

    def test_the_oldest_queued_command_comes_first(self):
        first = self.add_command(self.agent.id)
        self.add_command(self.agent.id)
        self.assertEqual(self.poll().json()["command_id"], first)

    def test_a_poll_never_returns_the_command_of_another_client(self):
        command_id = self.add_command(self.other.id)
        self.assertEqual(self.poll().json()["action"], "none")
        self.assertEqual(self.command(command_id)["status"], "queued")

    def test_a_stale_claim_is_handed_out_again(self):
        command_id = self.add_command(self.agent.id, status="claimed", claimed_at=hours_ago(1))
        body = self.poll().json()
        self.assertEqual(body["action"], "backup")
        self.assertEqual(body["command_id"], command_id)

    def test_a_fresh_claim_stays_with_the_agent(self):
        command_id = self.add_command(self.agent.id, status="claimed", claimed_at=core.now_iso())
        self.assertEqual(self.poll().json()["action"], "none")
        self.assertEqual(self.command(command_id)["status"], "claimed")

    def test_a_running_policy_cleanup_holds_the_command_back(self):
        command_id = self.add_command(self.agent.id)
        self.insert(
            "policy_cleanup_runs", policy_id=self.default_policy_id(), policy_name="x", status="running",
            requested_at=core.now_iso(),
        )
        self.assertEqual(self.poll().json()["action"], "none")
        self.assertEqual(self.command(command_id)["status"], "queued")

    def test_a_config_update_is_sent_on_a_version_mismatch(self):
        self.execute("UPDATE clients SET agent_config_version=5 WHERE id=?", self.agent.id)
        update = self.poll(config_version=4).json()["config_update"]
        self.assertEqual(update["version"], 5)
        config = core.tomllib.loads(base64.b64decode(update["content_b64"]).decode("utf-8"))
        self.assertEqual(config["backup"]["config_version"], 5)
        self.assertEqual(config["backup"]["expected_source_hostname"], self.agent.hostname)
        self.assertEqual(config["status"]["token"], self.agent.token)
        self.assertEqual(
            [item["target_name"] for item in config["backup_paths"]], ["etc", "home"]
        )

    def test_no_config_update_is_sent_on_a_matching_version(self):
        self.execute("UPDATE clients SET agent_config_version=5 WHERE id=?", self.agent.id)
        self.assertNotIn("config_update", self.poll(config_version=5).json())

    def test_a_poll_without_a_version_gets_the_config(self):
        response = self.http.post("/api/agent/poll", json={}, headers=self.agent.headers)
        self.assertEqual(response.json()["config_update"]["version"], 1)

    def test_a_config_update_stays_readable_with_a_quote_in_the_smtp_password(self):
        # build_agent_config pastes the password into the TOML without escaping
        # it. The agent then receives a file it cannot parse.
        self.execute(
            "UPDATE smtp_settings SET password_ciphertext=?", core.encrypt_deployment_token('pa"ss\\word')
        )
        update = self.poll(config_version=0).json()["config_update"]
        config = core.tomllib.loads(base64.b64decode(update["content_b64"]).decode("utf-8"))
        self.assertEqual(config["smtp"]["password"], 'pa"ss\\word')

    def test_a_different_script_digest_gets_the_current_script(self):
        update = self.poll(script_sha256="0" * 64).json()["script_update"]
        self.assertEqual(base64.b64decode(update["content_b64"]), AGENT_SCRIPT)
        self.assertEqual(self.poll(script_sha256=update["sha256"]).json().get("script_update"), None)

    def test_a_malformed_script_digest_is_refused(self):
        self.assertEqual(self.poll(script_sha256="xyz").status_code, 400)


class AgentCommandStateTests(AgentTestCase):
    def test_running_records_the_start(self):
        command_id = self.add_command(self.agent.id, status="claimed")
        response = self.set_command_state(command_id, status="running", run_id="run-1", message="los")
        self.assertEqual(response.status_code, 200)
        row = self.command(command_id)
        self.assertEqual(row["status"], "running")
        self.assertEqual(row["run_id"], "run-1")
        self.assertEqual(row["message"], "los")
        self.assertIsNotNone(row["started_at"])
        self.assertIsNone(row["finished_at"])

    def test_every_final_state_records_the_end_and_keeps_the_run_id(self):
        for status in ("success", "failure", "skipped"):
            with self.subTest(status):
                command_id = self.add_command(self.agent.id, status="running", run_id="run-1")
                self.assertEqual(self.set_command_state(command_id, status=status).status_code, 200)
                row = self.command(command_id)
                self.assertEqual(row["status"], status)
                self.assertEqual(row["run_id"], "run-1")
                self.assertIsNotNone(row["finished_at"])

    def test_a_final_state_takes_a_new_run_id(self):
        command_id = self.add_command(self.agent.id, status="running")
        self.set_command_state(command_id, status="success", run_id="run-2")
        self.assertEqual(self.command(command_id)["run_id"], "run-2")

    def test_a_status_outside_the_contract_is_refused(self):
        command_id = self.add_command(self.agent.id)
        for status in ("queued", "claimed", "satisfied", ""):
            with self.subTest(status):
                self.assertEqual(self.set_command_state(command_id, status=status).status_code, 400)
        self.assertEqual(self.command(command_id)["status"], "queued")

    def test_a_body_that_is_no_json_is_refused(self):
        command_id = self.add_command(self.agent.id)
        response = self.http.post(
            f"/api/agent/commands/{command_id}", content=b"nonsense", headers=self.agent.headers
        )
        self.assertEqual(response.status_code, 400)

    def test_an_unknown_command_is_not_found(self):
        self.assertEqual(self.set_command_state(99, status="running").status_code, 404)

    def test_a_client_cannot_touch_the_command_of_another_client(self):
        command_id = self.add_command(self.other.id, status="claimed")
        for status in ("running", "success", "failure", "skipped"):
            with self.subTest(status):
                response = self.set_command_state(command_id, agent=self.agent, status=status, run_id="forged")
                self.assertEqual(response.status_code, 404)
        row = self.command(command_id)
        self.assertEqual(row["status"], "claimed")
        self.assertIsNone(row["run_id"])


class AgentStatusTests(AgentTestCase):
    def test_a_bad_token_is_refused(self):
        response = self.http.post("/api/agent/status", json={"event": "started"}, headers=bearer("wrong"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.count("status_events"), 0)

    def test_an_unknown_event_is_refused(self):
        self.assertEqual(self.report("exploded").status_code, 400)
        self.assertEqual(self.count("status_events"), 0)

    def test_a_body_that_is_no_json_is_refused(self):
        response = self.http.post("/api/agent/status", content=b"nonsense", headers=self.agent.headers)
        self.assertEqual(response.status_code, 400)

    def test_started_opens_the_command_and_the_client(self):
        command_id = self.add_command(self.agent.id, status="claimed")
        self.assertEqual(self.report("started", command_id=command_id, run_id="run-1").status_code, 200)
        row = self.command(command_id)
        self.assertEqual(row["status"], "running")
        self.assertEqual(row["run_id"], "run-1")
        self.assertIsNotNone(row["started_at"])
        self.assertEqual(self.client_row()["last_event"], "started")
        self.assertEqual([event["event"] for event in self.events()], ["started"])

    def test_started_keeps_the_time_the_command_state_recorded(self):
        started_at = hours_ago(1)
        command_id = self.add_command(self.agent.id, status="running", started_at=started_at)
        self.report("started", command_id=command_id)
        self.assertEqual(self.command(command_id)["started_at"], started_at)

    def test_success_closes_the_command_and_records_the_success(self):
        command_id = self.add_command(self.agent.id, status="running")
        self.report("success", command_id=command_id, run_id="run-1")
        row = self.command(command_id)
        self.assertEqual(row["status"], "success")
        self.assertIsNotNone(row["finished_at"])
        client = self.client_row()
        self.assertEqual(client["last_event"], "success")
        self.assertIsNotNone(client["last_success_at"])

    def test_failure_closes_the_command_without_recording_a_success(self):
        command_id = self.add_command(self.agent.id, status="running")
        self.report("failure", command_id=command_id, error="kaputt")
        self.assertEqual(self.command(command_id)["status"], "failure")
        client = self.client_row()
        self.assertEqual(client["last_event"], "failure")
        self.assertIsNone(client["last_success_at"])

    def test_a_heartbeat_leaves_the_command_alone(self):
        command_id = self.add_command(self.agent.id, status="running")
        self.report("heartbeat", command_id=command_id)
        self.assertEqual(self.command(command_id)["status"], "running")

    def test_the_payload_is_stored_with_the_event(self):
        self.report("success", run_id="run-1", logical_run_bytes=4096)
        event = self.events()[0]
        self.assertEqual(event["run_id"], "run-1")
        self.assertEqual(json.loads(event["payload"])["logical_run_bytes"], 4096)
        self.assertEqual(json.loads(self.client_row()["last_payload"])["logical_run_bytes"], 4096)

    def test_a_client_cannot_touch_the_command_of_another_client(self):
        command_id = self.add_command(self.other.id, status="running", run_id="genuine")
        for event in ("started", "success", "failure"):
            with self.subTest(event):
                response = self.report(event, agent=self.agent, command_id=command_id, run_id="forged")
                self.assertEqual(response.status_code, 200)
                row = self.command(command_id)
                self.assertEqual(row["status"], "running")
                self.assertEqual(row["run_id"], "genuine")
                self.assertIsNone(row["finished_at"])
        self.assertEqual(self.events(self.other), [])
        self.assertIsNone(self.client_row(self.other)["last_event"])


class CloseDeadRunTests(AgentTestCase):
    def open_run(self, **columns):
        self.execute(
            "UPDATE clients SET last_event='started',last_event_at=? WHERE id=?", hours_ago(1), self.agent.id
        )
        return self.add_command(self.agent.id, status="running", started_at=hours_ago(1), **columns)

    def test_a_poll_closes_the_run_of_a_dead_agent(self):
        command_id = self.open_run(run_id="run-1")
        self.assertEqual(self.poll().status_code, 200)
        row = self.command(command_id)
        self.assertEqual(row["status"], "failure")
        self.assertEqual(row["message"], "Agent hat den Lauf ohne Abschlussmeldung beendet")
        self.assertIsNotNone(row["finished_at"])
        self.assertEqual(self.client_row()["last_event"], "failure")

    def test_a_poll_writes_one_event_for_the_closed_run(self):
        self.open_run()
        self.poll()
        events = self.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "failure")
        self.assertEqual(
            json.loads(events[0]["payload"]), {"error": "Agent hat den Lauf ohne Abschlussmeldung beendet"}
        )

    def test_the_next_poll_writes_no_second_event(self):
        self.open_run()
        self.poll()
        self.poll()
        self.assertEqual(len(self.events()), 1)

    def test_a_poll_with_nothing_open_writes_no_event(self):
        self.execute(
            "UPDATE clients SET last_event='success',last_event_at=? WHERE id=?", hours_ago(1), self.agent.id
        )
        self.add_command(self.agent.id, status="success")
        self.assertEqual(self.poll().status_code, 200)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.client_row()["last_event"], "success")

    def test_a_host_without_any_history_writes_no_event(self):
        self.poll()
        self.assertEqual(self.events(), [])
        self.assertIsNone(self.client_row()["last_event"])

    def test_a_started_event_without_a_command_is_closed_too(self):
        self.execute(
            "UPDATE clients SET last_event='started',last_event_at=? WHERE id=?", hours_ago(1), self.agent.id
        )
        self.poll()
        self.assertEqual(self.client_row()["last_event"], "failure")
        self.assertEqual(len(self.events()), 1)

    def test_a_running_command_without_a_started_event_is_closed_too(self):
        command_id = self.add_command(self.agent.id, status="running", started_at=hours_ago(1))
        self.poll()
        self.assertEqual(self.command(command_id)["status"], "failure")
        self.assertEqual(len(self.events()), 1)

    def test_a_queued_or_claimed_command_is_no_open_run(self):
        claimed = self.add_command(self.agent.id, status="claimed", claimed_at=core.now_iso())
        queued = self.add_command(self.agent.id, status="queued")
        self.poll()
        self.assertEqual(self.command(claimed)["status"], "claimed")
        self.assertEqual(self.command(queued)["status"], "claimed")
        self.assertEqual(self.events(), [])

    def test_the_run_of_another_host_stays_open(self):
        self.open_run()
        other_command = self.add_command(self.other.id, status="running", started_at=hours_ago(1))
        self.poll()
        self.assertEqual(self.command(other_command)["status"], "running")
        self.assertEqual(self.events(self.other), [])

    def test_the_host_gets_a_scheduled_command_afterwards(self):
        self.open_run()
        workers.enqueue_due_schedules()
        self.assertEqual(self.commands_in("queued"), 0)
        self.assertEqual(self.poll().json()["action"], "none")
        workers.enqueue_due_schedules()
        body = self.poll().json()
        self.assertEqual(body["action"], "backup")
        self.assertEqual(body["reason"], "schedule")

    def test_the_host_gets_a_manual_command_afterwards(self):
        self.open_run()
        admin = self.session("admin")
        trigger = f"/clients/{self.agent.id}/backup/trigger"
        self.assertEqual(admin.submit(trigger, force="1").status_code, 409)
        self.poll()
        self.assertEqual(admin.submit(trigger, force="1").status_code, 303)
        self.assertEqual(self.poll().json()["action"], "backup")


class ReleaseSilentAgentsTests(AgentTestCase):
    SILENT = workers.SILENT_AGENT_HOURS + 1
    RECENT = workers.SILENT_AGENT_HOURS - 1

    def silent_run(self, hours):
        self.execute(
            "UPDATE clients SET last_event='started',last_event_at=? WHERE id=?", hours_ago(hours), self.agent.id
        )
        return self.add_command(self.agent.id, status="running", started_at=hours_ago(hours))

    def test_a_run_older_than_the_limit_is_closed(self):
        command_id = self.silent_run(self.SILENT)
        workers.release_silent_agents()
        row = self.command(command_id)
        self.assertEqual(row["status"], "failure")
        self.assertEqual(row["message"], LATE_REPORT)
        self.assertEqual(self.client_row()["last_event"], "failure")
        self.assertEqual([event["event"] for event in self.events()], ["failure"])

    def test_a_younger_run_stays_open(self):
        command_id = self.silent_run(self.RECENT)
        workers.release_silent_agents()
        self.assertEqual(self.command(command_id)["status"], "running")
        self.assertEqual(self.client_row()["last_event"], "started")
        self.assertEqual(self.events(), [])

    def test_a_silent_command_alone_is_enough(self):
        command_id = self.add_command(self.agent.id, status="running", started_at=hours_ago(self.SILENT))
        workers.release_silent_agents()
        self.assertEqual(self.command(command_id)["status"], "failure")

    def test_a_silent_started_event_alone_is_enough(self):
        self.execute(
            "UPDATE clients SET last_event='started',last_event_at=? WHERE id=?",
            hours_ago(self.SILENT), self.agent.id,
        )
        workers.release_silent_agents()
        self.assertEqual(self.client_row()["last_event"], "failure")

    def test_only_the_silent_host_is_closed(self):
        command_id = self.silent_run(self.SILENT)
        other_command = self.add_command(self.other.id, status="running", started_at=hours_ago(self.RECENT))
        workers.release_silent_agents()
        self.assertEqual(self.command(command_id)["status"], "failure")
        self.assertEqual(self.command(other_command)["status"], "running")

    def test_running_it_twice_writes_one_event(self):
        self.silent_run(self.SILENT)
        workers.release_silent_agents()
        workers.release_silent_agents()
        self.assertEqual(len(self.events()), 1)

    def test_a_closed_host_is_free_for_the_next_command(self):
        self.silent_run(self.SILENT)
        workers.release_silent_agents()
        workers.enqueue_due_schedules()
        self.assertEqual(self.commands_in("queued"), 1)

    def test_a_late_success_report_overrides_the_closure(self):
        command_id = self.silent_run(self.SILENT)
        workers.release_silent_agents()
        self.assertEqual(self.report("success", command_id=command_id, run_id="run-1").status_code, 200)
        row = self.command(command_id)
        self.assertEqual(row["status"], "success")
        self.assertEqual(row["run_id"], "run-1")
        client = self.client_row()
        self.assertEqual(client["last_event"], "success")
        self.assertIsNotNone(client["last_success_at"])
        self.assertEqual([event["event"] for event in self.events()], ["failure", "success"])

    def test_a_late_command_state_overrides_the_closure(self):
        command_id = self.silent_run(self.SILENT)
        workers.release_silent_agents()
        self.set_command_state(command_id, status="success", message="Backup erfolgreich")
        row = self.command(command_id)
        self.assertEqual(row["status"], "success")
        self.assertEqual(row["message"], "Backup erfolgreich")

    def test_a_late_success_satisfies_the_slot(self):
        command_id = self.silent_run(self.SILENT)
        workers.release_silent_agents()
        self.report("success", command_id=command_id)
        workers.enqueue_due_schedules()
        self.assertEqual(self.commands_in("queued"), 0)
        self.assertEqual(self.commands_in("satisfied"), 1)


class EnqueueDueSchedulesTests(AgentTestCase):
    def setUp(self):
        super().setUp()
        self.execute("DELETE FROM clients WHERE id=?", self.other.id)

    def queued(self):
        return self.rows("SELECT * FROM backup_commands WHERE status='queued' ORDER BY id")

    def freeze(self, moment):
        FrozenClock.current = moment
        for module in PORTAL_MODULES:
            if hasattr(module, "datetime"):
                self.patch(module, "datetime", new=FrozenClock)

    def test_a_due_host_gets_a_command_with_the_policy(self):
        workers.enqueue_due_schedules()
        commands = self.queued()
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0]["client_id"], self.agent.id)
        self.assertEqual(commands[0]["reason"], "schedule")
        self.assertEqual(commands[0]["force"], 0)
        self.assertEqual(commands[0]["schedule_key"].split(":", 1)[0], str(self.agent.id))
        policy = json.loads(commands[0]["policy_snapshot"])
        self.assertEqual(policy["id"], self.default_policy_id())

    def test_every_pass_of_one_slot_creates_one_command(self):
        for _ in range(3):
            workers.enqueue_due_schedules()
        self.assertEqual(self.count("backup_commands"), 1)

    def test_a_failed_command_is_not_repeated_within_its_slot(self):
        workers.enqueue_due_schedules()
        self.execute("UPDATE backup_commands SET status='failure'")
        workers.enqueue_due_schedules()
        self.assertEqual(self.count("backup_commands"), 1)

    def test_the_next_slot_creates_the_next_command(self):
        start = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
        self.freeze(start)
        workers.enqueue_due_schedules()
        self.execute("UPDATE backup_commands SET status='failure'")
        FrozenClock.current = start + timedelta(hours=24)
        workers.enqueue_due_schedules()
        self.assertEqual(self.count("backup_commands"), 2)
        self.assertEqual(len(self.queued()), 1)

    def test_every_host_gets_its_own_command(self):
        self.add_client("charlie")
        workers.enqueue_due_schedules()
        self.assertEqual(self.count("backup_commands", "status='queued'"), 2)

    def test_a_host_with_an_open_command_is_skipped(self):
        for status in ("queued", "claimed", "running"):
            with self.subTest(status):
                self.execute("DELETE FROM backup_commands")
                self.add_command(self.agent.id, status=status)
                workers.enqueue_due_schedules()
                self.assertEqual(self.count("backup_commands"), 1)
                self.assertEqual(self.count("backup_commands", "reason='schedule'"), 0)

    def test_a_host_with_a_started_run_is_skipped(self):
        self.execute("UPDATE clients SET last_event='started' WHERE id=?", self.agent.id)
        workers.enqueue_due_schedules()
        self.assertEqual(self.count("backup_commands"), 0)

    def test_a_skipped_host_gets_its_command_once_the_run_ended(self):
        self.execute("UPDATE clients SET last_event='started' WHERE id=?", self.agent.id)
        workers.enqueue_due_schedules()
        self.execute("UPDATE clients SET last_event='failure' WHERE id=?", self.agent.id)
        workers.enqueue_due_schedules()
        self.assertEqual(self.count("backup_commands", "status='queued'"), 1)

    def test_a_host_during_a_policy_cleanup_is_skipped(self):
        self.insert(
            "policy_cleanup_runs", policy_id=self.default_policy_id(), policy_name="x", status="queued",
            requested_at=core.now_iso(),
        )
        workers.enqueue_due_schedules()
        self.assertEqual(self.count("backup_commands"), 0)

    def test_a_successful_host_only_gets_a_bookkeeping_row(self):
        self.execute("UPDATE clients SET last_success_at=? WHERE id=?", core.now_iso(), self.agent.id)
        workers.enqueue_due_schedules()
        workers.enqueue_due_schedules()
        rows = self.rows("SELECT status FROM backup_commands")
        self.assertEqual([row["status"] for row in rows], ["satisfied"])

    def test_inactive_and_unboarded_hosts_are_left_out(self):
        self.add_client("charlie", active=0)
        self.add_client("delta", agent_token_hash=None)
        self.execute("UPDATE clients SET active=0 WHERE id=?", self.agent.id)
        workers.enqueue_due_schedules()
        self.assertEqual(self.count("backup_commands"), 0)

    def host_with_jitter(self, slot, wanted, **columns):
        """Add a host of a spread 12:00 policy whose stable jitter for this slot suits the test."""
        policy_id = self.add_policy("Spread", schedule_hour=12, start_offset_minutes=60)
        jitter, slug = next(
            (workers.backup_schedule.slot_jitter(slug, slot, 60), slug)
            for slug in (f"host{index}" for index in range(200))
            if wanted(workers.backup_schedule.slot_jitter(slug, slot, 60))
        )
        return self.add_client(slug, policy_id=policy_id, **columns), jitter

    def test_a_positive_start_offset_holds_the_command_until_its_planned_moment(self):
        slot = datetime(2026, 10, 30, 12, 0).astimezone()
        host, jitter = self.host_with_jitter(slot, lambda minutes: minutes >= 30)
        self.freeze(slot + timedelta(minutes=jitter - 1))
        workers.enqueue_due_schedules()
        self.assertEqual(self.commands_in("queued", host), 0)
        FrozenClock.current = slot + timedelta(minutes=jitter)
        workers.enqueue_due_schedules()
        self.assertEqual(self.commands_in("queued", host), 1)

    @unittest.expectedFailure
    def test_a_negative_start_offset_starts_the_host_before_the_wish_time(self):
        # The policy form promises "± Minuten um die Wunschzeit". slot_plan only
        # switches to the new slot at the wish time itself, so a negative jitter
        # is lost and all those hosts start at the same moment.
        slot = datetime(2026, 10, 30, 12, 0).astimezone()
        previous_success = (slot - timedelta(hours=23)).isoformat()
        host, jitter = self.host_with_jitter(
            slot, lambda minutes: minutes <= -30, last_success_at=previous_success
        )
        self.freeze(slot + timedelta(minutes=jitter + 1))
        workers.enqueue_due_schedules()
        self.assertEqual(self.commands_in("queued", host), 1)


class PolicyUpdateTests(AgentTestCase):
    FORM = {
        "name": "Geaenderte Policy", "schedule_hour": 3, "schedule_minute": 15, "interval_hours": 12,
        "retention_days": 14, "minimum_snapshots_to_keep": 3,
    }

    def setUp(self):
        super().setUp()
        self.policy_id = self.add_policy("Assigned")
        self.bystander = self.other
        self.execute("UPDATE clients SET policy_id=? WHERE id=?", self.policy_id, self.agent.id)
        self.second = self.add_client("charlie", policy_id=self.policy_id, agent_config_version=7)
        self.admin = self.session("admin")

    def versions(self):
        return {
            agent.slug: self.client_row(agent)["agent_config_version"]
            for agent in (self.agent, self.second, self.bystander)
        }

    def test_saving_a_policy_bumps_its_assigned_clients(self):
        response = self.admin.submit(f"/policies/{self.policy_id}", **self.FORM)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.versions(), {"alpha": 2, "charlie": 8, "bravo": 1})
        self.assertIsNotNone(self.client_row()["agent_config_updated_at"])
        self.assertIsNone(self.client_row(self.bystander)["agent_config_updated_at"])

    def test_adding_a_path_bumps_its_assigned_clients(self):
        response = self.admin.submit(
            f"/policies/{self.policy_id}/paths", source_path="/srv/data", target_name="data", mode="tar"
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.versions(), {"alpha": 2, "charlie": 8, "bravo": 1})
        path = self.row("SELECT * FROM policy_paths WHERE policy_id=?", self.policy_id)
        self.assertEqual((path["source_path"], path["target_name"], path["mode"]), ("/srv/data", "data", "tar"))

    def test_removing_a_path_bumps_its_assigned_clients(self):
        path_id = self.insert(
            "policy_paths", policy_id=self.policy_id, source_path="/srv", target_name="srv", mode="tar"
        )
        response = self.admin.submit(f"/policies/{self.policy_id}/paths/{path_id}/delete")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.versions(), {"alpha": 2, "charlie": 8, "bravo": 1})

    def test_a_refused_change_bumps_nothing(self):
        before = self.versions()
        cases = (
            (f"/policies/{self.policy_id}", {**self.FORM, "schedule_hour": 25}),
            (f"/policies/{self.policy_id}", {**self.FORM, "interval_hours": 5}),
            (f"/policies/{self.policy_id}", {**self.FORM, "name": "x"}),
            (f"/policies/{self.policy_id}/paths", {"source_path": "/", "target_name": "x", "mode": "tar"}),
            (f"/policies/{self.policy_id}/paths", {"source_path": "/srv/../etc", "target_name": "x", "mode": "tar"}),
            (f"/policies/{self.policy_id}/paths", {"source_path": "/srv", "target_name": "x", "mode": "snapshot"}),
        )
        for path, form in cases:
            with self.subTest(path, form=form):
                self.assertEqual(self.admin.submit(path, **form).status_code, 400)
        self.assertEqual(self.versions(), before)

    def test_removing_a_path_that_does_not_exist_bumps_nothing(self):
        # policy_path_delete commits the version bump before it answers 404, so
        # a double click on "remove" makes every agent rewrite its config.
        before = self.versions()
        self.assertEqual(self.admin.submit(f"/policies/{self.policy_id}/paths/999/delete").status_code, 404)
        self.assertEqual(self.versions(), before)

    def test_a_duplicate_path_is_refused(self):
        form = {"source_path": "/srv/data", "target_name": "data", "mode": "tar"}
        self.admin.submit(f"/policies/{self.policy_id}/paths", **form)
        before = self.versions()
        self.assertEqual(self.admin.submit(f"/policies/{self.policy_id}/paths", **form).status_code, 409)
        self.assertEqual(self.versions(), before)

    def test_an_unknown_policy_is_not_found(self):
        self.assertEqual(self.admin.submit("/policies/999", **self.FORM).status_code, 404)

    def test_the_next_poll_delivers_the_new_config_and_schedule(self):
        self.admin.submit(f"/policies/{self.policy_id}", **self.FORM)
        body = self.poll(config_version=1).json()
        self.assertEqual(body["config_update"]["version"], 2)
        self.assertEqual(body["schedule"]["hour"], 3)
        self.assertEqual(body["schedule"]["minute"], 15)
        self.assertEqual(body["schedule"]["interval_hours"], 12)
        config = core.tomllib.loads(base64.b64decode(body["config_update"]["content_b64"]).decode("utf-8"))
        self.assertEqual(config["schedule"], {"hour": 3, "minute": 15, "interval_hours": 12})


class MirrorScheduleTestCase(PortalTestCase):
    def retry(self, target_id):
        with closing(core.db()) as connection, connection:
            workers.schedule_mirror_retry(connection, target_id)

    def next_run_at(self, target_id):
        return self.row("SELECT next_run_at FROM mirror_targets WHERE id=?", target_id)["next_run_at"]

    def assert_pulled_forward(self, target_id):
        distance = datetime.fromisoformat(self.next_run_at(target_id)) - datetime.now(timezone.utc)
        self.assertLess(abs(distance - timedelta(hours=workers.MIRROR_RETRY_HOURS)), timedelta(minutes=1))


class ScheduleMirrorRetryTests(MirrorScheduleTestCase):
    def test_moves_a_distant_run_earlier(self):
        target_id = self.add_mirror_target(next_run_at=hours_ahead(216))
        self.retry(target_id)
        self.assert_pulled_forward(target_id)

    def test_never_moves_a_nearer_run_later(self):
        for hours in (workers.MIRROR_RETRY_HOURS - 1, 1, -1):
            with self.subTest(hours):
                next_run_at = hours_ahead(hours)
                target_id = self.add_mirror_target(f"box{hours}", next_run_at=next_run_at)
                self.retry(target_id)
                self.assertEqual(self.next_run_at(target_id), next_run_at)

    def test_leaves_a_target_alone_that_is_due_anyway(self):
        target_id = self.add_mirror_target(next_run_at=None)
        self.retry(target_id)
        self.assertIsNone(self.next_run_at(target_id))

    def test_touches_only_the_given_target(self):
        target_id = self.add_mirror_target("box1", next_run_at=hours_ahead(216))
        next_run_at = hours_ahead(216)
        other_id = self.add_mirror_target("box2", next_run_at=next_run_at)
        self.retry(target_id)
        self.assertEqual(self.next_run_at(other_id), next_run_at)


class FinishMirrorRunTests(MirrorScheduleTestCase):
    def finish(self, status, **columns):
        target_id = self.add_mirror_target(**columns)
        run_id = self.add_mirror_run(target_id, "running", started_at=hours_ago(1))
        workers.finish_mirror_run(run_id, target_id, status, exit_code=0, summary="Ergebnis", output="Ausgabe")
        return target_id, run_id

    def test_a_failure_pulls_the_next_run_forward(self):
        target_id, _run_id = self.finish("failure", next_run_at=hours_ahead(216))
        self.assert_pulled_forward(target_id)

    def test_a_failure_never_pushes_a_nearer_run_back(self):
        next_run_at = hours_ahead(1)
        target_id, _run_id = self.finish("failure", next_run_at=next_run_at)
        self.assertEqual(self.next_run_at(target_id), next_run_at)

    def test_a_success_leaves_the_next_run_alone(self):
        next_run_at = hours_ahead(216)
        target_id, _run_id = self.finish("success", next_run_at=next_run_at)
        self.assertEqual(self.next_run_at(target_id), next_run_at)

    def test_the_outcome_lands_on_the_run_and_the_target(self):
        target_id, run_id = self.finish("failure")
        run = self.row("SELECT * FROM mirror_runs WHERE id=?", run_id)
        self.assertEqual((run["status"], run["summary"], run["output"]), ("failure", "Ergebnis", "Ausgabe"))
        self.assertIsNotNone(run["finished_at"])
        target = self.row("SELECT * FROM mirror_targets WHERE id=?", target_id)
        self.assertEqual((target["last_status"], target["last_message"]), ("failure", "Ergebnis"))
        self.assertIsNotNone(target["last_run_at"])


class StartupTests(MirrorScheduleTestCase):
    def start_and_stop(self):
        app.startup()
        app.shutdown()

    def test_a_running_mirror_run_is_marked_interrupted(self):
        target_id = self.add_mirror_target(next_run_at=hours_ahead(216))
        run_id = self.add_mirror_run(target_id, "running", started_at=hours_ago(1))
        self.start_and_stop()
        run = self.row("SELECT * FROM mirror_runs WHERE id=?", run_id)
        self.assertEqual(run["status"], "interrupted")
        self.assertIsNotNone(run["finished_at"])
        self.assertEqual(run["summary"], "Portal wurde waehrend des Laufs beendet")

    def test_the_target_shows_the_interruption_and_retries_sooner(self):
        target_id = self.add_mirror_target(next_run_at=hours_ahead(216), last_status="success")
        self.add_mirror_run(target_id, "running", started_at=hours_ago(1))
        self.start_and_stop()
        target = self.row("SELECT * FROM mirror_targets WHERE id=?", target_id)
        self.assertEqual(target["last_status"], "interrupted")
        self.assertEqual(target["last_message"], "Portal wurde waehrend des Laufs beendet")
        self.assertIsNotNone(target["last_run_at"])
        self.assert_pulled_forward(target_id)

    def test_an_interrupted_target_never_moves_later(self):
        next_run_at = hours_ahead(1)
        target_id = self.add_mirror_target(next_run_at=next_run_at)
        self.add_mirror_run(target_id, "running", started_at=hours_ago(1))
        self.start_and_stop()
        self.assertEqual(self.next_run_at(target_id), next_run_at)

    def test_other_targets_and_runs_stay_as_they_are(self):
        next_run_at = hours_ahead(216)
        target_id = self.add_mirror_target(next_run_at=next_run_at, last_status="success")
        queued = self.add_mirror_run(target_id, "queued")
        finished = self.add_mirror_run(target_id, "success")
        self.start_and_stop()
        self.assertEqual(self.row("SELECT status FROM mirror_runs WHERE id=?", queued)["status"], "queued")
        self.assertEqual(self.row("SELECT status FROM mirror_runs WHERE id=?", finished)["status"], "success")
        target = self.row("SELECT * FROM mirror_targets WHERE id=?", target_id)
        self.assertEqual((target["last_status"], target["next_run_at"]), ("success", next_run_at))

    def test_startup_starts_the_workers_and_shutdown_ends_them(self):
        app.startup()
        threads = [app.SCHEDULER_THREAD, app.CHECKER_THREAD, app.MIRROR_THREAD, app.STORAGE_THREAD]
        self.assertEqual({thread.name for thread in threads}, WORKER_THREADS)
        app.shutdown()
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertFalse(WORKER_THREADS & {thread.name for thread in threading.enumerate()})

    def test_startup_leaves_the_credential_directory_to_the_harness(self):
        self.start_and_stop()
        self.discard_credentials.assert_called_once_with()


class CheckerMirrorStateTests(PortalTestCase):
    def test_the_states_are_wrapped_for_the_checker(self):
        self.assertEqual(workers.checker_mirror_states(), {"mirrors": []})

    def test_only_enabled_targets_are_reported(self):
        self.add_mirror_target("box1")
        self.add_mirror_target("box2", enabled=0)
        states = workers.checker_mirror_states()["mirrors"]
        self.assertEqual([state["name"] for state in states], ["box1"])

    def test_every_field_of_the_alarm_is_reported(self):
        self.add_mirror_target(last_status="failure", last_message="rsync endete mit Status 10", last_run_at="x")
        state = workers.checker_mirror_states()["mirrors"][0]
        self.assertEqual(
            state,
            {
                "name": "box1", "interval_hours": 216, "last_status": "failure",
                "last_message": "rsync endete mit Status 10", "last_run_at": "x", "last_success_at": None,
            },
        )

    def test_last_success_at_is_the_newest_finished_success(self):
        target_id = self.add_mirror_target()
        older, newer, failed = hours_ago(48), hours_ago(24), hours_ago(1)
        self.add_mirror_run(target_id, "success", finished_at=older)
        self.add_mirror_run(target_id, "success", finished_at=newer)
        self.add_mirror_run(target_id, "failure", finished_at=failed)
        self.assertEqual(workers.checker_mirror_states()["mirrors"][0]["last_success_at"], newer)

    def test_last_success_at_stays_with_its_own_target(self):
        first = self.add_mirror_target("box1")
        self.add_mirror_target("box2")
        self.add_mirror_run(first, "success", finished_at=hours_ago(1))
        states = {state["name"]: state for state in workers.checker_mirror_states()["mirrors"]}
        self.assertIsNotNone(states["box1"]["last_success_at"])
        self.assertIsNone(states["box2"]["last_success_at"])

    def test_the_checker_reads_what_the_portal_hands_over(self):
        now = datetime.now(timezone.utc)
        healthy = self.add_mirror_target("healthy", last_status="success", last_run_at=hours_ago(1))
        self.add_mirror_run(healthy, "success", finished_at=hours_ago(1))
        self.add_mirror_target("broken", last_status="failure", last_message="rsync endete mit Status 10")
        results = {
            result.user: result
            for result in backup_check.mirror_results(workers.checker_mirror_states()["mirrors"], now)
        }
        self.assertEqual(results["MIRROR_healthy"].status, "OK")
        self.assertEqual(results["MIRROR_broken"].status, "ERROR")
        self.assertIn("rsync endete mit Status 10", results["MIRROR_broken"].detail)


if __name__ == "__main__":
    unittest.main()
