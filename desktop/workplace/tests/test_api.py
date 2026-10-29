"""Tests for the stdlib-only client layer. Must not import gi."""

import http.server
import json
import os
import socketserver
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from workplace import api  # noqa: E402
from workplace.locked import explain, is_locked, read_lock_files  # noqa: E402


class DemoClientTests(unittest.TestCase):
    def setUp(self):
        self.c = api.DemoClient()

    def test_is_demo_and_banner(self):
        self.assertTrue(self.c.is_demo)
        self.assertIn("eld", api.DEMO_BANNER_TEXT)

    def test_compliance_shape(self):
        comp = self.c.get_compliance()
        self.assertIn(comp["state"], ("green", "amber", "red"))
        for check in comp["checks"]:
            self.assertIn(check["status"], ("pass", "warn", "fail", "unknown"))
            if check["fix"]:
                api.validate_action(check["fix"]["action"])

    def test_every_fix_action_is_known(self):
        for check in self.c.get_compliance()["checks"]:
            if check["fix"]:
                self.c.run_action(check["fix"]["action"], check["fix"]["params"])

    def test_catalog_has_open_source_and_proprietary_office_and_browsers(self):
        apps = self.c.list_catalog()["apps"]
        kinds = {(a["category"], a["license_kind"]) for a in apps}
        for cat in ("browser", "office"):
            self.assertIn((cat, "open-source"), kinds)
            self.assertIn((cat, "proprietary"), kinds)

    def test_install_and_approval(self):
        self.c.install_app("com.google.Chrome")
        installed = {a["id"] for a in self.c.list_catalog()["apps"] if a["installed"]}
        self.assertIn("com.google.Chrome", installed)
        with self.assertRaises(api.ControlError):
            self.c.install_app("com.slack.Slack")
        res = self.c.request_app("com.slack.Slack", "Team uses it")
        self.assertEqual(res["status"], "pending-approval")

    def test_locked_default_app_cannot_change(self):
        with self.assertRaises(api.ControlError):
            self.c.set_default_app("mail", "org.mozilla.Thunderbird")
        self.c.set_default_app("browser", "com.microsoft.Edge")
        self.assertEqual(self.c.get_default_apps()["browser"]["current"], "com.microsoft.Edge")

    def test_elevation_validation(self):
        with self.assertRaises(ValueError):
            self.c.request_elevation("local-admin", "x", 30)
        with self.assertRaises(ValueError):
            self.c.request_elevation("local-admin", "install printer driver", 10_000)
        res = self.c.request_elevation("local-admin", "install printer driver", 30)
        self.assertEqual(res["status"], "pending-approval")
        self.assertEqual(len(self.c.list_grants()["requests"]), 1)

    def test_defer_is_bounded(self):
        left = self.c.get_updates()["deferral_hours_left"]
        with self.assertRaises(api.ControlError):
            self.c.defer_restart(left + 1)
        self.c.defer_restart(4)
        self.assertEqual(self.c.get_updates()["deferral_hours_left"], left - 4)

    def test_unknown_action_and_bad_names(self):
        with self.assertRaises(api.ControlError):
            self.c.run_action("nope.nothing")
        with self.assertRaises(ValueError):
            self.c.run_action("../etc")
        with self.assertRaises(ValueError):
            api.validate_provider("Bad Name")

    def test_facts_are_copies(self):
        self.c.get_facts("device")["name"] = "changed"
        self.assertNotEqual(self.c.get_facts("device")["name"], "changed")


class _Handler(http.server.BaseHTTPRequestHandler):
    calls = []

    def log_message(self, *args):
        pass

    def address_string(self):
        return "unix"

    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.calls.append(("GET", self.path, None))
        if self.path == "/v1/facts/updates":
            self._send(200, {"pending": [], "reboot_required": False})
        else:
            self._send(404, {"error": {"code": "not-found", "message": "unknown provider"}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        self.calls.append(("POST", self.path, body))
        if self.path == "/v1/actions/apps.install":
            self._send(200, {"status": "completed"})
        else:
            self._send(403, {"error": {"code": "forbidden", "message": "not allowed"}})


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class RestClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sock = os.path.join(self.tmp.name, "api.sock")
        _Handler.calls = []
        self.server = _UnixServer(self.sock, _Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.c = api.RestClient(self.sock, timeout=5)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def test_get_facts(self):
        self.assertEqual(self.c.get_updates()["reboot_required"], False)
        self.assertEqual(_Handler.calls[-1][:2], ("GET", "/v1/facts/updates"))

    def test_action_sends_params(self):
        self.c.install_app("org.mozilla.firefox")
        method, path, body = _Handler.calls[-1]
        self.assertEqual((method, path), ("POST", "/v1/actions/apps.install"))
        self.assertEqual(body.get("params", body).get("id"), "org.mozilla.firefox")

    def test_errors_are_control_errors(self):
        with self.assertRaises(api.ControlError) as ctx:
            self.c.get_facts("encryption")
        self.assertEqual(ctx.exception.status, 404)
        with self.assertRaises(api.ControlError) as ctx:
            self.c.restart_now()
        self.assertEqual(ctx.exception.status, 403)

    def test_missing_socket_is_unavailable(self):
        c = api.RestClient(os.path.join(self.tmp.name, "missing.sock"), timeout=1)
        with self.assertRaises(api.ControlUnavailable):
            c.get_facts("device")


class SelectClientTests(unittest.TestCase):
    def test_selection_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            sock = os.path.join(tmp, "api.sock")
            client, reason = api.select_client(demo=True, socket_path=sock, environ={})
            self.assertTrue(client.is_demo)
            client, _ = api.select_client(socket_path=sock, environ={"WORKPLACE_DEMO": "1"})
            self.assertTrue(client.is_demo)
            client, reason = api.select_client(socket_path=sock, environ={})
            self.assertTrue(client.is_demo)
            self.assertIn("No socket", reason)
            open(sock, "w").close()
            client, reason = api.select_client(socket_path=sock, environ={})
            self.assertFalse(client.is_demo)
            self.assertIsNone(reason)


class LockedTests(unittest.TestCase):
    def test_explain(self):
        keys = ["/org/gnome/desktop/session/idle-delay", "/org/gnome/system/proxy/"]
        self.assertTrue(is_locked("/org/gnome/system/proxy/mode", keys))
        self.assertFalse(is_locked("/org/gnome/desktop/interface/color-scheme", keys))
        locked, title, reason = explain("/org/gnome/desktop/session/idle-delay", keys)
        self.assertTrue(locked)
        self.assertEqual(title, "Managed by your organization")
        self.assertIn("lock", reason)
        self.assertFalse(explain("/org/gnome/desktop/interface/color-scheme", keys)[0])

    def test_read_lock_files_matches_repo_dconf(self):
        db = os.path.join(os.path.dirname(__file__), "..", "..", "dconf", "db")
        keys = read_lock_files(db)
        self.assertIn("/org/gnome/desktop/session/idle-delay", keys)
        self.assertIn("/org/gnome/login-screen/banner-message-text", keys)

    def test_demo_locked_keys_exist_in_repo_dconf(self):
        db = os.path.join(os.path.dirname(__file__), "..", "..", "dconf", "db")
        repo = read_lock_files(db)
        for key in api.DemoClient().get_locked_keys():
            self.assertTrue(is_locked(key, repo), key)


if __name__ == "__main__":
    unittest.main()
