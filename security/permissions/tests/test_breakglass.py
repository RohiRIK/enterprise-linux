import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _helpers import TempRootCase, quiet  # noqa: E402

from elperm.breakglass import BreakGlass, generate_password  # noqa: E402
from elperm.util import BREAKGLASS_STATE, ElPermError  # noqa: E402

ESCROW = ["/usr/libexec/el/escrow-breakglass"]


class BreakGlassTests(TempRootCase):
    def bg(self, **settings):
        return BreakGlass(self.ctx, {"escrowCommand": ESCROW, **settings})

    def test_password_generator(self):
        pw = generate_password(24)
        self.assertEqual(len(pw), 24)
        self.assertTrue(any(c.islower() for c in pw) and any(c.isupper() for c in pw))
        self.assertTrue(any(c.isdigit() for c in pw))
        self.assertNotIn(":", pw)
        self.assertNotEqual(pw, generate_password(24))

    def test_rotate_escrows_before_chpasswd_and_never_logs_password(self):
        res = self.bg().rotate()
        self.assertTrue(res["rotated"])
        progs = self.runner.programs()
        self.assertLess(progs.index("escrow-breakglass"), progs.index("chpasswd"))
        escrow_in = json.loads(self.runner.calls[progs.index("escrow-breakglass")][1])
        chpw_in = self.runner.calls[progs.index("chpasswd")][1].decode()
        self.assertEqual(chpw_in, f"elbreakglass:{escrow_in['password']}\n")
        chpw_argv = self.runner.calls[progs.index("chpasswd")][0]
        self.assertEqual(chpw_argv[:2], ["chpasswd", "-R"])  # test root, not the host
        for ev in self.events.sent:
            self.assertNotIn(escrow_in["password"], json.dumps(ev))
        state = (self.root / BREAKGLASS_STATE.lstrip("/")).read_text()
        self.assertNotIn(escrow_in["password"], state)
        self.assertEqual(self.mode(BREAKGLASS_STATE), 0o600)
        self.assertIn("breakglass.rotated", self.events.names())

    def test_escrow_failure_leaves_password_unchanged(self):
        self.runner.fail.add("escrow-breakglass")
        with self.assertRaisesRegex(ElPermError, "escrow hook failed"):
            self.bg().rotate()
        self.assertNotIn("chpasswd", self.runner.programs())
        self.assertIn("breakglass.rotation_failed", self.events.names())

    def test_chpasswd_failure_alerts(self):
        self.runner.fail.add("chpasswd")
        with self.assertRaises(ElPermError):
            self.bg().rotate()
        ev = [e for e in self.events.sent if e["event"] == "breakglass.rotation_failed"][0]
        self.assertEqual(ev["severity"], "alert")

    def test_refuses_without_escrow_or_reveal(self):
        with self.assertRaisesRegex(ElPermError, "would be lost"):
            BreakGlass(self.ctx, {"escrowCommand": None}).rotate()
        self.assertNotIn("chpasswd", self.runner.programs())

    def test_reveal_to_pipe(self):
        buf = io.StringIO()
        BreakGlass(self.ctx, {"escrowCommand": None}).rotate(reveal_stream=buf)
        pw = buf.getvalue().strip()
        self.assertEqual(len(pw), 24)
        self.assertEqual(self.runner.calls[-1][1].decode(), f"elbreakglass:{pw}\n")

    def test_cli_refuses_reveal_to_tty(self):
        from elperm.cli import breakglass_main

        class TTY(io.StringIO):
            def isatty(self):
                return True
        import contextlib
        old = sys.stdout
        sys.stdout = TTY()
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                rc = breakglass_main(["rotate", "--reveal-to-stdout-for-escrow-pipe"], self.ctx)
        finally:
            out = sys.stdout.getvalue()
            sys.stdout = old
        self.assertNotEqual(rc, 0)
        self.assertNotIn("chpasswd", self.runner.programs())
        self.assertEqual(out, "")

    def test_missing_account(self):
        with self.assertRaisesRegex(ElPermError, "does not exist"):
            self.bg(account="nosuch").rotate()

    def test_mark_used_schedules_rotation(self):
        bg = self.bg(rotateAfterUseMinutes=60)
        bg.rotate()
        self.assertFalse(bg.rotate(if_due=True)["rotated"])
        bg.mark_used(source="manual")
        ev = [e for e in self.events.sent if e["event"] == "breakglass.used"][0]
        self.assertEqual(ev["severity"], "crit")
        self.clock.advance(59 * 60)
        self.assertFalse(bg.rotate(if_due=True)["rotated"])
        self.clock.advance(60)
        res = bg.rotate(if_due=True)
        self.assertTrue(res["rotated"])
        self.assertEqual(res["generation"], 2)
        self.assertFalse(bg.status()["rotation_due"])

    def test_periodic_rotation(self):
        bg = self.bg(rotateEveryDays=30)
        bg.rotate()
        self.clock.advance(30 * 86400)
        self.assertTrue(bg.rotate(if_due=True)["rotated"])

    def test_pam_hook_only_for_breakglass_account(self):
        bg = self.bg()
        self.assertIsNone(bg.pam_hook({"PAM_USER": "alice", "PAM_TYPE": "open_session"}))
        self.assertNotIn("breakglass.used", self.events.names())
        bg.pam_hook({"PAM_USER": "elbreakglass", "PAM_TYPE": "open_session",
                     "PAM_SERVICE": "login", "PAM_TTY": "tty2"})
        ev = [e for e in self.events.sent if e["event"] == "breakglass.used"][0]
        self.assertEqual(ev["source"], "pam")
        self.assertEqual(ev["tty"], "tty2")

    def test_pam_hook_cli_never_fails(self):
        from elperm.cli import breakglass_main
        self.ctx.pam_env = {"PAM_USER": "elbreakglass", "PAM_TYPE": "open_session"}
        with quiet():
            self.assertEqual(breakglass_main(["pam-hook"], self.ctx), 0)
        self.assertIn("breakglass.used", self.events.names())

    def test_reads_rendered_settings(self):
        self.render()  # writes /etc/el/roles/breakglass.json from the example policy
        bg = BreakGlass(self.ctx)
        self.assertEqual(bg.account, "elbreakglass")
        self.assertEqual(bg.settings["escrowCommand"], ESCROW)


if __name__ == "__main__":
    unittest.main()
