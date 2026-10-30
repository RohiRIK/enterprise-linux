import json
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _helpers import TempRootCase, example_policy  # noqa: E402

from elperm.util import (ACCESS_CONF, BREAKGLASS_CONF, GROUPMAP, MANIFEST, POLKIT_ROLES,  # noqa: E402
                         SUDOERS_ROLES, sha256_bytes)


class RenderTests(TempRootCase):
    def test_renders_all_files_with_modes(self):
        self.assertEqual(self.render(), 0)
        self.assertEqual(self.mode(SUDOERS_ROLES), 0o440)
        for f in (POLKIT_ROLES, ACCESS_CONF, GROUPMAP, BREAKGLASS_CONF, MANIFEST):
            self.assertEqual(self.mode(f), 0o644, f)
        self.assertIn("roles.rendered", self.events.names())

    def test_sudoers_content(self):
        self.render()
        s = self.read(SUDOERS_ROLES)
        self.assertIn("Defaults use_pty", s)
        self.assertIn('Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"', s)
        self.assertIn('Defaults logfile="/var/log/sudo.log"', s)
        self.assertNotIn("NOPASSWD", s)
        self.assertNotIn("log_output", s)  # recording off in the example
        self.assertIn("%it-linux-admins, !%offboarding ALL=(ALL:ALL) ALL", s)
        self.assertIn("%helpdesk-t1, !%offboarding ALL=(root) /usr/libexec/el/collect-logs, "
                      "/usr/bin/systemctl restart NetworkManager.service", s)
        self.assertIn("elbreakglass ALL=(ALL:ALL) ALL", s)
        self.assertNotIn("engineering", s)  # power-user disabled
        # visudo was asked to validate the temp file before rename
        self.assertIn("visudo", self.runner.programs())

    def test_session_recording_sudo_vs_sudo_rs(self):
        doc = example_policy()
        doc["spec"]["sessionRecording"]["enabled"] = True
        self.render(policy_doc=doc)
        s = self.read(SUDOERS_ROLES)
        self.assertIn("Defaults log_output", s)
        self.assertIn("Defaults iolog_dir=/var/log/sudo-io/%{user}", s)
        self.ctx.sudo_impl = "sudo-rs"
        self.render(policy_doc=doc)
        s = self.read(SUDOERS_ROLES)
        self.assertNotIn("log_output", s)
        self.assertNotIn("logfile", s)
        self.assertIn("tlog", s)
        self.assertIn("Defaults use_pty", s)

    def test_sudo_impl_autodetect(self):
        self.ctx.sudo_impl = None
        self.runner.sudo_version = b"sudo-rs 0.2.5\n"
        self.render()
        self.assertIn("sudo implementation: sudo-rs", self.read(SUDOERS_ROLES))

    def test_nopasswd_only_with_opt_in(self):
        doc = example_policy()
        doc["spec"]["sudo"]["allowNopasswd"] = True
        doc["spec"]["roles"]["helpdesk"]["sudo"]["nopasswd"] = True
        self.render(policy_doc=doc)
        self.assertIn("(root) NOPASSWD: /usr/libexec/el/collect-logs", self.read(SUDOERS_ROLES))

    def test_polkit_rules(self):
        self.render()
        js = self.read(POLKIT_ROLES)
        self.assertIn('return ["unix-user:elbreakglass", "unix-group:it-linux-admins"];', js)
        self.assertIn('var DENY_GROUPS = ["offboarding"];', js)
        self.assertIn('if (inAny(subject, ["it-linux-admins"])) {\n            return polkit.Result.AUTH_ADMIN_KEEP;', js)
        self.assertIn('["NetworkManager.service", "cups.service"].indexOf(action.lookup("unit")) >= 0', js)
        self.assertIn('action.id.indexOf("org.freedesktop.packagekit.") == 0) { return polkit.Result.NO; }', js)
        # deny check precedes every role block
        self.assertLess(js.index("inAny(subject, DENY_GROUPS)"), js.index("role local-admin"))
        # higher priority roles first
        self.assertLess(js.index("role local-admin"), js.index("role helpdesk"))
        self.assertLess(js.index("role helpdesk"), js.index("role user"))
        if shutil.which("node"):
            js_copy = self.root / "rules-check.js"
            js_copy.write_text(js)
            subprocess.run(["node", "--check", str(js_copy)], check=True)

    def test_access_conf_deny_before_allow(self):
        self.render()
        lines = [l for l in self.read(ACCESS_CONF).splitlines() if l and not l.startswith("#")]
        self.assertEqual(lines, ["+:root elbreakglass:LOCAL", "-:(offboarding):ALL",
                                 "+:(all-employees):ALL", "-:ALL:ALL"])

    def test_groupmap(self):
        self.render()
        gm = json.loads(self.read(GROUPMAP))
        m = {g["directory"]: g["posix"] for g in gm["groups"]}
        self.assertEqual(m["entra:group:IT-Linux-Admins"], "it-linux-admins")
        self.assertEqual(m["entra:group:All-Employees"], "all-employees")
        self.assertIn("SSSD", gm["explanation"])

    def test_manifest_hashes(self):
        self.render()
        man = json.loads(self.read(MANIFEST))
        self.assertEqual(man["mode"], "normal")
        for path, meta in man["files"].items():
            self.assertEqual(meta["sha256"], sha256_bytes((self.root / path.lstrip("/")).read_bytes()))

    def test_idempotent(self):
        self.render()
        first = self.read(SUDOERS_ROLES) + self.read(POLKIT_ROLES)
        self.clock.advance(3600)
        self.render()
        self.assertEqual(first, self.read(SUDOERS_ROLES) + self.read(POLKIT_ROLES))

    def test_visudo_failure_aborts_and_keeps_old_file(self):
        self.render()
        before = self.read(SUDOERS_ROLES)
        self.runner.fail.add("visudo")
        doc = example_policy()
        doc["metadata"]["version"] = "2026.10.1"
        self.assertNotEqual(self.render(policy_doc=doc), 0)
        self.assertEqual(self.read(SUDOERS_ROLES), before)
        leftovers = [p.name for p in (self.root / "etc/sudoers.d").iterdir() if p.name.startswith(".")]
        self.assertEqual(leftovers, [])

    def test_missing_visudo_warns_or_fails_strict(self):
        self.ctx.which = lambda n: None if n == "visudo" else f"/usr/bin/{n}"
        self.assertEqual(self.render(), 0)
        self.ctx.strict_visudo = True
        self.assertNotEqual(self.render(), 0)

    @unittest.skipUnless(shutil.which("visudo"), "visudo not installed")
    def test_real_visudo_accepts_output(self):
        from elperm.policy import validate_policy
        from elperm.render import render_sudoers
        p = validate_policy(example_policy())
        for impl in ("sudo", "sudo-rs"):
            for mode in ("normal", "degraded"):
                f = self.root / f"s-{impl}-{mode}"
                f.write_text(render_sudoers(p, mode, impl))
                res = subprocess.run(["visudo", "-cf", str(f)], capture_output=True)
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


class DriftTests(TempRootCase):
    def test_check_clean_after_render(self):
        self.render()
        self.assertEqual(self.render("--check", with_policy=False), 0)

    def test_check_detects_manual_edit(self):
        self.render()
        p = self.root / SUDOERS_ROLES.lstrip("/")
        os.chmod(p, 0o640)
        p.write_text(p.read_text() + "alice ALL=(ALL) NOPASSWD: ALL\n")
        os.chmod(p, 0o440)
        from elperm.cli import render_main
        from _helpers import quiet
        with quiet():
            self.assertEqual(render_main(["--check", "--json"], self.ctx), 2)
        drift = [e for e in self.events.sent if e["event"] == "roles.drift"][-1]
        self.assertEqual(drift["modified"], [SUDOERS_ROLES])
        self.assertEqual(drift["stale"], [SUDOERS_ROLES])

    def test_check_reports_mode_change_and_missing(self):
        self.render()
        os.chmod(self.root / POLKIT_ROLES.lstrip("/"), 0o666)
        (self.root / ACCESS_CONF.lstrip("/")).unlink()
        self.assertEqual(self.render("--check", with_policy=False), 2)
        drift = [e for e in self.events.sent if e["event"] == "roles.drift"][-1]
        self.assertEqual(drift["badmode"], [POLKIT_ROLES])
        self.assertEqual(drift["missing"], [ACCESS_CONF])

    def test_check_flags_unmanaged_sudoers_dropin(self):
        self.render()
        (self.root / "etc/sudoers.d/99-local-hack").write_text("alice ALL=(ALL) ALL\n")
        self.assertEqual(self.render("--check", with_policy=False), 2)

    def test_check_with_new_policy_reports_stale_without_writing(self):
        self.render()
        before = self.read(SUDOERS_ROLES)
        doc = example_policy()
        doc["spec"]["roles"]["local-admin"]["groups"].append("entra:group:Linux-Admins-2")
        self.assertEqual(self.render("--check", policy_doc=doc), 2)
        self.assertEqual(self.read(SUDOERS_ROLES), before)

    def test_check_warns_about_standing_admin_in_main_sudoers(self):
        self.render()
        (self.root / "etc/sudoers").write_text("root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n")
        from elperm.cli import render_main
        from elperm.policy import validate_policy
        from elperm.render import check
        rep = check(self.ctx, validate_policy(example_policy()), "normal")
        self.assertTrue(any("%sudo" in w for w in rep["warnings"]))
        from _helpers import quiet
        with quiet():
            self.assertEqual(render_main(["--check"], self.ctx), 0)


if __name__ == "__main__":
    unittest.main()
