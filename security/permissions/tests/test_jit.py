import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _helpers import TempRootCase, example_policy, quiet  # noqa: E402

from elperm.cache import write_device_cache  # noqa: E402
from elperm.jit import Jit, JitDenied  # noqa: E402
from elperm.util import GRANTS, POLKIT_JIT  # noqa: E402

MIN = 60


class JitBase(TempRootCase):
    approver_mode = "helpdesk"

    def setUp(self):
        super().setUp()
        doc = example_policy()
        doc["spec"]["jit"]["approver"]["mode"] = self.approver_mode
        self.policy_doc = doc
        write_device_cache(self.ctx, doc, 7)
        self.jit = Jit(self.ctx)

    def dropins(self):
        d = self.root / "etc/sudoers.d"
        return sorted(p.name for p in d.iterdir() if p.name.startswith("60-el-jit-")) if d.exists() else []

    def grants(self):
        return json.loads(self.read(GRANTS))["grants"]


class GrantExpireTests(JitBase):
    def test_full_grant_writes_dropin_polkit_and_record(self):
        res = self.jit.grant("alice", 30 * MIN, "install printer driver")
        self.assertEqual(self.dropins(), ["60-el-jit-alice"])
        s = self.read("/etc/sudoers.d/60-el-jit-alice")
        self.assertIn("alice, !%offboarding ALL=(ALL:ALL) NOTAFTER=", s)
        self.assertTrue(s.rstrip().endswith(" ALL"))
        self.assertNotIn("NOPASSWD", s)
        self.assertEqual(self.mode("/etc/sudoers.d/60-el-jit-alice"), 0o440)
        self.assertEqual(self.mode(GRANTS), 0o600)
        js = self.read(POLKIT_JIT)
        self.assertIn(f'"alice": {(self.clock.t + 1800) * 1000:.0f}', js)
        self.assertIn("hasOwnProperty", js)
        g = self.grants()[0]
        self.assertEqual(g["expires_at"], int(self.clock.t) + 1800)
        self.assertEqual(res["status"], "granted")
        ev = [e for e in self.events.sent if e["event"] == "roles.granted"][0]
        self.assertEqual(ev["user"], "alice")
        self.assertEqual(ev["role"], "local-admin")

    def test_sudo_rs_has_no_notafter(self):
        self.ctx.sudo_impl = "sudo-rs"
        self.jit.grant("alice", 10 * MIN, "x")
        self.assertNotIn("NOTAFTER", self.read("/etc/sudoers.d/60-el-jit-alice"))

    def test_directory_user_name_file_token(self):
        self.nss.groups["alice@corp.example"] = {"all-employees"}
        self.jit.grant("alice@corp.example", 10 * MIN, "x")
        [name] = self.dropins()
        self.assertNotIn(".", name)
        self.assertIn("alice@corp.example, !%offboarding", self.read(f"/etc/sudoers.d/{name}"))

    def test_max_duration_enforced(self):
        with self.assertRaisesRegex(JitDenied, "exceeds jit.maxDuration"):
            self.jit.grant("alice", 61 * MIN, "x")
        with self.assertRaises(JitDenied):
            self.jit.request("alice", "x", 2 * 3600)
        self.assertEqual(self.dropins(), [])

    def test_default_duration(self):
        self.jit.grant("alice", None, "x")
        self.assertEqual(self.grants()[0]["expires_at"] - self.grants()[0]["granted_at"], 30 * MIN)

    def test_deny_overrides_allow(self):
        self.nss.groups["dave"].add("it-linux-admins-standby")
        with self.assertRaisesRegex(JitDenied, "deny overrides allow"):
            self.jit.grant("dave", 10 * MIN, "x")
        self.assertIn("roles.denied", self.events.names())
        self.assertEqual(self.dropins(), [])

    def test_unknown_user_refused(self):
        with self.assertRaisesRegex(JitDenied, "does not resolve"):
            self.jit.grant("mallory", 10 * MIN, "x")

    def test_reason_required(self):
        with self.assertRaisesRegex(JitDenied, "reason"):
            self.jit.grant("alice", 10 * MIN, "  ")

    def test_breakglass_account_not_grantable(self):
        with self.assertRaises(JitDenied):
            self.jit.grant("elbreakglass", 10 * MIN, "x")

    def test_unsafe_username_rejected(self):
        with self.assertRaises(Exception):
            self.jit.grant("alice ALL=(ALL) NOPASSWD: ALL #", 10 * MIN, "x")

    def test_expire_with_fake_clock(self):
        self.jit.grant("alice", 10 * MIN, "a")
        self.jit.grant("carol", 40 * MIN, "c")
        self.clock.advance(10 * MIN - 1)
        self.assertEqual(self.jit.expire()["expired"], [])
        self.clock.advance(1)
        res = self.jit.expire()
        self.assertEqual(len(res["expired"]), 1)
        self.assertEqual(self.dropins(), ["60-el-jit-carol"])
        self.assertNotIn('"alice"', self.read(POLKIT_JIT))
        self.clock.advance(30 * MIN)
        self.jit.expire()
        self.assertEqual(self.dropins(), [])
        self.assertFalse(self.exists(POLKIT_JIT))
        self.assertEqual(self.events.names().count("roles.expired"), 2)

    def test_logout_revokes(self):
        self.jit.grant("alice", 30 * MIN, "a")
        self.jit.expire(user="alice", logout=True)
        self.assertEqual(self.dropins(), [])
        ev = [e for e in self.events.sent if e["event"] == "roles.expired"][0]
        self.assertEqual(ev["reason"], "logout")

    def test_revoke(self):
        self.jit.grant("alice", 30 * MIN, "a")
        self.jit.grant("alice", 30 * MIN, "b", commands=["/usr/bin/apt-get install ./foo_1.0.deb"])
        self.assertEqual(len(self.dropins()), 2)
        self.assertEqual(len(self.jit.revoke("alice", by="carol")["revoked"]), 2)
        self.assertEqual(self.dropins(), [])
        self.assertEqual(self.events.names().count("roles.revoked"), 2)

    def test_regrant_replaces_full_grant(self):
        self.jit.grant("alice", 10 * MIN, "a")
        self.jit.grant("alice", 20 * MIN, "b")
        self.assertEqual(len(self.grants()), 1)

    def test_expired_cache_blocks_and_revokes(self):
        self.jit.grant("alice", 60 * MIN, "a")
        self.clock.advance(7 * 86400)
        jit = Jit(self.ctx)
        with self.assertRaisesRegex(JitDenied, "cache is expired"):
            jit.grant("carol", 10 * MIN, "x")
        res = jit.expire()
        self.assertEqual(len(res["expired"]), 1)
        self.assertEqual(self.dropins(), [])

    def test_visudo_rejection_leaves_no_grant(self):
        self.runner.fail.add("visudo")
        with self.assertRaises(Exception):
            self.jit.grant("alice", 10 * MIN, "x")
        self.assertEqual(self.dropins(), [])
        self.assertFalse(self.exists(GRANTS) and self.grants())


class CommandScopedTests(JitBase):
    def test_allowlisted_command(self):
        self.jit.grant("alice", 10 * MIN, "install", commands=["/usr/bin/apt-get  install ./foo_1.0.deb"])
        [name] = self.dropins()
        self.assertRegex(name, r"^60-el-jit-alice-cmd-[0-9a-f]{8}$")
        s = self.read(f"/etc/sudoers.d/{name}")
        self.assertIn("ALL=(ALL:ALL) NOTAFTER=", s)
        self.assertTrue(s.rstrip().endswith("/usr/bin/apt-get install ./foo_1.0.deb"))
        self.assertFalse(self.exists(POLKIT_JIT))  # command grants never get polkit admin

    def test_not_allowlisted(self):
        with self.assertRaisesRegex(JitDenied, "not in jit.commandAllowlist"):
            self.jit.grant("alice", 10 * MIN, "x", commands=["/usr/bin/bash"])

    def test_wildcards_and_specials_rejected(self):
        for cmd in ["/usr/bin/apt-get install ./*.deb", "/usr/bin/systemctl restart a.service, /bin/sh",
                    "/usr/bin/apt-get install ./x.deb\n/bin/sh"]:
            with self.assertRaises(JitDenied, msg=cmd):
                self.jit.grant("alice", 10 * MIN, "x", commands=[cmd])


class HelpdeskApprovalTests(JitBase):
    approver_mode = "helpdesk"

    def test_request_pending_then_approved_by_helpdesk(self):
        res = self.jit.request("alice", "need docker", 20 * MIN)
        self.assertEqual(res["status"], "pending")
        self.assertEqual(self.dropins(), [])
        rid = res["request"]["id"]
        out = self.jit.approve(rid, "bob")
        self.assertEqual(out["grant"]["approver"], "bob")
        self.assertEqual(self.dropins(), ["60-el-jit-alice"])
        self.assertEqual(self.jit.list()["requests"], [])

    def test_non_approver_cannot_approve(self):
        rid = self.jit.request("alice", "x", 10 * MIN)["request"]["id"]
        with self.assertRaisesRegex(JitDenied, "not in an approver role"):
            self.jit.approve(rid, "erin")

    def test_self_approval_refused(self):
        rid = self.jit.request("bob", "x", 10 * MIN)["request"]["id"]
        with self.assertRaisesRegex(JitDenied, "self-approval"):
            self.jit.approve(rid, "bob")

    def test_deny_request(self):
        rid = self.jit.request("alice", "x", 10 * MIN)["request"]["id"]
        self.jit.deny(rid, "bob")
        self.assertEqual(self.dropins(), [])
        with self.assertRaises(Exception):
            self.jit.approve(rid, "bob")


class AutoApprovalTests(JitBase):
    approver_mode = "auto"

    def test_auto_group_granted_immediately(self):
        res = self.jit.request("erin", "on call", 15 * MIN)
        self.assertEqual(res["status"], "granted")
        self.assertEqual(res["grant"]["approver"], "auto")

    def test_others_fall_back_to_pending(self):
        self.assertEqual(self.jit.request("alice", "x", 15 * MIN)["status"], "pending")


class TicketApprovalTests(JitBase):
    approver_mode = "ticket"

    def test_ticket_required_and_pattern(self):
        with self.assertRaises(JitDenied):
            self.jit.request("alice", "x", 10 * MIN)
        with self.assertRaises(JitDenied):
            self.jit.request("alice", "x", 10 * MIN, ticket="INC12; rm")
        res = self.jit.request("alice", "x", 10 * MIN, ticket="INC123456")
        self.assertEqual(res["grant"]["approver"], "ticket:INC123456")

    def test_ticket_verifier_hook(self):
        doc = example_policy()
        doc["spec"]["jit"]["approver"].update(mode="ticket", ticketVerifyCommand=["/usr/libexec/el/verify-ticket"])
        write_device_cache(self.ctx, doc, 7)
        jit = Jit(self.ctx)
        self.runner.fail.add("verify-ticket")
        with self.assertRaisesRegex(JitDenied, "rejected"):
            jit.request("alice", "x", 10 * MIN, ticket="INC123456")
        self.runner.fail.clear()
        jit.request("alice", "x", 10 * MIN, ticket="INC123456")
        self.assertIn(["/usr/libexec/el/verify-ticket", "INC123456", "alice"],
                      [a for a, _ in self.runner.calls])


class JitCliTests(JitBase):
    def test_cli_grant_list_revoke_json(self):
        from elperm.cli import jit_main
        self.ctx.caller = "carol"
        with quiet():
            self.assertEqual(jit_main(["grant", "alice", "--for", "30m", "--reason", "x"], self.ctx), 0)
            self.assertEqual(jit_main(["grant", "alice", "--for", "2h", "--reason", "x"], self.ctx), 5)
            self.assertEqual(jit_main(["list", "--json"], self.ctx), 0)
            self.assertEqual(jit_main(["revoke", "alice"], self.ctx), 0)
        self.assertEqual(self.dropins(), [])

    def test_cli_request_cannot_impersonate(self):
        from elperm.cli import jit_main
        self.ctx.caller = "alice"
        with quiet():
            self.assertNotEqual(jit_main(["request", "--user", "bob", "--reason", "x"], self.ctx), 0)
            self.assertEqual(jit_main(["request", "--reason", "x", "--for", "10m"], self.ctx), 0)
        self.assertEqual(len(self.jit.list()["requests"]), 1)


if __name__ == "__main__":
    unittest.main()
