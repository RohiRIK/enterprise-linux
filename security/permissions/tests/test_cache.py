import json
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _helpers import TempRootCase, example_policy, quiet  # noqa: E402

from elperm.cache import load_cache, make_bundle, write_device_cache  # noqa: E402
from elperm.util import CACHE, CACHE_KEY, MANIFEST, POLKIT_ROLES, SUDOERS_ROLES, Context  # noqa: E402

DAY = 86400


class HmacCacheTests(TempRootCase):
    def test_roundtrip_and_key_mode(self):
        write_device_cache(self.ctx, example_policy(), 7)
        st = load_cache(self.ctx)
        self.assertEqual(st.state, "valid")
        self.assertEqual(self.mode(CACHE_KEY), 0o600)
        self.assertEqual(self.mode(CACHE), 0o600)

    def test_tamper_detected(self):
        write_device_cache(self.ctx, example_policy(), 7)
        p = self.root / CACHE.lstrip("/")
        doc = json.loads(p.read_text())
        doc["policy"]["spec"]["roles"]["local-admin"]["groups"] = ["entra:group:Everyone"]
        p.write_text(json.dumps(doc))
        self.assertEqual(load_cache(self.ctx).state, "invalid")

    def test_extending_expiry_breaks_signature(self):
        write_device_cache(self.ctx, example_policy(), 7)
        p = self.root / CACHE.lstrip("/")
        doc = json.loads(p.read_text())
        doc["expires_at"] += 365 * DAY
        p.write_text(json.dumps(doc))
        self.assertEqual(load_cache(self.ctx).state, "invalid")

    def test_wrong_key_invalid(self):
        write_device_cache(self.ctx, example_policy(), 7)
        (self.root / CACHE_KEY.lstrip("/")).write_bytes(os.urandom(32))
        self.assertEqual(load_cache(self.ctx).state, "invalid")

    def test_expiry_and_clock_rollback(self):
        write_device_cache(self.ctx, example_policy(), 7)
        self.clock.advance(7 * DAY - 1)
        self.assertEqual(load_cache(self.ctx).state, "valid")
        self.clock.advance(1)
        self.assertEqual(load_cache(self.ctx).state, "expired")
        self.clock.t -= 30 * DAY
        self.assertEqual(load_cache(self.ctx).state, "invalid")

    def test_missing(self):
        self.assertEqual(load_cache(self.ctx).state, "missing")


class OfflineRenderTests(TempRootCase):
    def test_expired_cache_drops_elevated_roles(self):
        self.render()
        self.clock.advance(8 * DAY)
        self.assertEqual(self.render(with_policy=False), 0)
        s = self.read(SUDOERS_ROLES)
        self.assertNotIn("it-linux-admins", s)
        self.assertNotIn("helpdesk-t1", s)
        self.assertIn("elbreakglass ALL=(ALL:ALL) ALL", s)
        self.assertIn("degraded", s)
        js = self.read(POLKIT_ROLES)
        self.assertIn('return ["unix-user:elbreakglass"];', js)
        self.assertNotIn("helpdesk-t1", js)
        self.assertIn("role user", js)  # user rules (non-elevated) stay
        self.assertEqual(json.loads(self.read(MANIFEST))["mode"], "degraded")
        self.assertIn("roles.degraded", self.events.names())
        # login rules are kept
        self.assertIn("+:(all-employees):ALL", self.read("/etc/security/el-access.conf"))
        # drift check in degraded mode is clean
        self.assertEqual(self.render("--check", with_policy=False), 0)

    def test_fresh_sync_restores_roles(self):
        self.render()
        self.clock.advance(8 * DAY)
        self.render(with_policy=False)
        self.render()  # MDM sync again
        self.assertIn("%it-linux-admins", self.read(SUDOERS_ROLES))

    def test_invalid_cache_writes_nothing(self):
        self.render()
        before = self.read(SUDOERS_ROLES)
        (self.root / CACHE_KEY.lstrip("/")).write_bytes(os.urandom(32))
        self.assertEqual(self.render(with_policy=False), 3)
        self.assertEqual(self.read(SUDOERS_ROLES), before)
        self.assertIn("roles.cache_invalid", self.events.names())

    def test_missing_cache_errors(self):
        self.assertNotEqual(self.render(with_policy=False), 0)
        self.assertFalse(self.exists(SUDOERS_ROLES))

    def test_grace_days_from_policy(self):
        doc = example_policy()
        doc["spec"]["offline"]["graceDays"] = 1
        self.render(policy_doc=doc)
        self.clock.advance(DAY + 1)
        self.render(with_policy=False)
        self.assertNotIn("it-linux-admins", self.read(SUDOERS_ROLES))


def _openssl_ed25519_ok() -> bool:
    if not shutil.which("openssl"):
        return False
    res = subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519"], capture_output=True)
    return res.returncode == 0


@unittest.skipUnless(_openssl_ed25519_ok(), "openssl with ed25519 not available")
class Ed25519BundleTests(TempRootCase):
    def setUp(self):
        super().setUp()
        # real openssl for these tests, stub for everything else
        stub = self.runner

        def run(argv, input=None, env=None):
            if argv[0] == "openssl":
                return subprocess.run(argv, input=input, capture_output=True)
            return stub(argv, input, env)
        self.ctx.run = run
        self.ctx.which = shutil.which
        self.ctx.sudo_impl = "sudo"
        keys = self.root.parent / f"{self.root.name}-keys"
        keys.mkdir()
        self.addCleanup(shutil.rmtree, keys, True)
        self.priv, self.pub = keys / "mdm.key", keys / "mdm.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(self.priv)], check=True)
        subprocess.run(["openssl", "pkey", "-in", str(self.priv), "-pubout", "-out", str(self.pub)], check=True)
        dst = self.root / "etc/el/roles/mdm-signing.pub"
        dst.parent.mkdir(parents=True)
        shutil.copy(self.pub, dst)

    def _bundle(self, doc=None) -> str:
        doc = doc or example_policy()
        doc["spec"]["offline"]["signing"] = "ed25519"
        b = make_bundle(self.ctx, doc, str(self.priv), 7)
        path = self.root.parent / f"{self.root.name}-bundle.json"
        path.write_text(json.dumps(b))
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return str(path)

    def test_signed_bundle_renders(self):
        from elperm.cli import render_main
        with quiet():
            self.assertEqual(render_main(["--bundle", self._bundle()], self.ctx), 0)
        self.assertEqual(load_cache(self.ctx).state, "valid")
        self.assertIn("%it-linux-admins", self.read(SUDOERS_ROLES))

    def test_forged_bundle_rejected(self):
        from elperm.cli import render_main
        path = self._bundle()
        with open(path) as fh:
            doc = json.load(fh)
        doc["policy"]["spec"]["roles"]["local-admin"]["groups"] = ["entra:group:Attacker"]
        from elperm.util import canonical_json, sha256_bytes
        doc["policy_sha256"] = sha256_bytes(canonical_json(doc["policy"]))
        with open(path, "w") as fh:
            fh.write(json.dumps(doc))
        with quiet():
            self.assertEqual(render_main(["--bundle", path], self.ctx), 3)
        self.assertFalse(self.exists(SUDOERS_ROLES))

    def test_plain_policy_refused_in_ed25519_mode(self):
        doc = example_policy()
        doc["spec"]["offline"]["signing"] = "ed25519"
        self.assertNotEqual(self.render(policy_doc=doc), 0)


if __name__ == "__main__":
    unittest.main()
