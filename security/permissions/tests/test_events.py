"""Event delivery through PATH stubs for logger / systemd-cat."""

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _helpers import FakeClock  # noqa: E402

from elperm.events import Emitter, message_id  # noqa: E402
from elperm.util import Context  # noqa: E402


def _stub(dirpath: Path, name: str, out: Path, rc: int = 0):
    p = dirpath / name
    p.write_text(f'#!/bin/sh\necho "ARGS: $*" >> "{out}"\ncat >> "{out}"\nexit {rc}\n')
    p.chmod(p.stat().st_mode | stat.S_IXUSR)


class EmitterTests(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td, True)
        self.bin = self.td / "bin"
        self.bin.mkdir()
        self.out = self.td / "captured"
        self.path_env = str(self.bin)

    def ctx(self):
        return Context(root=self.td, now=FakeClock(),
                       which=lambda n: shutil.which(n, path=self.path_env))

    def test_logger_journald_fields(self):
        _stub(self.bin, "logger", self.out)
        em = Emitter(self.ctx())
        em("roles.granted", user="alice", role="local-admin", grant_id="ab12cd34",
           reason="multi\nline")
        cap = self.out.read_text()
        self.assertIn("ARGS: --journald", cap)
        self.assertIn(f"MESSAGE_ID={message_id('roles.granted')}", cap)
        self.assertIn("PRIORITY=5", cap)
        self.assertIn("EL_EVENT=roles.granted", cap)
        self.assertIn("EL_USER=alice", cap)
        self.assertIn("EL_REASON=multi line", cap)
        data = [l for l in cap.splitlines() if l.startswith("EL_DATA=")][0][8:]
        self.assertEqual(json.loads(data)["grant_id"], "ab12cd34")

    def test_systemd_cat_fallback(self):
        _stub(self.bin, "logger", self.out, rc=1)
        _stub(self.bin, "systemd-cat", self.out)
        Emitter(self.ctx())("breakglass.used", severity="crit", user="elbreakglass")
        cap = self.out.read_text()
        self.assertIn("ARGS: -t el-perm -p 2", cap)
        self.assertIn('"event": "breakglass.used"', cap)

    def test_stdout_json(self):
        import contextlib
        import io
        buf = io.StringIO()
        _stub(self.bin, "logger", self.out)
        with contextlib.redirect_stdout(buf):
            Emitter(self.ctx(), to_stdout=True)("roles.expired", user="alice")
        self.assertEqual(json.loads(buf.getvalue())["event"], "roles.expired")

    def test_message_ids_stable_and_distinct(self):
        self.assertEqual(message_id("roles.granted"), message_id("roles.granted"))
        self.assertNotEqual(message_id("roles.granted"), message_id("roles.revoked"))
        self.assertEqual(len(message_id("breakglass.used")), 32)


class ScriptSyntaxTests(unittest.TestCase):
    def test_shell_hooks_parse(self):
        import subprocess
        pam = Path(__file__).resolve().parent.parent / "pam"
        for f in ("el-jit-session-close", "el-breakglass-session-open"):
            subprocess.run(["bash", "-n", str(pam / f)], check=True)
            self.assertTrue(os.access(pam / f, os.X_OK), f)

    def test_bin_wrappers_executable_and_run(self):
        import subprocess
        binp = Path(__file__).resolve().parent.parent / "bin"
        for f in ("el-perm-render", "el-jit", "el-breakglass"):
            self.assertTrue(os.access(binp / f, os.X_OK), f)
            res = subprocess.run([sys.executable, "-I", str(binp / f), "--help"], capture_output=True)
            self.assertEqual(res.returncode, 0, res.stderr)


if __name__ == "__main__":
    unittest.main()
