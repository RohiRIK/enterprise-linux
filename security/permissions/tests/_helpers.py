"""Shared test fixtures: temp root, fake clock, stub command runner, fake NSS."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG_ROOT = HERE.parent
sys.path.insert(0, str(PKG_ROOT / "lib"))

from elperm.events import MemoryEmitter  # noqa: E402
from elperm.util import Context  # noqa: E402

EXAMPLE = PKG_ROOT / "policy" / "roles.example.json"
T0 = 1_793_000_000  # fixed "now" (2026-10-26) for deterministic tests


def example_policy() -> dict:
    return json.loads(EXAMPLE.read_text())


class FakeClock:
    def __init__(self, t: float = T0):
        self.t = float(t)

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float):
        self.t += seconds


class StubRunner:
    """Records every external command; behaviour configurable per program."""

    def __init__(self):
        self.calls: list[tuple[list[str], bytes | None]] = []
        self.fail: set[str] = set()
        self.sudo_version = b"Sudo version 1.9.15p5\n"

    def __call__(self, argv, input=None, env=None):
        argv = list(argv)
        self.calls.append((argv, input))
        prog = Path(argv[0]).name
        rc = 1 if prog in self.fail else 0
        out = b""
        if prog == "visudo" and rc == 0:
            # emulate visudo -cf: reject a file containing the marker SYNTAX-ERROR
            if b"SYNTAX-ERROR" in Path(argv[-1]).read_bytes():
                rc = 1
        if prog == "sudo":
            out = self.sudo_version
        return subprocess.CompletedProcess(argv, rc, out, b"stub failure" if rc else b"")

    def programs(self) -> list[str]:
        return [Path(a[0]).name for a, _ in self.calls]


class FakeNSS:
    def __init__(self, groups: dict[str, set[str]] | None = None):
        self.groups = groups or {}
        self.users = set(self.groups) | {"elbreakglass"}

    def groups_of(self, user):
        return set(self.groups.get(user, set()))

    def user_exists(self, user):
        return user in self.users or user in self.groups


class TempRootCase(unittest.TestCase):
    sudo_impl = "sudo"

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        self.clock = FakeClock()
        self.runner = StubRunner()
        self.nss = FakeNSS({
            "alice": {"all-employees"},
            "bob": {"all-employees", "helpdesk-t1"},
            "carol": {"all-employees", "it-linux-admins"},
            "dave": {"all-employees", "offboarding"},
            "erin": {"all-employees", "it-linux-admins-standby"},
        })
        self.events = MemoryEmitter()
        self.ctx = self.make_ctx()

    def tearDown(self):
        self._td.cleanup()

    def make_ctx(self, **kw) -> Context:
        which = kw.pop("which", lambda name: f"/usr/bin/{name}")
        return Context(root=self.root, now=self.clock, run=self.runner,
                       groups_of=self.nss.groups_of, user_exists=self.nss.user_exists,
                       which=which, emit=self.events, sudo_impl=self.sudo_impl, **kw)

    def write_policy(self, doc: dict | None = None, name: str = "policy.json") -> str:
        doc = doc if doc is not None else example_policy()
        path = self.root.parent / f"{self.root.name}-{name}"
        path.write_text(json.dumps(doc))
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return str(path)

    def read(self, abs_path: str) -> str:
        return (self.root / abs_path.lstrip("/")).read_text()

    def exists(self, abs_path: str) -> bool:
        return (self.root / abs_path.lstrip("/")).exists()

    def mode(self, abs_path: str) -> int:
        return (self.root / abs_path.lstrip("/")).stat().st_mode & 0o7777

    def render(self, *args, policy_doc=None, with_policy=True) -> int:
        from elperm.cli import render_main
        argv = list(args)
        if with_policy and "--policy" not in argv:
            argv = ["--policy", self.write_policy(policy_doc)] + argv
        with quiet():
            return render_main(argv, self.ctx)


@contextlib.contextmanager
def quiet():
    """Swallow CLI stdout/stderr in tests."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        yield


def deep(doc):
    return copy.deepcopy(doc)
