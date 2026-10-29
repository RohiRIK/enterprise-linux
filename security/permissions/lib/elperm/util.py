"""Shared helpers: runtime context, paths, durations, atomic writes."""

from __future__ import annotations

import dataclasses
import datetime as _dt
import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence


class ElPermError(Exception):
    """Expected, user-facing failure. CLI prints the message and exits non-zero."""

    exit_code = 1


class PolicyError(ElPermError):
    exit_code = 4


class CacheError(ElPermError):
    exit_code = 3


# --------------------------------------------------------------------------
# Durations
# --------------------------------------------------------------------------

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "": 60}


def parse_duration(text: str | int) -> int:
    """Parse '30m', '2h', '1d', '90s' or a bare number (minutes) into seconds."""
    if isinstance(text, int):
        if text <= 0:
            raise ElPermError(f"duration must be positive: {text}")
        return text * 60
    m = _DURATION_RE.match(str(text))
    if not m:
        raise ElPermError(f"invalid duration {text!r}; use e.g. 30m, 2h, 1d")
    seconds = int(m.group(1)) * _UNIT[m.group(2)]
    if seconds <= 0:
        raise ElPermError(f"duration must be positive: {text!r}")
    return seconds


def format_duration(seconds: int) -> str:
    if seconds % 86400 == 0:
        return f"{seconds // 86400}d"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def iso(ts: float) -> str:
    return _dt.datetime.fromtimestamp(int(ts), _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sudoers_timestamp(ts: float) -> str:
    """sudoers NOTAFTER/NOTBEFORE generalized time (UTC)."""
    return _dt.datetime.fromtimestamp(int(ts), _dt.timezone.utc).strftime("%Y%m%d%H%M%SZ")


# --------------------------------------------------------------------------
# Hashing / JSON
# --------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> bytes:
    """Deterministic JSON encoding used for signatures and policy hashes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def pretty_json(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


# --------------------------------------------------------------------------
# Runtime context (dependency injection for tests)
# --------------------------------------------------------------------------


def _default_run(argv: Sequence[str], input: Optional[bytes] = None,
                 env: Optional[dict] = None) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), input=input, capture_output=True, env=env, check=False)


def _default_groups_of(user: str) -> set[str]:
    """POSIX group names of a user as NSS (SSSD/authd/Himmelblau/files) reports them."""
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return set()
    names = set()
    for gid in os.getgrouplist(user, pw.pw_gid):
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            continue
    return names


def _default_user_exists(user: str) -> bool:
    try:
        pwd.getpwnam(user)
        return True
    except KeyError:
        return False


@dataclasses.dataclass
class Context:
    """Everything that touches the outside world, injectable for tests.

    root      -- output root; '/' on a device, a temp dir in tests.
    now       -- wall clock (seconds since epoch).
    run       -- subprocess runner for visudo/chpasswd/logger/openssl/hooks.
    emit      -- event sink; default is elperm.events.Emitter (set lazily).
    groups_of -- user -> set of POSIX group names (NSS).
    """

    root: Path = Path("/")
    now: Callable[[], float] = time.time
    run: Callable[..., subprocess.CompletedProcess] = _default_run
    groups_of: Callable[[str], set] = _default_groups_of
    user_exists: Callable[[str], bool] = _default_user_exists
    which: Callable[[str], Optional[str]] = shutil.which
    emit: Optional[object] = None
    sudo_impl: Optional[str] = None  # force 'sudo' or 'sudo-rs'
    strict_visudo: bool = False
    caller: Optional[str] = None      # el-jit: invoking identity (tests); default from SUDO_USER etc.
    pam_env: Optional[dict] = None    # el-breakglass pam-hook: PAM_* variables (tests)

    def path(self, absolute: str) -> Path:
        """Map an absolute device path under the output root."""
        return self.root / absolute.lstrip("/")

    @property
    def is_real_root(self) -> bool:
        return self.root.resolve() == Path("/")


# Device paths (absolute on the device; always mapped through Context.path).
SUDOERS_ROLES = "/etc/sudoers.d/50-el-roles"
SUDOERS_JIT_PREFIX = "/etc/sudoers.d/60-el-jit-"
# polkit evaluates rules from /etc and /usr/share in lexical basename order and
# the first admin rule returning a value wins. We sort before the distro's
# 49-/50-default.rules so our admin identities and role rules take effect.
POLKIT_ROLES = "/etc/polkit-1/rules.d/40-el-roles.rules"
POLKIT_JIT = "/etc/polkit-1/rules.d/39-el-jit.rules"
ACCESS_CONF = "/etc/security/el-access.conf"
GROUPMAP = "/etc/el/roles/groupmap.json"
BREAKGLASS_CONF = "/etc/el/roles/breakglass.json"
CACHE_KEY = "/etc/el/roles/cache.key"
MDM_PUBKEY = "/etc/el/roles/mdm-signing.pub"
STATE_DIR = "/var/lib/el/roles"
MANIFEST = "/var/lib/el/roles/manifest.json"
CACHE = "/var/lib/el/roles/cache.json"
GRANTS = "/var/lib/el/roles/grants.json"
BREAKGLASS_STATE = "/var/lib/el/roles/breakglass-state.json"
LOCK = "/var/lib/el/roles/.lock"


# --------------------------------------------------------------------------
# Filesystem
# --------------------------------------------------------------------------


def atomic_write(path: Path, data: bytes | str, mode: int,
                 validate: Optional[Callable[[Path], None]] = None) -> None:
    """Write via temp file in the same directory, fsync, optional validation,
    chmod, then rename(2) over the target. The target is never half-written.

    `validate` receives the temp path and raises to abort (temp is removed).
    Temp names start with '.' so sudo's includedir ignores them.
    """
    if isinstance(data, str):
        data = data.encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        if os.geteuid() == 0:
            os.fchown(fd, 0, 0)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if validate is not None:
            validate(Path(tmp))
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def remove_file(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def read_json(path: Path, default=None):
    try:
        with open(path, "rb") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


class StateLock:
    """Exclusive flock on the state directory (serialises el-jit/el-breakglass)."""

    def __init__(self, ctx: Context):
        self.path = ctx.path(LOCK)
        self.fh = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, "a")
        fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
        self.fh.close()


# --------------------------------------------------------------------------
# Name validation shared by sudoers / polkit / access.conf generators
# --------------------------------------------------------------------------

# Conservative: covers local names and directory names such as alice@corp.com,
# and contains no sudoers/access.conf/JS special characters.
USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,255}$")
POSIX_GROUP_RE = re.compile(r"^[a-z_][a-z0-9_.@-]{0,255}$")


def check_user(name: str) -> str:
    if not USER_RE.match(name or ""):
        raise ElPermError(f"refusing unsafe user name {name!r}")
    return name


def safe_file_token(name: str) -> str:
    """Token usable in a sudoers.d file name. sudo skips names containing '.'
    or ending in '~', so normalise and add a short hash when we changed it."""
    token = re.sub(r"[^A-Za-z0-9_-]", "_", name)
    if token != name:
        token = f"{token}_{sha256_bytes(name.encode())[:6]}"
    return token


def unique(seq: Iterable) -> list:
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out
