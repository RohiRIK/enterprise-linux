"""Signed offline cache of the last-known role policy (PERMISSIONS.md section 5).

Two signing modes:

hmac-sha256 (default)
    The device signs the cache itself with a random 32-byte key in
    /etc/el/roles/cache.key (0600 root). Pure stdlib. Detects corruption,
    edits by anything that cannot read the key, and caches copied from another
    device. It does NOT prove the MDM issued the mapping, and it cannot stop
    local root (root can rewrite sudoers directly anyway).

ed25519 (when the MDM signs)
    The MDM produces a signed bundle {policy, issued_at, expires_at}; the
    device verifies it with the MDM public key provisioned at enrollment
    (/etc/el/roles/mdm-signing.pub) using the `openssl pkeyutl -rawin` CLI
    (OpenSSL >= 3.0; present on Ubuntu 24.04+ and RHEL 9+). Proves issuer
    authenticity and lets the MDM, not the device, decide expiry. Requires the
    openssl binary; Python's stdlib has no ed25519.

States returned by load_cache(): valid | expired | invalid | missing.
Expired means "signature fine, grace period over": the renderer then drops
elevated roles (user + break-glass only). Invalid means "do not trust".
"""

from __future__ import annotations

import base64
import dataclasses
import hmac
import hashlib
import json
import os
import tempfile
from pathlib import Path

from .util import (CACHE, CACHE_KEY, MDM_PUBKEY, CacheError, Context, atomic_write,
                   canonical_json, read_json, sha256_bytes)

FORMAT = 1
CLOCK_SKEW = 300  # seconds of tolerated clock skew before "issued in the future" is invalid


@dataclasses.dataclass
class CacheStatus:
    state: str  # valid | expired | invalid | missing
    reason: str = ""
    doc: dict | None = None

    @property
    def policy(self) -> dict | None:
        return self.doc["policy"] if self.doc else None


def _payload(doc: dict) -> bytes:
    return canonical_json({k: v for k, v in doc.items() if k != "sig"})


# ------------------------------------------------------------------ HMAC
def _hmac_key(ctx: Context, create: bool) -> bytes | None:
    path = ctx.path(CACHE_KEY)
    try:
        key = path.read_bytes()
        if len(key) >= 32:
            return key
    except FileNotFoundError:
        pass
    if not create:
        return None
    key = os.urandom(32)
    atomic_write(path, key, 0o600)
    return key


def write_device_cache(ctx: Context, raw_policy: dict, grace_days: int) -> dict:
    now = int(ctx.now())
    doc = {
        "format": FORMAT,
        "alg": "hmac-sha256",
        "issuer": "device",
        "issued_at": now,
        "expires_at": now + grace_days * 86400,
        "policy_sha256": sha256_bytes(canonical_json(raw_policy)),
        "policy": raw_policy,
    }
    key = _hmac_key(ctx, create=True)
    doc["sig"] = base64.b64encode(hmac.new(key, _payload(doc), hashlib.sha256).digest()).decode()
    atomic_write(ctx.path(CACHE), json.dumps(doc, indent=2, sort_keys=True) + "\n", 0o600)
    return doc


# --------------------------------------------------------------- ed25519
def _openssl(ctx: Context, args: list[str]):
    if not ctx.which("openssl"):
        raise CacheError("ed25519 signing selected but the openssl CLI is not available")
    return ctx.run(["openssl", *args])


def make_bundle(ctx: Context, raw_policy: dict, private_key: str, grace_days: int) -> dict:
    """MDM-side helper (also used by tests): produce an ed25519-signed bundle."""
    now = int(ctx.now())
    doc = {
        "format": FORMAT, "alg": "ed25519", "issuer": "mdm",
        "issued_at": now, "expires_at": now + grace_days * 86400,
        "policy_sha256": sha256_bytes(canonical_json(raw_policy)), "policy": raw_policy,
    }
    with tempfile.TemporaryDirectory() as td:
        data, sig = Path(td, "data"), Path(td, "sig")
        data.write_bytes(_payload(doc))
        res = _openssl(ctx, ["pkeyutl", "-sign", "-inkey", private_key, "-rawin",
                             "-in", str(data), "-out", str(sig)])
        if res.returncode != 0:
            raise CacheError(f"openssl sign failed: {res.stderr.decode(errors='replace').strip()}")
        doc["sig"] = base64.b64encode(sig.read_bytes()).decode()
    return doc


def _verify_ed25519(ctx: Context, doc: dict, pubkey: Path) -> bool:
    if not pubkey.is_file():
        return False
    with tempfile.TemporaryDirectory() as td:
        data, sig = Path(td, "data"), Path(td, "sig")
        data.write_bytes(_payload(doc))
        sig.write_bytes(base64.b64decode(doc["sig"]))
        res = _openssl(ctx, ["pkeyutl", "-verify", "-pubin", "-inkey", str(pubkey), "-rawin",
                             "-in", str(data), "-sigfile", str(sig)])
        return res.returncode == 0


def store_bundle(ctx: Context, doc: dict, pubkey: str | None = None) -> CacheStatus:
    status = check_doc(ctx, doc, pubkey)
    if status.state != "valid":
        raise CacheError(f"refusing bundle: {status.state}: {status.reason}")
    atomic_write(ctx.path(CACHE), json.dumps(doc, indent=2, sort_keys=True) + "\n", 0o600)
    return status


# ---------------------------------------------------------------- verify
def check_doc(ctx: Context, doc: dict, pubkey: str | None = None) -> CacheStatus:
    try:
        if doc.get("format") != FORMAT:
            return CacheStatus("invalid", "unknown cache format")
        alg = doc.get("alg")
        if alg == "hmac-sha256":
            key = _hmac_key(ctx, create=False)
            if key is None:
                return CacheStatus("invalid", "device cache key missing")
            want = hmac.new(key, _payload(doc), hashlib.sha256).digest()
            if not hmac.compare_digest(want, base64.b64decode(doc.get("sig", ""))):
                return CacheStatus("invalid", "bad HMAC signature")
        elif alg == "ed25519":
            key_path = Path(pubkey) if pubkey else ctx.path(MDM_PUBKEY)
            if not _verify_ed25519(ctx, doc, key_path):
                return CacheStatus("invalid", "bad or unverifiable ed25519 signature")
        else:
            return CacheStatus("invalid", f"unknown signing algorithm {alg!r}")
        if sha256_bytes(canonical_json(doc["policy"])) != doc.get("policy_sha256"):
            return CacheStatus("invalid", "policy hash mismatch")
        now = ctx.now()
        if now + CLOCK_SKEW < doc["issued_at"]:
            return CacheStatus("invalid", "cache issued in the future (clock rollback?)", doc)
        if now >= doc["expires_at"]:
            return CacheStatus("expired", "offline grace period elapsed", doc)
        return CacheStatus("valid", "", doc)
    except (KeyError, TypeError, ValueError) as exc:
        return CacheStatus("invalid", f"malformed cache: {exc}")


def load_cache(ctx: Context, pubkey: str | None = None) -> CacheStatus:
    try:
        doc = read_json(ctx.path(CACHE))
    except (json.JSONDecodeError, OSError) as exc:
        return CacheStatus("invalid", f"unreadable cache: {exc}")
    if doc is None:
        return CacheStatus("missing", "no cache; run el-perm-render --policy first")
    return check_doc(ctx, doc, pubkey)
