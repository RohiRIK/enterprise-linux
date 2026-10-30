"""Load, validate and normalise a RolePolicy document."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

from . import jsonschema_lite
from .naming import GroupNamer
from .util import PolicyError, canonical_json, parse_duration, sha256_bytes, unique

_HERE = Path(__file__).resolve()
SCHEMA_CANDIDATES = [
    _HERE.parent.parent.parent / "policy" / "roles.schema.json",  # repo / /usr/lib/el/permissions
    Path("/usr/share/el/permissions/roles.schema.json"),
]

ROLE_DEFAULT_PRIORITY = {"local-admin": 100, "helpdesk": 50, "power-user": 20, "user": 0}


def load_schema() -> dict:
    for cand in SCHEMA_CANDIDATES:
        if cand.is_file():
            return json.loads(cand.read_text())
    raise PolicyError("roles.schema.json not found")


def load_policy_file(path: str | Path) -> dict:
    try:
        with open(path, "rb") as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise PolicyError(f"policy file not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise PolicyError(f"policy is not valid JSON: {exc}") from None


class Policy:
    """Validated policy with defaults applied. `raw` is the input document."""

    def __init__(self, raw: dict):
        self.raw = raw
        self.sha256 = sha256_bytes(canonical_json(raw))
        doc = copy.deepcopy(raw)
        self.name = doc["metadata"]["name"]
        self.version = doc["metadata"]["version"]
        spec = doc["spec"]

        self.sudo = {"implementation": "auto",
                     "securePath": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                     "allowNopasswd": False, "logfile": "/var/log/sudo.log",
                     **spec.get("sudo", {})}
        self.namer = GroupNamer(spec.get("groupNaming"))

        self.roles: dict[str, dict] = {}
        for name, role in spec["roles"].items():
            r = {"enabled": True, "elevated": name != "user",
                 "priority": ROLE_DEFAULT_PRIORITY.get(name, 10),
                 "groups": [], "sudo": None, "polkit": {}, **role}
            r["name"] = name
            if r["sudo"] is not None:
                r["sudo"] = {"runas": "ALL:ALL", "nopasswd": False, **r["sudo"]}
            r["polkit"] = {"admin": False, "default": None, "actions": [], **r["polkit"]}
            self.roles[name] = r

        self.login = {"deny": [], "alwaysAllowLocal": [], **spec["login"]}
        self.offline = {"graceDays": 7, "signing": "hmac-sha256", **spec.get("offline", {})}
        jit = {"enabled": False, "role": "local-admin", "maxDuration": "60m",
               "defaultDuration": "30m", "requireReason": True, "revokeOnLogout": True,
               "approver": {"mode": "helpdesk"}, "commandAllowlist": [], **spec.get("jit", {})}
        jit["approver"] = {"autoApproveGroups": [], "approverRoles": ["helpdesk", "local-admin"],
                           "ticketPattern": None, "ticketVerifyCommand": None, **jit["approver"]}
        self.jit = jit
        self.recording = {"enabled": False, "iologDir": "/var/log/sudo-io/%{user}",
                          **spec.get("sessionRecording", {})}
        self.breakglass = {"passwordLength": 24, "escrowCommand": None,
                           "rotateAfterUseMinutes": 60, "rotateEveryDays": 30,
                           **spec["breakGlass"]}
        self._semantic_checks()

    # ----------------------------------------------------------------- checks
    def _semantic_checks(self):
        errs = []
        for name, r in self.roles.items():
            s = r["sudo"]
            if s:
                if "ALL" in s["commands"] and len(s["commands"]) > 1:
                    errs.append(f"roles.{name}.sudo.commands: 'ALL' must be the only entry")
                if s["nopasswd"] and not self.sudo["allowNopasswd"]:
                    errs.append(f"roles.{name}.sudo.nopasswd requires spec.sudo.allowNopasswd=true")
            if name != "user" and r["enabled"] and not r["groups"]:
                errs.append(f"roles.{name}: enabled role has no groups")
        if self.roles["user"]["sudo"]:
            errs.append("roles.user must not grant sudo (no standing admin)")
        if self.roles["user"]["polkit"]["admin"]:
            errs.append("roles.user must not be a polkit admin identity")
        if self.jit["enabled"]:
            jr = self.roles.get(self.jit["role"])
            if not jr or not jr["enabled"]:
                errs.append(f"jit.role {self.jit['role']!r} is not an enabled role")
            for ar in self.jit["approver"]["approverRoles"]:
                if ar not in self.roles:
                    errs.append(f"jit.approver.approverRoles: unknown role {ar!r}")
            try:
                if parse_duration(self.jit["defaultDuration"]) > parse_duration(self.jit["maxDuration"]):
                    errs.append("jit.defaultDuration exceeds jit.maxDuration")
            except Exception as exc:  # noqa: BLE001
                errs.append(f"jit durations: {exc}")
            ap = self.jit["approver"]
            if ap["mode"] == "ticket" and not ap["ticketPattern"]:
                errs.append("jit.approver.mode=ticket requires ticketPattern")
            if ap["ticketPattern"]:
                try:
                    re.compile(ap["ticketPattern"])
                except re.error as exc:
                    errs.append(f"jit.approver.ticketPattern: {exc}")
        allow, deny = set(self.login["allow"]), set(self.login["deny"])
        if allow & deny:
            errs.append(f"login: groups in both allow and deny: {sorted(allow & deny)} (deny would win)")
        if self.breakglass["account"] in self.login["alwaysAllowLocal"]:
            pass  # harmless; break-glass is always allowed anyway
        # Every group reference must map to a valid, unique POSIX name.
        seen: dict[str, str] = {}
        for ref in self.all_group_refs():
            try:
                posix = self.namer.posix_name(ref)
            except PolicyError as exc:
                errs.append(str(exc))
                continue
            if posix in seen and seen[posix] != ref:
                errs.append(f"groups {seen[posix]!r} and {ref!r} both map to {posix!r}")
            seen[posix] = ref
        if errs:
            raise PolicyError("policy failed semantic validation:\n  " + "\n  ".join(errs))

    # ---------------------------------------------------------------- helpers
    def all_group_refs(self) -> list[str]:
        refs = []
        for name in sorted(self.roles):  # deterministic regardless of JSON key order
            refs += self.roles[name]["groups"]
        refs += self.login["allow"] + self.login["deny"]
        refs += self.jit["approver"]["autoApproveGroups"]
        return unique(refs)

    def posix(self, refs) -> list[str]:
        return unique(self.namer.posix_name(r) for r in refs)

    def roles_by_priority(self, include_elevated: bool = True) -> list[dict]:
        rs = [r for r in self.roles.values() if r["enabled"]]
        if not include_elevated:
            rs = [r for r in rs if not r["elevated"]]
        return sorted(rs, key=lambda r: (-r["priority"], r["name"]))

    @property
    def max_jit_seconds(self) -> int:
        return parse_duration(self.jit["maxDuration"])

    @property
    def default_jit_seconds(self) -> int:
        return parse_duration(self.jit["defaultDuration"])


def validate_policy(raw: dict) -> Policy:
    errors = jsonschema_lite.validate(raw, load_schema())
    if errors:
        raise PolicyError("policy failed schema validation:\n  " + "\n  ".join(errors[:50]))
    return Policy(raw)
