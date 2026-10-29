"""Directory group -> POSIX group name resolution.

The identity layer (SSSD for AD/IdM, authd or Himmelblau for Entra ID) is what
actually exposes directory groups to NSS. Each of them names groups its own
way (e.g. SSSD `use_fully_qualified_names`, `re_expression`; Entra display
name vs object id). This module does NOT talk to the directory: it applies a
deterministic, policy-configurable rule so the rendered sudoers/polkit/
access.conf reference the same name NSS will report. If the rule does not
match the provider's naming, use `groupNaming.overrides`.
"""

from __future__ import annotations

import re

from .util import POSIX_GROUP_RE, PolicyError, sha256_bytes

DEFAULT_RULES = {
    "entra": {"template": "{slug}", "maxLength": 32},
    "ad": {"template": "{slug}", "maxLength": 32},
    "local": {"template": "{name}", "maxLength": 256},
}

PROVIDER_HINTS = {
    "entra": "Provided by the Entra ID identity module (authd or Himmelblau) via NSS. "
             "Verify the module's group naming matches this rule or set an override.",
    "ad": "Provided by SSSD (AD or IdM). Match SSSD use_fully_qualified_names / "
          "full_name_format, or set an override.",
    "local": "Local group from /etc/group (or an image-managed systemd-sysusers entry).",
}


def parse_ref(ref: str) -> tuple[str, str]:
    try:
        source, kind, name = ref.split(":", 2)
    except ValueError:
        raise PolicyError(f"bad group reference {ref!r}") from None
    if kind != "group" or source not in DEFAULT_RULES or not name:
        raise PolicyError(f"bad group reference {ref!r}")
    return source, name


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9_.-]+", "-", name.lower()).strip("-.")
    if not slug or not re.match(r"[a-z_]", slug[0]):
        slug = "g" + slug
    return slug


class GroupNamer:
    def __init__(self, naming_cfg: dict | None):
        cfg = naming_cfg or {}
        self.rules = {k: dict(v) for k, v in DEFAULT_RULES.items()}
        for src, rule in (cfg.get("sources") or {}).items():
            self.rules[src].update(rule)
        self.overrides = dict(cfg.get("overrides") or {})

    def posix_name(self, ref: str) -> str:
        if ref in self.overrides:
            name = self.overrides[ref]
        else:
            source, raw = parse_ref(ref)
            rule = self.rules[source]
            name = rule["template"].replace("{name}", raw).replace("{slug}", slugify(raw))
            max_len = int(rule.get("maxLength", 32))
            if len(name) > max_len:
                # Truncate deterministically with a hash suffix to avoid collisions.
                suffix = "-" + sha256_bytes(ref.encode())[:6]
                name = name[: max_len - len(suffix)].rstrip("-.") + suffix
        if not POSIX_GROUP_RE.match(name):
            raise PolicyError(
                f"group {ref!r} maps to {name!r}, which is not a safe POSIX group name; "
                "adjust groupNaming or add an override")
        return name

    def mapping(self, refs) -> list[dict]:
        out = []
        for ref in refs:
            source, _ = parse_ref(ref)
            out.append({
                "directory": ref,
                "posix": self.posix_name(ref),
                "source": source,
                "rule": "override" if ref in self.overrides else self.rules[source]["template"],
                "providedBy": PROVIDER_HINTS[source],
            })
        return out
