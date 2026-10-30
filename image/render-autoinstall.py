#!/usr/bin/env python3
"""Fill @NAME@ placeholders in the autoinstall template and check the result.

    render-autoinstall.py TEMPLATE OUT NAME=VALUE...

Fails if a placeholder is left over or the result is not a valid
autoinstall v1 document with the keys image/late/el-install-target needs.
"""
import re
import sys

import yaml


def render(template: str, values: dict) -> str:
    def sub(m):
        key = m.group(1)
        if key not in values:
            raise SystemExit(f"render-autoinstall: no value for @{key}@")
        return values[key]
    return re.sub(r"@([A-Z_]+)@", sub, template)


def check(text: str) -> dict:
    doc = yaml.safe_load(text)
    ai = doc.get("autoinstall") if isinstance(doc, dict) else None
    if not isinstance(ai, dict) or ai.get("version") != 1:
        raise SystemExit("render-autoinstall: not an autoinstall v1 document")
    layout = ai.get("storage", {}).get("layout", {})
    if layout.get("name") != "lvm" or not layout.get("password"):
        raise SystemExit("render-autoinstall: storage must be encrypted LVM")
    if ai.get("drivers", {}).get("install") is not False:
        raise SystemExit("render-autoinstall: third-party drivers must stay off (docs/KERNEL.md)")
    late = " ".join(ai.get("late-commands", []))
    if "el-install-target" not in late:
        raise SystemExit("render-autoinstall: late-commands must run el-install-target")
    if "identity" not in ai and "identity" not in (ai.get("interactive-sections") or []):
        raise SystemExit("render-autoinstall: needs identity or interactive identity")
    return doc


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    values = dict(a.split("=", 1) for a in argv[3:])
    text = render(open(argv[1]).read(), values)
    check(text)
    with open(argv[2], "w") as f:
        f.write(text)


if __name__ == "__main__":
    main(sys.argv)
