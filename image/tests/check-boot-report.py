#!/usr/bin/env python3
"""Check the EL-CI-REPORT block that el-ci-report prints on first boot.

    check-boot-report.py SERIAL_LOG

Exit 0 when the installed system shows the boot-chain properties promised
in docs/KERNEL.md; prints each check either way.
"""
import json
import re
import sys


def parse(log: str) -> dict:
    m = re.search(r"EL-CI-REPORT-BEGIN\r?\n(.*?)EL-CI-REPORT-END", log, re.S)
    if not m:
        raise SystemExit("check-boot-report: no EL-CI-REPORT block in the log")
    body = m.group(1).replace("\r", "")
    fields, key = {}, None
    for line in body.splitlines():
        hm = re.match(r"^([a-z_.-]+):\s?(.*)$", line)
        if hm and hm.group(1) in KEYS:
            key = hm.group(1)
            fields[key] = hm.group(2)
        elif key:
            fields[key] += "\n" + line
    return fields


KEYS = {"kernel", "cmdline", "lockdown", "sig_enforce", "secureboot", "eld",
        "elctl-whoami", "install.json", "harden-verify", "failed-units"}


def checks(f: dict):
    yield "stock Ubuntu generic kernel", f.get("kernel", "").endswith("-generic")
    yield "cmdline has lockdown=integrity", "lockdown=integrity" in f.get("cmdline", "")
    yield "cmdline has module.sig_enforce=1", "module.sig_enforce=1" in f.get("cmdline", "")
    yield "lockdown active ([integrity] or stronger)", re.search(r"\[(integrity|confidentiality)\]", f.get("lockdown", "")) is not None
    yield "module signatures enforced", f.get("sig_enforce", "").strip() == "Y"
    yield "Secure Boot enabled", f.get("secureboot", "").strip() == "1"
    yield "eld running", f.get("eld", "").strip() == "active"
    yield "elctl talks to eld", "roles:" in f.get("elctl-whoami", "")
    try:
        inst = json.loads(f.get("install.json", ""))
        ok = inst.get("schema") == "el.image.install/v1"
    except ValueError:
        ok = False
    yield "install record written", ok


def main(argv):
    if len(argv) != 2:
        raise SystemExit(__doc__)
    f = parse(open(argv[1], errors="replace").read())
    failed = 0
    for name, ok in checks(f):
        print(("PASS " if ok else "FAIL ") + name)
        failed += not ok
    print("failed units:", f.get("failed-units", "").strip() or "none")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
