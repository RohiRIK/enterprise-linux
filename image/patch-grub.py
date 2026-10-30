#!/usr/bin/env python3
"""Patch the live ISO grub.cfg: brand the first entry and add kernel args.

    patch-grub.py GRUB_CFG "EXTRA ARGS"

Only `linux /casper/...` lines change; the args go before the `---`
separator so they reach the live kernel, not the installed system.
"""
import re
import sys

path, extra = sys.argv[1], sys.argv[2].strip()
text = open(path).read()
n = 0


def add_args(m):
    global n
    n += 1
    line = m.group(0)
    if not extra:
        return line
    if " ---" in line:
        return line.replace(" ---", f" {extra} ---", 1)
    return f"{line} {extra}"


text = re.sub(r"(?m)^\s*linux\s+/casper/\S+.*$", add_args, text)
if n == 0:
    raise SystemExit("patch-grub: no 'linux /casper/...' line found")
text = re.sub(r'(?m)^(menuentry\s+)"[^"]*"', r'\1"Install Enterprise Linux"', text, count=1)
text = re.sub(r"(?m)^set timeout=\d+", "set timeout=5", text)
open(path, "w").write(text)
