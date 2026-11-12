#!/usr/bin/env python3
"""Patch the live ISO grub.cfg: brand the first entry and add kernel args.

    patch-grub.py GRUB_CFG "EXTRA ARGS" [--verbose] [--require ARG]

--verbose      drop `quiet` and `splash` so the kernel command line and boot
               messages reach the serial console (CI).
--require ARG  fail unless every patched `linux /casper/...` line has ARG.

Prints every patched `linux` line (they carry no secrets).

Only `linux /casper/...` lines change; the args go before the `---`
separator so they reach the live kernel, not the installed system.
"""
import re
import sys

path, extra = sys.argv[1], sys.argv[2].strip()
opts = sys.argv[3:]
verbose = "--verbose" in opts
require = opts[opts.index("--require") + 1] if "--require" in opts else None
text = open(path).read()
n = 0


def add_args(m):
    global n
    n += 1
    line = m.group(0)
    if verbose:
        line = re.sub(r"[ \t]+(quiet|splash)(?=\s|$)", "", line)
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
lines = re.findall(r"(?m)^\s*linux\s+/casper/\S+.*$", text)
for line in lines:
    print("patch-grub:", line.strip())
if require and any(require not in line.split() for line in lines):
    raise SystemExit(f"patch-grub: a 'linux /casper/...' line lacks {require!r}")
open(path, "w").write(text)
