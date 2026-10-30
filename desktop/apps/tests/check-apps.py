#!/usr/bin/env python3
"""Checks for desktop/apps: dock favorites stay in step with catalog/ (stdlib only)."""

import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
APPS = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(APPS))
CATALOG = os.path.join(REPO, "catalog")
# Launchers that come from the desktop layer itself, not from a catalog bundle.
OWN = {"org.enterpriselinux.Workplace.desktop", "org.gnome.Nautilus.desktop"}
errors = []


def profile_bundles(name):
    text = open(os.path.join(CATALOG, "profiles", name + ".yaml"), encoding="utf-8").read()
    m = re.search(r"^\s*bundles:\s*\[([^\]]*)\]", text, re.M)
    return [b.strip() for b in m.group(1).split(",")] if m else []


profiles = sorted(f[:-5] for f in os.listdir(os.path.join(CATALOG, "profiles")) if f.endswith(".yaml"))
favorites = sorted(f[:-6] for f in os.listdir(os.path.join(APPS, "favorites")) if f.endswith(".dconf"))
if profiles != favorites:
    errors.append("favorites %s do not match catalog profiles %s" % (favorites, profiles))

for name in favorites:
    text = open(os.path.join(APPS, "favorites", name + ".dconf"), encoding="utf-8").read()
    m = re.search(r"^favorite-apps=\[(.*)\]$", text, re.M)
    if not m:
        errors.append("%s: no favorite-apps" % name)
        continue
    ids = re.findall(r"'([^']+)'", m.group(1))
    for must in OWN:
        if must not in ids:
            errors.append("%s: missing %s" % (name, must))
    if name not in profiles:
        continue
    bundle_text, todo, seen = "", profile_bundles(name), set()
    while todo:  # follow `includes:` of meta bundles
        b = todo.pop()
        path = os.path.join(CATALOG, "bundles", b + ".yaml")
        if b in seen or not os.path.isfile(path):
            continue
        seen.add(b)
        text = open(path, encoding="utf-8").read()
        bundle_text += text
        inc = re.search(r"^\s*includes:\s*\[([^\]]*)\]", text, re.M)
        if inc:
            todo += [x.strip() for x in inc.group(1).split(",") if x.strip()]
    for i in ids:
        if i not in OWN and i not in bundle_text:
            errors.append("%s: %s is not provided by any bundle of the profile" % (name, i))

for name in favorites:
    with tempfile.TemporaryDirectory() as root:
        r = subprocess.run([os.path.join(APPS, "install-apps.sh"), "--profile", name, "--root", root],
                           capture_output=True, text=True)
        if r.returncode:
            errors.append("install-apps.sh %s failed: %s" % (name, r.stderr.strip()))
            continue
        written = sorted(os.path.relpath(os.path.join(d, f), root)
                         for d, _, fs in os.walk(root) for f in fs)
        if written != ["etc/dconf/db/enterprise-linux.d/20-favorites"]:
            errors.append("install-apps.sh %s wrote %s (must only write the favorites)" % (name, written))

r = subprocess.run([os.path.join(APPS, "install-apps.sh"), "--profile", "nope", "--root", "/nonexistent"],
                   capture_output=True, text=True)
if r.returncode == 0:
    errors.append("install-apps.sh accepted an unknown profile")

for e in errors:
    print("FAIL", e)
print("check-apps: %d profile(s), %d problem(s)" % (len(favorites), len(errors)))
sys.exit(1 if errors else 0)
