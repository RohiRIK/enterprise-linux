#!/usr/bin/env python3
"""Checks for desktop/apps: JSON policies, mimeapps.list, favorites, installer."""

import configparser
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
APPS = os.path.dirname(HERE)
errors = []


def no_dupes(pairs):
    keys = [k for k, _ in pairs]
    dupes = {k for k in keys if keys.count(k) > 1}
    if dupes:
        raise ValueError("duplicate keys: %s" % sorted(dupes))
    return dict(pairs)


def readme_ids():
    text = open(os.path.join(APPS, "README.md"), encoding="utf-8").read()
    return set(re.findall(r"`([\w.+-]+\.desktop)`", text))


known = readme_ids()
for dirpath, _, files in os.walk(APPS):
    for name in files:
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, APPS)
        if name.endswith(".json"):
            try:
                json.load(open(path), object_pairs_hook=no_dupes)
            except ValueError as exc:
                errors.append("%s: %s" % (rel, exc))
        elif name == "mimeapps.list":
            cp = configparser.ConfigParser(strict=True, interpolation=None)
            cp.optionxform = str
            try:
                cp.read(path)
            except configparser.Error as exc:
                errors.append("%s: %s" % (rel, exc))
                continue
            if cp.sections() != ["Default Applications"]:
                errors.append("%s: expected only [Default Applications]" % rel)
                continue
            for mime, app in cp["Default Applications"].items():
                if "/" not in mime or not app.endswith(".desktop"):
                    errors.append("%s: bad entry %s=%s" % (rel, mime, app))
                elif app not in known:
                    errors.append("%s: %s not in README desktop-id table" % (rel, app))
        elif name == "favorites.dconf":
            text = open(path).read()
            m = re.search(r"^favorite-apps=\[(.*)\]$", text, re.M)
            if not m:
                errors.append("%s: no favorite-apps" % rel)
                continue
            ids = re.findall(r"'([^']+)'", m.group(1))
            for must in ("org.enterpriselinux.Workplace.desktop", "org.gnome.Nautilus.desktop"):
                if must not in ids:
                    errors.append("%s: missing %s" % (rel, must))
            for i in ids:
                if i not in known:
                    errors.append("%s: %s not in README desktop-id table" % (rel, i))

expected = [
    "etc/xdg/mimeapps.list",
    "etc/dconf/db/enterprise-linux.d/20-favorites",
    "etc/firefox/policies/policies.json",
    "etc/opt/chrome/policies/managed/enterprise-linux.json",
    "etc/opt/edge/policies/managed/enterprise-linux.json",
    "etc/chromium/policies/managed/enterprise-linux.json",
]
for profile in sorted(os.listdir(os.path.join(APPS, "profiles"))):
    with tempfile.TemporaryDirectory() as root:
        r = subprocess.run([os.path.join(APPS, "install-apps.sh"), "--profile", profile, "--root", root],
                           capture_output=True, text=True)
        if r.returncode:
            errors.append("install-apps.sh %s failed: %s" % (profile, r.stderr.strip()))
            continue
        for f in expected:
            if not os.path.isfile(os.path.join(root, f)):
                errors.append("install-apps.sh %s: missing %s" % (profile, f))
        if profile == "microsoft-365" and not os.path.isfile(
                os.path.join(root, "etc/opt/edge/policies/managed/edge-m365.json")):
            errors.append("microsoft-365: Edge web-app overlay not installed")

r = subprocess.run([os.path.join(APPS, "install-apps.sh"), "--profile", "nope", "--root", "/nonexistent"],
                   capture_output=True, text=True)
if r.returncode == 0:
    errors.append("install-apps.sh accepted an unknown profile")

for e in errors:
    print("FAIL", e)
print("check-apps: %d problem(s)" % len(errors))
sys.exit(1 if errors else 0)
