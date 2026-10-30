#!/usr/bin/env python3
"""Validate the dconf tiers in desktop/dconf (stdlib only).

Rules (see desktop/README.md):
  1. Keyfiles parse: [section] headers and key=value lines only.
  2. Locked-tier files (00-*, 90-*, and every gdm.d file) have every key locked.
  3. Org-default files (10-*, 20-*, 30-*) have no key locked.
  4. Every lock points at a key that some keyfile in the same db sets.
  5. User-tier and accessibility keys are never locked.
  6. With --schemas DIR: each key exists in the installed GSettings schemas.
     A key whose whole schema is missing is a warning (e.g. extensions,
     GNOME Software not installed), unless --strict.
  7. @TEMPLATE@ markers name keys defined in branding/branding.conf.
"""

import argparse
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

DESKTOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_ROOT = os.path.join(DESKTOP, "dconf", "db")

# Never lockable: the user tier and accessibility (DESKTOP-UX.md section 3 and 6).
NEVER_LOCK = (
    "/org/gnome/desktop/a11y/",
    "/org/gnome/desktop/interface/color-scheme",
    "/org/gnome/desktop/interface/accent-color",
    "/org/gnome/desktop/interface/text-scaling-factor",
    "/org/gnome/desktop/interface/cursor-size",
    "/org/gnome/desktop/interface/high-contrast",
    "/org/gnome/desktop/peripherals/",
    "/org/gnome/desktop/sound/",
    "/org/gnome/settings-daemon/plugins/color/",
    "/org/gnome/desktop/background/",
    "/org/gnome/shell/favorite-apps",
    "/org/gnome/desktop/input-sources/",
)
# Locks that security/hardening/el-harden-verify checks for; never drop them.
REQUIRED_LOCKS = {
    "enterprise-linux.d": (
        "/org/gnome/desktop/session/idle-delay",
        "/org/gnome/desktop/screensaver/lock-enabled",
        "/org/gnome/desktop/media-handling/autorun-never",
    ),
    "gdm.d": ("/org/gnome/login-screen/disable-user-list",),
}
LOCKED_PREFIXES = ("00-", "90-")
DEFAULT_PREFIXES = ("10-", "20-", "30-")

errors, warnings = [], []


def parse_keyfile(path):
    keys, section = {}, None
    for n, raw in enumerate(open(path, encoding="utf-8"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^\[([a-z0-9/._-]+)\]$", line, re.I)
        if m:
            section = "/" + m.group(1).strip("/")
            continue
        m = re.match(r"^([A-Za-z0-9-]+)=(.+)$", line)
        if not m or section is None:
            errors.append("%s:%d: cannot parse %r" % (path, n, line))
            continue
        full = "%s/%s" % (section, m.group(1))
        if full in keys:
            errors.append("%s:%d: %s set twice" % (path, n, full))
        keys[full] = m.group(2)
    return keys


def parse_locks(path):
    out = []
    for n, raw in enumerate(open(path, encoding="utf-8"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("/"):
            errors.append("%s:%d: lock must be an absolute path: %r" % (path, n, line))
        out.append(line)
    return out


def load_schemas(schema_dir):
    """Map dconf directory path -> set of key names, from *.gschema.xml."""
    by_path = {}
    for f in glob.glob(os.path.join(schema_dir, "*.gschema.xml")):
        try:
            tree = ET.parse(f)
        except ET.ParseError:
            continue
        for schema in tree.getroot().iter("schema"):
            path = schema.get("path")
            if path:
                by_path.setdefault(path, set()).update(k.get("name") for k in schema.iter("key"))
    return by_path


def branding_keys():
    keys = set()
    for line in open(os.path.join(DESKTOP, "branding", "branding.conf"), encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            keys.add(line.split("=", 1)[0])
    return keys


def check_db(db_dir, schemas, strict, brand):
    name = os.path.basename(db_dir)
    files = sorted(f for f in glob.glob(os.path.join(db_dir, "*")) if os.path.isfile(f))
    lock_files = sorted(glob.glob(os.path.join(db_dir, "locks", "*")))
    locks = set()
    for lf in lock_files:
        locks.update(parse_locks(lf))
    all_keys = {}
    for f in files:
        base = os.path.basename(f)
        text = open(f, encoding="utf-8").read()
        for marker in re.findall(r"@([A-Z][A-Z0-9_]*)@", text):
            if marker not in brand:
                errors.append("%s: @%s@ not defined in branding.conf" % (f, marker))
        keys = parse_keyfile(f)
        for k in keys:
            if k in all_keys:
                errors.append("%s: %s also set in %s" % (f, k, all_keys[k]))
            all_keys[k] = base
        locked_tier = name == "gdm.d" or base.startswith(LOCKED_PREFIXES)
        if locked_tier:
            for k in keys:
                if k not in locks:
                    errors.append("%s: %s is in a locked-tier file but not locked" % (f, k))
        elif base.startswith(DEFAULT_PREFIXES):
            for k in keys:
                if k in locks:
                    errors.append("%s: %s is org-default tier but locked" % (f, k))
        else:
            errors.append("%s: file name must start with 00-, 10-, 20-, 30- or 90-" % f)
    for required in REQUIRED_LOCKS.get(name, ()):
        if required not in locks:
            errors.append("%s: %s must stay locked (checked by el-harden-verify)" % (name, required))
    for lock in sorted(locks):
        if lock.endswith("/"):
            if not any(k.startswith(lock) for k in all_keys):
                errors.append("%s: directory lock %s covers no key" % (name, lock))
        elif lock not in all_keys:
            errors.append("%s: lock %s has no value in any keyfile" % (name, lock))
        for never in NEVER_LOCK:
            if lock.startswith(never) or never.startswith(lock if lock.endswith("/") else lock + "/"):
                errors.append("%s: %s must never be locked (user tier / accessibility)" % (name, lock))
    if schemas is not None:
        for k in sorted(all_keys):
            directory, key = k.rsplit("/", 1)
            known = schemas.get(directory + "/")
            if known is None:
                (errors if strict else warnings).append("%s: no installed schema for %s/" % (name, directory))
            elif key not in known:
                errors.append("%s: %s is not a key of the schema at %s/" % (name, key, directory))
    return all_keys, locks


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--schemas", help="GSettings schema dir, e.g. /usr/share/glib-2.0/schemas")
    ap.add_argument("--strict", action="store_true", help="missing schemas are errors")
    args = ap.parse_args()
    schemas = load_schemas(args.schemas) if args.schemas else None
    brand = branding_keys()
    total_keys = total_locks = 0
    for db_dir in sorted(glob.glob(os.path.join(DB_ROOT, "*.d"))):
        keys, locks = check_db(db_dir, schemas, args.strict, brand)
        total_keys += len(keys)
        total_locks += len(locks)
    for w in sorted(set(warnings)):
        print("warning:", w)
    for e in errors:
        print("error:", e)
    print("validate-dconf: %d keys, %d locks, %d warning(s), %d error(s)"
          % (total_keys, total_locks, len(set(warnings)), len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
