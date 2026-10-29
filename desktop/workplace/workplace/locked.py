"""Explain locked desktop settings ("Managed by your organization").

GNOME greys out a setting whose dconf key is locked, but says nothing about
why. Workplace is the place the explanation lives: Settings pages (and the
Home page) can link to ``workplace --explain /org/gnome/...``.

Stdlib only. Locked keys come from the Control API (``desktop.locked_keys``)
when eld runs; otherwise from the dconf lock files on disk.
"""

from __future__ import annotations

import glob
import os

DCONF_DB_DIR = "/etc/dconf/db"
MANAGED_TEXT = "Managed by your organization"

# Plain-language reasons per key prefix. Longest matching prefix wins.
_REASONS = {
    "/org/gnome/desktop/screensaver/": "Your screen locks automatically to protect company data.",
    "/org/gnome/desktop/session/idle-delay": "Your screen locks automatically to protect company data.",
    "/org/gnome/desktop/lockdown/": "Keeps the device supportable and protects sign-in.",
    "/org/gnome/desktop/notifications/show-in-lock-screen": "Message previews are hidden while the screen is locked.",
    "/org/gnome/desktop/privacy/usb-protection": "New USB devices are blocked while the screen is locked.",
    "/org/gnome/desktop/privacy/": "Diagnostics are not sent to third parties from managed devices.",
    "/org/gnome/desktop/media-handling/": "Removable media never runs programs automatically.",
    "/org/gnome/desktop/remote-desktop/": "Remote access only through IT remote assist, which you must accept.",
    "/org/gnome/system/proxy/": "Network access goes through your organization's proxy.",
    "/org/gnome/shell/": "Only extensions approved by your organization are allowed.",
    "/org/gnome/software/": "Updates are installed by your organization's update service. See the Updates tab.",
    "/org/gnome/login-screen/": "The sign-in screen is set by your organization.",
}
_DEFAULT_REASON = "Your organization manages this setting."


def read_lock_files(db_dir=DCONF_DB_DIR):
    """Return every key or directory listed in ``<db_dir>/*.d/locks/*``."""
    keys = set()
    for path in glob.glob(os.path.join(db_dir, "*.d", "locks", "*")):
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("/") and not line.startswith("#"):
                        keys.add(line)
        except OSError:
            continue
    return sorted(keys)


def is_locked(key, locked_keys):
    """True if ``key`` is locked directly or by a locked directory (``/a/b/``)."""
    for lock in locked_keys:
        if lock == key or (lock.endswith("/") and key.startswith(lock)):
            return True
    return False


def explain(key, locked_keys):
    """Return ``(locked, title, reason)`` for a dconf key path."""
    if not is_locked(key, locked_keys):
        return False, "You can change this setting", ""
    best = ""
    for prefix in _REASONS:
        if key.startswith(prefix) and len(prefix) > len(best):
            best = prefix
    return True, MANAGED_TEXT, _REASONS.get(best, _DEFAULT_REASON)
