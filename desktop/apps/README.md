# Dock favorites per app profile

**Status:** configuration files, not yet tested on a real image.

The desktop layer only decides **what is pinned in the dock**. All other app
settings come from the curated catalog ([`catalog/`](../../catalog/README.md)),
which is applied by `scripts/apps/elapps`:

| What | Owner |
|---|---|
| Which apps and browsers are installed | `catalog/bundles/*.yaml` |
| Browser policies (Firefox, Edge, Chrome, Chromium, Brave) | `policies/browsers/`, installed by `elapps` |
| Microsoft 365 web apps (Edge policy) | `policies/office/microsoft365/`, installed by `elapps` |
| Default apps (`/etc/xdg/mimeapps.list`) | `defaults:` in `catalog/profiles/*.yaml`, written by `elapps` |
| **Dock favorites** | **this directory** |

Before this split, both layers wrote `/etc/firefox/policies/policies.json` and
`/etc/xdg/mimeapps.list`, and both force-installed the Microsoft 365 web apps,
so whichever ran last would win. `tests/check-apps.py` now fails if this
directory writes anything other than the favorites file.

## Files

```
favorites/<catalog profile>.dconf  -> /etc/dconf/db/enterprise-linux.d/20-favorites
install-apps.sh                    -> installer, called by desktop/install.sh
tests/check-apps.py                -> python3 desktop/apps/tests/check-apps.py
```

There is one favorites file for each profile in `catalog/profiles/` (`default`,
`developer`, `microsoft365`, `open-source`). The check fails when they drift
apart, or when a pinned launcher is not provided by a bundle of that profile.
The exceptions are Files and Workplace, which the desktop layer ships itself.

Each app is listed under every launcher name it can have, e.g.
`firefox-esr.desktop` (apt), `firefox.desktop` (dnf/zypper) and
`org.mozilla.firefox.desktop` (Flatpak). GNOME Shell skips favorites that are
not installed, so one file works on every package family.

Favorites are in the **org default** tier: users can re-arrange the dock, and
"reset desktop settings" brings this list back.

## Order

| Profile | Dock, left to right |
|---|---|
| `default` | Edge, Firefox, Files, Writer, Calc, Impress, Thunderbird, Workplace |
| `developer` | as `default` plus VS Code |
| `microsoft365` | Edge, Firefox, Files, Workplace (Microsoft 365 web apps open from the app grid; Edge names their launchers from a URL hash, so they cannot be pinned ahead of time) |
| `open-source` | Firefox, Files, Writer, Calc, Impress, Thunderbird, Workplace |
