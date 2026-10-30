# Desktop layer: locked-down GNOME

**Status:** first implementation of [DESKTOP-UX.md](../docs/DESKTOP-UX.md). The
configuration installs into a root filesystem and is verified with `dconf` and
`gsettings` by `tests/test-install.sh` (Ubuntu 24.04, GNOME 46). It has **not** been booted on a real
image yet, and `eld` (which will apply policy changes at runtime) does not exist.

```
desktop/
├── install.sh            # one entry point for the image build
├── dconf/                # GNOME settings by tier (system dconf database)
├── branding/             # wallpaper, login logo, banner text, org name
├── apps/                 # dock favorites per catalog profile
├── workplace/            # IT self-service app (GTK 4 / libadwaita skeleton)
└── tests/                # validate-dconf.py, test-install.sh
```

## Install

```sh
scripts/apps/elapps apply --profile open-source --root /path/to/rootfs  # apps, browser policies, default apps
desktop/install.sh --root /path/to/rootfs --profile open-source         # same profile name
desktop/install.sh --root /path/to/rootfs --branding /path/to/acme-branding.conf
# then, inside the target: dconf update
```

`--root` is required, so the script never touches the build machine by
accident. `--root /` installs on the running system and runs `dconf update`.

## Customization tiers

Every setting sits in exactly one tier. The tier is decided by the **file name**
in `dconf/db/enterprise-linux.d/`, and `tests/validate-dconf.py` enforces it.

| Tier | File | Locked? | What is in it |
|---|---|---|---|
| **Locked (org)** | `00-locked-security` | Yes, every key | Screen lock (on, 5 min, immediate, on suspend), user accounts admin off, no notifications on lock screen, telemetry off, USB protection on lock screen, no autorun, remote desktop off, proxy, extension set (taskbar + tray), GNOME Software updates off |
| **Org default** | `10-org-defaults` | No | Minimize/maximize buttons, no hot corner, weekday clock, battery %, US + Hebrew keyboards, location off, tap to click |
| **Org default** | `20-favorites` (from `apps/`) | No | Dock favorites for the chosen profile |
| **Org default** | `30-branding` | No | Wallpaper (light and dark), lock screen picture |
| **Hidden** | `90-hidden` | Yes | Looking Glass off, no experimental mutter features, log out always allowed |
| **Login screen** | `dconf/db/gdm.d/00-login-screen` | Yes | Org logo, acceptable-use banner, no user list |
| **User** | *nothing set* | Never | Dark/light mode, accent, fonts and scaling, mouse/touchpad, sound, night light, accessibility, input methods |

The validator rejects a lock on any user-tier or accessibility key, a key in a
locked file that is not locked, a key in a default file that is locked, a lock
with no value, and keys that do not exist in the installed GNOME schemas.

**"Managed by your organization":** GNOME Settings greys out locked keys but
gives no reason. Workplace explains them:
`workplace --explain /org/gnome/desktop/session/idle-delay`.

### Known limits

- GNOME cannot set a *maximum* idle delay, only lock one value. `eld` can enforce a max later.
- `accent-color` exists only from GNOME 47, so it is not set here.
- The proxy lock holds `mode='none'` as a placeholder; `eld` will write the org's proxy.
- The taskbar uses the Dash to Panel and AppIndicator extensions. They must be in the `core` bundle; until then GNOME shows its default layout.
- Default apps are an org default; a user's own choice wins (see `apps/README.md`).

## Branding

Edit `branding/branding.conf` (org name, login banner, colour, support contact)
and replace the SVGs. Values fill `@KEY@` markers in the dconf files at install
time and are copied to `/etc/enterprise-linux/branding.conf` for Workplace.

## Apps, browsers and default apps

These come from the curated catalog, not from this directory. `catalog/`
decides which apps and browsers are installed, `policies/` holds the browser
and Microsoft 365 policies, and the profile's `defaults:` set
`/etc/xdg/mimeapps.list`. All of it is applied by `scripts/apps/elapps`.
`desktop/` only adds the dock favorites for the same profile name. See
[`apps/README.md`](apps/README.md).

## Workplace (IT app)

GTK 4 / libadwaita skeleton with all seven tabs from the design, running on
labelled demo data until `eld` exists. Details: [`workplace/README.md`](workplace/README.md).

## Tests

```sh
python3 desktop/tests/validate-dconf.py --schemas /usr/share/glib-2.0/schemas
python3 desktop/apps/tests/check-apps.py
desktop/tests/test-install.sh          # needs dconf-cli + GNOME schemas
(cd desktop/workplace && python3 -m unittest discover -s tests)
```

CI for all of these is ready in `desktop/ci/desktop.yml`; copy it to `.github/workflows/` to enable it.
