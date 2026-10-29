# Default apps and browsers

**Status:** configuration files, not tested on a real image yet. Which apps get
*installed* is decided by the app bundles in `catalog/` ([CURATED-APPS.md](../../docs/CURATED-APPS.md));
this directory only decides which installed app is the **default** and how
browsers are **configured**.

## Two profiles

An org picks one at image build time (`desktop/install.sh --profile ...`).
Both preinstall several browsers and both keep LibreOffice so documents open
offline.

| | `open-source` | `microsoft-365` |
|---|---|---|
| Default browser | Firefox ESR | Microsoft Edge |
| Other browsers in the dock | Google Chrome | Firefox ESR |
| Office | LibreOffice (Writer, Calc, Impress) | Word, Excel, PowerPoint, Outlook and Teams as Edge web apps, force-installed by policy; LibreOffice for local files |
| Mail and calendar | Thunderbird | Thunderbird (Outlook web app also installed) |
| Typical org | Mixed or Google Workspace shops, cost-sensitive, public sector | Microsoft 365 and Entra shops |

Why Edge is the default in the Microsoft 365 profile: Microsoft's Intune docs
for Linux describe Entra conditional access and device compliance working
through Microsoft Edge with the Intune app. Verify against the current Intune
docs before relying on it. Other browsers still work for sites that do not
require a compliant device.

The default apps are the **org default, user can change** tier: they live in
`/etc/xdg/mimeapps.list`, and a user's choice in Settings (stored in
`~/.config/mimeapps.list`) wins. An org that must force a browser does it with
an `eld` policy that resets the user's choice; there is no clean dconf lock
for this.

## Browsers and their policies

Every browser gets a managed policy file with the same baseline:

- No in-browser update prompts (updates come from the frozen repo snapshot).
- Telemetry and metrics off; no default-browser nag; no first-run wizard.
- Extensions blocked by default (`*`), with an empty allowlist the org fills in.
- DNS-over-HTTPS off, so corporate DNS and filtering keep working.
- Safe Browsing / SmartScreen on. Firefox trusts the enterprise root CAs from the OS store.
- Homepage `https://intranet.example.com` (**placeholder**, set per org).

| Browser | Source | Policy file | Installed to |
|---|---|---|---|
| Firefox ESR | Mozilla APT repo (native deb) | `browsers/firefox/policies.json` | `/etc/firefox/policies/policies.json` |
| Google Chrome | Google repo (native) | `browsers/chrome/enterprise-linux.json` | `/etc/opt/chrome/policies/managed/` |
| Microsoft Edge | Microsoft repo (native) | `browsers/edge/enterprise-linux.json` (+ `profiles/microsoft-365/edge-m365.json`) | `/etc/opt/edge/policies/managed/` |
| Chromium | Distro package where native (Debian, Fedora/RHEL EPEL); on Ubuntu it is a snap, so skip it there | `browsers/chromium/enterprise-linux.json` | `/etc/chromium/policies/managed/` |

Browsers ship as native vendor packages, not Flatpaks, because managed policy
files under `/etc` are the documented way to configure them, and Flatpak
sandboxes hide `/etc` from the browser.

## Desktop file IDs

Used by `mimeapps.list` and the dock favorites. `tests/check-apps.py` fails if a
profile uses an ID that is not in this table. **Confirm each against the bundles
work in `catalog/`** before the first image build.

| Desktop ID | App | Source | Confidence |
|---|---|---|---|
| `firefox-esr.desktop` | Firefox ESR | Mozilla APT repo | Medium: check the installed file name |
| `google-chrome.desktop` | Google Chrome | Google repo | High |
| `microsoft-edge.desktop` | Microsoft Edge | Microsoft repo | High |
| `chromium.desktop` | Chromium | Debian / Fedora | Medium (not on Ubuntu) |
| `libreoffice-writer.desktop` | LibreOffice Writer | Distro package | High |
| `libreoffice-calc.desktop` | LibreOffice Calc | Distro package | High |
| `libreoffice-impress.desktop` | LibreOffice Impress | Distro package | High |
| `org.mozilla.Thunderbird.desktop` | Thunderbird | Flatpak (curated remote) | Medium: Ubuntu's deb is a snap shim |
| `org.gnome.Nautilus.desktop` | Files | Core | High |
| `org.gnome.Evince.desktop` | Document Viewer (PDF) | Core | High; GNOME 47+ may ship Papers instead |
| `org.gnome.Loupe.desktop` | Image Viewer | Core | High on GNOME 45+ |
| `org.gnome.FileRoller.desktop` | Archive Manager | Core | High |
| `org.gnome.TextEditor.desktop` | Text Editor | Core | High |
| `org.enterpriselinux.Workplace.desktop` | Workplace (IT app) | This repo, `desktop/workplace/` | High |

The Microsoft 365 web apps are not pinned: Edge names their launchers
`msedge-<hash>-Default.desktop`, from a hash of the URL, so they cannot be
listed ahead of time.

## Files

```
profiles/<name>/mimeapps.list     -> /etc/xdg/mimeapps.list
profiles/<name>/favorites.dconf   -> /etc/dconf/db/enterprise-linux.d/20-favorites
profiles/<name>/edge-*.json       -> extra Edge policy for that profile
browsers/<browser>/...            -> browser policy files (table above)
install-apps.sh                   -> installer, called by desktop/install.sh
tests/check-apps.py               -> checks (run: python3 desktop/apps/tests/check-apps.py)
```

## Open questions

1. Is Chrome needed in the open-source profile, or is Firefox plus Chromium enough?
2. Mail in the Microsoft 365 profile: Thunderbird (Exchange support is new; test it), Evolution with EWS, or Outlook web only?
3. Which extensions go on the default allowlist (password manager, Microsoft SSO extension)?
4. Edge on Linux and Entra SSO: confirm the current Intune app requirements per substrate.
