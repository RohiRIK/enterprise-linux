# Office options — policy files

**Status:** design stage. These files and the manifests that install them exist;
none of it has been tested on a released image. The substrate is not locked, so
everything is written for the `apt`, `dnf` and `zypper` families (see
[`catalog/README.md`](../../catalog/README.md)).

There is **no Microsoft-supported native Microsoft Office for Linux**. "Office"
on this workstation means one or both of:

| Bundle | What the user gets |
|---|---|
| [`office-microsoft365`](../../catalog/bundles/office-microsoft365.yaml) | Microsoft 365 web apps (Microsoft 365 portal, Outlook, Word, Excel, PowerPoint, OneNote, OneDrive, Teams) pinned as PWAs by Microsoft Edge policy: own window, launcher icon, taskbar entry. Needs a Microsoft 365 subscription and network. |
| [`office-oss`](../../catalog/bundles/office-oss.yaml) | LibreOffice (native or Flatpak) with locked-down defaults, ONLYOFFICE Desktop Editors (Flatpak), Thunderbird, Evolution with Exchange Web Services (EWS). Works offline. |
| [`office`](../../catalog/bundles/office.yaml) | Meta bundle: both of the above. |

## Trade-offs

| | M365 web apps (Edge PWA) | LibreOffice | ONLYOFFICE Desktop Editors |
|---|---|---|---|
| OOXML (.docx/.xlsx/.pptx) fidelity | Native format; web apps lack some desktop-Office features | Good for most documents; complex layouts, SmartArt, some charts can shift | Very good layout fidelity (OOXML is its internal model) |
| ODF (.odt/.ods/.odp) | Opens / converts | Native format, best | Supported, less mature |
| Offline | No (Outlook web has limited offline) | Yes | Yes |
| Real-time co-authoring | Yes, in the tenant | No (local files) | Only when connected to an ONLYOFFICE Docs / Nextcloud server |
| Macros | Excel web does not run VBA | Basic/VBA macros; locked to "Very high" security here | Its own JavaScript macros; no VBA |
| License / cost | Proprietary, per-user subscription | MPL-2.0, no cost | AGPL-3.0-only, no cost (desktop) |
| Entra ID Conditional Access | Works with Edge; "compliant device" needs Intune enrollment of the Linux device (Microsoft lists Ubuntu and RHEL; our OS: open question) | Not applicable (local files); files from OneDrive/SharePoint go through the browser | Not applicable |
| Updates | Microsoft, continuous | OS package manager / curated Flatpak remote | Curated Flatpak remote (bundles its own Chromium engine) |
| Hebrew / RTL | Yes | Yes (needs locale bundle for UI pack + dictionaries) | Yes |

Mail and calendar:

| | Outlook (web PWA) | Thunderbird | Evolution + evolution-ews |
|---|---|---|---|
| Microsoft 365 | Full | IMAP/SMTP with OAuth2; Exchange (EWS) in recent releases | EWS — Microsoft has announced EWS retirement for Exchange Online, so plan for that |
| On-prem Exchange | OWA only | EWS (recent releases) | EWS |
| Offline | Limited | Yes | Yes |
| System `mailto:` handler | Not without extra glue | Yes (`defaultFor`) | Yes (`defaultFor`) |

Teams: Microsoft retired the native Teams for Linux client in 2022. The web app /
PWA is the remaining path and is part of `office-microsoft365`. OneDrive has no
Microsoft sync client for Linux; the OneDrive PWA is browser access only.

## Files and where they install

| File | Installed to | When |
|---|---|---|
| `microsoft365/30-m365-pwas.json` | `/etc/opt/edge/policies/managed/30-enterprise-linux-m365-pwas.json` | `office-microsoft365` enabled, Edge installed natively |
| `libreoffice/enterprise-linux.xcd` | apt: `/usr/lib/libreoffice/share/registry/enterprise-linux.xcd`<br>dnf, zypper: `/usr/lib64/libreoffice/share/registry/enterprise-linux.xcd` | `libreoffice` installed natively (`appliesTo: [native]`) |

### `30-m365-pwas.json`

One Edge policy, `WebAppInstallForceList`, with every M365 URL in one list
(`default_launch_container: window`, `create_desktop_shortcut: true`). It is a
single file because a list policy set in two managed JSON files does not merge —
one wins. That also means the `browsers` bundle's Edge baseline must **not** set
`WebAppInstallForceList` itself (coordination point). The file is attached to the
`m365-portal` app; per-app removal via `apps.block` needs the installer to
render the list from the enabled `install.pwa` entries (not built yet).

Portal URL: `https://www.office.com/` (Microsoft redirects it to
`https://m365.cloud.microsoft/`). The `/launch/<app>` URLs are verify items: if
a URL has no web-app manifest, Edge installs it as a plain shortcut app.

Flatpak Edge: whether it reads `/etc/opt/edge/policies/managed/` from the host
is unverified, so the policy is limited to native Edge.

### `enterprise-linux.xcd`

A LibreOffice configuration layer, read after `main.xcd`. Settings:

| Setting | Value | Locked |
|---|---|---|
| Macro security (`Common/Security/Scripting/MacroSecurityLevel`) | 3 = Very high | yes |
| Default save format (`Setup/Office/Factories/.../ooSetupFactoryDefaultFilter`) | Word/Excel/PowerPoint 2007+ XML | no — documented choice, see open question 2 |
| Keep-format warning (`Common/Save/Document/WarnAlienFormat`) | off | no |
| Online update check (`Jobs/.../UpdateCheck/Arguments/AutoCheckEnabled`) | off (OS updates LibreOffice) | yes — verify |
| Crash report upload (`Common/Misc/CrashReport`) | off | yes — verify |
| Donate / Get involved / Tip of the day (`Common/Misc/ShowDonation`, `ShowGetInvolved`, `ShowTipOfTheDay`) | off | no — verify prop names per release |
| AutoRecovery (`Recovery/AutoSave`, `Recovery/RecoveryInfo`) | on, every 5 minutes | no |

The Flatpak LibreOffice reads its registry from its own read-only `/app` tree,
so this file does not apply there. Options for Flatpak (open question 4): a
Flatpak extension carrying the `.xcd`, or a per-user `registrymodifications.xcu`
seeded by the session — neither is built.

Debian also has `/etc/libreoffice/registry/`; whether a file there is picked up
instead of `share/registry/` is a verify item.

## How to verify (once a test image exists)

```sh
# Files are well-formed
python3 -c "import xml.etree.ElementTree as E; E.parse('policies/office/libreoffice/enterprise-linux.xcd')"
python3 -m json.tool policies/office/microsoft365/30-m365-pwas.json >/dev/null

# Edge: policy loaded and PWAs installed
#   open edge://policy  -> WebAppInstallForceList shows status OK
#   open edge://apps    -> the M365 apps are listed
ls ~/.local/share/applications/ | grep -i msedge

# LibreOffice: settings applied
#   Tools > Options > LibreOffice > Security > Macro Security: "Very high", greyed out
#   Tools > Options > Load/Save > General: "Always save as" = Word 2007-365
#   Tools > Options > Advanced > Open Expert Configuration: search MacroSecurityLevel
# Crash/update/infobar props: start LibreOffice from a terminal and look for
# "unknown prop" warnings — those mark a wrong prop name.

# Default apps (when the profile sets defaults.office / defaults.mail)
xdg-mime query default application/vnd.openxmlformats-officedocument.wordprocessingml.document
xdg-mime query default x-scheme-handler/mailto
```

## Open questions

1. **Default office app** for .docx/.xlsx/.pptx: `libreoffice` (current
   profile example) or `onlyoffice-desktopeditors` (better OOXML layout
   fidelity)? M365 PWAs cannot be the file handler for local files.
2. **Default save format:** OOXML (current, interoperates with M365 users) or
   ODF (ISO standard, LibreOffice's native format, some public-sector mandates)?
   Lock it or leave it user-changeable (current)?
3. **Default mail client:** Thunderbird or Evolution — and what replaces EWS for
   Exchange Online after Microsoft retires it.
4. **LibreOffice Flatpak policy:** how to apply the same defaults when the
   Flatpak is used (RHEL 10 and rebuilds no longer ship LibreOffice packages, so
   dnf-family devices there depend on the Flatpak).
5. **Conditional Access:** does Intune enrollment / Entra device compliance work
   on our OS, or only on the Microsoft-listed distributions?
6. **ONLYOFFICE native packages:** worth enabling the vendor repo
   (`catalog/repos/onlyoffice.yaml`, fingerprint still `TODO-verify`) or stay
   Flatpak-only?
7. **Tenant restriction:** should the M365 bundle use the profile's
   `m365_tenant_domain` (e.g. Edge tenant restrictions) — belongs in the Edge
   baseline policy of the `browsers` bundle.
