# Curated apps and selectable built-in bundles

**Status:** first build — bundle manifests, browser and office policy files, and a reference installer exist in [`catalog/`](../catalog/README.md), [`policies/`](../policies/), and `scripts/apps/elapps`. Validated and rendered locally (CI workflow staged in `ci/`); **not yet installed on a real image**. Seed v0 below is a proposal for Rohi to confirm.  
**Date:** 2026-10-29 (built from the 2026-10-28 design)  
See `docs/ARCHITECTURE.md` §5.4 and §8 (app seed v0). Related: [CONTROL-API.md](CONTROL-API.md), [DESKTOP-UX.md](DESKTOP-UX.md), [MARKETPLACE.md](MARKETPLACE.md).

## Intent

Org-approved application set — baked into the default image profile and/or installable only from our gated set. **The org chooses which built-in apps ship**, instead of taking one fixed list.

---

## 1. Three moments to choose apps

| When | Who chooses | How |
|---|---|---|
| **Build time** | Org IT, in the image build config | Pick bundles in the build manifest → apps baked into the image (fast first boot, works offline) |
| **Enrollment time** | MDM policy, per group | `apps.bundles: [base, office, dev]` → installed on first sync |
| **Self-service** | The employee, inside the allowed catalog | Desktop "App Center" ([DESKTOP-UX.md](DESKTOP-UX.md)); may need approval per app |

All three use the same catalog and the same API (`apps.*` in [CONTROL-API.md](CONTROL-API.md)).

---

## 2. Bundles (built as manifests in `catalog/bundles/`)

| Bundle | Purpose | Contents | In default profile |
|---|---|---|---|
| **core** (not removable) | What the OS needs to be managed and secure | Flatpak + portals, xdg-utils, CUPS, firewalld, installer runtime. `eld`/`elctl` join when packaged | Yes |
| **base** | Daily work (GNOME apps) | Evince (PDF), Loupe (images), File Roller, Calculator, Text Editor, Document Scanner | Yes |
| **browsers** | Managed browsers | Microsoft Edge, Google Chrome, Firefox ESR — each with enterprise policies preconfigured | Yes |
| **browsers-extra** | Opt-in browsers | Chromium, Brave (Brave blocked until its repo key is verified) | No |
| **office-microsoft365** | Microsoft Office on Linux | Microsoft 365 web apps pinned as PWAs by Edge policy: Office portal, Outlook, Word, Excel, PowerPoint, OneNote, OneDrive, Teams | Yes (via `office`) |
| **office-oss** | Open-source office | LibreOffice (locked macro security, OOXML save default), ONLYOFFICE, Thunderbird, Evolution + EWS | Yes (via `office`) |
| **office** | Meta bundle | `office-microsoft365` + `office-oss` | Yes |
| **collaboration** | Meetings and chat | Zoom, Slack (Teams is in office-microsoft365) | No |
| **dev** | Engineering (power-user) | Git, VS Code, VSCodium, Podman, Distrobox | No |
| **design-media** | Creative work | GIMP, Inkscape, Krita, Kdenlive, OBS | No |
| **security-tools** | SOC / IT, restricted group | Wireshark, Nmap, KeePassXC | No |
| **accessibility** | Assistive tech | Orca + espeak-ng | Yes |
| **locale-he** | Hebrew / RTL | Noto + Culmus Hebrew fonts, Hebrew spelling | Yes |

**Profiles** (`catalog/profiles/`) pick bundles and the system default apps for a device group:

| Profile | Bundles | Default browser / office / mail |
|---|---|---|
| `default` | core, base, browsers, office, accessibility, locale-he | Edge / LibreOffice / Thunderbird |
| `microsoft365` | core, base, browsers, office-microsoft365, accessibility | Edge / (web) / (web) |
| `open-source` | core, base, browsers, office-oss, accessibility | Firefox ESR / LibreOffice / Thunderbird |
| `developer` | default + collaboration + dev | Edge / LibreOffice / Thunderbird |

Format, rules, and the installer are documented in [`catalog/README.md`](../catalog/README.md). Browser policy details: [`policies/browsers/README.md`](../policies/browsers/README.md). Office options and trade-offs: [`policies/office/README.md`](../policies/office/README.md).

### Microsoft Office on Linux — what is real

Microsoft ships **no native desktop Office for Linux**. The supported path is the Microsoft 365 web apps; we pin them as installed web apps (own window, launcher icon) through Edge's `WebAppInstallForceList` policy. The native Teams client for Linux was retired by Microsoft, and there is no OneDrive sync client for Linux. For offline work and local files, LibreOffice or ONLYOFFICE handle `.docx` / `.xlsx` / `.pptx`.

## 3. Packaging rules

- **System components:** native packages (deb/rpm) from our **frozen, signed repo snapshot**.
- **User apps:** **Flatpak from our own curated remote** (mirrored and pinned from Flathub/vendors), never unbounded Flathub. Portal permissions are set by policy per app.
- **Web apps:** PWAs installed and pinned by policy for SaaS (M365, Google Workspace, Jira) — no local install needed.
- **Vendor apps** (Teams, Zoom, Slack, VPN clients, EDR): vendor-signed packages mirrored into our repo after review.
- **Dev escape hatch:** `power-user` role gets Toolbox/Distrobox containers — packages install *inside* a container, never on the host.
- **No** AppImage / curl-pipe-bash / unsigned repos on managed devices (blocked by allowlisting in [HARDENING.md](HARDENING.md)).

---

## 4. Catalog governance

- Every app has an **owner**, a **review date**, a **source**, a **license**, and a **risk note**.
- New app request → review (security + license) → added to catalog → visible in App Center for the allowed groups.
- Apps can be **blocked fleet-wide** within one policy cycle (`apps.block`), e.g. after a CVE.
- Seed and catalog changes enter through this repo + review.

---

## 5. Seed v0 (proposal)

The `default` profile above is the proposed seed v0. Each app's package names per family, Flatpak ref, owner, review date, license, and risk note live in its bundle manifest. Rohi to confirm or change.

---

## 6. Open questions

1. ~~Is the browser Firefox ESR, Chromium, Edge, or org choice?~~ Built as org choice: three managed browsers ship, the profile sets the default (Edge in `default`, because M365 sign-in and conditional access work best there).
2. ~~Office: LibreOffice locally, M365 web only, or both?~~ Built as both (`office` meta bundle) with profiles for either side. Still open: default save format (OOXML now) and default mail client (Thunderbird now).
3. Should bundle choice be offered in a **first-boot wizard** to the user, or only by IT?
4. Do we host our own Flatpak remote from day 1 or start with a pinned allowlist of Flathub refs?
