# Catalog — curated app bundles

**Status:** first build of the bundle format. Manifests, policy files, and the
installer exist. A CI workflow (`ci/catalog.workflow.yml`, to be moved into
`.github/workflows/`) checks schema, references, and rendering on Ubuntu,
Debian, Fedora, AlmaLinux, and openSUSE containers. Nothing has been
installed on a real image yet, and the substrate is not locked (see [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) §8).
Marketplace plugins are still not live. Design background:
[`docs/CURATED-APPS.md`](../docs/CURATED-APPS.md).

## Layout

```
catalog/
  bundles/<name>.yaml     AppBundle manifests (what an org can switch on)
  repos/<name>.yaml       VendorRepo definitions (signed third-party package repos)
  profiles/<name>.yaml    BundleProfile: which bundles + default apps for a device group
  schema/                 JSON Schemas for the three kinds
policies/
  browsers/<browser>/     Managed browser policy files (installed by the bundle)
  office/<app>/           Office app default configuration
scripts/apps/elapps       Installer / validator (Python 3 + PyYAML only)
```

## Distro-agnostic by design

The substrate is not locked, so every app declares how to get it on each
package family. The installer detects the family at run time:

| Family key | Package manager | Covers |
|---|---|---|
| `apt` | apt / dpkg | Ubuntu, Debian |
| `dnf` | dnf / rpm | RHEL, Fedora, AlmaLinux, Rocky |
| `zypper` | zypper / rpm | SUSE / openSUSE |
| `flatpak` | flatpak | any family, from the curated remote |
| `pwa` | browser policy | any family; web app pinned by a managed browser |

An app lists one or more methods. The profile's `prefer` order (default
`[native, flatpak, pwa]`) picks the first method that exists for the device's
family, where `native` means the `apt` / `dnf` / `zypper` key that matches.

## AppBundle

```yaml
apiVersion: enterprise-linux/v1
kind: AppBundle
metadata:
  name: browsers                 # == file name
  version: 2026.10.0             # CalVer, bumped on any change
  owner: it-platform
  description: Managed web browsers with enterprise default policies.
spec:
  removable: true                # false only for core
  includes: []                   # other bundles pulled in with this one
  apps:
    - id: microsoft-edge         # stable catalog id, used by policy (apps.block)
      name: Microsoft Edge
      category: browser          # browser | office | mail | pdf | ... (free text)
      license: proprietary       # SPDX id or "proprietary"
      review: { owner: it-platform, date: 2026-10-28 }
      risk: Vendor binary; telemetry limited by policy.
      provides: [browser]        # roles this app can fill as a system default
      desktopFile: microsoft-edge.desktop   # used for default-app selection
      install:
        apt:     { packages: [microsoft-edge-stable], repo: microsoft-edge }
        dnf:     { packages: [microsoft-edge-stable], repo: microsoft-edge }
        zypper:  { packages: [microsoft-edge-stable], repo: microsoft-edge }
        flatpak: { ref: com.microsoft.Edge, remote: curated }
        # pwa:   { url: https://..., browser: microsoft-edge }   # web apps only
      policies:                  # files copied after install, path relative to repo root
        - file: policies/browsers/edge/10-baseline.json
          dest: /etc/opt/edge/policies/managed/10-enterprise-linux-baseline.json
          # dest may also be a map per family: { default: ..., apt: ..., dnf: ... }
          # appliesTo: [native]  # optional: only for these install methods
```

Optional app fields:

- `desktopFile` may be a map when the launcher differs:
  `{ native: ..., flatpak: ..., apt: ..., dnf: ..., zypper: ..., default: ... }`.
  Lookup order is install method, then family, then `default`. For Flatpak
  apps without an entry, `<ref>.desktop` is used.
- `defaultFor: [{ mime, desktopFile }]` lists the MIME types the app claims
  when a profile makes it the default for one of its `provides` roles (used by
  office apps and mail clients). Without it the installer uses its built-in
  list for the role (`browser`, `mail`, `calendar`, `pdf`, `image`, `archive`).

Rules:

- `remote: curated` is our own mirrored Flatpak remote. Until it exists the
  installer maps it to Flathub with the pinned ref only (open question 4 in
  `CURATED-APPS.md`).
- `repo:` must name a file in `catalog/repos/`. No repo is added unless its
  signing-key fingerprint is listed there.
- Policy files never contain secrets, tenant IDs, or org URLs. Org values come
  from the profile (`settings:`) and are rendered at install time from
  `{{ placeholders }}`. Placeholders sit inside JSON strings so files stay
  valid JSON. When a setting is empty, the string that uses it is **dropped**
  with its key or list slot (so `".*@{{ m365_tenant_domain }}"` never becomes
  a pattern that matches every account). Every placeholder must be defined in
  every profile.
- A profile may not use an app whose vendor repo has an unverified key
  fingerprint (`TODO-verify`); `validate` fails and `apply` refuses.

## VendorRepo

```yaml
apiVersion: enterprise-linux/v1
kind: VendorRepo
metadata: { name: microsoft-edge, owner: it-platform }
spec:
  key:
    url: https://packages.microsoft.com/keys/microsoft.asc
    fingerprint: BC528686B50D79E339D3721CEB3E94ADBE1229CF   # verified before trust
  apt:    { uri: https://packages.microsoft.com/repos/edge, suite: stable, components: [main] }
  dnf:    { baseurl: https://packages.microsoft.com/yumrepos/edge }
  zypper: { baseurl: https://packages.microsoft.com/yumrepos/edge }
```

On managed devices these URLs are replaced by our frozen mirror; the upstream
URLs are the mirror's source.

## BundleProfile

```yaml
apiVersion: enterprise-linux/v1
kind: BundleProfile
metadata: { name: default }
spec:
  prefer: [native, flatpak, pwa]
  bundles: [core, base, browsers, office-microsoft365, office-oss]
  defaults:                      # system-wide default apps (/etc/xdg/mimeapps.list)
    browser: microsoft-edge
    mail: thunderbird
    office: libreoffice          # opens .docx / .xlsx / .pptx / .odt ...
    pdf: evince
  settings:                      # values rendered into policy placeholders
    homepage: https://www.office.com
    m365_tenant_domain: ""       # e.g. contoso.com; empty = not restricted
```

## What ships today

| Bundle | Apps |
|---|---|
| `core` | flatpak + portals, xdg-utils, printing, firewalld, installer runtime |
| `base` | evince, loupe, file-roller, gnome-calculator, gnome-text-editor, simple-scan |
| `browsers` | microsoft-edge, google-chrome, firefox-esr |
| `browsers-extra` | chromium, brave (opt-in) |
| `office` | meta: office-microsoft365 + office-oss |
| `office-microsoft365` | m365-portal, m365-outlook, m365-word, m365-excel, m365-powerpoint, m365-onenote, m365-onedrive, m365-teams (PWAs in Edge) |
| `office-oss` | libreoffice, onlyoffice-desktopeditors, thunderbird, evolution |
| `collaboration` | zoom, slack |
| `dev` | git, vscode, vscodium, podman, distrobox |
| `design-media` | gimp, inkscape, krita, kdenlive, obs-studio |
| `security-tools` | wireshark, nmap, keepassxc |
| `accessibility` | orca |
| `locale-he` | hebrew-fonts, hebrew-spelling |

Profiles: `default`, `microsoft365`, `open-source`, `developer`. Package
names marked `# verify` in the manifests have not been checked on that family.

## Using the installer

```sh
scripts/apps/elapps validate                       # schema + cross-reference checks
scripts/apps/elapps list                           # bundles and apps
scripts/apps/elapps plan --profile default         # what would happen on this machine
scripts/apps/elapps plan --profile default --family dnf   # ... on another family
sudo scripts/apps/elapps apply --profile default   # install + write policies + defaults
scripts/apps/elapps apply --profile default --root /tmp/img --files-only   # stage files into an image root
```

`plan` never changes the system. `apply` is idempotent. The future `eld`
daemon ([`docs/CONTROL-API.md`](../docs/CONTROL-API.md), `apps.*`) is expected
to call the same logic; until then this script is the reference.
