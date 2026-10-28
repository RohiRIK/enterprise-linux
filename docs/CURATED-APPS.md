# Curated apps and selectable built-in bundles

**Status:** design only — nothing built. Seed v0 still waits on Rohi.  
**Date:** 2026-10-28 (expanded from the original stub)  
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

## 2. Bundles (draft — names and content to be confirmed)

| Bundle | Purpose | Example contents (illustrative) | Default |
|---|---|---|---|
| **core** (not removable) | What the OS needs to be managed and secure | Desktop shell, file manager, settings app, our desktop app, identity module, `eld`/`elctl`, firewall, update client | Always |
| **base** | Daily work | Browser (Firefox ESR and/or Chromium/Edge as policy), PDF viewer, image viewer, calculator, archive tool, screenshot tool, printer/scanner support | On |
| **office** | Office productivity | LibreOffice, or M365 web apps as PWAs; mail/calendar (Thunderbird / Evolution with EWS) | Optional |
| **collaboration** | Meetings and chat | Teams/Zoom/Slack as vendor-supported packages or PWAs | Optional |
| **dev** | Engineering | Git, VS Code / VSCodium, Podman + Toolbox/Distrobox, language runtimes, terminal extras | Optional, power-user role |
| **design / media** | Creative work | GIMP, Inkscape, Krita, Kdenlive, OBS | Optional |
| **security-tools** | SOC / IT | Wireshark, nmap, KeePassXC | Optional, restricted group |
| **accessibility** | Assistive tech | Orca, high-contrast themes, on-screen keyboard | Always available, per user |
| **locale packs** | Languages, input methods, RTL fonts (e.g. Hebrew + Arabic fonts, IBus) | Per org |

Each bundle is a **versioned manifest** in this repo (`catalog/bundles/<name>.yaml`, when built):

```yaml
apiVersion: enterprise-linux/v1
kind: AppBundle
metadata: { name: base, version: 2026.10.0, owner: it-platform }
apps:
  - id: org.mozilla.firefox         # Flatpak ref
    source: flatpak:curated
    pin: "esr"
    permissions: { filesystem: [ "xdg-download" ], devices: [] }
  - id: libreoffice
    source: native                  # deb/rpm from the frozen repo snapshot
```

---

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

## 5. Seed v0

Empty until Rohi names must-have apps. When filled, list package IDs / flatpak IDs we pin, with owner and why.

---

## 6. Open questions

1. Is the browser Firefox ESR, Chromium, Edge, or org choice? (Affects SSO/conditional access — Entra device compliance in the browser.)
2. Office: LibreOffice locally, M365 web only, or both?
3. Should bundle choice be offered in a **first-boot wizard** to the user, or only by IT?
4. Do we host our own Flatpak remote from day 1 or start with a pinned allowlist of Flathub refs?
