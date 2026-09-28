# Architecture: Enterprise Linux (org workstation OS)

**Status:** concept ADR (not a shipping OS)  
**Owner:** cto-max-grok  
**Repo (proposed):** `RohiRIK/enterprise-linux`  
**Date:** 2026-09-28  

This document is design-only. No ISO, no distro fork, no support contract claims.

---

## 1. Problem

Organizations that want Linux on **employee workstations** (not only servers) usually get one of:

- A generic desktop distro with weak SSO, weak fleet update story, and no org image pipeline.
- A locked vendor stack (expensive, slow to customize).
- Homegrown golden images that rot because nobody owns supply chain, identity, or harden as one system.

**Enterprise Linux (working name)** is a *workstation-oriented* Linux distribution *line* aimed at that gap: one opinionated path from **CI → signed image → identity join → hardened defaults → controlled updates**, so an org can run Linux laptops/desktops without inventing the platform each time.

Primary user: IT / security / platform owners who already live in Microsoft 365 / Entra (or classic AD) and want Linux next to Windows, not instead of an identity plane.

---

## 2. Non-goals (day 1 and near term)

- **Not** rewriting the kernel or inventing a new userspace from scratch.
- **Not** competing with Red Hat (or Canonical) support contracts on day 1.
- **Not** a cloud server OS product (servers may drink from the same image later; workstation is the wedge).
- **Not** shipping an Omarchy fork as the org base (Omarchy stays a personal / power-user desktop family; see base options).
- **Not** marketing fluff, App Store narratives, or “AI OS” claims.
- **Not** promising FedRAMP / CIS certification on day 1 (we can *track* baselines; we do not claim certified).
- **Not** building a full MDM competitor before we have one image that boots, joins, and updates.

---

## 3. Base options

| Option | What it is | Pros | Cons |
|---|---|---|---|
| **A. Ubuntu 24.04 LTS** | Derive images via autoinstall / cloud-init; keep Ubuntu packages + HWE as needed | Best laptop hardware story; huge package index; familiar autoinstall + cloud-init; easy GitHub Actions builders; Entra/AD paths exist (sssd, Ubuntu auth story, third-party) | Not RHEL-compatible; some regulated shops demand RHEL ABI |
| **B. Rocky (RHEL-compatible)** | Rocky 9/10 as base; kickstart / image builder | SELinux default culture; RHEL muscle memory; better fit for “must look like RHEL” orgs | Laptop/GPU pain higher; slower desktop polish; smaller “just works” laptop path |
| **C. Omarchy-family desktop** | Treat Omarchy (or a Quattro profile) as the org desktop | Continuity with Rohi’s public Omarchy plugins; great developer UX | Niche; not an SSO/fleet/compliance base; wrong wedge for *enterprise org* workstations |

### Recommendation

**Day-1 base: Ubuntu 24.04 LTS (option A).**

Why: the product is an *org workstation* line. Hardware breadth, autoinstall, and identity glue matter more than RHEL ABI for the first buyers we can actually serve. Rocky becomes a **second track** only if Rohi names RHEL-compatible shops as a hard requirement.

**Omarchy:** keep as an optional **developer workstation profile** later (apps, bar plugins, defaults) layered *on* the org image — not the foundation.

---

## 4. Day-1 pillars

### 4.1 Identity (SSO)

- **Primary bet:** Entra ID join / SSO for org users (aligns with Argus / M365 world).
- **Secondary:** classic AD via sssd documented, not necessarily automated in MVP.
- **Rule:** a workstation is not “done” until a standard user can unlock/login with org identity and get a home that is not a local-only orphan.
- **Non-goal:** inventing our own IdP.

### 4.2 Harden

- Disk encryption on by default for laptop profiles (TPM unlock where available; recovery key escrow story documented even if escrow automation is later).
- Firewall on; SSH off by default on laptop images (on only for break-glass profile).
- Unattended security updates for the OS package set; no silent major-release upgrades.
- Start from a public baseline (e.g. Ubuntu Security Guide / CIS-oriented controls) as a *checklist we implement*, not a certification claim.
- Local admin: break-glass account pattern; day-to-day user is standard.

### 4.3 Image / supply (CI → image)

- **Source of truth:** this GitHub repo (autoinstall, cloud-init, package seed, harden scripts, version pins).
- **Pipeline:** GitHub Actions builds a reproducible image artifact (ISO and/or raw/qcow for VM test) on tag; checksums published; signing when Rohi supplies signing keys (unsigned is OK for private early; public needs a signature story before “trust us”).
- **No** hand-rolled ISOs on a laptop as the release process.
- Installers / first-boot must follow Omarchy-family rule spirit: only touch files/links *this* project created (marker + checksum). Do not clobber user desktop entries or foreign configs.

### 4.4 Update story

- Security updates: unattended-upgrades (or equivalent) with a documented reboot window.
- App/desktop layer: prefer distro packages + a small curated flatpak allowlist if needed; avoid “curl | bash” as the update channel.
- Major version (24.04 → next LTS): explicit release train, not automatic.
- Inventory signal: every image reports version / build id so fleet drift is visible (osquery or a tiny inventory agent — decide in MVP).

---

## 5. MVP boundary (about 4–8 weeks of focused work)

**In**

1. Public (or private) repo skeleton + this ADR + short README (what / why / non-goals).
2. One **laptop-oriented** Ubuntu 24.04 autoinstall seed (packages + harden hooks).
3. CI that builds *something bootable in a VM* on tag (even if ugly) with checksums.
4. Identity path documented + scripted for **one** of: Entra join *or* AD/sssd (pick with Rohi — default proposal Entra).
5. Update path: security unattended-upgrades on; major upgrade off.
6. Inventory: build id in `/etc/os-release`-style custom fields or a small fact file; optional osquery later.
7. Docs: install in VM, join identity, verify updates — three pages max.

**Out (explicit)**

- Custom kernel, Secure Boot signing infrastructure beyond “document what we need”.
- Full MDM, compliance dashboards, device attestation product.
- Rocky track, Omarchy profile pack, app store.
- Guarantees about battery life, GPU, or dock support matrices.
- Support SLAs.

---

## 6. Suggested layout (repo skeleton)

```
README.md                 # short: what / why / non-goals
LICENSE                   # MIT
docs/ARCHITECTURE.md      # this file
docs/IDENTITY.md          # stub until path chosen
docs/HARDENING.md         # stub checklist
docs/IMAGE-PIPELINE.md    # stub CI → artifact
image/                    # autoinstall / cloud-init seeds (placeholders OK)
scripts/                  # harden / first-boot helpers (placeholders OK)
.github/workflows/        # build on tag (can land empty then fill)
```

No ISO blobs in git. Artifacts live on Releases.

---

## 7. Open questions for Rohi

1. **Visibility:** public MIT from day 1, or private until first VM image boots?
2. **Identity wedge:** Entra-first (recommended), AD-first, or both in MVP?
3. **Name lock:** keep `enterprise-linux`, or prefer a short product name (still English, still boring)?
4. **RHEL-compatible:** is Rocky a hard day-1 requirement for a named customer, or later track?
5. **Omarchy:** confirm “profile later, not base” — or do you want a developer flavor in MVP?
6. **Signing:** do we have (or will we create) a release-signing key before public image claims?
7. **Fleet assumption:** tens of machines (script + docs OK) or hundreds (needs inventory + update policy sooner)?

---

## 8. Decision summary

| Topic | Decision |
|---|---|
| Product wedge | Org **workstations**, not servers |
| Base | **Ubuntu 24.04 LTS** |
| Rocky / Omarchy | Later tracks / profiles — not day-1 base |
| Pillars | SSO, harden, CI→image, controlled updates |
| License | MIT (unless Rohi flips) |
| Now | Memo + repo skeleton only |

When Rohi answers §7, revise this ADR in place and unlock joe’s image-pipeline SHIP.
