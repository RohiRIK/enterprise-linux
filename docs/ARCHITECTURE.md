# Architecture: Enterprise Linux (org workstation OS)

**Status:** concept ADR (not a shipping OS)  
**Owner:** cto-max-grok  
**Repo:** `RohiRIK/enterprise-linux`  
**Date:** 2026-09-28 (revised: drop desktop-family coupling; Arch scout; frozen core)

This document is design-only. No ISO, no distro fork, no support contract claims.

---

## 1. Problem

Organizations that want Linux on **employee workstations** (not only servers) usually get one of:

- A generic desktop distro with weak SSO, weak fleet update story, and no org image pipeline.
- A locked vendor stack (expensive, slow to customize).
- Homegrown golden images that rot because nobody owns supply chain, identity, or harden as one system.
- Rolling / enthusiast desktops that move under the user’s feet — fine for a daily driver, wrong for an org fleet.

**Enterprise Linux (working name)** is a *workstation-oriented* Linux line aimed at that gap: a **frozen core** (pinned base, controlled updates, reproducible images) plus one opinionated path from **CI → image (signed when keys exist) → identity join → hardened defaults → controlled updates**.

Primary user: IT / security / platform owners who already live in Microsoft 365 / Entra (or classic AD) and want Linux next to Windows, not instead of an identity plane.

---

## 2. Non-goals (day 1 and near term)

- **Not** rewriting the kernel or inventing a new userspace from scratch.
- **Not** competing with Red Hat (or Canonical) support contracts on day 1.
- **Not** a cloud server OS product (servers may drink from the same image later; workstation is the wedge).
- **Not** a rolling desktop experiment or a personal daily-driver distro product.
- **Not** marketing fluff, App Store narratives, or “AI OS” claims.
- **Not** promising FedRAMP / CIS certification on day 1 (we can *track* baselines; we do not claim certified).
- **Not** building a full MDM competitor before we have one image that boots, joins, and updates.

---

## 3. Design thesis: frozen core

**Frozen core** means:

- One **pinned** base release (not a rolling tip).
- Package and config changes enter through **this repo + CI**, not through “user ran pacman -Syu on Monday.”
- Security updates are allowed on a controlled channel; **major** upgrades are an explicit release train.
- The golden image is reproducible: same inputs → same build id.

This is the opposite of a hobbyist rolling desktop. Org workstations need predictability more than newest packages.

---

## 4. Base options

| Option | What it is | Pros for org workstations | Cons |
|---|---|---|---|
| **A. Vanilla Ubuntu 24.04 LTS** | Derive images via autoinstall / cloud-init; Ubuntu archive + pins | Best laptop hardware story; LTS freeze matches frozen-core; huge package index; autoinstall + cloud-init; easy Actions builders; Entra/AD paths exist (sssd / Ubuntu auth / third-party) | Not RHEL-compatible; some regulated shops demand RHEL ABI |
| **B. Rocky (RHEL-compatible)** | Rocky 9/10; kickstart / image builder | SELinux culture; RHEL muscle memory | Laptop/GPU pain higher; slower “just works” laptop path |
| **C. Arch (scout)** | Arch or an Arch-based frozen snapshot (e.g. dated mirror + package list lock) | Excellent packaging; easy to reason about a *declared* package set; good if the hard criterion is “minimal base we fully pin ourselves” | Default Arch is **rolling** — fights frozen-core unless we invent and maintain our own freeze/mirror discipline; weaker out-of-box org SSO / laptop fleet story; higher support load for IT |

### Arch scout (brief)

Arch only wins day 1 if Rohi has a **hard** criterion that Ubuntu fails, for example:

- Must own every package pin without an LTS vendor train, **and**
- Will fund a private freeze mirror + update train as a first-class product surface.

Otherwise Arch’s rolling default is the wrong shape for org workstations. A home-grown Arch freeze is real engineering (mirrors, rebuild, security backport policy) — it is not free just because `pacman` is nice.

**Rocky** stays a later track if RHEL-compatible shops appear — unchanged from prior ADR.

### Recommendation

**Day-1 base: vanilla Ubuntu 24.04 LTS (option A).**

Stay on Ubuntu unless Arch (or Rocky) wins on an explicit hard criterion from Rohi. Do not couple this product to any personal desktop project; this repo stands alone.

---

## 5. Day-1 pillars

### 5.1 Identity (SSO)

- **Primary bet:** Entra ID join / SSO for org users (aligns with M365-heavy orgs).
- **Secondary:** classic AD via sssd documented, not necessarily automated in MVP.
- **Rule:** a workstation is not “done” until a standard user can unlock/login with org identity and get a home that is not a local-only orphan.
- **Non-goal:** inventing our own IdP.

### 5.2 Harden

- Disk encryption on by default for laptop profiles (TPM unlock where available; recovery key escrow story documented even if escrow automation is later).
- Firewall on; SSH off by default on laptop images (on only for break-glass profile).
- Unattended **security** updates for the OS package set; no silent major-release upgrades.
- Start from a public baseline (e.g. Ubuntu Security Guide / CIS-oriented controls) as a *checklist we implement*, not a certification claim.
- Local admin: break-glass account pattern; day-to-day user is standard.

### 5.3 Image / supply (CI → image)

- **Source of truth:** this GitHub repo (autoinstall, cloud-init, package seed, harden scripts, version pins).
- **Pipeline:** GitHub Actions builds a reproducible image artifact (ISO and/or raw/qcow for VM test) on tag; checksums published; **signing when keys exist** (unsigned is OK early; public “trust us” needs a signature story).
- **No** hand-rolled ISOs on a laptop as the release process.
- First-boot / install helpers may only create or update files and links **this** project owns (marker + checksum). Do not clobber foreign desktop entries or unrelated configs.

### 5.4 Update story (frozen core in practice)

- Security updates: unattended-upgrades (or equivalent) with a documented reboot window.
- App/desktop layer: prefer distro packages + a small curated flatpak allowlist if needed; avoid `curl | bash` as the update channel.
- Major version (24.04 → next LTS): explicit release train, not automatic.
- Inventory signal: every image reports version / build id so fleet drift is visible (osquery or a tiny fact file — decide in MVP).

---

## 6. MVP boundary (about 4–8 weeks of focused work)

**In**

1. Public repo + this ADR + short README (what / why / non-goals).
2. One **laptop-oriented** Ubuntu 24.04 autoinstall seed (packages + harden hooks + pins).
3. CI that builds *something bootable in a VM* on tag (even if ugly) with checksums; signing when keys exist.
4. Identity path documented + scripted for **one** of: Entra join *or* AD/sssd (pick with Rohi — default proposal Entra).
5. Update path: security unattended-upgrades on; major upgrade off.
6. Inventory: build id in custom os-release fields or a small fact file.
7. Docs: install in VM, join identity, verify updates — three pages max.

**Out (explicit)**

- Custom kernel, Secure Boot signing infrastructure beyond “document what we need”.
- Full MDM, compliance dashboards, device attestation product.
- Rocky track, Arch freeze mirror product, personal-desktop flavors.
- Guarantees about battery life, GPU, or dock support matrices.
- Support SLAs.

---

## 7. Suggested layout (repo skeleton)

```
README.md                 # short: what / why / non-goals
LICENSE                   # MIT
docs/ARCHITECTURE.md      # this file
docs/IDENTITY.md          # stub until path chosen
docs/HARDENING.md         # stub checklist
docs/IMAGE-PIPELINE.md    # stub CI → artifact
image/                    # autoinstall / cloud-init seeds
scripts/                  # harden / first-boot helpers
.github/workflows/        # build on tag (when workflow scope exists)
```

No ISO blobs in git. Artifacts live on Releases.

---

## 8. Open questions for Rohi

1. **Identity wedge:** Entra-first (recommended), AD-first, or both in MVP?
2. **Name lock:** keep `enterprise-linux`, or prefer a short product name (still English, still boring)?
3. **RHEL-compatible:** is Rocky a hard day-1 requirement for a named customer, or later track?
4. **Arch:** any hard criterion that would force an Arch frozen-core track instead of Ubuntu LTS? (Default: no.)
5. **Signing:** do we have (or will we create) a release-signing key before public image claims?
6. **Fleet assumption:** tens of machines (script + docs OK) or hundreds (needs inventory + update policy sooner)?

Visibility is already **public MIT** on `RohiRIK/enterprise-linux` unless Rohi flips it.

---

## 9. Decision summary

| Topic | Decision |
|---|---|
| Product wedge | Org **workstations**, frozen core — not rolling desktop |
| Base | **Vanilla Ubuntu 24.04 LTS** |
| Arch | Scouted; **do not adopt** unless a hard criterion wins |
| Rocky | Later track if RHEL shops appear |
| Personal desktop projects | **Decoupled** — out of scope for this product |
| Pillars | SSO, harden, CI→image (sign when keys exist), controlled updates |
| License | MIT |
| Next | Image pipeline after Rohi answers §8 |

When Rohi answers §8, revise this ADR in place and unlock the image-pipeline SHIP.
