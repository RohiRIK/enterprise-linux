# Architecture: Enterprise Linux (org workstation OS)

**Status:** concept ADR (not a shipping OS)  
**Owner:** cto-max-grok  
**Repo:** `RohiRIK/enterprise-linux`  
**Date:** 2026-09-28 (revised: product thesis — curated experience on Ubuntu substrate)

This document is design-only. No ISO, no distro fork, no support contract claims. No live marketplace yet.

---

## 1. Problem

Organizations that want Linux on **employee workstations** usually get one of:

- A vanilla desktop distro with weak SSO, weak fleet updates, and no org image pipeline.
- A locked vendor stack (expensive, slow to customize).
- Homegrown golden images that rot because nobody owns supply chain, identity, apps, and harden as one system.
- Rolling / enthusiast desktops that move under the fleet’s feet.

“Install Ubuntu and hope” is not a product. IT needs a **curated workstation experience**: identity that works on day one, a frozen OS core, an org-approved app set, and (later) a controlled channel for plugins *we* prepare — not another untitled remix.

**Enterprise Linux (working name)** is that product line. **Ubuntu 24.04 LTS is the substrate**, not the brand story.

Primary user: IT / security / platform owners in Microsoft 365 / Entra (or classic AD) shops who want Linux next to Windows.

---

## 2. Product thesis

Four equal pillars (none optional in the vision; MVP ships a subset — see §7):

| Pillar | Meaning |
|---|---|
| **Frozen core** | Pinned Ubuntu LTS base; changes enter via this repo + CI; security updates controlled; major upgrades are an explicit train — not rolling desktop experiments. |
| **Strong SSO** | Headline, not a footnote. Org login (Entra-first) is how a machine becomes “done.” |
| **Curated apps** | Pre-defined, org-approved application set — baked into the image and/or gated by policy. Not “user install whatever from the internet.” |
| **Controlled plugin marketplace** | *Optional* channel of plugins **we prepare and sign/publish**. Not a random third-party free-for-all. Concept until supply chain + signing exist. |

**Non-positioning:** we are **not** competing as “another Ubuntu remix” brand-only. The substrate is Ubuntu; the product is the curated stack above it.

---

## 3. Non-goals (day 1 and near term)

- **Not** rewriting the kernel or inventing a new userspace from scratch.
- **Not** competing with Red Hat / Canonical support contracts on day 1.
- **Not** a cloud server OS product (workstation is the wedge).
- **Not** a rolling desktop or a personal daily-driver distro product.
- **Not** an open third-party app store / sideload free-for-all.
- **Not** claiming a live marketplace, signed plugin trust, or FedRAMP/CIS certification before those exist.
- **Not** marketing fluff or “AI OS” claims.
- **Not** full MDM before one image boots, joins SSO, and updates.

---

## 4. Substrate: base options

| Option | Role | Verdict |
|---|---|---|
| **A. Vanilla Ubuntu 24.04 LTS** | Substrate for frozen core + autoinstall / cloud-init | **Day-1 choice** |
| **B. Rocky (RHEL-compatible)** | Later track if a named customer requires RHEL ABI | Not day 1 |
| **C. Arch (scout)** | Only if Rohi names a hard criterion that forces a self-funded freeze mirror | **Do not adopt** by default — rolling fights frozen core |

### Recommendation

**Substrate: Ubuntu 24.04 LTS.** Product value lives in SSO + curated apps + (later) controlled marketplace + image pipeline — not in forking Ubuntu for its own sake.

Arch scout (unchanged): Arch wins only with an explicit hard criterion and funding for freeze/mirror/security backport as a product surface. Default remains Ubuntu.

---

## 5. Pillars in detail

### 5.1 Frozen core

- One pinned LTS base; package/config changes via this repo + CI.
- Security updates on a controlled channel; major upgrades = release train.
- Reproducible golden image: same inputs → same build id.
- Opposite of a hobbyist rolling desktop.

### 5.2 Strong SSO (headline)

- **Primary:** Entra ID join / SSO.
- **Secondary:** classic AD via sssd (documented; automate only if Rohi picks it for MVP).
- Done = standard user unlocks with org identity; home is not a local-only orphan.
- Non-goal: inventing our own IdP.

### 5.3 Curated apps

- A **declared** org-approved app set (seed list in-repo): browsers, collab, security agents, etc. as Rohi/IT name them.
- Delivery: baked into the image for the default profile, and/or installable only from our gated set.
- Out of MVP: unlimited user choice from upstream stores without policy.
- Flatpak allowlist is acceptable *only* as a curated list we pin — not “Flathub unbounded.”

### 5.4 Controlled plugin marketplace (concept)

- **What it is:** a catalog of plugins / extensions **we** build or vendor, reviewed, and published through *our* channel.
- **What it is not:** arbitrary third-party uploads, unsigned blobs, or “npm of the desktop.”
- **Day 1:** document the shape + empty catalog / placeholder API; **do not** claim a live store.
- **Before public “install plugin”:** signing keys, update/revoke story, and Sam-clear supply chain.
- Optional for a given org: marketplace can be disabled; curated apps + frozen core + SSO still stand.

### 5.5 Image / supply (CI → image)

- Source of truth: this repo (autoinstall, cloud-init, app seed, harden, pins).
- CI builds bootable artifact on tag; checksums always; **signing when keys exist**.
- No hand-rolled laptop ISOs as the release process.
- First-boot helpers only touch files/links this project owns (marker + checksum).

### 5.6 Harden + updates

- Laptop: disk encryption default; firewall on; SSH off by default (break-glass profile only).
- Unattended **security** updates; no silent major upgrades.
- Baseline checklists (USG / CIS-oriented) as implementation guides — not certification claims.
- Inventory: build id visible for fleet drift.

---

## 6. MVP boundary (about 4–8 weeks cognitive)

**In**

1. Repo + this ADR + short README (product thesis / non-goals — not “Ubuntu remix”).
2. One laptop-oriented Ubuntu 24.04 autoinstall seed with **pins + curated app seed** (even if the seed is small).
3. CI → VM-bootable artifact + checksums (signing when keys exist).
4. **Strong SSO path** scripted for one of Entra or AD (default proposal: Entra).
5. Security unattended-upgrades on; major upgrade off; build id fact.
6. Marketplace: **docs + stub only** (catalog empty; no install UX that pretends plugins are live).
7. Short verify docs: VM install → SSO → updates → app seed present.

**Out**

- Live plugin marketplace, third-party submissions, public trust claims without keys.
- Custom kernel / full Secure Boot PKI beyond documenting needs.
- Full MDM / compliance product.
- Rocky or Arch tracks.
- Support SLAs; hardware guarantee matrices.

---

## 7. Suggested layout

```
README.md
LICENSE
docs/ARCHITECTURE.md      # this file
docs/IDENTITY.md
docs/HARDENING.md
docs/IMAGE-PIPELINE.md
docs/CURATED-APPS.md      # seed list + policy (stub OK)
docs/MARKETPLACE.md       # concept + non-goals for third-party (stub OK)
image/
scripts/
catalog/                  # placeholder for later controlled plugins (empty)
.github/workflows/        # when workflow scope exists
```

No ISO blobs in git. Artifacts on Releases.

---

## 8. Open questions for Rohi

1. **Identity:** Entra-first (recommended), AD-first, or both in MVP?
2. **Name lock:** keep `enterprise-linux` or a short product name?
3. **Curated app seed v0:** which apps are must-have on the first image?
4. **Marketplace timing:** stub-only through MVP (recommended), or a single first-party plugin as proof?
5. **Rocky / Arch:** any hard customer criterion, or Ubuntu substrate only for now?
6. **Signing:** when do release + plugin signing keys get created?
7. **Fleet size:** tens (docs + scripts) vs hundreds (inventory/update policy sooner)?

---

## 9. Decision summary

| Topic | Decision |
|---|---|
| Product | Curated org workstation — **not** “just Ubuntu” |
| Substrate | **Ubuntu 24.04 LTS** |
| Pillars | Frozen core + **strong SSO** + curated apps + controlled marketplace (concept) |
| Marketplace | First-party / we-prepare only; no third-party free-for-all; not live yet |
| Arch / Rocky | Out unless hard criterion |
| Personal desktop projects | Decoupled — out of scope |
| License | MIT |
| Next | Docs SHIP this revise; image pipeline after §8 answers |

When Rohi answers §8, revise in place and unlock image-pipeline + app-seed SHIP.
