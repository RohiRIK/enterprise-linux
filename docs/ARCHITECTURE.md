# Architecture: Enterprise Linux (org workstation OS)

**Status:** concept ADR (not a shipping OS)  
**Owner:** cto-max-grok  
**Repo:** `RohiRIK/enterprise-linux`  
**Date:** 2026-09-28 (revised: MDM headline + AI-for-investigation research + locked auto-updates)

This document is design-only. No ISO, no distro fork, no support contract claims. No live MDM connector, marketplace, or AI feature shipping yet.

---

## 1. Problem

Organizations that want Linux on **employee workstations** usually get one of:

- Vanilla Ubuntu (or similar) that is **not MDM-ready** the way Windows/macOS are — weak enroll, weak policy, weak inventory.
- A locked vendor stack (expensive, slow to customize).
- Homegrown golden images that rot: no single owner for identity, harden, apps, updates, and device management.
- DIY boxes where users install whatever and “security updates” means hope.

A stock distribution as a blank canvas is not enough for org fleets. IT needs a **locked, pre-hardened, curated workstation product**: strong SSO, strong MDM support, frozen core, curated apps, controlled auto-updates, and (later) a first-party plugin channel — with room to explore a **distinct AI-for-investigation** capability that does not exist yet (research only until it earns a ship).

**Enterprise Linux (working name)** is that product. **The substrate remains under comparison**, not the brand story; see [`DISTRO-COMPARISON.md`](DISTRO-COMPARISON.md).

Primary user: IT / security / platform owners in M365 / Entra (or AD) shops who want Linux next to Windows under the same control plane expectations.

---

## 2. Product thesis

Headline pillars (vision). MVP ships a subset — see §7. Nothing below claims a live connector or AI product today.

| Pillar | Meaning |
|---|---|
| **Frozen core** | Pinned chosen-substrate LTS; changes via this repo + CI; major upgrades = release train. |
| **Strong SSO** | Org login (Entra-first) is how a machine becomes “done.” |
| **Strong MDM support** | **Headline.** Product is designed MDM-ready for Intune / Jamf-class (or equivalent Linux management) — enroll, policy, inventory, remote actions as the target story. Specifics TBD; not “install a stock distribution and figure out MDM yourself.” |
| **Curated apps** | Org-approved app set baked and/or gated. |
| **Locked security + automatic updates** | Pre-hardened image; controlled **automatic** security/system update path; not a DIY unpatched box. |
| **Controlled plugin marketplace** | Optional channel of plugins **we** prepare. Concept until signing + supply chain exist. |
| **AI-for-investigation (research)** | Explore a *distinct* AI capability that does not exist yet. Open research track — **not** AI-washing, not a ship claim. |

**Non-positioning:** not a brand-only distro remix. Substrate = under comparison; product = the locked curated stack + MDM-ready control plane above it.

**Locked ahead of time:** the default image is ready and constrained before it reaches the user — apps, harden, update policy, identity hooks, MDM hooks — not a blank DIY install.

---

## 3. Non-goals (day 1 and near term)

- **Not** rewriting the kernel or inventing a new userspace from scratch.
- **Not** competing with Red Hat / Canonical support contracts on day 1.
- **Not** a cloud server OS product (workstation is the wedge).
- **Not** a rolling desktop or personal daily-driver product.
- **Not** an open third-party app/plugin free-for-all.
- **Not** claiming a **live** MDM integration, live marketplace, signed plugin trust, or shipping AI feature until each exists and is Sam-clear.
- **Not** AI-washing (“AI OS”) or bolting a chatbot onto the login screen and calling it differentiation.
- **Not** promising FedRAMP / CIS **certification** on day 1 (baselines as checklists OK).
- **Not** building a full MDM *vendor* that replaces Intune/Jamf — we **integrate / are ready for** org MDM, not rebrand as one on day 1.
- **Linux-only:** no Windows-native clients, no live MDM/marketplace/AI claims, no Intune/Jamf badges, and no new dependencies.

---

## 4. Substrate: candidates under comparison

The candidate set is documented in [`DISTRO-COMPARISON.md`](DISTRO-COMPARISON.md): Ubuntu 24.04 LTS, RHEL, Rocky, AlmaLinux, Debian Stable, SUSE/Leap, and a custom minimal frozen core.

| Candidate lane | Role | Status |
|---|---|---|
| Ubuntu 24.04 LTS | LTS workstation substrate candidate | Under comparison |
| RHEL-compatible (RHEL, Rocky, AlmaLinux) | Enterprise-compatible substrate candidates | Under comparison |
| Debian Stable | Stable, community substrate candidate | Under comparison |
| SUSE / Leap | Enterprise or community substrate candidates | Under comparison |
| Custom minimal frozen core | Full-control substrate candidate | Under comparison |

**Decision:** no substrate is locked yet. Rohi reads the comparison before choosing; there is no day-1 lock or recommendation here. Product value remains SSO + MDM-ready design + curated apps + locked updates + (later) marketplace + AI-for-investigation research — not any one base for its own sake.

---

## 5. Pillars in detail

### 5.1 Frozen core

- Pinned chosen-substrate LTS; repo + CI as source of truth; reproducible build ids once the substrate is selected.
- Opposite of rolling enthusiast desktops.

### 5.2 Strong SSO (headline)

- Entra-first; AD/sssd secondary.
- Done = org identity unlock + real home, not local-only orphan.
- Non-goal: own IdP.

### 5.3 Strong MDM support (headline)

- **Target story:** enroll into org MDM (Intune-class and/or Jamf-class Linux management — exact vendors TBD with Rohi), apply policy, inventory, and support remote actions the platform allows.
- **Day-1 design obligations:** image and first-boot leave clean hooks (agent slots, device identity, compliance facts, update/reboot policy surfaces) so MDM is not a retrofit science project.
- **Not yet claimed:** a shipping Intune/Jamf connector, portal, or “works with Intune” badge — those need a named design + Sam CLEAR before README claims.
- Open research: which Linux MDM paths are real in 2026 (Intune Linux, fleet, Landscape, etc.) — pick in a follow-on ADR after Rohi names must-have vendors.

### 5.4 Curated apps

- Declared org-approved seed in-repo; baked and/or gated.
- Flatpak only as a **pinned allowlist**, not unbounded Flathub.

### 5.5 Locked security + automatic system updates

- Pre-hardened laptop defaults: encryption, firewall on, SSH off by default, break-glass admin pattern.
- **Automatic** security/system updates on a controlled channel with documented reboot windows.
- No silent major-release upgrades; no “user will remember to patch.”
- Baseline checklists (USG / CIS-oriented) as implementation guides — not certification claims.

### 5.6 Controlled plugin marketplace (concept)

- First-party / we-prepare only; no third-party free-for-all.
- Stub catalog until signing + revoke story exist.
- Orgs may disable the channel entirely.

### 5.7 AI-for-investigation (research only)

- Goal: find **one distinct** capability that does not exist yet (or is not productized for org Linux workstations) — e.g. fleet-aware assist that respects MDM/SSO boundaries, offline-safe policy help, or something sharper once researched.
- **Process:** short research notes → Rohi pick → design ADR → only then SHIP.
- **Forbidden:** shipping a generic chatbot skin; marketing “AI OS”; implying AI is live in this repo today.

### 5.8 Image / supply (CI → image)

- CI → bootable artifact on tag; checksums always; **signing when keys exist**.
- First-boot only touches project-owned paths (marker + checksum).

---

## 6. MVP boundary (about 4–8 weeks cognitive)

**In**

1. Repo + ADR + README reflecting product thesis (not “just a stock distribution”).
2. Chosen-substrate LTS installer seed: pins + harden + curated app seed + update policy on, after the substrate decision.
3. CI → VM-bootable artifact + checksums.
4. Strong SSO path for one IdP (default proposal: Entra).
5. **MDM-ready hooks** documented + stubbed (agent slot, facts, enroll doc) — **not** a live vendor integration unless Rohi greenlights a named MVP connector.
6. Marketplace + AI-for-investigation: **docs / research stubs only**.
7. Verify docs: VM install → SSO → updates → app seed → MDM hook checklist.

**Out**

- Live Intune/Jamf connector, live marketplace, or shipping AI-for-investigation feature.
- Custom kernel / full Secure Boot PKI beyond documenting needs.
- Full in-house MDM product replacing vendors.
- Additional substrate tracks before the substrate decision; support SLAs; hardware guarantee matrices.

---

## 7. Suggested layout

```
README.md
LICENSE
docs/ARCHITECTURE.md
docs/DISTRO-COMPARISON.md
docs/IDENTITY.md
docs/HARDENING.md
docs/IMAGE-PIPELINE.md
docs/CURATED-APPS.md
docs/MARKETPLACE.md          # concept / not live
docs/MDM.md                  # target story + hooks; no live claim
docs/AI-RESEARCH.md          # AI-for-investigation; no ship claim
docs/FEATURE-IDEAS.md         # ideas-only concept backlog; not shipped
image/
scripts/
catalog/                     # empty
.github/workflows/
```

No ISO blobs in git.

---

## 8. Open questions for Rohi

1. **Identity:** Entra-first (recommended), AD-first, or both in MVP?
2. **MDM must-have vendor(s):** Intune Linux, Jamf, other, or “hooks only” in MVP?
3. **Name lock:** `enterprise-linux` or short product name?
4. **Curated app seed v0:** must-have apps on image one?
5. **Marketplace:** stub through MVP (recommended) vs one first-party plugin proof?
6. **AI-for-investigation brief:** any constraint (must be offline? must use org IdP? must not leave tenant?) before exploration?
7. **Signing:** when for image + future plugins?
8. **Fleet size:** tens vs hundreds?

---

## 9. Decision summary

| Topic | Decision |
|---|---|
| Product | Locked curated org workstation — **not** a DIY distribution install |
| Substrate | **Under comparison; not locked** — see [`DISTRO-COMPARISON.md`](DISTRO-COMPARISON.md) |
| Headlines | Strong **SSO** + strong **MDM support** + frozen core + locked auto-updates + curated apps |
| Marketplace | Controlled, first-party; concept until ready |
| AI-for-investigation | Distinct capability **research**; no AI-wash; no ship yet |
| Claims | No live MDM/AI/marketplace until built + CLEAR |
| Next | Joe SHIP this revise; image pipeline after §8 |

When Rohi answers §8, revise in place and unlock the next SHIP gate.

## 10. Related docs

See [`FEATURE-IDEAS.md`](FEATURE-IDEAS.md) for the ideas-only concept backlog; none of those ideas are shipped or product claims.
