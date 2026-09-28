# Enterprise Linux — overview

**Status:** concept only. Not a shipping OS. No ISO in this repo yet.  
**Audience:** anyone who needs the product story in one place.  
**Date:** 2026-09-28

This page is the plain-English front door. Deeper stubs live under `docs/`. Nothing here claims a live MDM connector, marketplace, signed plugins, or AI product.

---

## What this is

**Enterprise Linux** (working name) is a **Linux-only** org workstation product idea: a locked, pre-configured image and control story for employee fleets — not a blank DIY install, and not a Windows or macOS client.

Organizations that want Linux next to Windows usually get stock distros with weak enroll/policy/inventory, expensive vendor stacks, or golden images that rot. The product thesis is the curated stack *on top of* a chosen Linux base — not “another remix” for its own sake.

Primary reader: IT / security / platform owners in M365 / Entra (or AD) shops who want Linux under the same *control-plane expectations* as Windows. Windows appears only as that bar for Linux fleets. There are **no Windows-native clients or agents** in this product.

---

## Product pillars (vision)

These are the headline pillars. MVP would ship a subset. None of them is a live integration claim today.

1. **Frozen core** — a pinned LTS (or equivalent stable) base; changes through this repo and CI; major upgrades as a release train, not rolling enthusiast desktop.
2. **Curated apps** — org-approved set, baked into the image and/or gated after enroll.
3. **Controlled marketplace** — optional channel of plugins **we** prepare and sign. Concept/stub until signing and supply chain exist. **Not live.**
4. **Strong SSO** — org login (Entra-first target) is how a machine becomes “done.”
5. **Strong MDM *support*** — product is designed so org MDM can enroll, apply policy, inventory, and run remote actions. We integrate / are ready for org MDM; we are **not** building a day-1 Intune/Jamf replacement, and we claim **no live connector** and **no vendor badges** until a named path is implemented and reviewed.
6. **Locked automatic updates** — pre-hardened image; security/system updates on by policy; no silent major upgrades; not an unpatched DIY box.
7. **AI-for-investigation** — a **research** track for one distinct capability. **Not shipping.** Not “AI OS.” Not a chatbot on the login screen.

**Locked ahead of time** means the default image is constrained before it reaches the user (apps, harden, update policy, identity hooks, MDM hooks) — not a blank install.

---

## Substrate (base Linux) — still unlocked

The **base distribution is not locked.** Ubuntu remains a **candidate** alongside RHEL, Rocky, Alma, Debian, SUSE/Leap, and custom minimal. See the full pros/cons matrix:

→ [`docs/DISTRO-COMPARISON.md`](DISTRO-COMPARISON.md)

Do not read older notes as “we are an Ubuntu product.” Substrate is the plate; the product is the pillars above. Decision waits on Rohi after that comparison.

---

## What is *not* claimed

- No live MDM, marketplace, signed-plugin trust, or AI feature.
- No Intune / Jamf / CIS / FedRAMP / SOC2 **certification** badges (CIS/SOC2 may appear later only as *idea* evidence-pack tooling — see feature ideas).
- No kernel rewrite; no competing with RHEL/Canonical support contracts on day 1.
- No open third-party plugin free-for-all.
- No ISO, installer, or support contract in this repo yet.
- No marketing fluff.

---

## Docs map

| Doc | Role |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | ADR — design detail |
| [`DISTRO-COMPARISON.md`](DISTRO-COMPARISON.md) | Substrate decision input; **no base locked** |
| [`IDENTITY.md`](IDENTITY.md) | SSO stub |
| [`MDM.md`](MDM.md) | MDM target story + hooks (**no live claim**) |
| [`HARDENING.md`](HARDENING.md) | Harden + locked updates stub |
| [`IMAGE-PIPELINE.md`](IMAGE-PIPELINE.md) | Image build stub |
| [`CURATED-APPS.md`](CURATED-APPS.md) | Curated apps stub |
| [`MARKETPLACE.md`](MARKETPLACE.md) | Marketplace concept (**not live**) |
| [`AI-RESEARCH.md`](AI-RESEARCH.md) | AI-for-investigation research (**no ship claim**) |
| [`FEATURE-IDEAS.md`](FEATURE-IDEAS.md) | Concept backlog — **ideas only, not shipped** |

---

## Feature ideas (not shipped)

Brainstorm backlog lives in [`FEATURE-IDEAS.md`](FEATURE-IDEAS.md). Examples: admin GUI, TPM/device trust, air-gap update packs, break-glass admin, policy-as-code, app sandboxes, secret escrow, compliance export, remote assist, and the AI-for-investigation research track.

Every item there is an **idea**. None is a product claim, live capability, or committed roadmap.

---

## Suggested build path (when engineering starts)

Rough order once Rohi locks substrate and MVP scope:

**CI → image (signing when keys exist) → SSO → MDM hooks → harden → curated apps → locked auto-updates** → marketplace only after signing → AI only after research pick + ADR.

Until then this repo is architecture and stubs.

---

## Open decisions (for Rohi)

- Which substrate after reading [`DISTRO-COMPARISON.md`](DISTRO-COMPARISON.md).
- Must-have MDM vendor path (e.g. Intune-class day 1 or not).
- Product name, curated app seed, marketplace timing, AI constraints, signing, expected fleet size.

Architect owns ADRs; coder ships docs/code; reviewer clears overclaim. New product claims need review before they go live in README language.
