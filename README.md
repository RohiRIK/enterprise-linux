# enterprise-linux

Concept ADR and repo skeleton for a **locked, curated org workstation** Linux product under [RohiRIK](https://github.com/RohiRIK).

## What

Not DIY Ubuntu. **Ubuntu 24.04 LTS is the substrate**; the product is the stack on top:

- **Frozen core** — pinned base, controlled updates, reproducible images
- **Strong SSO** — Entra-first org login (headline)
- **Strong MDM support** — MDM-ready design (Intune/Jamf-class target story; **no live connector claimed**)
- **Curated apps** — org-approved set, baked and/or gated
- **Locked security + automatic updates** — pre-hardened; controlled auto security/system updates
- **Controlled plugin marketplace** — plugins *we* prepare (concept/stub; **not live**)
- **AI direction** — research for a *distinct* capability (**not shipping**; no AI-wash)

Path: **CI → image (signing when keys exist) → SSO → MDM hooks → harden → curated apps → locked auto-updates**. Not a shipping OS yet.

Primary audience: IT / security / platform owners in M365 / Entra (or AD) shops who want Linux under the same control-plane expectations as Windows.

## Why

Stock Ubuntu is a blank canvas — weak enroll, weak policy, weak inventory next to Windows/macOS MDM. Vendor stacks are slow. Homegrown images rot. This repo holds the architecture for a locked curated experience, not another untitled remix.

## Non-goals

- No kernel rewrite; no new userspace from scratch.
- No day-1 competition with RHEL/Canonical support contracts.
- No “Ubuntu remix” brand-only story (substrate ≠ product).
- No open third-party app/plugin free-for-all.
- No **live** MDM integration, marketplace, signed-plugin trust, or AI feature claims until each exists and is reviewed.
- No AI-washing (“AI OS”) or bolting a chatbot on login.
- No building a full MDM *vendor* that replaces Intune/Jamf on day 1 — we integrate / are ready for org MDM.
- No FedRAMP/CIS certification claims; no ISO in this repo yet.
- No marketing fluff.

## Status

**Concept only.** Substrate: Ubuntu 24.04 LTS. MDM, marketplace, and AI are docs/research stubs — not live. Open questions for Rohi are in the ADR.

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — ADR
- [`docs/IDENTITY.md`](docs/IDENTITY.md) — SSO stub
- [`docs/MDM.md`](docs/MDM.md) — target story + hooks (**no live claim**)
- [`docs/HARDENING.md`](docs/HARDENING.md) — locked updates / harden stub
- [`docs/IMAGE-PIPELINE.md`](docs/IMAGE-PIPELINE.md) — stub
- [`docs/CURATED-APPS.md`](docs/CURATED-APPS.md) — stub
- [`docs/MARKETPLACE.md`](docs/MARKETPLACE.md) — concept stub (**not live**)
- [`docs/AI-RESEARCH.md`](docs/AI-RESEARCH.md) — research stub (**no ship claim**)

## License

[MIT](LICENSE)
