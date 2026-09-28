# enterprise-linux

Concept ADR and repo skeleton for a **Linux-only, locked, curated org workstation** product under [RohiRIK](https://github.com/RohiRIK).

## What

Not DIY Linux. **The substrate is under comparison**; the product is the stack on top. See [`docs/DISTRO-COMPARISON.md`](docs/DISTRO-COMPARISON.md) for the decision input:

- **Frozen core** — pinned chosen-substrate LTS, controlled updates, reproducible images
- **Strong SSO** — Entra-first org login (headline)
- **Strong MDM support** — MDM-ready design with the vendor path still TBD (**no live connector claimed**)
- **Curated apps** — org-approved set, baked and/or gated
- **Locked security + automatic updates** — pre-hardened; controlled auto security/system updates
- **Controlled plugin marketplace** — plugins *we* prepare (concept/stub; **not live**)
- **AI-for-investigation** — research for a *distinct* capability (**not shipping**; no AI-wash)

Path: **CI → image (signing when keys exist) → SSO → MDM hooks → harden → curated apps → locked auto-updates**. Not a shipping OS yet.

Primary audience: IT / security / platform owners in M365 / Entra (or AD) shops who want Linux under the same control-plane expectations as Windows.

## Why

Stock distributions are a blank canvas — weak enroll, weak policy, weak inventory next to Windows/macOS MDM. Vendor stacks are slow. Homegrown images rot. This repo holds the architecture for a locked curated experience, not another untitled remix.

## Non-goals

- No kernel rewrite; no new userspace from scratch.
- No day-1 competition with RHEL/Canonical support contracts.
- No brand-only remix story (substrate ≠ product).
- No open third-party app/plugin free-for-all.
- No **live** MDM integration, marketplace, signed-plugin trust, or AI feature claims until each exists and is reviewed.
- No Windows-native clients; this is a Linux-only product.
- No Intune/Jamf badges, and no new dependencies.
- No AI-washing (“AI OS”) or bolting a chatbot on login.
- No building a full MDM *vendor* that replaces Intune/Jamf on day 1 — we integrate / are ready for org MDM.
- No FedRAMP/CIS certification claims; no ISO in this repo yet.
- No marketing fluff.

## Status

**Concept only.** Substrate: under comparison, not locked. MDM, marketplace, and AI are docs/research stubs — not live. Open questions for Rohi are in the ADR and the [distro comparison](docs/DISTRO-COMPARISON.md).

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — ADR
- [`docs/DISTRO-COMPARISON.md`](docs/DISTRO-COMPARISON.md) — substrate decision input; no base locked
- [`docs/IDENTITY.md`](docs/IDENTITY.md) — SSO stub
- [`docs/MDM.md`](docs/MDM.md) — target story + hooks (**no live claim**)
- [`docs/HARDENING.md`](docs/HARDENING.md) — locked updates / harden stub
- [`docs/IMAGE-PIPELINE.md`](docs/IMAGE-PIPELINE.md) — stub
- [`docs/CURATED-APPS.md`](docs/CURATED-APPS.md) — stub
- [`docs/MARKETPLACE.md`](docs/MARKETPLACE.md) — concept stub (**not live**)
- [`docs/AI-RESEARCH.md`](docs/AI-RESEARCH.md) — AI-for-investigation research stub (**no ship claim**)
- [`docs/FEATURE-IDEAS.md`](docs/FEATURE-IDEAS.md) — ideas-only concept backlog (**not shipped**)

## License

[MIT](LICENSE)
