# enterprise-linux

Concept ADR and repo skeleton for a **curated org workstation** Linux product under [RohiRIK](https://github.com/RohiRIK).

## What

Not “just Ubuntu.” **Ubuntu 24.04 LTS is the substrate**; the product is the stack on top:

- **Frozen core** — pinned base, controlled updates, reproducible images
- **Strong SSO** — Entra-first org login as a headline pillar
- **Curated apps** — org-approved app set, baked and/or gated
- **Controlled plugin marketplace** — plugins *we* prepare (concept/stub only; not live)

Path: **CI → image (signing when keys exist) → SSO join → harden → curated apps → controlled updates**. Not a shipping OS yet.

Primary audience: IT / security / platform owners in Microsoft 365 / Entra (or classic AD) shops who want Linux next to Windows.

## Why

Vanilla distros leave SSO, fleet updates, and org apps half-solved. Vendor stacks are slow to customize. Homegrown images rot. Rolling desktops move under the fleet. This repo holds the architecture — and later the image seed and CI — for a curated experience, not another untitled remix.

## Non-goals

- No kernel rewrite; no new userspace from scratch.
- No day-1 competition with RHEL/Canonical support contracts.
- No “Ubuntu remix” brand-only story (substrate ≠ product).
- No open third-party app store / sideload free-for-all.
- No live marketplace, signed-plugin trust, or FedRAMP/CIS claims before those exist.
- No rolling desktop or personal daily-driver distro product.
- No ISO in this repo yet — design + skeleton only.
- No full MDM before one image boots, joins SSO, and updates.
- No marketing fluff or “AI OS” claims.

## Status

**Concept only.** Substrate: Ubuntu 24.04 LTS. Marketplace and catalog are stubs. Open questions for Rohi are in the ADR.

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — ADR
- [`docs/IDENTITY.md`](docs/IDENTITY.md) — stub (SSO)
- [`docs/HARDENING.md`](docs/HARDENING.md) — stub
- [`docs/IMAGE-PIPELINE.md`](docs/IMAGE-PIPELINE.md) — stub
- [`docs/CURATED-APPS.md`](docs/CURATED-APPS.md) — stub seed / policy
- [`docs/MARKETPLACE.md`](docs/MARKETPLACE.md) — concept stub (not live)

## License

[MIT](LICENSE)
