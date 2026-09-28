# enterprise-linux

Concept ADR and repo skeleton for an **org workstation** Linux line under [RohiRIK](https://github.com/RohiRIK).

## What

A design home for a workstation-oriented Linux distribution *line*: one path from **CI → signed image → identity join → hardened defaults → controlled updates**. Not a shipping OS yet.

Primary audience: IT / security / platform owners who already run Microsoft 365 / Entra (or classic AD) and want Linux next to Windows.

## Why

Generic desktop distros leave SSO, fleet updates, and org image supply half-solved. Vendor stacks are slow to customize. Homegrown golden images rot. This repo is where we write the architecture and, later, the autoinstall seed and CI that build a real image.

## Non-goals

- No kernel rewrite; no new userspace from scratch.
- No day-1 competition with RHEL/Canonical support contracts.
- No cloud-server product wedge (workstation first).
- No Omarchy fork as the org base (Omarchy may become a later developer profile).
- No ISO or distro fork in this repo yet — design + skeleton only.
- No FedRAMP/CIS certification claims; no full MDM product before one image boots, joins, and updates.
- No marketing fluff or “AI OS” claims.

## Status

**Concept only.** Day-1 base recommendation is Ubuntu 24.04 LTS (see architecture). Open questions for Rohi are in the ADR.

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — ADR (problem, non-goals, base options, pillars, MVP, open questions)
- [`docs/IDENTITY.md`](docs/IDENTITY.md) — stub
- [`docs/HARDENING.md`](docs/HARDENING.md) — stub
- [`docs/IMAGE-PIPELINE.md`](docs/IMAGE-PIPELINE.md) — stub

## License

[MIT](LICENSE)
