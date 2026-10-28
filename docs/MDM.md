# Strong MDM support

**Status: design / stub only. No live Intune, Jamf, or other MDM connector claimed.**

See `docs/ARCHITECTURE.md` §5.3 and §8. The device-side contract is the [Control API](CONTROL-API.md).

## Target story

Enroll into org MDM (Intune-class and/or Jamf-class Linux management — vendors TBD with Rohi): policy, inventory, and remote actions the platform allows.

## Day-1 design obligations (hooks)

Image and first-boot should leave clean surfaces so MDM is not a retrofit:

- Agent install slot(s) — documented path, MAC policy, allowlisting trust
- Device identity / facts for inventory — `GET /v1/facts`
- Compliance-related facts — `GET /v1/facts/compliance`
- Update / reboot policy surfaces aligned with locked auto-updates — `updates.*`
- Remote actions — lock, wipe (crypto-erase), collect logs, rotate recovery key, notify user

All of these are defined once in [CONTROL-API.md](CONTROL-API.md); each MDM gets a thin wrapper, not its own integration logic.

## MDM landscape (research, 2026-10)

| Path | Linux reality | Fit |
|---|---|---|
| **Microsoft Intune** | Ubuntu 24.04/26.04 LTS and RHEL 9/10 only. Compliance: allowed distro/version, device encryption (dm-crypt/LUKS), password policy, **custom compliance scripts**. No full config profiles like Windows. | Compliance + conditional access for M365. Custom compliance script → our `elctl facts get compliance --json`. |
| **Jamf** | Linux support is limited / inventory-focused — verify current offering before relying on it | Low for v1 |
| **Canonical Landscape** | Ubuntu only; inventory, packages, scripts, Entra login rollout; REST API | Strong if Ubuntu |
| **Red Hat Satellite + Insights** | RHEL family; content, errata, remote execution, compliance; REST API | Strong if RHEL family |
| **SUSE Multi-Linux Manager** | Multi-distro, Salt-based | Medium |
| **Fleet (osquery)** | Multi-distro, open-source core, policies + scripts + REST API | Strong cross-distro option, fits our facts model |
| **Himmelblau** | Open-source Entra/Intune client for Linux | Research — could provide Intune enrollment on more distros |

Sources and detail: [RESEARCH-ENTERPRISE-DISTROS.md](RESEARCH-ENTERPRISE-DISTROS.md).

**Likely shape for v1:** Intune for **compliance + conditional access** (because customers already own it) **plus** one policy/config channel (Fleet, Landscape, or Satellite depending on substrate) — both talking to the same Control API.

## EDR

EDR is a separate agent chosen by the org (Defender for Endpoint, CrowdStrike, SentinelOne, Wazuh …). We provide the slot, the facts, the event stream, and response actions — see [CONTROL-API.md §5](CONTROL-API.md#edr). Keep the image recognizably upstream so EDR vendor support applies.

## Not claimed today

- Shipping connector, portal, or “works with Intune/Jamf” badge
- That we are an MDM vendor replacing Intune/Jamf

## Next

Rohi names must-have vendor(s) or “hooks only” for MVP → follow-on ADR → then SHIP.
