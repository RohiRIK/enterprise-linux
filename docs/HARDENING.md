# Hardening, security mechanisms, and locked automatic updates

**Status:** design; first implementation in [`security/hardening/`](../security/hardening/README.md) (container-tested only, not hardware-tested). Baselines are implementation guides, **not certification claims**.  
**Date:** 2026-10-28 (expanded from the original stub)  
See `docs/ARCHITECTURE.md` §5.5 and §5.1. Related: [ENCRYPTION.md](ENCRYPTION.md), [PERMISSIONS.md](PERMISSIONS.md), [CONTROL-API.md](CONTROL-API.md).

## Intent

Pre-hardened laptop defaults and a controlled **automatic** security/system update path — not a DIY unpatched box. Defence in depth: each layer below assumes the one above it can fail.

---

## 1. Layered model

| # | Layer | Mechanism (substrate-neutral; RHEL / Ubuntu specifics in brackets) | Default |
|---|---|---|---|
| 1 | **Boot chain** | UEFI Secure Boot → signed shim → **signed Unified Kernel Image (UKI)** with embedded cmdline → kernel lockdown (integrity) | On |
| 2 | **Measured boot / device trust** | TPM2 PCR measurements; local unlock bound to them ([ENCRYPTION.md](ENCRYPTION.md)); optional remote attestation (Keylime-style) reported as a compliance fact | Measured on; remote attestation phase 2 |
| 3 | **Immutable system** | Read-only `/usr` (image mode: bootc / ostree / A/B), writable `/etc` overlay tracked for drift, `/var` and `/home` writable | Target design — see §4 |
| 4 | **Encryption** | LUKS2 + TPM2, escrowed recovery | On ([ENCRYPTION.md](ENCRYPTION.md)) |
| 5 | **Identity & privilege** | Directory login only, no standing admin, JIT elevation, break-glass | On ([PERMISSIONS.md](PERMISSIONS.md)) |
| 6 | **Mandatory access control** | SELinux enforcing [RHEL family] / AppArmor enforce [Ubuntu]; confined services incl. `eld` | Enforcing |
| 7 | **Application allowlisting** | Only binaries from the image, signed packages, or the curated Flatpak catalog may execute; `noexec` on `/home`, `/tmp`, removable media. [fapolicyd on RHEL family; AppArmor + `noexec` + IMA appraisal elsewhere] | Enforcing for *user*, audit-only for *power-user* (configurable) |
| 8 | **Device control** | USBGuard (allowlist HID/known docks; storage per policy); Thunderbolt/USB4 authorization (bolt) default "user approval"; Bluetooth class allowlist | On |
| 9 | **Network** | Host firewall default-deny inbound (firewalld / nftables), SSH server **off**, no listening services, mDNS off on untrusted networks, optional always-on VPN | On |
| 10 | **Kernel hardening** | sysctl baseline (kptr_restrict, dmesg_restrict, unprivileged BPF off, ptrace scope, yama), module signing enforced, unused filesystems/protocols blacklisted | On |
| 11 | **Sandboxing** | Curated apps as Flatpak with policy-defined portal permissions; browsers sandboxed; systemd service hardening (`ProtectSystem`, `NoNewPrivileges`, etc.) for our services | On |
| 12 | **Memory-safe base tools** | Prefer sudo-rs / rust-coreutils where the substrate ships them (Ubuntu 26.04 default) | Follow substrate |
| 13 | **Audit & integrity** | auditd rules (privilege use, policy changes, auth), file integrity (AIDE or IMA), journald forward-secure sealing, logs forwarded to SIEM | On |
| 14 | **EDR slot** | Documented install slot + MAC policy + allowlist trust for third-party EDR (Defender, CrowdStrike, SentinelOne, Wazuh …). We do not ship our own EDR. | Slot ready; agent chosen by org |
| 15 | **Compliance scanning** | OpenSCAP / ComplianceAsCode (CIS L1/L2 workstation, DISA STIG) run on schedule; result exposed as `compliance` facts | On (report), remediation by policy |
| 16 | **Screen & session** | Auto-lock (policy timeout), lock on lid close, no guest session, no autologin, idle logout optional | On |

---

## 2. Locked automatic updates

- **Rings:** `canary → pilot → broad` (Red Hat content-view / lifecycle-environment idea). Each ring receives a **frozen, signed snapshot**; promotion happens in our CI after soak time + health signals.
- **Security updates automatic** inside a maintenance window; reboot nag → forced reboot after `maxDeferralDays`.
- **Atomic + rollback** (target): image-based update applied to the inactive slot / new deployment, health-checked on boot, auto-rollback on failure.
- **Livepatch** where the substrate offers it (Ubuntu Pro Livepatch, RHEL kpatch) to reduce forced reboots.
- **No silent major-release upgrades.** Majors are a release train decided by policy.
- **Offline / air-gapped:** signed update bundles importable via the Control API (see [FEATURE-IDEAS.md](FEATURE-IDEAS.md)).
- All of the above are `updates.*` settings/facts/actions in the [Control API](CONTROL-API.md).

---

## 3. Vulnerability & supply chain

- Every image build produces an **SBOM** (SPDX/CycloneDX) and is **signed** (cosign/sigstore or GPG) — publish both with the release.
- CVE status per device = SBOM × advisory feed (OVAL/OSV) → `security.vulnerabilities` fact; MDM/EDR can query instead of rescanning.
- Reproducible builds as a goal; pinned inputs in repo.

---

## 4. Image-based ("immutable") vs package-based — decision input

| | Package-based (classic apt/dnf) | Image-based (bootc / ostree / A/B) |
|---|---|---|
| Drift | High unless heavily managed | Low — `/usr` is read-only |
| Rollback | Hard | One reboot |
| Matches "frozen core" thesis | Partially | **Yes** |
| Vendor support (Intune / EDR) | Best tested | RHEL image mode is supported by Red Hat; Ubuntu Core Desktop is not GA — **verify per vendor** |
| Admin familiarity | High | Growing |

Recommendation for discussion: **image-based on RHEL-family (bootc) or package-based with strong drift control on Ubuntu**; this ties into the substrate decision in [DISTRO-COMPARISON.md](DISTRO-COMPARISON.md).

---

## 5. Checklist direction (not certification)

- Disk encryption default; firewall on; SSH off by default; break-glass admin
- Unattended security updates with documented reboot windows
- No silent major-release upgrades
- Public baseline (USG / CIS / STIG-oriented via ComplianceAsCode) as implementation guide only — do not claim certified
