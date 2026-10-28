# Research: what enterprise Linux vendors already do

**Status:** research / decision input — nothing here is built or claimed  
**Date:** 2026-10-28  
**Purpose:** learn from Red Hat, Canonical, SUSE, and the immutable-desktop projects before we design our own control plane, permissions, encryption, security, and desktop UX. Each section ends with **what we borrow** and **gap we can fill**.

**Honesty rule:** this page describes *other* vendors' products as they publicly document them. It does not claim we integrate with any of them today.

---

## 1. Red Hat (RHEL ecosystem)

| Component | What it does | Interface |
|---|---|---|
| **Red Hat Satellite** (Foreman + Katello + Pulp) | Content views (frozen, promoted package sets per lifecycle environment), provisioning, errata, remote execution, Ansible, OpenSCAP | Web UI, **REST API** (everything the UI does), `hammer` CLI built on the same API |
| **Red Hat Insights** (Hybrid Cloud Console) | Vulnerability, compliance (SCAP), advisor, patch, drift, malware detection, inventory | Hosted UI + **REST APIs**; `insights-client` on the host |
| **Identity Management (IdM / FreeIPA)** | Central users, groups, hosts, **HBAC** (who may log in where), **centralized sudo rules**, SELinux user maps, Kerberos, certificates, OTP/passkey | Web UI, `ipa` CLI, JSON-RPC API, Ansible `freeipa.ansible_freeipa` |
| **SSSD** | Client side of IdM/AD/LDAP; offline credential cache; enforces HBAC and sudo from the directory | config + D-Bus |
| **Image Builder / image mode (bootc)** | Build OS images from a blueprint; RHEL 9.6/10 "image mode" ships the OS as a bootable OCI container image, updated atomically, rolled back on failure | `composer-cli`, `bootc`, Containerfile |
| **System Roles** | Supported Ansible roles for crypto policy, firewall, SELinux, NBDE, logging, etc. | Ansible |
| **crypto-policies** | One system-wide switch (`DEFAULT`, `FUTURE`, `FIPS`, + subpolicies) that configures OpenSSL, GnuTLS, NSS, OpenSSH, Kerberos together. RHEL 10 adds post-quantum key exchange. | `update-crypto-policies` |
| **SELinux (enforcing)** | Mandatory access control by default; confined users | `semanage`, booleans |
| **fapolicyd** | Application allowlisting: only trusted (RPM-database or explicitly trusted) binaries may execute | rules + `fapolicyd-cli` |
| **USBGuard** | Allow/deny USB devices by attributes | `usbguard` CLI + D-Bus |
| **NBDE (Clevis + Tang)** | LUKS unlock automatically when on the corporate network (Tang) and/or TPM2 present; falls back to passphrase | `clevis luks bind` |
| **Keylime** | Remote attestation: TPM measured boot + runtime file integrity (IMA) verified by a central verifier | REST API |
| **auditd / AIDE / OpenSCAP** | Kernel audit trail, file integrity, SCAP profiles (CIS, STIG, PCI-DSS, etc.) with remediation scripts | CLI, SCAP content |
| **Cockpit** | Web console for a single host | web + D-Bus |
| **RHEL Lightspeed** | Optional natural-language assistant on the command line for troubleshooting/log interpretation (RHEL 9.6 / 10) | CLI |

**What we borrow**
- *Everything the UI can do, the API can do, and the CLI is a client of the API* (Satellite/`hammer` pattern). This is the core rule of our [Control API](CONTROL-API.md).
- **Content views / lifecycle environments** → our update rings (`canary → pilot → broad`) with frozen, promoted snapshots.
- **Centralized HBAC + sudo rules** delivered from the directory, cached offline → our [permissions model](PERMISSIONS.md).
- **crypto-policies** as a single switch → our `crypto.profile` setting in [ENCRYPTION.md](ENCRYPTION.md).
- **fapolicyd + USBGuard + SELinux** as the three-layer local enforcement stack → [HARDENING.md](HARDENING.md).
- **NBDE** and **Keylime** as design references for encryption unlock and device trust.
- **Image mode (bootc)** as a reference for atomic, rollback-able, image-based workstations.

**Gap we can fill**
- Satellite/Insights are server-first. There is no Red Hat answer for "an employee laptop, Entra-joined, managed by Intune, with a friendly desktop and a self-service app store." The workstation story is mostly "RHEL for Workstations" subscriptions plus your own glue.
- IdM assumes you run IdM. Entra-first shops do not want a second directory.

---

## 2. Canonical (Ubuntu)

| Component | What it does | Interface |
|---|---|---|
| **Landscape** | Fleet management: inventory, package/repo control, scripts, compliance reporting, Entra ID login rollout | Web UI, REST API, `landscape-api` CLI |
| **Ubuntu Pro** | ESM security patches for universe, Livepatch, FIPS packages, **USG** (CIS/DISA-STIG tooling) | `pro` CLI |
| **authd** (official in 26.04 LTS) | OIDC login to Entra ID / Google IAM with MFA and conditional access | PAM/NSS module + broker |
| **TPM-backed FDE** (GA in 26.04 LTS) | LUKS unlocked by TPM with predictable recovery keys; **Security Center** app shows FDE state, recovery, Secure Boot | GUI + `snapd` |
| **sudo-rs / rust-coreutils** (26.04 default) | Memory-safe replacements for sudo and coreutils | — |
| **AppArmor** | MAC; experimental permission prompting for snaps | profiles |
| **Intune (Microsoft)** | Ubuntu 24.04 / 26.04 can enroll in Intune for compliance (see §4) | Intune portal + Graph API |

**What we borrow**
- **authd-style OIDC login** is the shortest path to our Entra-first SSO headline.
- **Security Center** as a pattern: one place a user sees encryption / Secure Boot / recovery status — we extend it into our daily-use [desktop app](DESKTOP-UX.md).
- **USG** as a reference for CIS/STIG profiles applied as code.

**Gap we can fill**
- Landscape and Intune are two separate control planes; neither gives a single local, documented, versioned API that *any* MDM or EDR can drive.

---

## 3. SUSE

- **SUSE Multi-Linux Manager** (formerly SUSE Manager, Uyuni upstream): Salt-based fleet management for SUSE, RHEL family, and Ubuntu; XML-RPC/JSON API.
- **Transactional updates** (SLE Micro, openSUSE Aeon/Kalpa): read-only root, Btrfs snapshots, atomic update + rollback on reboot.
- **KIWI** image builder; **AutoYaST** for unattended installs.

**What we borrow:** atomic updates with automatic rollback; a manager that is not tied to one vendor's distro.

---

## 4. Microsoft on Linux (MDM and EDR reality check)

These two facts directly affect the substrate decision in [DISTRO-COMPARISON.md](DISTRO-COMPARISON.md):

- **Intune for Linux** (Microsoft Learn, compliance settings reference, checked 2026-10-28) supports **Ubuntu Desktop 24.04 / 26.04 LTS and RHEL 9 / 10** only. Linux compliance settings are: allowed distributions/versions, **device encryption** (any dm-crypt, LUKS preferred), **password policy**, and **custom compliance scripts**. Rocky, Alma, Debian, and SUSE are not on that list.
- **Microsoft Defender for Endpoint on Linux** supports a much wider list (RHEL, Rocky, Alma, Ubuntu, Debian, SLES, Leap, Oracle, Amazon, Fedora). It is configured by a managed JSON file and the `mdatp` CLI. Microsoft states that **customized OSes derived from a supported distribution may run but are treated as custom configurations** — so our image should stay recognizably the upstream distro (same `/etc/os-release` ID, same kernel packages) to stay inside vendor support.

**Implication:** if Intune compliance on day 1 is a must-have, the substrate shortlist is **Ubuntu LTS or RHEL**, not the rebuilds. If "EDR from any major vendor" is the must-have, almost any LTS base works.

**What we borrow:** Intune's custom compliance script model (JSON in → discovered facts out) is exactly the contract our Control API should expose as `facts`.

---

## 5. Immutable / image-based desktops

| Project | Idea |
|---|---|
| **Fedora Silverblue / Kinoite**, **Universal Blue / Bluefin** | rpm-ostree / bootc: the OS is one signed image; apps are Flatpaks; rollbacks are one reboot |
| **ChromeOS / ChromeOS Flex** | Verified boot, read-only root, A/B updates, admin console decides almost everything; the gold standard for "user can change wallpaper, not the OS" |
| **Endless OS** | ostree base + curated Flatpak app center for non-technical users |
| **NixOS** | Declarative, reproducible system config with generations to roll back |

**What we borrow:** A/B or ostree/bootc style atomic updates, read-only system, Flatpak for user apps, and ChromeOS's *tiered customization* model (org decides, user tweaks inside the fence).

---

## 6. Open-source fleet / security building blocks

| Tool | Use |
|---|---|
| **osquery** + **Fleet** | SQL over device state; Fleet adds MDM-style policies and a REST API. Natural fit for our `facts` model. |
| **Wazuh** | Open-source XDR/SIEM agent (FIM, rootcheck, SCA) |
| **OpenSCAP / ComplianceAsCode** | CIS/STIG profiles for Ubuntu, RHEL, Debian, SUSE |
| **Himmelblau** | Open-source Entra ID / Intune client for Linux (incl. compliance) |
| **systemd** (`systemd-cryptenroll`, `systemd-homed`, UKI, `systemd-sysext`, `systemd-measure`) | TPM2 LUKS enrollment, signed Unified Kernel Images, measured boot policy, system extensions |

---

## 7. Summary: our differentiation

Nobody ships all of this together for **employee laptops**:

1. **One local Control API** (CLI + D-Bus + REST over a Unix socket) that MDM, EDR, Ansible, and our own GUI all use — documented, versioned, audited. → [CONTROL-API.md](CONTROL-API.md)
2. **Directory-driven permissions** without running a second directory (Entra groups → roles → polkit/sudo/HBAC). → [PERMISSIONS.md](PERMISSIONS.md)
3. **Selectable app bundles** chosen at build, at enrollment, or self-service. → [CURATED-APPS.md](CURATED-APPS.md)
4. **Encryption with escrow by default** (TPM2 + recovery key escrowed to the org). → [ENCRYPTION.md](ENCRYPTION.md)
5. **Layered security** borrowed from RHEL (MAC + allowlisting + USB control + attestation). → [HARDENING.md](HARDENING.md)
6. **A daily-use desktop with tiered customization** (ChromeOS-style fence). → [DESKTOP-UX.md](DESKTOP-UX.md)

---

## Sources

- Red Hat: [Why upgrade to RHEL 9.6 or 10](https://www.redhat.com/en/blog/why-upgrade-red-hat-enterprise-linux-96-or-10-now); [Satellite administration tools](https://docs.redhat.com/en/documentation/red_hat_satellite/6.19/html/overview_concepts_and_deployment_considerations/tools-for-administration-of-satellite_planning); [Hammer CLI guide](https://docs.redhat.com/en/documentation/red_hat_satellite/6.15/html-single/hammer_cli_guide/index); [IdM: users, groups, hosts and access control rules (RHEL 10)](https://docs.redhat.com/ko/documentation/red_hat_enterprise_linux/10/html/managing_idm_users_groups_hosts_and_access_control_rules/index); [Login to RHEL using Microsoft Entra ID](https://access.redhat.com/node/7076188)
- Canonical: [What's new in security for Ubuntu 26.04 LTS](https://canonical.com/blog/ubuntu-26-04-lts-security-updates); [Entra ID authentication on Ubuntu at scale with Landscape](https://ubuntu.com/blog/entra-id-authentication-on-ubuntu-at-scale-with-landscape); [Ubuntu compliance monitoring with Intune](https://canonical.com/blog/ubuntu-compliance-monitoring-with-microsoft-intune)
- Microsoft: [Intune Linux compliance settings](https://learn.microsoft.com/en-us/intune/device-security/compliance/ref-linux-settings); [Intune Linux platform guide](https://learn.microsoft.com/intune/fundamentals/platform-guide-linux); [Defender for Endpoint on Linux prerequisites](https://learn.microsoft.com/defender-endpoint/mde-linux-prerequisites); [MDE Linux resources (mdatp CLI)](https://learn.microsoft.com/defender-endpoint/linux-resources)
- Other: [Himmelblau Intune docs](https://himmelblau-idm.org/docs/intune/)
