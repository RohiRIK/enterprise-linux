# Our own management agent (multi-MDM connectors)

**Status:** design only — nothing built. No "works with Intune" claim. `el-agent` is a working name.  
**Date:** 2026-10-28  
**Related:** [CONTROL-API.md](CONTROL-API.md), [MDM.md](MDM.md), [IDENTITY.md](IDENTITY.md), [RESEARCH-ENTERPRISE-DISTROS.md](RESEARCH-ENTERPRISE-DISTROS.md)

---

## 1. Why our own agent

The [Control API](CONTROL-API.md) makes the device *manageable*. Something still has to **talk to the org's MDM**: pull policy, push facts, run actions, report results. Today every Linux MDM ships its own agent with its own model, and most cover only part of what we need.

`el-agent` is one small agent with **pluggable connectors**. Each connector translates one MDM's model into Control API calls. The MDM-specific code stays thin; the device logic stays in `eld`.

```
   Intune ──┐                         ┌── Fleet / osquery
 Landscape ─┤                         ├── Satellite / Insights
            │     ┌────────────┐      │
            └────►│  el-agent  │◄─────┘      (one or more connectors enabled per device)
                  │ connectors │
                  └─────┬──────┘
                        │ Control API (Unix socket / D-Bus) as svc:mdm principal
                  ┌─────▼──────┐
                  │    eld     │  facts · settings · actions · events · audit
                  └────────────┘
```

Goals:

- **One device model, many MDMs.** Orgs keep the MDM they already pay for.
- **No root shell scripts as the integration.** Connectors call typed API methods; arbitrary scripts are an exception path, signed and audited.
- **Offline-tolerant.** Last policy keeps being enforced by `eld`; the agent only syncs.
- **Small and confined.** Runs as its own user with the `svc:mdm` role from [PERMISSIONS.md](PERMISSIONS.md), not as root.

---

## 2. Connectors (draft list)

| Connector | Transport | What it can do | v1? |
|---|---|---|---|
| **intune** | Microsoft's official Linux agent (Ubuntu/RHEL) + its script channels, or Himmelblau on other distros | Compliance, conditional access, scripts → policy (see §3) | **Research spike first** |
| **fleet** | fleetd / osquery extension | Facts as osquery tables, policies, scripts, software inventory | Candidate |
| **landscape** | Landscape client (Ubuntu) | Inventory, packages, scripts | If Ubuntu |
| **satellite** | subscription-manager + remote execution (RHEL family) | Content, errata, remote execution, compliance | If RHEL family |
| **git / https-pull** | Signed policy documents pulled from a URL or git repo | Policy-as-code for small fleets with no MDM | Candidate (cheap, good for demos) |
| **local** | `elctl` only | Manual / air-gapped | Always |

Connectors are plain modules with a fixed interface: `sync_policy()`, `report_facts()`, `poll_actions()`, `report_result()`, `forward_events()`.

---

## 3. Making Intune work (what is realistic)

### What Intune offers on Linux (research, 2026-10-28)

- **Supported distros:** Ubuntu Desktop 24.04/26.04 LTS and RHEL 9/10 only, with Microsoft's Intune app + identity broker.
- **Compliance:** allowed distro/version, disk encryption (dm-crypt/LUKS), password policy, and **custom compliance** (discovery script + JSON rules).
- **Custom configuration = bash scripts:** `.sh` only, run as **user** (default, at sign-in) or **root** (device level), default every **15 minutes**, configurable retries.
- **Custom compliance discovery scripts:** any interpreter via shebang, **run in the user's context** (cannot read root-only state), max **1 MB** script, **1 MB** output, **5 minutes** run time; one script per compliance policy.
- **No** Settings Catalog configuration profiles for Linux like Windows/macOS have.

So Intune on Linux is **compliance + scripts**, not full configuration management. The scripts are our way in.

### Pattern A — "policy inside the script" (on Ubuntu/RHEL with the official Intune app)

Intune root script = a tiny, generic wrapper that carries a **signed policy document** and hands it to our API:

```bash
#!/bin/bash
# Intune custom configuration script (runs as root, every 15 min)
# The payload is a signed DevicePolicy; eld rejects it if the signature is invalid.
exec /usr/bin/elctl settings apply --signed - <<'POLICY'
-----BEGIN EL POLICY-----
...base64 signed DevicePolicy (well under 1 MB)...
-----END EL POLICY-----
POLICY
```

- Idempotent: applying an unchanged policy every 15 minutes is a no-op.
- Exit code and short JSON summary are what Intune shows as the script result.
- **Signature check** means an Intune admin account compromise alone cannot push arbitrary *policy* (it can still push arbitrary root scripts — that is an Intune property we document, not something we can remove).
- Remote actions (rotate recovery key, collect logs) = one-line scripts calling `elctl action run ...`, assigned to a device group and removed after they report success.

### Pattern B — compliance from our facts

Intune custom compliance discovery script:

```bash
#!/bin/bash
exec /usr/bin/elctl facts get compliance --format intune
```

- Because discovery scripts run **as the user**, `eld` must allow the `user` role to read the **compliance facts** subset (read-only, non-sensitive). This is a design requirement for [CONTROL-API.md](CONTROL-API.md).
- We publish the matching **compliance JSON rules file** (encryption, Secure Boot, MAC enforcing, firewall on, EDR running, update age, policy version, …) so customers import one file instead of writing rules.
- Result: Intune conditional access can block M365 on a Linux device that is not encrypted, unpatched, or missing EDR — using our facts.

### Pattern C — distros Intune does not support

- **Himmelblau** evaluates Intune compliance locally and supports Entra login on more distros than Microsoft's app. Research: maturity, support model, whether its policy path can carry our signed policies.
- Microsoft's EDR (Defender) still works on many more distros; compliance via Defender device risk is another signal.
- **Honest default:** if Intune compliance is a must-have, choose Ubuntu or RHEL as substrate (see [DISTRO-COMPARISON.md](DISTRO-COMPARISON.md)).

### Spike plan (before any claim)

1. Ubuntu 24.04 VM + Intune trial tenant + official Intune app → enroll.
2. Deploy Pattern A root script with a dummy signed policy → measure delay, result reporting, failure modes.
3. Deploy Pattern B discovery script + rules JSON → verify conditional access blocks a non-compliant VM.
4. Repeat on RHEL 9/10. Then try Himmelblau on a third distro.
5. Write findings into this doc; only then decide whether `intune` is a v1 connector.

---

## 4. Multiple MDMs on one device

- Orgs may run **Intune for compliance + Fleet/Landscape/Satellite for config** at the same time.
- Each connector registers its own principal (`svc:mdm:intune`, `svc:mdm:fleet`) with a **scope** in policy (e.g. intune: compliance read + notify; fleet: settings + actions).
- Overlapping writes to the same key are rejected and raised as `policy.conflict` events — never last-write-wins silently.

---

## 5. Agent security

- Runs as an unprivileged system user; only `eld` touches the system.
- Enrollment binds the agent to a **TPM-backed device key**; MDM credentials stored sealed.
- Policies signed by an org key; the trust anchor is set at enrollment and rotatable.
- Agent self-update goes through the same signed update channel as the OS.
- All agent actions appear in the audit stream as their connector principal.

---

## 6. Later: our own lightweight console (idea, not committed)

For small orgs with no MDM, a minimal web console (policy editor, fleet facts, actions) speaking the git/https-pull connector protocol. Not a competitor to Intune; listed in [FEATURE-IDEAS.md](FEATURE-IDEAS.md) as the Admin GUI idea.

---

## 7. Open questions

1. Which connector is v1: Intune (needs the spike), Fleet, or git/https-pull?
2. Is it acceptable that Intune integration depends on Microsoft's Linux app on Ubuntu/RHEL only?
3. Who holds the policy signing key — the org's IT, or us for a hosted option?
4. Same language as `eld` (Rust/Go) — or a separate one per connector?

---

## Sources

- [Intune custom configuration (bash scripts) for Linux](https://github.com/MicrosoftDocs/memdocs/blob/main/memdocs/intune/configuration/custom-settings-linux.md)
- [Intune custom compliance discovery scripts](https://learn.microsoft.com/en-us/intune/device-security/compliance/create-custom-script)
- [Intune Linux compliance settings](https://learn.microsoft.com/en-us/intune/device-security/compliance/ref-linux-settings)
- [Himmelblau: Intune compliance on Linux](https://himmelblau-idm.org/docs/advanced/Device-Compliance-Settings-for-Linux-in-Intune-with-Himmelblau/)
