# Control API: CLI and API for everything

**Status:** design, with a working v0 prototype in Rust (`crates/`); see [ELD.md](ELD.md) for what is built and what is not. Names (`eld`, `elctl`) are working names.  
**Date:** 2026-10-28  
**Related:** [MDM.md](MDM.md), [PERMISSIONS.md](PERMISSIONS.md), [HARDENING.md](HARDENING.md), [RESEARCH-ENTERPRISE-DISTROS.md](RESEARCH-ENTERPRISE-DISTROS.md)

---

## 1. Principle

> **Every setting, fact, and action on the device is reachable through one documented, versioned API. The CLI, the desktop GUI, MDM agents, EDR agents, and Ansible are all clients of that same API.**

This is the Red Hat Satellite pattern (UI = API = `hammer` CLI) applied to a single workstation. It means:

- An MDM vendor never has to scrape config files or run fragile shell scripts.
- An EDR can ask "is disk encrypted? is Secure Boot on? which policy version?" and get typed JSON.
- Our own GUI has no private back door — if the GUI can do it, an admin can script it.
- Everything goes through one place where it is **authorized and audited**.

---

## 2. Components

```
            ┌────────────────────────────────────────────────────────┐
            │                     Clients                            │
            │  elctl CLI │ Desktop app │ MDM agent │ EDR agent │ Ansible│
            └─────┬──────────┬─────────────┬───────────┬──────────┬──┘
                  │          │             │           │          │
         D-Bus (system bus)  │     REST/JSON over Unix socket      │
                  │          │   /run/eld/api.sock (local only)    │
            ┌─────▼──────────▼─────────────▼───────────▼──────────▼──┐
            │  eld  — control daemon (systemd service, confined)      │
            │  authz (polkit + roles) · audit · schema validation     │
            ├───────────────────────────┬────────────────────────────┤
            │ Providers (plugins)       │ Event bus                  │
            │ identity · updates · apps │ journald + JSON event      │
            │ encryption · firewall ·   │ stream (SSE on socket)     │
            │ usb · mac · devices · …   │                            │
            └───────────────────────────┴────────────────────────────┘
                     │ uses native tools underneath (systemd, nmcli/firewalld,
                     │ cryptsetup, usbguard, flatpak, apt/dnf, sssd/authd …)
```

- **`eld`** — a small system daemon. It does not reimplement anything; it wraps native tools behind a stable schema. Runs confined (SELinux/AppArmor profile), no network listener by default.
- **`elctl`** — CLI. Human output by default, `--json` / `--yaml` for machines, stable exit codes.
- **Transports**
  - **D-Bus** `org.enterpriselinux.Control1` on the system bus — natural for the desktop GUI and polkit.
  - **REST/JSON over a Unix socket** `/run/eld/api.sock` — easiest for MDM/EDR agents in any language. Peer credentials (`SO_PEERCRED`) identify the calling process/user.
  - **No TCP listener by default.** Remote control always goes through the org's MDM/EDR agent or SSH-less channels the org already trusts. An optional mTLS listener is a later, opt-in idea.
- **Providers** — one module per domain. Each declares its settings schema, facts, and actions.

---

## 3. Resource model

Four kinds of things, the same for every domain:

| Kind | Meaning | Example |
|---|---|---|
| **facts** | Read-only state the device reports | `encryption.root.status = "encrypted"`, `boot.secure_boot = true` |
| **settings** | Desired state, declared by policy | `updates.ring = "pilot"`, `usb.storage = "block"` |
| **actions** | Imperative, audited operations | `device.lock`, `updates.install-now`, `encryption.rotate-recovery-key` |
| **events** | Things that happened | `policy.applied`, `usb.blocked`, `login.failed`, `compliance.changed` |

### Namespaces (v1 draft)

| Namespace | Facts | Settings | Actions |
|---|---|---|---|
| `device` | serial, model, TPM present, firmware, enrollment state | name, owner group, asset tag | lock, reboot, wipe (with confirmation token), collect-logs |
| `os` | distro, version, image id, build hash, kernel | — | — |
| `updates` | pending updates, last success, reboot required | ring, maintenance window, max deferral | check, install-now, rollback |
| `identity` | joined IdP, last sync, cached users | allowed login groups, offline grace | resync |
| `roles` | effective roles per user | role → group mapping | grant-temporary (JIT), revoke |
| `apps` | installed apps + versions | bundles enabled, allowed catalog, blocked apps | install, remove, repair |
| `encryption` | per-volume status, unlock method, escrow status | require encryption, TPM PCR policy, crypto profile | rotate-recovery-key, escrow-now |
| `security` | MAC mode, allowlisting mode, firewall state, Secure Boot | baseline profile, firewall rules, USB policy | run-compliance-scan |
| `network` | interfaces, VPN state | Wi-Fi profiles, VPN, proxy, DNS | — |
| `desktop` | session type, theme | locked keys, wallpaper, favorites, extensions allowed | send-notification |
| `compliance` | overall state + failing rules | which checks are required | evaluate |
| `audit` | — | log forwarding target | export |

---

## 4. Examples

```bash
# Facts
elctl facts get encryption --json
elctl facts get --all --json > facts.json          # what an MDM inventory call would do

# Settings (desired state)
elctl settings set updates.ring pilot
elctl settings apply -f policy.yaml                # whole policy document, validated against schema
elctl settings diff -f policy.yaml                 # dry run

# Actions
elctl action run updates.install-now
elctl action run encryption.rotate-recovery-key --escrow mdm
elctl action run roles.grant-temporary --user alice@corp --role local-admin --for 30m --ticket INC-1234

# Events
elctl events follow --json                          # stream, for EDR/SIEM
```

REST equivalents over the Unix socket:

```
GET  /v1/facts/encryption
PUT  /v1/settings            (body: policy document; ETag for optimistic concurrency)
POST /v1/actions/updates.install-now
GET  /v1/events?follow=true  (Server-Sent Events)
GET  /v1/schema              (JSON Schema / OpenAPI of everything above)
```

### Policy document (draft shape)

```yaml
apiVersion: enterprise-linux/v1
kind: DevicePolicy
metadata:
  name: finance-laptops
  version: 2026.10.3
spec:
  updates:   { ring: broad, window: "Mon-Fri 12:00-13:00", maxDeferralDays: 7 }
  encryption: { required: true, unlock: tpm2+pin, escrow: mdm }
  security:  { baseline: cis-l1-workstation, usb: { storage: block, allow: [ "vendor:046d" ] } }
  apps:      { bundles: [ base, office ], allowSelfService: true }
  desktop:   { lock: [ wallpaper=false, screensaver.timeout=true, extensions=true ] }
  roles:     { local-admin: [ "entra:group:IT-Linux-Admins" ], helpdesk: [ "entra:group:Helpdesk" ] }
```

Policies are **declarative and idempotent**: applying the same document twice changes nothing. The device stores the last applied version and reports it as a fact so the MDM can tell drift from success.

---

## 5. Integration contracts

### MDM
- **Inventory** = `GET /v1/facts`. Stable keys, documented units, semantic versioning of the schema.
- **Policy** = `PUT /v1/settings` with a full `DevicePolicy`. Response returns per-key result (`applied`, `unchanged`, `rejected: reason`).
- **Compliance** = `GET /v1/facts/compliance`. Designed so an Intune *custom compliance script* is a three-line wrapper: call `elctl facts get compliance --json` and print it.
- **Remote actions** = `POST /v1/actions/...`. Destructive actions (`device.wipe`) require a signed confirmation token from the MDM, not just local root.
- **Precedence** when several sources set the same key: `MDM policy > local admin (elctl) > user`. Conflicts are reported as events, never silently overwritten.

### EDR
- **Read** any fact (posture context for detections).
- **Subscribe** to the event stream (USB blocks, policy changes, privilege grants, failed logins, allowlisting denials).
- **Response actions** an EDR may request, if the org allows it in policy: `network.isolate` (firewall to EDR/MDM endpoints only), `device.lock`, `session.logout`, `apps.block`. Each is a normal audited action.
- **Coexistence rules:** we never fight the EDR for the same kernel hook. EDR agents (e.g. Defender's `mdatp`, CrowdStrike, SentinelOne, Wazuh) install into a documented **agent slot** with a known SELinux/AppArmor policy and fapolicyd trust entry.
- **Supportability:** keep `/etc/os-release` and kernel packages identical to the upstream substrate so vendor support matrices still apply (see [research §4](RESEARCH-ENTERPRISE-DISTROS.md#4-microsoft-on-linux-mdm-and-edr-reality-check)).

### SIEM / logging
- Every API call → structured audit record (who, which client process, what, old → new, result) in journald with a stable `MESSAGE_ID`, plus optional forwarding (syslog/TLS, OTLP).

### Config management
- An Ansible collection / Salt module is a thin wrapper over `elctl` — no separate logic.

---

## 6. Security of the API itself

- **AuthN:** Unix peer credentials (UID, PID, SELinux/AppArmor label of the caller). No passwords or tokens on the local socket.
- **AuthZ:** every method maps to a polkit action (`org.enterpriselinux.updates.install` …). Roles from [PERMISSIONS.md](PERMISSIONS.md) decide which actions each user/agent gets. MDM and EDR agents are registered **service principals** with their own scoped role.
- **Audit:** all writes and all actions audited; reads of sensitive facts (recovery key metadata) audited too. Recovery keys themselves are **never** returned by the API — only escrowed.
- **Rate limiting and confirmation** for destructive actions.
- **Schema-first:** OpenAPI + JSON Schema published per release; breaking changes only on a major API version, with the old version served for one release train.

---

## 7. Open questions

1. ~~Daemon language: Rust vs Go?~~ **Decided 2026-10-29: Rust**, minimal dependencies (serde, serde_json, libc). See [ELD.md](ELD.md).
2. Do we expose an opt-in mTLS network listener at all, or always rely on the MDM/EDR agent on the box?
3. Which MDM do we write the first reference wrapper for (Intune custom compliance, Fleet, Landscape)?
4. Policy files are JSON in v0; YAML input needs a parser dependency. Should the policy format be compatible with an existing standard (e.g. osquery/Fleet policies, Kubernetes-style YAML as drafted above)?
