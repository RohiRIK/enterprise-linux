# Permissions management

**Status:** design; first implementation in [`security/permissions/`](../security/permissions/README.md) (container-tested only, not hardware-tested).  
**Date:** 2026-10-28  
**Related:** [IDENTITY.md](IDENTITY.md), [CONTROL-API.md](CONTROL-API.md), [HARDENING.md](HARDENING.md)

---

## 1. Goals

- **No standing local admin** for regular users. Admin is a role you get, for a reason, for a time.
- **Permissions come from the org directory** (Entra groups first, AD/IdM groups second) — not from hand-edited `/etc/sudoers` or `/etc/group`.
- **Works offline** with cached decisions and a defined grace period.
- **Every privilege use is audited** and visible to MDM/EDR/SIEM via the [Control API](CONTROL-API.md).
- **One model** for the user, the helpdesk, the MDM agent, and the EDR agent.

Reference: Red Hat IdM centralizes **HBAC** (who may log in to which host) and **sudo rules** in the directory and SSSD enforces them with an offline cache. We take the same model but source it from Entra groups so customers do not need a second directory. See [research §1](RESEARCH-ENTERPRISE-DISTROS.md#1-red-hat-rhel-ecosystem).

---

## 2. Roles (default set)

| Role | Who | Can | Cannot |
|---|---|---|---|
| **user** | Every employee allowed on the device | Log in, use apps, install from the curated self-service catalog, change "user" tier desktop settings, connect allowed Wi-Fi/VPN, pair Bluetooth audio, print | Install arbitrary packages, change security settings, sudo |
| **power-user** (optional) | Developers | Everything in *user* + rootless containers (Podman), developer bundle, local VMs, selected `elctl` actions (e.g. restart network) | Change security baseline, disable encryption/firewall/EDR |
| **helpdesk** | IT support | Read all facts, collect logs, reset desktop settings, re-run policy, trigger updates, **approve** JIT requests | Read user files, disable security controls |
| **local-admin** | IT Linux admins | Full `sudo`, all `elctl` actions except those reserved to MDM | Remove MDM/EDR agent or turn off audit (only MDM policy can) |
| **break-glass** | Emergency only | Local root with a one-time password rotated and escrowed by MDM (LAPS-style) | Be used without generating a high-severity event |
| **svc:mdm**, **svc:edr** | Agent service principals | Scoped API rights as defined in policy | Anything outside their scope |

Roles are mapped to directory groups in policy:

```yaml
roles:
  local-admin: [ "entra:group:IT-Linux-Admins" ]
  helpdesk:    [ "entra:group:Helpdesk-T1" ]
  power-user:  [ "entra:group:Engineering" ]
login:
  allow:       [ "entra:group:All-Employees" ]    # HBAC equivalent
  deny:        [ "entra:group:Offboarding" ]
```

---

## 3. Enforcement layers

| Layer | Mechanism | Driven by |
|---|---|---|
| **Who can log in** | PAM access via the identity module (authd/SSSD/Himmelblau-class) + login allow/deny groups | `login.allow` / `login.deny` |
| **sudo** | sudo-rs / sudo with rules rendered from roles; no user-editable sudoers; `NOPASSWD` never by default | `roles.local-admin` |
| **GUI admin prompts** | **polkit** rules generated from roles (e.g. helpdesk may restart NetworkManager, users may not install printer drivers) | role → polkit action map |
| **Control API** | Every API method is a polkit action; service principals get scoped grants | [CONTROL-API.md §6](CONTROL-API.md#6-security-of-the-api-itself) |
| **App permissions** | Flatpak portals + sandbox overrides set by policy (camera, mic, filesystem, network) | `apps.permissions` |
| **Devices** | USBGuard rules; Bluetooth class allowlist; camera/mic hardware kill via policy | `security.usb`, `devices.*` |
| **MAC** | SELinux confined users (RHEL family) or AppArmor (Ubuntu) to cap what even sudo shells can do | baseline profile |

---

## 4. Just-in-time (JIT) elevation

Inspired by Windows LAPS / Endpoint Privilege Management and Red Hat IdM sudo rules with time limits.

1. User clicks **"Request admin"** in the desktop app (or `elctl request admin --reason ... --for 30m`).
2. Request goes to the approver channel defined in policy: auto-approve for listed groups, helpdesk approval in the MDM/ITSM, or a ticket number.
3. On approval, `eld` grants the `local-admin` role for N minutes, writes a `roles.granted` event, and **revokes automatically** at expiry or logout.
4. Optional: **command-scoped elevation** — approve only specific commands (e.g. install one `.deb`/`.rpm` from an allowed source) instead of a full shell.
5. Optional: session recording (tlog, as in RHEL) for elevated shells.

---

## 5. Offline behaviour

- Last-known role mappings are cached and signed; cache lifetime set by policy (default: 7 days).
- After expiry: users can still log in with cached credentials (if allowed), but **elevated roles drop to user** until the device can sync.
- Break-glass works fully offline (password escrowed in MDM, rotated after use).

---

## 6. What is audited

`login.success/failed`, `roles.granted/revoked/expired`, `sudo.command`, `polkit.authorized/denied`, `api.write`, `breakglass.used`. All as structured events (see [CONTROL-API.md §5](CONTROL-API.md#siem--logging)).

---

## 7. Open questions

1. Do we need a **power-user** role at all in v1, or only user/helpdesk/admin?
2. Where do JIT approvals live — our own lightweight approver, the MDM, or an ITSM (ServiceNow/Jira) webhook?
3. Default offline grace period (7 days?) and whether laptops that never sync should lock.
4. Session recording: on by default for elevated sessions or opt-in (privacy/labour-law dependent, e.g. EU works councils)?
