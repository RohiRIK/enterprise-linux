# eld and elctl: implementation notes (v0 prototype)

**Status:** working prototype of the [Control API](CONTROL-API.md). Builds, runs and is tested (CI workflow ready in `dist/ci/`), but it is **not packaged into an image yet** and most settings are **recorded, not enforced** (see §4). Nothing here is a claim of a shipping product.  
**Date:** 2026-10-29  
**Language:** Rust (decided 2026-10-29, closes CONTROL-API.md open question 1)

---

## 1. Layout

```
Cargo.toml                 workspace
crates/eld-api/            wire types + tiny Unix-socket HTTP client (shared by daemon and CLI)
crates/eld/                the daemon
  src/server.rs            routing, authz checks, audit, socket loop
  src/authz.rs             peer credentials -> roles (groups, policy mappings, JIT grants, service principals)
  src/store.rs             persisted desired state (/var/lib/eld/state.json, atomic writes, ETag)
  src/settings.rs          validation, policy flattening, precedence planning
  src/audit.rs             JSON-lines audit log + journald (stable MESSAGE_ID)
  src/events.rs            event bus with replay buffer, served as SSE
  src/http.rs              minimal HTTP/1.1 codec (Content-Length only, strict limits)
  src/sys.rs               the only code that touches the host (files + commands), fakeable in tests
  src/builtin.rs           namespaces backed by eld state: policy, roles, audit
  src/providers/*.rs       one module per domain: device, os, security, updates, apps, encryption,
                           network, identity, desktop, compliance
crates/elctl/              the CLI
dist/systemd/eld.service   hardened unit
dist/eld.json              example daemon config
dist/ci/rust.yml           GitHub Actions workflow (fmt, clippy -D warnings, test, release build); copy to .github/workflows/
examples/policy.json       the CONTROL-API §4 policy as JSON (tested to apply cleanly)
```

Dependencies are deliberately few: `serde`, `serde_json`, `libc` (for `SO_PEERCRED`). No async runtime, no HTTP framework: one thread per connection, capped at 64.

## 2. Build and try it

```bash
cargo build --release
sudo ./target/release/eld --socket /run/eld/api.sock          # or install dist/systemd/eld.service
elctl whoami
elctl facts get security
elctl settings diff  -f examples/policy.json
sudo elctl settings apply -f examples/policy.json
elctl --json facts get compliance
sudo elctl action run device.reboot --dry-run
sudo elctl action run roles.grant-temporary --user alice --role local-admin --for 30m --ticket INC-1234
sudo elctl events follow --json
```

For development without root: `eld --config /dev/null --socket ./api.sock --state-dir ./state --audit-log ./audit.jsonl --no-journald` and `elctl --socket ./api.sock ...` (or `ELD_SOCKET=./api.sock`).

## 3. What works

| Area | v0 behaviour |
|---|---|
| Transport | REST/JSON over `/run/eld/api.sock`, no TCP listener. Endpoints exactly as CONTROL-API.md §4, plus `PATCH /v1/settings`, `DELETE /v1/settings/{key}`, `GET /v1/whoami`. |
| AuthN | `SO_PEERCRED` (uid, gid, pid) + SELinux/AppArmor label from `/proc/<pid>/attr/current`. No tokens or passwords. |
| Roles | root = local-admin; others = user, plus roles from `groupRoles` in config, policy keys `roles.<role>` (directory group names as surfaced by authd/SSSD), and unexpired JIT grants. MDM/EDR agents are service principals by Unix account. |
| AuthZ | Reads: any local user (encryption reads audited). Settings writes: local-admin or svc:mdm. Events: helpdesk+. Each action declares its minimum role. Destructive actions rate-limited. |
| Precedence | Every stored value remembers its source; `mdm > local-admin > user`. Lower sources are rejected per key and a `settings.conflict` event is raised. A full policy `PUT` removes keys that source no longer sets. |
| Policy | `DevicePolicy` JSON, validated per key against the schema, idempotent (second apply = all `unchanged`), dry run via `POST /v1/settings/diff`, optimistic concurrency via `ETag`/`If-Match`. Applied name/version reported as `policy` facts. |
| Facts | 13 namespaces. Real readers for os-release, DMI, TPM, efivars Secure Boot, SELinux/AppArmor, firewalld/ufw/nftables, sshd, USBGuard, fapolicyd, auditd, apt/dnf/zypper pending updates and reboot state, lsblk + cryptsetup LUKS/TPM2 token detection, Flatpak and package inventory, NetworkManager VPN, authd/SSSD/Himmelblau, logind sessions. Anything unreadable is `"unknown"`, never a guess. |
| Compliance | Rule engine over the other namespaces' facts (`compliance` facts + `compliance.evaluate`). Required rules set by `compliance.required`. |
| Actions | Implemented: `device.lock/reboot/collect-logs`, `updates.check/install-now`, `apps.install/remove/repair` (allow-list + self-service policy enforced), `identity.resync` (SSSD), `security.run-compliance-scan` (OpenSCAP), `roles.grant-temporary/revoke`, `audit.export`, `compliance.evaluate`. Every mutating action supports `--dry-run`, which returns the exact native commands. |
| Audit | Every write, action, denial and event: who, process, polkit action id, old -> new, outcome. JSON lines (0600) + journald native protocol. |
| Distro support | Branches on substrate family only (Debian/Ubuntu, RHEL-family, SUSE), never on a distro name. Tested on Ubuntu 24.04; RHEL paths are covered by fixture tests only. |

## 4. What is honest-not-done

- **Enforcement.** Every setting reports `"enforced": false` in `/v1/schema`. eld stores, validates, reports and evaluates compliance against them, but does not yet render USBGuard rules, firewall zones, dconf locks, sudoers/polkit rules, or PAM access from them.
- **JIT grants** change what eld itself allows; they do not yet create sudo rights.
- **Declared but refusing** (`implemented: false`): `device.wipe` (needs MDM-signed confirmation tokens), `encryption.rotate-recovery-key` / `escrow-now` (escrow target not chosen), `updates.rollback` (needs image-based substrate), `network.isolate` / `release-isolation`, `desktop.send-notification`.
- **Transports and policy formats.** No D-Bus interface yet, so no polkitd delegation (polkit action ids are recorded in the audit log for when it lands). Policy files are JSON only; YAML needs a parser dependency we have not chosen.
- **Confinement.** No SELinux/AppArmor profile for eld yet; the systemd unit is narrowed but eld still runs as root because the tools it wraps need it.
- **Schema.** `/v1/schema` returns the settings/actions specs; a full OpenAPI document is not generated yet.

## 5. Adding a provider

Implement `provider::Provider` in `crates/eld/src/providers/<ns>.rs`, read the host only through `env.sys`, declare settings/actions with fully qualified names, honour `dry_run`, and register it in `eld::registry`. Tests use `sys::Host::fake(dir, FakeRunner::new().on("cmd args", exit, stdout))`.
