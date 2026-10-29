# security/permissions — role-based permissions (first implementation)

**Status:** design stage, first runnable code. Unit-tested in a temp root only.
It has **not** run on a real device or fleet. Nothing here has been tried
against a live Entra ID tenant, authd, Himmelblau or SSSD. Treat the group
naming defaults, PAM wiring and polkit action ids as starting points to check
on each substrate.

This directory turns [docs/PERMISSIONS.md](../../docs/PERMISSIONS.md) into code
that does not depend on one distro. It targets Ubuntu 24.04/26.04 (classic
`sudo` or `sudo-rs`) and RHEL 9/10-family. It needs Python 3.11+ (stdlib only)
and bash.

| PERMISSIONS.md | Here |
|---|---|
| §1 No standing local admin; permissions come from directory groups | `el-perm-render` builds sudoers/polkit/pam_access **only** from policy groups. `--check` flags hand-made `/etc/sudoers.d` files and `%sudo`/`%wheel` lines in `/etc/sudoers` |
| §2 Roles + YAML mapping | `policy/roles.example.json` + `policy/roles.schema.json` (`user`, optional `power-user`, `helpdesk`, `local-admin`, `breakGlass`) |
| §3 Who can log in | `/etc/security/el-access.conf` (pam_access) from `login.allow`/`login.deny` |
| §3 sudo, `NOPASSWD` never by default | `/etc/sudoers.d/50-el-roles`. `nopasswd` is a schema error unless `spec.sudo.allowNopasswd: true` |
| §3 polkit rules from roles | `/etc/polkit-1/rules.d/40-el-roles.rules` (see the note on the file name below) |
| §4 JIT elevation, auto-revoke, command-scoped, recording | `el-jit`, `el-jit-expire.timer`, PAM session-close hook, `sessionRecording` |
| §5 Signed offline cache, elevated roles drop on expiry, break-glass offline | `lib/elperm/cache.py`, degraded render mode, `el-breakglass` |
| §6 Audit events | `roles.granted/revoked/expired/requested/denied/degraded/drift/cache_invalid`, `breakglass.used/rotated/rotation_failed` sent to journald |
| svc:mdm / svc:edr | **Not covered.** These are Control API (`eld`) scopes, not something sudo or polkit controls |

## Policy format: JSON (not TOML)

The policy is JSON, checked against a JSON Schema. Why JSON:

* The Control API ([CONTROL-API.md](../../docs/CONTROL-API.md)) exchanges JSON,
  and the MDM pushes the policy as part of a `DevicePolicy`. JSON avoids a
  format conversion on the device.
* JSON Schema is the API's schema language, so one schema file covers both
  validation here and the published API.
* The stdlib can both read and write JSON. `tomllib` can only read TOML, and
  the signed cache must be written back out in a canonical form.

The schema is enforced by `lib/elperm/jsonschema_lite.py`. It implements a
subset of JSON Schema 2020-12 so there is no third-party dependency. After the
schema check, `policy.py` runs semantic checks:

* `user` may not have sudo.
* The same group may not appear in both `login.allow` and `login.deny`.
* `jit.defaultDuration` must not be longer than `jit.maxDuration`.
* `ALL` must be the only command in a list that contains it.
* Two directory groups may not map to the same POSIX name.

YAML (as drafted in PERMISSIONS.md) is a simple conversion step on the MDM side.

## Layout

Repository:

```
policy/roles.example.json       example policy (mirrors PERMISSIONS.md §2)
policy/roles.schema.json        JSON Schema
lib/elperm/                     Python package
  policy.py naming.py           validation, directory group -> POSIX naming
  render.py                     sudoers / polkit / pam_access / groupmap / manifest / drift
  cache.py                      signed offline cache (HMAC-SHA256 or ed25519 via openssl)
  jit.py breakglass.py          JIT grants, break-glass rotation
  events.py                     structured events -> journald
  cli.py                        entry points
bin/el-perm-render bin/el-jit bin/el-breakglass
pam/el-jit-session-close        pam_exec: revoke JIT grants on logout
pam/el-breakglass-session-open  pam_exec: break-glass login -> breakglass.used
pam/pam-auth-update.el-roles    Ubuntu pam-auth-update profile (untested)
systemd/el-jit-expire.{service,timer}         every minute
systemd/el-breakglass-rotate.{service,timer}  every 15 min, rotates when used/due
systemd/el-perm-render.{service,timer}        hourly re-render from cache (enforces grace expiry)
tests/                          unittest suite
```

On a device (proposed install paths):

| Path | Mode | Written by | Contents |
|---|---|---|---|
| `/etc/sudoers.d/50-el-roles` | 0440 | render | Group-based role rules + break-glass |
| `/etc/sudoers.d/60-el-jit-<user>[-cmd-<id>]` | 0440 | el-jit | Time-bounded grant |
| `/etc/polkit-1/rules.d/40-el-roles.rules` | 0644 | render | Role -> polkit results, admin identities |
| `/etc/polkit-1/rules.d/39-el-jit.rules` | 0644 | el-jit | Active full JIT grants, with expiry built into the JS |
| `/etc/security/el-access.conf` | 0644 | render | pam_access table |
| `/etc/el/roles/groupmap.json` | 0644 | render | Directory group -> POSIX name, rule used, which provider supplies it |
| `/etc/el/roles/breakglass.json` | 0644 | render | Break-glass account name and rotation settings (no secrets) |
| `/etc/el/roles/cache.key` | 0600 | render | HMAC key (hmac mode) |
| `/etc/el/roles/mdm-signing.pub` | 0644 | enrollment | MDM ed25519 public key (ed25519 mode) |
| `/var/lib/el/roles/cache.json` | 0600 | render | Signed last-known policy with `issued_at`/`expires_at` |
| `/var/lib/el/roles/manifest.json` | 0644 | render | sha256 + mode of each rendered file, policy hash, mode |
| `/var/lib/el/roles/grants.json` | 0600 | el-jit | Grants and pending requests |
| `/var/lib/el/roles/breakglass-state.json` | 0600 | el-breakglass | Rotation and use timestamps (never the password) |
| `/usr/lib/el/permissions/{lib,policy}` | | package | Code + schema |
| `/usr/libexec/el/el-jit-session-close`, `el-breakglass-session-open` | 0755 | package | PAM hooks |

Every write is atomic. Each file is written to a dot-prefixed temp file in the
target directory, then fsync'd, validated, chmod'ed, chowned to root, and
finally moved into place with `rename(2)`, followed by a directory fsync.
sudo's includedir skips dot-files and names that contain `.`, so a temp file
is never read as a live rule. For the same reason JIT file names never contain
`.`: `alice@corp.example` becomes `alice_corp_example_<hash>`.

## Flows

### Render (MDM sync)

```
el-perm-render --policy /run/el/policy.json      # fresh policy from the MDM/eld
```

1. Check the policy against the schema and the semantic rules.
2. Write the signed cache. Expiry = now + `offline.graceDays`.
3. Render the files. Each sudoers file is checked with `visudo -cf` **before**
   it replaces the live file. If visudo rejects it, the old file stays. If
   visudo is missing, render prints a warning; with `--strict-visudo` it fails
   instead (the systemd unit passes it).
4. Write the manifest and emit `roles.rendered`.

Other modes:

* `--check`: report drift without writing anything. Exit 2 if there is drift.
  Reports:
  * `modified`: the file on disk no longer matches the manifest (someone edited it).
  * `stale`: the policy changed and a render is needed.
  * `missing` and `badmode`.
  * `unmanaged`: extra `/etc/sudoers.d` files.
  * warnings, e.g. `%sudo`/`%wheel` lines in `/etc/sudoers`.
* `--check-nss`: list mapped groups that NSS cannot resolve right now.
* `--root DIR`: render into a test tree. Root is not required.
* `--sudo-impl sudo|sudo-rs`: skip auto-detection (`sudo --version`).

What gets rendered:

* **sudoers**:
  * `Defaults use_pty`, `secure_path`.
  * `logfile` (classic sudo only).
  * `log_output` + `iolog_dir` when `sessionRecording.enabled` is on and the
    implementation is classic sudo. sudo-rs has no I/O log, so the file gets a
    comment pointing at tlog instead.
  * One line per role group, e.g. `%it-linux-admins, !%offboarding ALL=(ALL:ALL) ALL`.
    In a sudoers user list the last match wins, so the trailing
    `!%<deny-group>` makes **deny override allow**.
  * The break-glass account line is always present.
* **polkit**:
  * One `addAdminRule` covering the break-glass user and the groups of roles
    with `polkit.admin: true`.
  * One `addRule`, checked in this order:
    1. Members of login-deny groups get `NO`.
    2. The break-glass user gets `AUTH_ADMIN_KEEP`.
    3. Each role, highest priority first: its action entries (exact id or
       `prefix.*`, optional systemd `units`/`verbs` filter), then its
       `default`. `local-admin` defaults to `auth_admin_keep`. `helpdesk` may
       restart NetworkManager/CUPS and use NetworkManager.
    4. The `user` rules, e.g. `NO` for PackageKit, printer-driver install and
       `systemd1.manage-units`.
* **File name note:** the brief asked for `50-el-roles.rules`. polkit reads
  `/etc` and `/usr/share` rules in lexical basename order, and the **first**
  admin rule that returns a value wins. Distros ship `50-default.rules`
  (`unix-group:wheel`/`sudo`), which sorts before `50-el-roles.rules`. So we
  use `40-el-roles.rules` and `39-el-jit.rules` to make our admin identities
  and role results apply.
* **pam_access**: lines are `+:root <breakglass>:LOCAL`, then
  `-:(<deny>):ALL`, then `+:(<allow>):ALL`, then `-:ALL:ALL`. First match wins.
  To turn it on:
  * Ubuntu: `pam/pam-auth-update.el-roles`.
  * RHEL: an authselect custom profile that adds
    `account required pam_access.so accessfile=/etc/security/el-access.conf`.
  * Both are untested.

### Directory groups -> POSIX groups

The rendered rules name POSIX groups. The identity module supplies them
through NSS:

* AD/IdM: SSSD.
* Entra ID: authd or Himmelblau.

`naming.py` applies a fixed, policy-defined rule to each reference
(`entra:group:X`, `ad:group:X`, `local:group:x`):

* `template` per source. `{slug}` lowercases the name and turns any run of
  characters outside `[a-z0-9_.-]` into `-`. `{name}` keeps the name as is.
* `maxLength`. Longer names are cut and given a sha256 suffix so the result
  stays deterministic.
* `overrides` takes priority over the template.

Every result must be a safe POSIX name, and two directory groups may not map
to the same one. `groupmap.json` records the mapping on the device.

**Assumption to verify per provider.** Each provider names groups its own way:

* SSSD: `use_fully_qualified_names` / `full_name_format`.
* Himmelblau and authd: their Entra group naming has to be checked.

If a provider's names differ from the rule, use `overrides` or a template such
as `{slug}@corp.example`.

### JIT elevation

```
el-jit request --reason "install scanner driver" --for 30m [--command "/usr/bin/apt-get install ./x.deb"] [--ticket INC123456]
el-jit grant alice --for 30m --reason ...        # helpdesk/admin
el-jit approve <request-id> | el-jit deny <request-id>
el-jit revoke alice
el-jit list [--json]
el-jit expire [--user U --logout]                # timer / PAM hook
```

* **Who runs it.** Every subcommand except `list` must run as root. On the
  device, a user's request reaches it through `eld` (D-Bus + polkit, per
  CONTROL-API.md) or pkexec. The caller is taken from `SUDO_USER`/`PKEXEC_UID`.
  A non-root caller cannot request on behalf of another user.
* **Approvers** (`jit.approver.mode`):
  * `auto`: members of `autoApproveGroups` are granted at once. Everyone else
    gets a pending request.
  * `helpdesk`: always a pending request. Members of `approverRoles` approve
    it. Self-approval is refused.
  * `ticket`: `--ticket` must match `ticketPattern`. An optional
    `ticketVerifyCommand` hook (`<cmd> <ticket> <user>`, exit 0 = valid) can
    also check it.
* **Checks before a grant:**
  * The user resolves via NSS.
  * The user is not in a login-deny group (deny overrides allow).
  * The user is not the break-glass account.
  * The duration is at most `jit.maxDuration`. This applies to admins too.
  * The policy's reason requirement is met.
  * The offline cache is valid. No JIT is possible once it has expired.
* **Command-scoped grants.** The command must match a
  `jit.commandAllowlist` fnmatch pattern. The sudoers rule then contains the
  **exact** command, never the pattern. Wildcards and sudoers special
  characters (`, : = \ # ! * ? [ ]`) are rejected. Command grants never get
  polkit admin.
* **What a grant writes.** A sudoers drop-in with `NOTAFTER=` (classic sudo
  only), checked with visudo. A polkit entry in `39-el-jit.rules` with the
  expiry in the JS, so it stops matching on time even if no timer runs. A
  record in `grants.json`. Then a `roles.granted` event. `NOPASSWD` is never
  used: the user re-authenticates through PAM (MFA where the identity module
  supports it).
* **Expiry** (`roles.expired`) comes from:
  * `el-jit-expire.timer`, every minute.
  * The PAM session-close hook (`revokeOnLogout`).
  * `NOTAFTER` (classic sudo) and the polkit clock check.
  * Render in degraded mode, and `el-jit expire` whenever the cache is not
    valid. Both revoke **all** grants.

### Break-glass

```
el-breakglass rotate [--if-due] [--reveal-to-stdout-for-escrow-pipe]
el-breakglass mark-used [--note ...]
el-breakglass status
el-breakglass pam-hook          # from pam_exec
```

* **Password.** Random, `passwordLength` long (24 by default), with at least
  one character from each class and no ambiguous characters.
* **Escrow before set.** The JSON `{account, password, generation,
  rotated_at}` is sent on stdin to `breakGlass.escrowCommand` (for example an
  MDM agent CLI). If escrow fails, nothing changes. After that, `chpasswd`
  sets the password; under `--root` it uses `-R`. If chpasswd fails after
  escrow, `breakglass.rotation_failed` fires at alert severity. **Escrow
  backends must keep password history** (LAPS does).
* **The password is never logged, stored or printed.** The one exception is
  `--reveal-to-stdout-for-escrow-pipe`, which is refused when stdout is a
  terminal.
* **Without an escrow command or that flag, rotation is refused**, because the
  new password would be lost.
* **Use is recorded.** The PAM hook (session open with `PAM_USER` = the
  account, which covers console login, `su` and `sudo -u`) or `mark-used`
  emits `breakglass.used` at **crit** and sets `rotate_due_at = now +
  rotateAfterUseMinutes`. `el-breakglass-rotate.timer` runs `rotate --if-due`.
  Periodic rotation follows `rotateEveryDays`.
* **Offline.** Settings come from `/etc/el/roles/breakglass.json`, not from
  the cache, so break-glass works offline even when the cache is expired or
  invalid. The account stays in sudoers and polkit in every mode.
* **Account creation** is an image step, e.g. `useradd -m -s /bin/bash
  elbreakglass` with a locked password until the first rotation. The tool
  does not create the account.

### Offline cache

| | `hmac-sha256` (default) | `ed25519` |
|---|---|---|
| Who signs | The device, with a random key in `/etc/el/roles/cache.key` (0600) | The MDM. The device verifies with `/etc/el/roles/mdm-signing.pub` |
| Dependency | stdlib `hmac` | `openssl pkeyutl -rawin` (OpenSSL ≥ 3.0, on Ubuntu 24.04+ / RHEL 9+) |
| Proves | Integrity; not copied from another device; not edited by anyone who cannot read the key | Also that the MDM issued it. The MDM, not the device clock, sets the expiry |
| Does not stop | Local root (which can edit sudoers directly anyway) | Local root |
| Input | `el-perm-render --policy file.json` | `el-perm-render --bundle signed.json` (`--make-bundle` is an MDM/test helper) |

HMAC is the default because it needs no extra tools and no MDM signing
infrastructure. ed25519 is the target once an MDM-side signer exists.

States:

| State | Meaning | What render does |
|---|---|---|
| `valid` | Signature good, not expired | Normal render |
| `expired` | Signature good, grace period over | **Degraded** render: every role with `elevated: true` (default for all except `user`) is left out of sudoers and polkit. Login rules stay. Break-glass stays. JIT grants are revoked. Emits `roles.degraded` |
| `invalid` | Bad signature, hash mismatch, key missing, malformed, or `issued_at` more than 5 min in the future (clock rollback) | Exit 3, write **nothing**, emit `roles.cache_invalid`. Existing files stay as they are, and `--check` shows the state |
| `missing` | No cache yet | Exit with an error |

Grace expiry only takes effect when something re-renders. That is the job of
`el-perm-render.timer` (hourly; it runs without `--policy`).

## Events

Each event is a JSON object: `{"event", "ts", "severity", "host", ...}`.

* It is sent with `logger --journald` and carries `MESSAGE_ID` (a stable
  UUIDv5 per event name), `PRIORITY`, `SYSLOG_IDENTIFIER=el-perm`, `EL_EVENT`,
  `EL_DATA` (the full JSON) and `EL_USER`/`EL_ROLE`/... fields that can be
  matched on.
* If that fails, it goes to `systemd-cat -t el-perm -p <prio>`, then to stderr.
* With `--json`, events and the command result are also printed to stdout as
  JSON Lines.
* Severities: `breakglass.used` is crit, `breakglass.rotation_failed` alert,
  `roles.cache_invalid` err, `roles.denied`/`roles.degraded`/`roles.drift`
  warning, and grant/revoke/expire notice.

## Security notes

* The bin wrappers use `#!/usr/bin/python3 -I`, so `PYTHONPATH`, user site
  and the current directory are ignored. The PAM hooks call fixed binary paths
  and never read paths from the PAM environment, which a user can influence.
  The hooks are `optional` and always exit 0, so they never block login or
  logout.
* User and group names are checked against a conservative pattern before they
  go into sudoers, access.conf or JS. Polkit strings are JSON-encoded, and the
  JIT JS uses `hasOwnProperty`, so a user named `constructor` cannot match.
* Commands in policy and JIT requests reject sudoers metacharacters. Helpdesk
  sudo commands in the example are fixed commands. Note that
  `/usr/libexec/el/collect-logs` is a placeholder wrapper and is not shipped
  yet. Do **not** grant `journalctl`, `less` and similar tools directly: their
  pager can open a root shell.
* **An expired grant does not end root shells that are already open**
  (`sudo -i` started before expiry). It only stops new elevation. Ending
  sessions at expiry is an open question.
* **Revoke on logout fires on any session close of that user**, including one
  of several terminals or an SSH session. That is the safe direction, but it
  can annoy users.
* systemd units use `ProtectSystem=strict` with explicit `ReadWritePaths`,
  `PrivateNetwork` and `NoNewPrivileges` where possible.
* sudo-rs compatibility is assumed from its documented sudoers subset. It has
  not been tested:
  * `!%group` negation, `secure_path` and `use_pty` are assumed to work.
  * `NOTAFTER`, `logfile` and I/O logging are not emitted for sudo-rs.

## Tests

```
cd security/permissions
python3 -m unittest discover        # 96 tests, stdlib only
```

* Tests render into a temp root and use a fake clock, a stub command runner
  (visudo, chpasswd, logger, the escrow hook, `sudo --version`) and a fake NSS
  group resolver.
* Event delivery is tested through PATH-stub `logger`/`systemd-cat` scripts.
* Two tests use real tools when installed:
  * real `visudo -cf` on the rendered sudoers for both implementations and
    both modes;
  * real `openssl` ed25519 sign/verify of a bundle.
* `node --check` runs on the polkit JS when node is present.

## Open questions / assumptions

1. **Who brokers `el-jit request` for unprivileged users?** The design is
   `eld` over D-Bus. Until it exists, the request path is root-only (pkexec or
   sudo-to-eld).
2. **Where approvals live** (PERMISSIONS.md Q2). Pending requests live in the
   local `grants.json`. An MDM/ITSM approver would call `el-jit approve`
   through `eld`, or confirm a ticket through `ticketVerifyCommand`.
3. **Expiry of an invalid cache.** It currently stops rendering and keeps the
   existing files. The alternative is to fall back to degraded mode, but login
   rules can't be trusted from a bad cache.
4. **Default `graceDays` 7** (PERMISSIONS.md Q3). Laptops that never sync are
   not locked. They only lose elevation.
5. **Session recording** (Q4) is off by default. With classic sudo it uses
   sudo I/O logs. tlog integration for sudo-rs and for GUI sessions is not
   implemented.
6. **power-user** (Q1) ships disabled.
7. **Group naming defaults** (`{slug}`) are guesses until they are checked
   against authd, Himmelblau and SSSD on real tenants.
8. **sudo/wheel group cleanup** in `/etc/sudoers` is left to the hardening
   baseline. Here it is only reported.
9. **pam_access `LOCAL`** for the break-glass console line needs checking with
   GDM/GNOME login (PAM_TTY values).
