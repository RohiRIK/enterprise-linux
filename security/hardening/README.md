# Hardening baseline (first cut)

**Status:** first real code for [docs/HARDENING.md](../../docs/HARDENING.md) §1 layers 6–13 and 16.
**Nothing here has been tested on real hardware or a real install yet.** The tests run offline against fake root trees and stubbed commands, nothing more.
**Not a certification claim.** This is an implementation guide oriented on CIS / DISA STIG. Where a setting has a [ComplianceAsCode](https://github.com/ComplianceAsCode/content) rule, it is cited as `Ref: <rule_id>`, and the CaC content maps that rule to CIS/STIG item numbers for whichever benchmark version you scan with. Real compliance evidence comes from an OpenSCAP scan (layer 15), not from this tool.

The substrate decision is still open, so the tree works on both target families:

| Family | Targets | MAC | Firewall | Allowlisting | Packages |
|---|---|---|---|---|---|
| `debian` | Ubuntu 24.04 / 26.04 | AppArmor | nftables (default) or ufw | AppArmor + `noexec` mounts (IMA appraisal later) | apt |
| `rhel` | RHEL 9 / 10, Alma / Rocky | SELinux | firewalld | fapolicyd + `noexec` mounts | dnf |

The family comes from `ID` / `ID_LIKE` in `/etc/os-release`. Anything else is refused unless you pass `--family`. Other releases in a known family work but print a warning.

---

## Layout

```
security/hardening/
├── bin/
│   ├── el-harden-apply            install baseline (Python 3 stdlib)
│   ├── el-harden-verify           live checks -> JSON facts (Python 3 stdlib)
│   ├── el-usbguard-rules          render USBGuard rules for a storage policy
│   └── el-selinux-confined-users  staff_u / user_u mapping (dry run by default)
├── data/
│   ├── files.tsv                  rootfs file -> layer, condition, mode
│   ├── services.tsv               units to mask / disable / enable
│   ├── packages.tsv               packages each layer needs (+ probe path)
│   ├── fstab.el-snippet           noexec,nosuid,nodev mounts
│   ├── login.defs.el, faillock.el managed key/value settings
│   ├── usbguard-rules.template
│   └── systemd-service-hardening.conf   drop-in template for our services
├── rootfs/etc/...                 files installed 1:1 at /etc/...
├── selinux/                       eld.te / eld.fc / eld.if + build.sh
└── tests/                         run-tests.sh, test_hardening.py
```

---

## Layer → files

| HARDENING.md layer | Files | Notes |
|---|---|---|
| **6 MAC** | `rootfs/etc/apparmor.d/usr.libexec.eld` (debian) · `selinux/eld.{te,fc,if}` + `selinux/build.sh` (rhel) · `bin/el-selinux-confined-users` | Apply sets `SELINUX=enforcing` in `/etc/selinux/config` but does not switch a running system to enforcing (that takes a reboot; a relabel is scheduled if SELinux was disabled). The eld policies are drafts for a daemon that does not exist yet. The SELinux domain ships as `permissive eld_t` until real AVC data exists. |
| **7 Allowlisting** | `rootfs/etc/fapolicyd/rules.d/{15,25,35}-el-*.rules` (rhel) · `data/fstab.el-snippet` → managed block in `/etc/fstab` · `rootfs/etc/systemd/system/tmp.mount.d/50-el-options.conf` · `rootfs/etc/udisks2/mount_options.conf` · `rootfs/etc/dconf/db/local.d/01-el-media` | fapolicyd runs with `permissive = 0` for workstation and `1` for developer. Apply edits only that key in `fapolicyd.conf` and keeps the rest. Our rules sit next to the distro rules: 25 trusts the **system** Flatpak store, 35 denies execution from `/tmp`, `/var/tmp`, `/dev/shm`, `/home` and media. |
| **8 Device control** | `rootfs/etc/usbguard/usbguard-daemon.conf` · `data/usbguard-rules.template` → `/etc/usbguard/rules.d/50-el-baseline.conf` · `/etc/udev/rules.d/90-el-usb-storage-ro.rules` (only for read-only) · `rootfs/etc/polkit-1/rules.d/60-el-udisks.rules` | `--usb-storage block\|read-only\|allow` (ENCRYPTION.md `media.removable`). HID, hubs, audio, video, smartcard, printer, BT and CDC-net classes are allowed with `equals` matching, so BadUSB-style composite devices are blocked. Apply also sets BlueZ `ClassicBondedOnly=true`, but only if `input.conf` already exists. |
| **9 Network** | `rootfs/etc/nftables/el-baseline.nft` + `rootfs/etc/nftables.conf` (debian) · `rootfs/etc/firewalld/zones/el-workstation.xml` (rhel) · `rootfs/etc/NetworkManager/conf.d/90-el-mdns.conf` · `rootfs/etc/systemd/resolved.conf.d/90-el.conf` · `data/services.tsv` | Inbound is denied by default. Allowed: loopback, established/related, ICMP/ICMPv6 essentials (including ND with hop limit 255) and DHCPv4/v6 client replies. No SSH: `ssh`/`sshd` service and socket are **masked**. mDNS and LLMNR are off. The nft file creates only its own `inet el_filter` table (no `flush ruleset`), so Docker/libvirt tables survive. |
| **10 Kernel** | `rootfs/etc/sysctl.d/90-el-hardening.conf` · `rootfs/etc/modprobe.d/90-el-blacklist.conf` | Each key has a comment and a CaC reference. Keys that exist only on some kernels carry a leading `-` so loading ignores them where they are missing. Module signing and lockdown come from layer 1 (signed UKI); verify reports them. |
| **11 Sandboxing** | `rootfs/etc/systemd/system/eld.service.d/50-el-sandbox.conf` · `data/systemd-service-hardening.conf` (template for unprivileged services) · `rootfs/etc/systemd/coredump.conf.d/90-el.conf` · `rootfs/etc/security/limits.d/90-el-nocore.conf` | Flatpak portal and browser policy belong to the apps layer. |
| **12 Memory-safe tools** | — (detect only) | "Follow substrate". The manifest records whether sudo-rs / rust-coreutils are present, and verify reports which sudo is installed (it never fails on this). |
| **13 Audit & integrity** | `rootfs/etc/audit/rules.d/{10,30,40,45,50,60,70,80,99}-el-*.rules` + generated `41-el-setuid.rules` · `rootfs/etc/systemd/journald.conf.d/90-el.conf` · `rootfs/etc/aide/aide.conf.d/90_el_paths` (debian) | Every rule has an `el_*` key (table below). `-e 2` (immutable rules) is present but **commented out** (see trade-offs). journald uses persistent storage with `Seal=yes`, but the sealing key is not generated automatically (pending item). |
| **16 Screen & session** | `rootfs/etc/dconf/db/local.d/00-el-screensaver` + `locks/` · `rootfs/etc/dconf/db/gdm.d/*` · `rootfs/etc/systemd/logind.conf.d/90-el.conf` · `rootfs/etc/lightdm/lightdm.conf.d/90-el.conf` · `rootfs/etc/security/pwquality.conf.d/90-el.conf` · `data/login.defs.el` · `data/faillock.el` | Screen locks after 5 minutes idle with no delay, and on suspend (Ubuntu key). Both are locked. The greeter hides the user list. GDM `custom.conf` gets auto/timed login off, `DisallowTCP`, XDMCP off (only edited when GDM is installed). |

### Audit keys (for SIEM filters)

| Key | What |
|---|---|
| `el_identity`, `el_auth_config` | account databases; PAM/NSS/SSSD/authd/Kerberos config |
| `el_system_locale` | hostname, hosts, issue, NetworkManager config |
| `el_logins`, `el_session` | lastlog/faillock; utmp/wtmp/btmp |
| `el_priv_scope`, `el_priv_actions` | sudoers/sudo-rs config; sudo log |
| `el_priv_sudo`, `el_priv_su`, `el_priv_polkit`, `el_priv_passwd`, `el_priv_usermod`, `el_priv_cron` | execution of privilege tools by logged-in users |
| `el_priv_setuid` | any other setuid/setgid binary (generated per system) |
| `el_priv_escalation` | execve where euid became 0 and uid did not |
| `el_polkit_config` | polkit rules/actions |
| `el_perm_mod`, `el_access`, `el_mounts` | chmod/chown/xattr; EACCES/EPERM opens; mount |
| `el_mac_policy`, `el_perm_chng` | SELinux/AppArmor policy; chcon/setfacl/semanage/setenforce |
| `el_allowlist_policy`, `el_device_policy`, `el_firewall_policy` | fapolicyd, usbguard/udisks, firewalld/nftables/ufw config |
| `el_modules`, `el_kernel_config` | module load/unload; sysctl/modprobe/cmdline/grub |
| `el_time_change` | clock changes, localtime, chrony/timesyncd |
| `el_config`, `el_state`, `el_jit_sudoers`, `el_eld_bin`, `el_eld_socket`, `el_eld_unit` | `/etc/el`, `/var/lib/el`, `/etc/sudoers.d` (JIT grants), eld binary/socket/unit |

---

## el-harden-apply

```bash
sudo bin/el-harden-apply --dry-run                 # show the plan for this host
sudo bin/el-harden-apply                           # workstation profile, USB storage blocked
sudo bin/el-harden-apply --profile developer       # fapolicyd audit-only, /home exec allowed
bin/el-harden-apply --root /path/to/image-tree     # offline, no root needed for a tree you own
     [--skip network,13] [--usb-storage read-only] [--allow-usb-id 17ef:30b4]
     [--home-noexec auto|yes|no] [--firewall auto|nftables|firewalld|ufw]
     [--family debian|rhel] [--install-packages] [--json]
```

- **Order:** kernel → audit → mac → allowlist → device → network → sandbox → memsafe → session. `--skip` takes layer names or numbers (`mac`=6 … `session`=16), repeated or comma-separated.
- **Files** from `rootfs/` are installed when their `files.tsv` condition matches the host features (`debian|rhel`, `apparmor|selinux`, `nftables|firewalld|ufw`, `fapolicyd`; `a+b` means both). Writes are atomic. A distro file is backed up once to `<file>.el-orig` before it is first replaced.
- **Managed edits** change a single key and keep everything else (`login.defs`, `faillock.conf`, `fapolicyd.conf`, `firewalld.conf`, `selinux/config`, GDM `custom.conf`, dconf profiles, ufw defaults). `/etc/fstab` gets a marked block. A mount point that already has its own fstab line is left alone, and apply prints a warning.
- **Services:** on a live system, `systemctl mask|disable|enable --now`. Offline, masks become `/dev/null` symlinks, `.wants` links are removed for disables, and enables/disables go into `/etc/systemd/system-preset/40-el-hardening.preset` for first boot.
- **Live reloads** only run when `--root /`: `sysctl --system`, `augenrules --load`, `apparmor_parser -r`, `fagenrules --load`, `udevadm control --reload`, `nft -f` / `firewall-cmd --reload` / `ufw enable`, `dconf update`, `authselect enable-feature with-faillock` (rhel). Offline runs never execute host tools; the tests check this.
- **Packages:** apply reports missing packages (`packages.tsv`) and installs them only with `--install-packages`.
- **Idempotent:** a second run changes nothing. The tests check that every file comes back `unchanged` and no edit is reported.
- **Manifest:** `/var/lib/el/hardening/applied.json` (`schema: el.hardening.applied/v1`) records the profile, family, firewall, layers applied/skipped, every file with its sha256 and action, edits, services, commands and results, missing packages, and **pending** items that still need a human or a later layer.
- Exit codes: `0` ok, `1` a command failed, `2` usage error or unsupported system.

## el-harden-verify

```bash
bin/el-harden-verify --pretty                      # all layers
bin/el-harden-verify --layer kernel --layer network
```

Prints one JSON document (`schema: el.hardening.verify/v1`) with `summary`, `compliant`, and `checks[]`. Each check is `{id, layer, title, status: pass|fail|skip, expected, actual}`. The output is meant to become the `security` / `compliance` facts of the [Control API](../../docs/CONTROL-API.md) (for example, `elctl facts get compliance --json` would wrap it). What it checks:

- every sysctl in the baseline (`sysctl -n`)
- blacklisted modules not loaded
- `sig_enforce` / lockdown
- Secure Boot (`mokutil --sb-state`, else `bootctl status`)
- AppArmor (`aa-enabled`, eld profile) or SELinux (`getenforce` + config)
- `/tmp`, `/var/tmp`, `/dev/shm` (and `/home` where expected) mounted `nosuid,nodev,noexec`
- fapolicyd running, in the mode the profile expects
- USBGuard running with implicit block
- the firewall backend is active (firewalld default zone, nft table with policy drop, or ufw active)
- ssh service and socket not active, avahi not active
- no TCP listeners on non-loopback addresses (`ss`)
- coredump off, eld drop-in present
- auditd running, `auditctl -s` enabled, and at least 60 % of the baseline's `el_*` rules loaded (`auditctl -l`)
- journald persistent storage and sealing
- dconf locks, GDM autologin off, greeter user list hidden

A missing tool gives `skip`, not `fail`. Exit code is `1` if any check fails. `--root` redirects file reads (`/etc`, `/proc`, `/sys`) for tests. Commands always come from `PATH`.

## Tests

```bash
security/hardening/tests/run-tests.sh -v
```

The tests need no root and no network. They cover:

- `bash -n` and shellcheck (when installed) on all bash scripts
- a compile check of the Python scripts
- a lint that every sysctl line parses and has a comment
- modprobe `install`/`blacklist` pairs
- audit rule syntax, `el_*` keys, and no duplicate rules
- `files.tsv` matching the rootfs tree exactly
- the nftables shape, plus `nft -c` when `nft` exists
- the firewalld zone XML, the AppArmor profile structure, and m4 quote balance and declared types in the SELinux module
- the USBGuard generator for all three storage policies
- offline apply into fake Ubuntu 24.04/26.04, RHEL 9 and Alma 10 roots: the right files land, no host commands run, idempotence, `.el-orig` backups, dry-run writes nothing, `--skip`, the developer profile, unknown distro refused, ufw backend
- verify with stubbed `sysctl`, `systemctl`, `auditctl`, `ss` and friends, for an all-pass case, a detected-failure case, and a missing-tools case

---

## Profiles and known usability trade-offs

| Setting | Workstation | Developer | Trade-off |
|---|---|---|---|
| fapolicyd | enforcing | **permissive** (audit-only) | Matches HARDENING.md layer 7: enforcing for *user*, audit-only for *power-user*. Denials still get logged in developer mode. |
| `noexec` on `/home` | **on** | off | `noexec /home` breaks Python venvs, `npm`/`cargo`/`go` binaries in `~/.local/bin` or `~/go/bin`, AppImages, JetBrains Toolbox, VS Code server, user Flatpaks and Steam. It is the main reason the developer profile exists. Override with `--home-noexec`. |
| `noexec` on `/tmp`, `/var/tmp`, `/dev/shm` | on | on | Some installers and build systems unpack and run helpers from `/tmp`. Workaround: point `TMPDIR` at an exec-allowed directory. |
| USB storage | `block` | `block` | Policy choice (ENCRYPTION.md open question 4). Any device that presents itself purely as a keyboard is still allowed (keystroke injectors included). |
| `kernel.kexec_load_disabled=1` | on | on | kdump (on by default on RHEL) can no longer arm. Remove the key where kdump is required. |
| `kernel.perf_event_paranoid=3`, `yama.ptrace_scope=1` | on | on | No unprivileged `perf`. Attaching gdb/strace to an *unrelated* process needs privilege; debugging your own children still works. |
| `ip_forward=0`, nft `forward` policy drop | on | on | Rootful Docker/libvirt NAT breaks unless the tool re-enables forwarding. Rootless Podman (pasta/slirp4netns) is unaffected. |
| mDNS / LLMNR / avahi off | on | on | Printer and Chromecast discovery stops on home networks. A policy can re-enable it per trusted connection. |
| HFS/HFS+ blacklisted | on | on | Mac-formatted disks cannot be mounted. `udf` is left loadable (optical media). |
| `kernel.sysrq=0` | on | on | No emergency REISUB on a hung laptop. |
| Core dumps off | on | on | Crash analysis needs a policy override. |
| audit `-e 2` (immutable) | **off** | off | With it on, audit rules could only change at reboot, so eld/MDM policy updates and EDRs that manage audit rules would stop working. Turn it on once the update/reboot flow exists. |
| `--loginuid-immutable` | off | off | Breaks some container runtimes. |

## Intentionally left for later

- **Image mode** (bootc / ostree, read-only `/usr`, layer 3). This baseline writes only to `/etc` and the `/var/lib/el` manifest, so it can become an image layer unchanged. Offline `--root` plus the preset file is the hook for that.
- **IMA measurement / appraisal** (allowlisting on non-RHEL, integrity on all families). Needs signed packages / an IMA policy and kernel cmdline from the UKI (layer 1).
- **Keylime / remote attestation** (layer 2, phase 2).
- **Loading the eld SELinux module and switching it to enforcing.** Needs `selinux-policy-devel` and a real eld to collect AVCs.
- **Confined-user mapping** (`bin/el-selinux-confined-users`). It is org-specific (directory group names), so it is not run by apply.
- **journald FSS keys.** The verification key must be escrowed through the Control API before keys are generated.
- **PAM integration on Ubuntu** (pam_faillock / pam_pwquality via `pam-auth-update`). Belongs to the identity layer.
- Bluetooth class allowlist, bolt/Thunderbolt policy, always-on VPN, DoT, OpenSCAP scheduling (layer 15), the EDR slot (layer 14).
- RHEL with the nftables backend: the sysconfig include is not automated. AIDE paths on RHEL (single `aide.conf`) are not automated.

## Open questions / assumptions

1. **Polkit group names:** `60-el-udisks.rules` uses a placeholder group `el-admins`. The real role→group rendering belongs to `security/permissions/`. Coordinate so that layer renders or replaces this rule.
2. **ufw vs nftables on Ubuntu:** the default is plain nftables, with ufw disabled to avoid two managers. `--firewall ufw` keeps ufw instead. Which one should eld drive?
3. **`/home` noexec when `/home` is its own partition:** apply does not rewrite that fstab line; it only warns. Should apply edit existing mount options?
4. **Ubuntu 26.04 specifics** (sudo-rs paths `/usr/lib/cargo/bin/*`, tmpfs `/tmp` by default) are based on public release notes and have not been verified on an install.
5. CaC rule ids are cited from the project's naming scheme. Confirm them against the CaC release we pin for layer 15 scans.
