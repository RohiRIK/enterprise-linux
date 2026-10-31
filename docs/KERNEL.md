# Kernel and boot chain

**Status:** decided 2026-10-30 (Rohi), first implementation in [`image/`](../image/README.md). Untested on real hardware.

**Decision:** use the **stock Ubuntu 26.04 LTS kernel** (`linux-generic`, Canonical-signed). We do not build, patch or configure our own kernel. What we own is the **command line**, the **module policy**, and the **signed UKI** that wraps the stock kernel.

## Why not a custom kernel

| Concern | Stock signed kernel | Custom kernel |
|---|---|---|
| Security fixes | Canonical ships them through `-security`; we only pin and roll out | We rebuild, test and ship every CVE fix ourselves, for the life of the LTS |
| Secure Boot | Signed by Canonical, boots through the Microsoft-signed shim on any laptop | Needs our key enrolled on every device (MOK or our own db) before it boots at all |
| Intune / MDM support | Intune supports Ubuntu 26.04 as shipped | A non-Ubuntu kernel puts us outside what vendors test |
| Hardware | Ubuntu's laptop certification and firmware | Our problem |
| Scope | ARCHITECTURE.md §3: "not rewriting the kernel" | Contradicts it |

The things a custom kernel would usually be built for are already on in the Ubuntu 7.0 kernel (checked against `/boot/config-7.0.0-14-generic`): module signing (`MODULE_SIG`, `MODULE_SIG_ALL`, SHA-512), the lockdown LSM, AppArmor, Landlock, Yama, IMA, `INIT_ON_ALLOC_DEFAULT_ON`, unprivileged BPF off by default. The one gap is that Ubuntu builds with `LOCK_DOWN_KERNEL_FORCE_NONE` and turns lockdown on only when it sees Secure Boot. We close that on the command line.

## Command line

Set by the image build in `/etc/default/grub.d/90-enterprise-linux.cfg` and `/etc/kernel/cmdline` (for the UKI):

```
lockdown=integrity module.sig_enforce=1
```

* `lockdown=integrity` - no unsigned kexec, no `/dev/mem`, no raw MSR / PCI BAR writes, no hibernation, even if Secure Boot is off or misreported. `confidentiality` would also block BPF/perf reads of kernel memory, which breaks EDR agents; revisit once an EDR is chosen.
* `module.sig_enforce=1` - only modules signed by the kernel's build key (or a key in the MOK list) load.

`el-build-uki` refuses to build a UKI whose command line lacks either. `el-harden-verify` checks both at runtime (`boot.lockdown`, `kernel.module_sig_enforce`), and the CI VM test fails without them.

## Modules and drivers

* Default image: **no DKMS, no third-party drivers** (`drivers: install: false` in autoinstall). An unsigned out-of-tree module would not load anyway.
* NVIDIA: Ubuntu ships Canonical-signed prebuilt NVIDIA modules (`linux-modules-nvidia-*`) that load under `sig_enforce`. Those can go into the developer profile later as a catalog bundle. A DKMS build cannot, unless we sign it with a MOK key.
* Unused filesystems and protocols are already blocked by `security/hardening/rootfs/etc/modprobe.d/90-el-blacklist.conf`. Module loads are audited (`el_modules`).

## Boot chain: two stages

**Stage 1 (now, default):** UEFI Secure Boot -> Microsoft-signed `shim` -> Canonical-signed GRUB -> Canonical-signed kernel + our command line. Works on any laptop with no key enrollment. LUKS2 unlock is bound to TPM2 **PCR 7** (Secure Boot state) by `el-luks-enroll`. Weak spot: GRUB's command line and the initrd are not measured into a PCR that we bind, so someone with physical access at the GRUB prompt can drop our command-line flags (unlock still needs PCR 7 to match, and the root disk stays encrypted).

**Stage 2 (when signing keys exist):** UEFI -> shim -> **our signed UKI** (stock kernel + initrd + locked command line in one PE file). The command line can no longer be edited at boot. The UKI carries a signed **PCR 11** policy (`.pcrsig`), so `el-luks-enroll --tpm2-public-key` binds unlock to "PCR 7 + any UKI we signed", and kernel updates do not need a TPM re-seal. `image/uki/el-build-uki` builds this today (checked: Canonical signature on the inner kernel, our `sbsign` signature on the UKI, `.pcrsig` section present).

## Signing

Stage 2 needs a decision from Rohi on who signs:

1. **Pipeline signs, devices never hold a key (recommended).** CI builds the UKI for every Ubuntu kernel update and ships it as a package (`el-kernel-uki`). The private keys live in an HSM or cloud KMS. Devices trust our certificate through **MOK** (one confirmation at the firmware prompt per device, or pre-enrolled by the OEM/IT) or, on fleets that manage firmware, our own **db** key.
2. **Device signs (lab only).** `/etc/el/uki.conf` points `el-build-uki` at a key on the device and `/etc/kernel/postinst.d/zz-el-uki` re-signs after every kernel update. Simple, but a root compromise steals the key. The image ships only `uki.conf.example`, so this is off unless someone turns it on.

Until then the hook does nothing and stage 1 is what boots.

## Updates

Kernel updates come from Ubuntu `-security` like every other package, gated by our update policy (docs/HARDENING.md "Locked updates"). The image pins `linux-generic` (the GA 7.0 kernel for 26.04). Moving to an HWE kernel is a release-train decision, not an automatic one.

## Open

1. Who holds the signing keys, and MOK vs own db (see "Signing").
2. `lockdown=confidentiality` once the EDR agent is known.
3. IMA appraisal (needs signed file hashes; phase 2 in HARDENING.md).
