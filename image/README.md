# image/

Builds the enterprise-linux installer from the **official Ubuntu 26.04 LTS desktop ISO**. We never rebuild Ubuntu: the ISO's boot records, shim, GRUB and kernel stay as Canonical signed them, and we add an autoinstall file plus our payload. No ISO blobs in git.

> **Status:** first implementation, 2026-10-30. Checked in a container: the eld `.deb` builds, installs and runs; `el-install-target` runs against a real Ubuntu 26.04 root tree (debootstrap); `el-build-uki` builds and signs a UKI from the real 26.04 kernel; the ISO remaster runs against the real 26.04.1 ISO, and the remastered ISO boots under UEFI Secure Boot (Microsoft keys) in QEMU into our GRUB entry and the 26.04.1 live session with the installer service started. **The full unattended install has not completed in a VM yet**: without KVM the emulated VM made no progress past the live session in 40 minutes, so whether the desktop installer picks up the autoinstall file is still unproven. That is what `dist/ci/image.yml` (with KVM) checks. Not tested on real hardware.

## Build

```sh
curl -O https://releases.ubuntu.com/26.04/ubuntu-26.04.1-desktop-amd64.iso
curl -O https://releases.ubuntu.com/26.04/SHA256SUMS
image/build-iso.sh --base-iso ubuntu-26.04.1-desktop-amd64.iso --sha256sums SHA256SUMS
# -> out/enterprise-linux-0.1.0-default-amd64.iso (+ .sha256)
```

Options: `--profile` (catalog profile: default, developer, microsoft365, open-source), `--unattended` (no "erase disk?" question), `--test-identity` and `--serial` (CI only). Needs `xorriso`, `python3-yaml`, `openssl` and, unless `--deb` is passed, `cargo` + `dpkg-deb`.

## What the installer does

1. Ubuntu's installer runs [`autoinstall/autoinstall.yaml.in`](autoinstall/autoinstall.yaml.in): `ubuntu-desktop-minimal`, `linux-generic`, LUKS2 on LVM, no third-party drivers, security updates, our hardening packages. It asks only for the first local account.
2. `late-commands` run [`late/el-install-target`](late/el-install-target) against `/target`:
   eld/elctl `.deb` -> security tools into `/usr/lib/el` -> curated apps (`elapps`, falls back to policy files only when offline) -> GNOME desktop layer -> hardening (offline) -> kernel command line + UKI hook ([docs/KERNEL.md](../docs/KERNEL.md)) -> TPM2 unlock slot -> `/var/lib/el/image/install.json`.
3. Anything left undone is listed under `pending` in `install.json`.

## Install key

The LUKS passphrase in autoinstall is a random key generated per build (`/el/install.key` on the ISO). `el-install-target` uses it to add the TPM2 slot. **The install key slot is not removed yet**, because removing it before a recovery key is escrowed could lock a user out for good, and where recovery keys go is still an open decision ([ENCRYPTION.md §6](../docs/ENCRYPTION.md)). Until that is decided, anyone with the ISO can unlock disks installed from it: treat these ISOs as test builds.

## Kernel

Stock Canonical-signed kernel, our command line (`lockdown=integrity module.sig_enforce=1`), signed UKI as stage 2. Full reasoning in [docs/KERNEL.md](../docs/KERNEL.md).

| File | Purpose |
|---|---|
| `build-iso.sh` | Remaster the official ISO |
| `render-autoinstall.py`, `patch-grub.py` | Template + GRUB entry helpers, with checks |
| `late/el-install-target` | Post-install steps on the target root |
| `uki/el-build-uki`, `uki/zz-el-uki`, `uki/uki.conf.example` | UKI build/sign + kernel hook (inactive until keys exist) |
| `tests/` | Unit tests, VM test (`vm-test.sh`), first-boot report and checker |

## CI

[`dist/ci/image.yml`](../dist/ci/image.yml) (copy to `.github/workflows/`): unit tests + shellcheck, then build a test ISO, install it into a QEMU VM with Secure Boot (Microsoft keys) and a software TPM, boot the installed disk, and check the first-boot report: stock kernel, `lockdown` active, module signatures enforced, Secure Boot on, eld running.
