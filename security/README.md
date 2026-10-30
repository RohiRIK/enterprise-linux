# security/

First implementation of the security design docs. **Status: early code, tested only in containers** (mocked commands, temp roots, and a LUKS2 loop device). Nothing here has run on real hardware, a real TPM, a real fleet, or against a live Entra/MDM tenant. Baselines are CIS/STIG-oriented implementation guides, **not certification claims**.

Distro-agnostic: targets Ubuntu 24.04/26.04 and RHEL 9/10-family; the substrate is still not locked. Bash + Python 3 stdlib only.

| Directory | Implements | Main entry points | Tests |
|---|---|---|---|
| [`encryption/`](encryption/README.md) | [docs/ENCRYPTION.md](../docs/ENCRYPTION.md) | `el-luks-enroll`, `el-recovery-escrow`, `el-crypto-erase`, `el-tpm-reseal`, `el-encryption-facts` | `python3 encryption/tests/run-tests.py`; root-only `encryption/tests/integration-loop.sh` |
| [`permissions/`](permissions/README.md) | [docs/PERMISSIONS.md](../docs/PERMISSIONS.md) | `el-perm-render`, `el-jit`, `el-breakglass` | `cd permissions && python3 -m unittest discover` |
| [`hardening/`](hardening/README.md) | [docs/HARDENING.md](../docs/HARDENING.md) layers 6–13, 16 | `el-harden-apply`, `el-harden-verify`, `el-usbguard-rules` | `hardening/tests/run-tests.sh` |

The `*-facts` / `verify` tools emit JSON shaped for the future `eld` providers ([docs/CONTROL-API.md](../docs/CONTROL-API.md)); `eld` itself is built elsewhere.

## Known cross-cutting gaps

- `hardening/rootfs/etc/polkit-1/rules.d/60-el-udisks.rules` uses a placeholder admin group `el-admins`; it should be rendered from the role map by `permissions/`.
- Removing standing `%sudo` / `%wheel` admin from `/etc/sudoers` is only reported by `el-perm-render --check`, not changed.
- Escrow / webhook contracts and the crypto-erase token format are our own drafts until an MDM or the Control API agrees to them.
