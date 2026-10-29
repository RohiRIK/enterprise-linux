# Encryption

**Status:** design; first implementation in [`security/encryption/`](../security/encryption/README.md) (container-tested only, not hardware-tested).  
**Date:** 2026-10-28  
**Related:** [HARDENING.md](HARDENING.md), [CONTROL-API.md](CONTROL-API.md), [MDM.md](MDM.md)

---

## 1. Goals

- **Every device is encrypted before first login.** Not optional, not "user may enable later."
- **No passphrase prompt for the common case**, but stolen laptops stay locked.
- **The org can always recover** a device (recovery key escrowed), and the user never needs to know the key.
- **MDM can verify** encryption state (Intune Linux compliance checks for dm-crypt/LUKS — see [research §4](RESEARCH-ENTERPRISE-DISTROS.md#4-microsoft-on-linux-mdm-and-edr-reality-check)).
- One switch for **crypto strength** across the system (Red Hat crypto-policies model).

---

## 2. Data at rest

| Item | Design |
|---|---|
| **Root + home** | LUKS2 (AES-XTS-512, Argon2id) on everything except the EFI partition. Encrypted at install time by the image pipeline / first boot. |
| **Unlock** | **TPM2** sealed to a PCR policy (Secure Boot state + our signed boot chain — PCR 7 + signed PCR 11 policy for UKI). Policy options: `tpm2` (silent), `tpm2+pin` (recommended for laptops), `tpm2+network` (Tang/NBDE for desktops in the office), `passphrase` (fallback). Implemented with `systemd-cryptenroll` or Clevis. |
| **Recovery key** | Generated on device, **escrowed** to the MDM/Entra/vault via the Control API, never shown to the user, **rotated after every use**. Helpdesk retrieves it from the escrow, not from the device. |
| **Firmware updates** | Before a firmware/bootloader update changes PCRs, the update flow re-seals (or uses a signed PCR policy) so users do not hit a recovery prompt. Ubuntu 26.04 calls this "predictable recovery-key handling" — we need the same. |
| **Swap / hibernation** | Swap inside the encrypted volume (or zram only). Hibernation off unless resume is inside LUKS. |
| **Removable media** | Policy choices: `block`, `read-only`, `allow-encrypted-only` (LUKS/BitLocker-to-go readers), `allow`. Enforced by USBGuard + udisks polkit rules. |
| **Per-user data** (idea) | `systemd-homed`-style per-user encrypted home so admins cannot read user data without the user, for shared devices. Phase 2. |
| **Wipe** | Remote wipe = destroy LUKS keyslots (crypto-erase), then reboot to reprovision. Requires MDM-signed confirmation. |

---

## 3. Data in transit

- **System-wide crypto profile**: `DEFAULT`, `FUTURE`, `FIPS` (mapped to RHEL `update-crypto-policies` or an equivalent we ship on other substrates). TLS 1.2+ only.
- **Post-quantum:** hybrid PQ key exchange is already default in OpenSSH 10.x (Ubuntu 26.04) and in RHEL 10. We keep those defaults and expose `crypto.pq = prefer|require|off` for orgs that want to enforce it.
- **Wi-Fi:** WPA3-Enterprise / EAP-TLS with device certificates issued at enrollment (SCEP/EST via MDM or ACME device attestation later).
- **VPN:** org-defined (WireGuard, IPsec, or vendor client) pushed by policy; optional always-on.
- **DNS:** DoT/DoH to org resolver configurable by policy.

---

## 4. Keys and secrets

- **Device identity key** lives in the TPM (non-exportable). Used for device certificates, attestation, and signing compliance reports.
- **User secrets:** GNOME Keyring / KWallet unlocked at login; SSH keys and certificates can be TPM- or FIDO2-backed.
- **FIDO2 / passkeys:** security keys for login and sudo (pam-u2f / IdP passkeys) as an optional policy.
- **FIPS mode:** offered only on substrates with validated modules (RHEL, Ubuntu Pro FIPS). We document; we do not claim certification.

---

## 5. What the API exposes

```
facts:   encryption.volumes[].{device, status, cipher, unlock_methods, tpm_pcrs}
         encryption.recovery.{escrowed: bool, escrow_target, last_rotated}
settings: encryption.required, encryption.unlock, encryption.escrow, crypto.profile, crypto.pq,
          media.removable
actions: encryption.rotate-recovery-key, encryption.escrow-now, device.crypto-erase
```

The recovery key itself is never readable through the API.

---

## 6. Open questions

1. Default unlock for laptops: `tpm2` (best UX) or `tpm2+pin` (stronger against cold-boot/evil-maid)?
2. Escrow target for v1: Intune (Linux has no native escrow today — needs research), Entra device object, or a vault (HashiCorp Vault / Azure Key Vault)?
3. Do we need FIPS on day 1 (forces RHEL or Ubuntu Pro)?
4. Removable media default: `block` or `read-only`?
