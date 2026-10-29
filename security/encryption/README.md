# security/encryption

First implementation of [docs/ENCRYPTION.md](../../docs/ENCRYPTION.md): LUKS2 +
TPM2 unlock, escrowed and rotated recovery keys, signed remote crypto-erase,
re-sealing around boot-chain updates, and a JSON facts provider for the future
`eld` daemon ([docs/CONTROL-API.md](../../docs/CONTROL-API.md)).

> **Status: early, untested on real hardware.** Everything here has run against
> mock binaries (`tests/run-tests.py`) and against real `cryptsetup` 2.7 /
> `systemd-cryptenroll` 255 on a file-backed loop device in a container
> (`tests/integration-loop.sh`, TPM steps skipped). Nothing has run on a laptop
> with a real TPM, a real Tang server, Vault, Azure Key Vault or an MDM. This is
> not a certified or compliance-validated product, and none of it is a "live
> MDM" integration yet.

Distro-agnostic by design: bash (`set -euo pipefail`) + coreutils + Python 3
stdlib, wrapping `cryptsetup`, `systemd-cryptenroll` (primary) and `clevis`
(Tang). Targets Ubuntu 24.04 / 26.04 and RHEL 9 / 10 family. No other
dependencies.

## Layout

| Path | What it does | ENCRYPTION.md |
|---|---|---|
| `sbin/el-luks-enroll` | Enrolls `tpm2`, `tpm2+pin`, `tang` (Clevis), `fido2` or `passphrase` on a LUKS2 volume. Refuses LUKS1, warns about cipher, key size and KDF, is idempotent, wipes the old slot only after the new one unlocks, edits `/etc/crypttab` with a backup, and supports `--dry-run` and `--json`. | §2 Root + home, Unlock |
| `sbin/el-recovery-escrow` | `escrow`, `rotate [--if-needed]`, `verify`, `mark-used`, `status`. Generates the recovery key, hands it to a backend, records metadata only after the backend confirms, then wipes the old slot. | §2 Recovery key; §5 `encryption.rotate-recovery-key`, `encryption.escrow-now` |
| `lib/escrow.d/{file,vault,azure-keyvault,webhook}` | Escrow backends you can swap. | §2 Recovery key, §6 Q2 |
| `sbin/el-crypto-erase` | Remote wipe: `cryptsetup luksErase` on every keyslot. Needs a signed confirmation token plus `--execute --yes`. Without them it only does a dry run. | §2 Wipe; §5 `device.crypto-erase` |
| `sbin/el-tpm-reseal` | Hook to call `pre-update` / `post-update` around firmware, shim, bootloader, dbx or UKI updates. | §2 Firmware updates |
| `sbin/el-encryption-facts` | Prints `encryption.volumes[]` and `encryption.recovery` as JSON. | §5 facts |
| `lib/el-common.sh`, `lib/elcrypt.py` | Shared helpers: dry-run runner, config parser, private secret dir, LUKS2 JSON summary, crypttab editor, escrow state, token claim checks. | – |
| `examples/` | crypttab, `/etc/el/encryption.conf`, systemd units and timer, systemd-repart first-boot snippet. | §2 |
| `tests/` | Mock-based test suite and a loop-device integration test. | – |

Install layout assumed by the units: scripts in `/usr/sbin`, `lib/` in
`/usr/lib/el/encryption/` (the scripts find `../lib` relative to themselves
first, so running from the repo also works), config `/etc/el/encryption.conf`,
state `/var/lib/el/encryption/` (0700).

## The tools

### el-luks-enroll

```
el-luks-enroll --device /dev/nvme0n1p3 --mode tpm2+pin --pin-file /run/el/pin \
    --tpm2-public-key /etc/systemd/tpm2-pcr-public-key.pem --unlock-key-file /run/el/install.key \
    --regenerate-initrd --json
```

* **Policy.** By default it binds PCR 7 (Secure Boot state) directly.
  `--tpm2-public-key` adds systemd's signed PCR policy, PCR 11 by default, so a
  UKI signed by our key can change without re-enrolling. This is the "PCR 7 +
  signed PCR 11" design from §2. Override with `--pcrs` / `EL_TPM2_PCRS`.
* **LUKS version.** Uses `cryptsetup isLuks --type luks2`. On LUKS1 it stops
  and prints the offline conversion steps. It never converts automatically.
* **Crypto checks** (warnings only). The data segment should be
  `aes-xts-plain64` with a 512-bit volume key. Passphrase slots should use
  `argon2id`. Slots behind a token (TPM2, FIDO2, recovery) are exempt from the
  KDF check because systemd deliberately puts a cheap PBKDF2 on high-entropy
  secrets.
* **Idempotent.** If a slot with the same PCRs, signed PCRs and PIN setting
  already exists, it does nothing. Otherwise it: (1) enrolls the new slot,
  (2) finds it by diffing the LUKS2 metadata, (3) tests it with
  `cryptsetup open --test-passphrase --token-only --token-id N`, Clevis with
  `clevis luks pass`, and (4) only then wipes the previous slots of the same
  kind. If the test fails, it removes the new slot and keeps the old ones.
  PIN and FIDO2 slots can't be tested without a terminal. In that case the old
  slots are kept, and it prints the exact wipe command to run later.
* **Secrets.** The PIN goes in through `--pin-file`. It is passed to
  systemd-cryptenroll as `$NEWPIN` and never appears in argv.
  `--passphrase-file` works the same way through `$NEWPASSWORD`.
* **crypttab.** It finds the entry by `UUID=`, `/dev/disk/by-uuid/`, the
  device path or `--crypttab-name`. It replaces only the options it owns
  (`tpm2-device`, `tpm2-pcrs`, `tpm2-signature`, `tpm2-pcrlock`, `fido2-*`) and
  keeps everything else (`discard`, …). Before writing it saves
  `crypttab.el-backup-<UTC time>`, then writes atomically (temp file, fsync,
  rename) and keeps the file mode.
* **`--dry-run`** runs only read-only probes (`isLuks`, `luksDump`,
  `--version`) and prints every state-changing command to stderr with a
  `[dry-run]` prefix. `--json` prints the resulting state (slots, tokens,
  methods, PCRs, warnings, crypttab change) to stdout.
* **Tang.** Pin the server key with `--tang-thp`. Trust-on-first-use needs
  `--tang-trust-first-use`. For combined policies (TPM2 **and** Tang), use a
  Clevis `sss` pin manually for now. The facts tool already reports it as
  `clevis-sss`.

Clevis as an alternative to systemd-cryptenroll for TPM2: `clevis luks bind -d
DEV tpm2 '{"pcr_ids":"7"}'` works on both distro families and is what RHEL's
NBDE documentation uses. We prefer systemd-cryptenroll because its signed PCR
policy and PIN support work for UKIs, and because `systemd-cryptsetup` reads
its tokens natively.

### el-recovery-escrow

```
el-recovery-escrow escrow  --device DEV [--unlock-key-file F | --unlock-tpm2]
el-recovery-escrow rotate  --device DEV [--if-needed]
el-recovery-escrow mark-used --device DEV      # helpdesk released the key
el-recovery-escrow verify  [--device DEV]      # record vs. device vs. backend
el-recovery-escrow status  [--device DEV]
```

Order of operations. A key is never left without escrow, and the old key is
never removed before the new one is confirmed:

1. Add a recovery slot. Primary: `systemd-cryptenroll --recovery-key`, with
   stdout (the key) and stderr (a QR code of the key) both captured to files
   in a 0700 directory under `/run/el`. If systemd is too old, or with
   `--fallback`, it generates 32 random bytes as 64 modhex characters (same
   format as systemd), adds them with `cryptsetup luksAddKey`, and tags the
   slot with an `el-recovery` LUKS2 token so later runs recognise it.
2. Pass the key file path to the backend (`EL_ESCROW_KEY_FILE`). If the
   backend fails, the new slot is wiped and the tool exits with code 75.
3. Write `/var/lib/el/encryption/escrow.json` (0600, atomic): `keyslot`,
   `token_id`, `backend`, `target`, `escrowed_at`, `fingerprint_sha256`, `used`,
   plus the last 10 history entries. The key itself is never written there.
4. Wipe the previous recovery slots, including any older recovery key that
   was never escrowed.

The key is shredded on exit. It never appears in argv, stdout, stderr, logs,
the journal or the state file. The tests check this for every backend.

**Rotation after use** (§2 "rotated after every use"). Upstream there is no
reliable way for the device to see which slot unlocked it. So the helpdesk or
MDM flow that hands out a key calls the `encryption.rotate-recovery-key`
action, which is `el-recovery-escrow rotate`, or `mark-used` followed by
`rotate --if-needed`. The daily timer (`examples/systemd/el-escrow-verify.*`)
runs `verify` and then `rotate --if-needed`. That rotates keys that were used,
are older than `EL_RECOVERY_MAX_AGE_DAYS`, or were never escrowed. Unattended
rotation needs a way to unlock the volume: `--unlock-tpm2` (systemd ≥ 256,
which means RHEL 10 and Ubuntu ≥ 24.10; it does **not** work on RHEL 9's
systemd 252) or a root-only unlock key file.

#### Escrow backend contract

A backend is an executable `lib/escrow.d/<name>` (name `[a-z0-9-]+`), called as
`<backend> escrow` or `<backend> verify` with these environment variables:

| Variable | Meaning |
|---|---|
| `EL_ESCROW_KEY_FILE` | (escrow only) 0600 file holding the key, no newline |
| `EL_ESCROW_UUID`, `EL_ESCROW_DEVICE`, `EL_ESCROW_KEYSLOT` | volume identity |
| `EL_ESCROW_FINGERPRINT` | sha256 hex of the key |
| `EL_ESCROW_HOSTNAME`, `EL_ESCROW_MACHINE_ID` | device identity |
| `EL_ESCROW_WORK` | private 0700 scratch dir (for headers and bodies) |
| `EL_ESCROW_TARGET` | (verify only) target string recorded at escrow time |
| `EL_*` | everything from `/etc/el/encryption.conf` |

`escrow` exits 0 **only after a read-back or acknowledgement proves the key is
stored**. Its last stdout line is the target reference that gets recorded.
`verify` exits 0 for a match, 1 for missing or mismatch, and 3 when the
backend can't verify.

| Backend | Transport | Confirmation | Notes |
|---|---|---|---|
| `file` | local dir (0700) | read-back fingerprint | **Testing only.** The key ends up on the disk it protects. |
| `vault` | Vault KV v2 `POST /v1/<mount>/data/<prefix>/<machine-id>/<uuid>` | GET + fingerprint compare | Token is read from a file (e.g. a Vault Agent sink) and sent with `curl -H @file`. Namespace and CA are optional. |
| `azure-keyvault` | `PUT {vault}/secrets/luks-<uuid>?api-version=7.4` | GET + fingerprint compare | Token from a file, or managed identity via IMDS (Azure VMs only; laptops need a token file from a trusted agent). |
| `webhook` | HTTPS POST JSON | server must echo `fingerprint_sha256` | Optional mTLS (`--cert/--key`), pinned CA, bearer token from a file. `verify` uses `EL_WEBHOOK_VERIFY_URL`. This is the hook point for an MDM or the Control API. |

All HTTP calls use `--proto =https` unless `EL_ALLOW_INSECURE_HTTP=1`. The one
exception is the IMDS call, which is link-local http by design. Tokens always
go through `-H @file`, never argv.

### el-crypto-erase

```
el-crypto-erase --token erase.json --signature erase.sig --device DEV      # dry run (default)
el-crypto-erase --token erase.json --signature erase.sig --all --execute --yes --poweroff
```

Gates, in order. All must pass:

1. A detached signature over the exact token bytes verifies against a
   **pinned** public key (`EL_ERASE_PUBKEY`, default
   `/etc/el/keys/crypto-erase.pub.pem`, shipped in the image). It works with
   RSA/ECDSA (`openssl dgst -sha256 -verify`) and Ed25519
   (`openssl pkeyutl -verify -rawin`, OpenSSL ≥ 3.0).
2. Claims: `action == "device.crypto-erase"`, `machine_id` equals
   `/etc/machine-id`, `luks_uuids` covers every target (or `"*"`), not expired,
   `issued_at` not more than 5 minutes in the future, lifetime ≤ 1 h, `nonce`
   ≥ 16 characters and never used before (`/var/lib/el/encryption/erase-nonces`).
3. `--execute` (otherwise it only prints what it would do) and `--yes`.

Then it runs `cryptsetup luksErase -q`, checks that no keyslots remain,
records the event in the journal, removes the volume's local escrow metadata,
and can `--reboot` or `--poweroff`. **Caveat:** a volume that is open keeps
its volume key in kernel memory until reboot, so always power off right away.
On SSDs, wear levelling can keep stale copies of old header areas in flash.
Someone holding both such a copy and an old passphrase could in theory
recover the data. A firmware-level secure erase (`nvme format --ses`) during
reprovisioning closes that gap.

### el-tpm-reseal

The update flow calls it around anything that changes measured boot:

```
el-tpm-reseal pre-update --kind uki|kernel|bootloader|shim|firmware|dbx [--predicted-pcrs 7:sha256=<hex>]
# install, reboot
el-tpm-reseal post-update        # el-tpm-reseal-post.service, first boot after update
```

For each systemd-tpm2 slot it compares the PCRs bound directly with the PCRs
that kind of update changes:

| Situation | Action |
|---|---|
| no overlap (e.g. UKI update, slot = PCR 7 + signed PCR 11) | nothing to do; the signed policy covers it (**preferred design**) |
| overlap + `--predicted-pcrs` | adds a slot sealed to the predicted values. `post-update` keeps it if it unlocks and wipes the old slot, otherwise re-seals to the current values. |
| overlap + `EL_RESEAL_ALLOW_BRIDGE=1` | adds a temporary bridge slot without the affected PCRs (still bound to the signed policy if there is one). `post-update` re-seals to the new measurements and wipes the bridge. While the bridge exists, protection is weaker. Compare BitLocker's "suspend". |
| otherwise | exits 2 with "recovery prompt expected", so the update flow can check `el-recovery-escrow verify` or postpone. |

PIN slots need `--pin-file` (or the user) to re-seal. Predicting PCR values is
the update tool's job (for example from the firmware capsule plus the TPM
event log). The long-term replacement is `systemd-pcrlock` (systemd ≥ 255),
which this tool doesn't use yet.

### el-encryption-facts

`el-encryption-facts [--compact]` prints:

```json
{"schema_version": 1, "collected_at": "…",
 "encryption": {
   "volumes": [{"device": "/dev/nvme0n1p3", "luks_uuid": "…", "status": "encrypted",
                "cipher": "aes-xts-plain64-512", "unlock_methods": ["recovery-key", "tpm2+pin"],
                "tpm_pcrs": [7], "tpm_signed_pcrs": [11], "opened": true,
                "mapper": "/dev/mapper/luks-root", "mountpoints": ["/", "/home"],
                "recovery_escrowed": true, "warnings": []}],
   "root_encrypted": true, "unencrypted_mounts": [],
   "recovery": {"escrowed": true, "escrow_target": "vault:secret/el/luks/…#v3",
                "last_rotated": "2026-10-28T10:00:00Z", "rotation_pending": false}}}
```

The keys from §5 are always present. The other keys are extensions, and
consumers must ignore keys they don't know. `status` is `encrypted` for LUKS2
and `encrypted-luks1` for LUKS1. `last_rotated` is the oldest across volumes,
which is the worst case. When lsblk has no udev data (containers, early boot),
it falls back to `cryptsetup isLuks`. It never prints blobs, salts, digests or
keys. An Intune or other custom compliance script can wrap it in three lines,
as CONTROL-API §5 intends.

## Threat model notes

* **Stolen powered-off laptop.** TPM2 sealed to PCR 7 (plus signed PCR 11)
  only releases the key into our signed boot chain. `tpm2+pin` adds a
  knowledge factor against TPM bus sniffing and DMA/cold-boot attacks on an
  unattended unlock. That is the trade-off in §6 Q1. Plain `tpm2` unlocks with
  no user present, so its strength rests on the login screen and the kernel
  lockdown being intact.
* **Evil maid / boot tampering.** Changing Secure Boot keys or db/dbx changes
  PCR 7, which leads to a recovery prompt. Booting an unsigned UKI fails the
  signed PCR 11 policy. Neither PCR binds the initrd unless it is inside the
  UKI, so UKIs are a requirement for the signed policy to mean anything.
* **Recovery key exposure.** The key sits in `/run` (tmpfs) for the few
  seconds of escrow and is then shredded. Escrow channels use TLS, optionally
  mTLS. Rotation after use limits how long a key handed out by the helpdesk
  stays valid. The fingerprint in `escrow.json` is a SHA-256 of a 256-bit
  random key, so it doesn't help an attacker.
* **Root on the running system can always read data.** Encryption at rest
  doesn't protect against a compromised running OS. That is the job of the
  hardening layers ([docs/HARDENING.md](../../docs/HARDENING.md)).
* **Remote wipe abuse.** Being local root is not enough. A token signed by the
  MDM's pinned key, bound to this machine and volume, short-lived and
  single-use, is required. If the signing key leaks, every device is exposed:
  keep it in an HSM and rotate it by shipping a new pinned key in the image.
* **Environment overrides** (`EL_STATE_DIR`, `EL_CRYPTTAB`, `EL_LIBDIR`,
  `EL_SKIP_ROOT_CHECK`, …) exist for tests and image builds. They don't widen
  the attack surface because setting them already requires control of a root
  process's environment. The config file is parsed and never sourced.

## Distro notes

| | Ubuntu 24.04 | Ubuntu 26.04 | RHEL 9 | RHEL 10 |
|---|---|---|---|---|
| systemd | 255 | ≥ 258 (expected) | 252 | 257 |
| cryptsetup | 2.7 | 2.8 (expected) | 2.6/2.7 | 2.7 |
| initrd | initramfs-tools (**ignores `tpm2-device=` for root**) | dracut | dracut | dracut |
| `--unlock-tpm2` (unattended rotation) | no | yes | no | yes |

On Ubuntu 24.04, TPM2 unlock of the root volume needs either a switch to
dracut or Canonical's snapd-based TPM-FDE, which is a separate mechanism this
code doesn't manage. `el-luks-enroll` warns when it detects initramfs-tools.
Clevis exists in both families (`clevis-dracut`, `clevis-initramfs`). Version
numbers marked "expected" come from published plans and still need checking.

## Testing

```
python3 security/encryption/tests/run-tests.py        # 50 tests, no root/TPM/network needed
sudo bash security/encryption/tests/integration-loop.sh   # real cryptsetup on a loop device; skips if unavailable
```

* `run-tests.py` puts `tests/mocks/` first on `PATH`. The mocks are fake
  `cryptsetup`, `systemd-cryptenroll`, `clevis`, `lsblk`, `curl`, `logger`,
  `systemctl`, `dracut` and `update-initramfs`. Each "device" is a JSON file
  shaped like `luksDump --dump-json-metadata`. The suite covers dry-run,
  idempotency, LUKS1 refusal, rollback on failed verification, PIN handling,
  signed policy, crypttab editing, every escrow backend (success, failure,
  bad ack), proof that keys and tokens never leak into argv or output,
  rotation after use, the fallback generator, crypto-erase signatures (EC and
  Ed25519) and claims (replay, expiry, wrong machine), the reseal strategies,
  the facts shape, config parsing, `bash -n`, and `shellcheck` when it is
  installed.
* `integration-loop.sh` formats a 64 MiB loop device with a real LUKS2
  header and runs facts, escrow, rotate, fallback rotate, LUKS1 refusal and
  crypto-erase end to end. TPM2 enrollment runs only if `/dev/tpmrm0` exists
  (e.g. a VM with swtpm).

Still to do before anyone relies on this: real laptops (Secure Boot on, TPM
2.0, UKI) on each target distro; swtpm-backed CI VMs; a real Tang server and a
Vault dev server; firmware/dbx update rehearsal for `el-tpm-reseal`.

## Open questions (in addition to ENCRYPTION.md §6)

1. Which component predicts PCR values for firmware/dbx updates (fwupd plugin,
   our own event-log tool, or `systemd-pcrlock`)?
2. Should the escrow channel to the MDM go through `eld` (the Control API)
   rather than straight from this tool? Today `webhook` is the stand-in.
3. Is the bridge strategy acceptable at all under the org policy, or should a
   PCR-7-changing update always require a recovery-ready state plus user
   presence?
4. Who issues and protects the crypto-erase signing key, and what is the
   rotation story for the pinned public key?
