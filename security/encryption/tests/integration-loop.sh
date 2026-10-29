#!/usr/bin/env bash
# integration-loop.sh - exercise the tools against a real LUKS2 header on a
# loop device. Needs root, cryptsetup, losetup and systemd-cryptenroll.
# Skips (exit 0 with "SKIP") otherwise. TPM2 enrollment is only tried when
# /dev/tpmrm0 exists (e.g. a VM with swtpm); FIDO2 is never tried.
#
# It only touches a temporary file-backed loop device it creates itself.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SBIN="$HERE/../sbin"

skip() { echo "SKIP: $*"; exit 0; }
[ "$(id -u)" -eq 0 ] || skip "needs root"
for c in cryptsetup losetup systemd-cryptenroll python3 openssl; do
    command -v "$c" >/dev/null 2>&1 || skip "$c not installed"
done
[ -e /dev/loop-control ] || skip "no loop device support"

T="$(mktemp -d)"
LOOP="" LOOP1=""
cleanup() {
    [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null || true
    [ -n "$LOOP1" ] && losetup -d "$LOOP1" 2>/dev/null || true
    rm -rf "$T"
}
trap cleanup EXIT

export EL_STATE_DIR="$T/state" EL_CRYPTTAB="$T/crypttab" EL_CONF="$T/encryption.conf" \
       EL_RUN_DIR="$T/run" EL_MACHINE_ID_FILE="$T/machine-id"
echo "0123456789abcdef0123456789abcdef" >"$EL_MACHINE_ID_FILE"
printf 'EL_ESCROW_BACKEND=file\nEL_ESCROW_FILE_DIR=%s\n' "$T/escrow" >"$EL_CONF"
: >"$EL_CRYPTTAB"

pass=0 fail=0
check() {   # description command...
    local d="$1"; shift
    if "$@" >"$T/out" 2>&1; then echo "ok   - $d"; pass=$((pass + 1))
    else echo "FAIL - $d"; sed 's/^/       /' "$T/out"; fail=$((fail + 1)); fi
}

truncate -s 64M "$T/disk.img"
LOOP="$(losetup --find --show "$T/disk.img")"
printf 'initial-passphrase' >"$T/pass"
cryptsetup luksFormat -q --type luks2 --cipher aes-xts-plain64 --key-size 512 \
    --pbkdf argon2id --pbkdf-memory 65536 --iter-time 200 --key-file "$T/pass" "$LOOP"
UUID="$(cryptsetup luksUUID "$LOOP")"

check "facts report the loop volume" \
    bash -c "'$SBIN/el-encryption-facts' | python3 -c 'import json,sys; v=[x for x in json.load(sys.stdin)[\"encryption\"][\"volumes\"] if x[\"luks_uuid\"]==\"$UUID\"]; assert v and v[0][\"cipher\"]==\"aes-xts-plain64-512\", v'"
check "dry-run enroll changes nothing" \
    "$SBIN/el-luks-enroll" --device "$LOOP" --dry-run --unlock-key-file "$T/pass" --no-crypttab
check "escrow (file backend)" \
    "$SBIN/el-recovery-escrow" escrow --device "$LOOP" --unlock-key-file "$T/pass"
SLOT1="$(python3 -c "import json;print(json.load(open('$EL_STATE_DIR/escrow.json'))['volumes']['$UUID']['keyslot'])")"
KEYFILE="$T/escrow/$UUID.json"
check "escrowed key unlocks the volume" bash -c \
    "python3 -c \"import json;print(json.load(open('$KEYFILE'))['recovery_key'],end='')\" | cryptsetup open --test-passphrase --key-file - '$LOOP'"
check "rotate" "$SBIN/el-recovery-escrow" rotate --device "$LOOP" --unlock-key-file "$T/pass"
SLOT2="$(python3 -c "import json;print(json.load(open('$EL_STATE_DIR/escrow.json'))['volumes']['$UUID']['keyslot'])")"
check "old recovery slot $SLOT1 wiped, new slot $SLOT2 present" bash -c \
    "! cryptsetup luksDump '$LOOP' | grep -qE '^  $SLOT1: luks2' || [ '$SLOT1' = '$SLOT2' ]"
check "status says escrowed" bash -c \
    "'$SBIN/el-recovery-escrow' status --device '$LOOP' | grep -q '\"escrowed\": true'"
check "rotate with fallback generator (luksAddKey + el-recovery token)" \
    "$SBIN/el-recovery-escrow" rotate --fallback --device "$LOOP" --unlock-key-file "$T/pass"
check "fallback key unlocks and is tagged" bash -c \
    "python3 -c \"import json;print(json.load(open('$KEYFILE'))['recovery_key'],end='')\" | cryptsetup open --test-passphrase --key-file - '$LOOP' && cryptsetup luksDump '$LOOP' | grep -q el-recovery && ! cryptsetup luksDump '$LOOP' | grep -q systemd-recovery"

if [ -e /dev/tpmrm0 ]; then
    check "enroll tpm2 (PCR 7)" "$SBIN/el-luks-enroll" --device "$LOOP" --unlock-key-file "$T/pass" \
        --crypttab-add itest
    check "re-enroll is idempotent" "$SBIN/el-luks-enroll" --device "$LOOP" --unlock-key-file "$T/pass"
else
    echo "skip - tpm2 enrollment (no /dev/tpmrm0)"
fi

truncate -s 32M "$T/disk1.img"
LOOP1="$(losetup --find --show "$T/disk1.img")"
cryptsetup luksFormat -q --type luks1 --key-file "$T/pass" "$LOOP1"
check "LUKS1 is refused" bash -c "! '$SBIN/el-luks-enroll' --device '$LOOP1' --no-crypttab"

openssl genpkey -algorithm ED25519 -out "$T/mdm.key" 2>/dev/null
openssl pkey -in "$T/mdm.key" -pubout -out "$T/mdm.pub"
python3 - "$T/token.json" "$UUID" <<'PY'
import datetime as d, json, os, sys
n = d.datetime.now(d.timezone.utc).replace(microsecond=0)
f = lambda t: t.isoformat().replace("+00:00", "Z")
json.dump({"action": "device.crypto-erase", "machine_id": "0123456789abcdef0123456789abcdef",
           "luks_uuids": [sys.argv[2]], "nonce": os.urandom(12).hex(),
           "issued_at": f(n), "expires_at": f(n + d.timedelta(minutes=10))}, open(sys.argv[1], "w"))
PY
openssl pkeyutl -sign -inkey "$T/mdm.key" -rawin -in "$T/token.json" -out "$T/token.sig"
check "crypto-erase dry run keeps keys" bash -c \
    "'$SBIN/el-crypto-erase' --token '$T/token.json' --signature '$T/token.sig' --pubkey '$T/mdm.pub' --device '$LOOP' && cryptsetup open --test-passphrase --key-file '$T/pass' '$LOOP'"
check "crypto-erase --execute --yes" "$SBIN/el-crypto-erase" --token "$T/token.json" \
    --signature "$T/token.sig" --pubkey "$T/mdm.pub" --device "$LOOP" --execute --yes
check "passphrase no longer opens the volume" bash -c \
    "! cryptsetup open --test-passphrase --key-file '$T/pass' '$LOOP'"

echo "integration: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
