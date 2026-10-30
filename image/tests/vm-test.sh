#!/usr/bin/env bash
# Install a --test-identity ISO into a UEFI Secure Boot VM with a software
# TPM, boot the installed disk, and check the first-boot report.
#
#   image/tests/vm-test.sh --iso out/enterprise-linux-*-ci.iso [--work DIR]
#                          [--install-timeout MIN] [--boot-timeout MIN]
#
# Needs qemu-system-x86_64, ovmf, swtpm; KVM strongly recommended.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
iso=""
work=vm
install_min=120
boot_min=20
while [ $# -gt 0 ]; do
  case "$1" in
    --iso) iso="${2:?}"; shift 2 ;;
    --work) work="${2:?}"; shift 2 ;;
    --install-timeout) install_min="${2:?}"; shift 2 ;;
    --boot-timeout) boot_min="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "vm-test: unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -r "$iso" ] || { echo "vm-test: --iso is required" >&2; exit 2; }

ovmf_code=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd
ovmf_vars=/usr/share/OVMF/OVMF_VARS_4M.ms.fd   # Microsoft UEFI CA enrolled, like a laptop
for f in "$ovmf_code" "$ovmf_vars"; do
  [ -r "$f" ] || { echo "vm-test: missing $f (apt install ovmf)" >&2; exit 2; }
done

mkdir -p "$work/tpm"
work="$(cd "$work" && pwd)"
cp "$ovmf_vars" "$work/vars.fd"
qemu-img create -f qcow2 "$work/disk.qcow2" 40G >/dev/null

swtpm socket --tpm2 --tpmstate "dir=$work/tpm" --ctrl "type=unixio,path=$work/tpm.sock" \
  --daemon --pid "file=$work/swtpm.pid" --log "file=$work/swtpm.log"
trap 'kill "$(cat "$work/swtpm.pid" 2>/dev/null)" 2>/dev/null || true' EXIT

accel=tcg
[ -w /dev/kvm ] && accel=kvm
qemu_args=(-machine "q35,smm=on,accel=$accel" -cpu max -smp 4 -m 8192
  -global driver=cfi.pflash01,property=secure,value=on
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=$ovmf_code"
  -drive "if=pflash,format=raw,unit=1,file=$work/vars.fd"
  -chardev "socket,id=chrtpm,path=$work/tpm.sock"
  -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0
  -drive "file=$work/disk.qcow2,if=virtio,format=qcow2"
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0
  -vga virtio -display none -no-reboot)

echo "vm-test: installing ($accel, up to $install_min min)"
timeout "$((install_min * 60))" qemu-system-x86_64 "${qemu_args[@]}" -cdrom "$iso" -boot d -serial "file:$work/install.log" \
  || { echo "vm-test: install did not finish (see install.log)" >&2; exit 1; }

# The TPM state carries over: swtpm keeps running between the two boots.
echo "vm-test: first boot (up to $boot_min min)"
timeout "$((boot_min * 60))" qemu-system-x86_64 "${qemu_args[@]}" -serial "file:$work/boot.log" \
  || { echo "vm-test: first boot did not power off (see boot.log)" >&2; exit 1; }

python3 "$here/check-boot-report.py" "$work/boot.log"
