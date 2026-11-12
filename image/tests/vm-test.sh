#!/usr/bin/env bash
# Install a --test-identity ISO into a UEFI Secure Boot VM with a software
# TPM, boot the installed disk, and check the first-boot report.
#
#   image/tests/vm-test.sh --iso out/enterprise-linux-*-ci.iso [--work DIR]
#                          [--install-timeout MIN] [--boot-timeout MIN]
#                          [--start-timeout MIN] [--quiet-timeout MIN]
#
# The install fails early when neither curtin output nor disk writes appear
# within --start-timeout (10) or install.log stops growing for --quiet-timeout (20),
# saving a QMP screenshot to WORK/screen.ppm.
#
# Needs qemu-system-x86_64, ovmf, swtpm; KVM strongly recommended.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
iso=""
work=vm
install_min=120
boot_min=20
start_min=10
quiet_min=20
while [ $# -gt 0 ]; do
  case "$1" in
    --iso) iso="${2:?}"; shift 2 ;;
    --work) work="${2:?}"; shift 2 ;;
    --install-timeout) install_min="${2:?}"; shift 2 ;;
    --boot-timeout) boot_min="${2:?}"; shift 2 ;;
    --start-timeout) start_min="${2:?}"; shift 2 ;;
    --quiet-timeout) quiet_min="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
  -global "driver=cfi.pflash01,property=secure,value=on"
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=$ovmf_code"
  -drive "if=pflash,format=raw,unit=1,file=$work/vars.fd"
  -chardev "socket,id=chrtpm,path=$work/tpm.sock"
  -tpmdev "emulator,id=tpm0,chardev=chrtpm" -device "tpm-tis,tpmdev=tpm0"
  -drive "file=$work/disk.qcow2,if=virtio,format=qcow2"
  -netdev "user,id=net0" -device "virtio-net-pci,netdev=net0"
  -vga virtio -display none -no-reboot)

# Record the live kernel command line the ISO will boot, so a run that lands
# in the live session instead of the installer shows whether `autoinstall`
# was there.
if command -v xorriso >/dev/null; then
  xorriso -osirrox on -indev "$iso" -extract /boot/grub/grub.cfg "$work/iso-grub.cfg" >/dev/null 2>&1 \
    && grep -nE '^\s*(menuentry|linux)\s' "$work/iso-grub.cfg" > "$work/grub.log" || true
fi

# One screenshot through QMP: with -display none this is the only view of
# a GUI installer that stalls.
screendump() {
  python3 - "$work/qmp.sock" "$work/screen.ppm" <<'PY' || true
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(20); s.connect(sys.argv[1])
f = s.makefile("rw")
f.readline()  # greeting
for cmd in ({"execute": "qmp_capabilities"},
            {"execute": "screendump", "arguments": {"filename": sys.argv[2]}}):
    f.write(json.dumps(cmd) + "\n"); f.flush(); f.readline()
PY
}

fail_install() {
  echo "vm-test: $1 (see install.log, screen.ppm)" >&2
  screendump
  kill "$qemu_pid" 2>/dev/null || true
  wait "$qemu_pid" 2>/dev/null || true
  exit 1
}

# Watchdog: fail early instead of idling out the whole budget.
#  - within $start_min minutes neither a `curtin` line in install.log nor
#    64 MiB written to the target disk: autoinstall never started (the
#    journal on ttyS0 may not carry curtin, the disk always shows writes);
#  - install.log silent for $quiet_min minutes: the install is stuck.
echo "vm-test: installing ($accel, up to $install_min min)"
: > "$work/install.log"
qemu-system-x86_64 "${qemu_args[@]}" -cdrom "$iso" -boot d -serial "file:$work/install.log" \
  -qmp "unix:$work/qmp.sock,server,nowait" &
qemu_pid=$!
start=$SECONDS last_size=0 last_change=$SECONDS started=""
while kill -0 "$qemu_pid" 2>/dev/null; do
  sleep 15
  now=$SECONDS
  size=$(stat -c %s "$work/install.log")
  [ "$size" != "$last_size" ] && { last_size=$size; last_change=$now; }
  if [ -z "$started" ]; then
    if grep -q 'curtin command' "$work/install.log" || [ "$(du -k "$work/disk.qcow2" | cut -f1)" -ge 65536 ]; then
      started=1; echo "vm-test: install started after $(( (now - start) / 60 )) min"
    elif [ $((now - start)) -ge $((start_min * 60)) ]; then
      fail_install "autoinstall did not start: no curtin output or disk writes after $start_min min"
    fi
  fi
  # A real crash writes a report (`subiquity/ErrorReporter/<id>/add_info`);
  # `subiquity/Error/load_autoinstall_data` is only that controller loading.
  if grep -qE 'subiquity/ErrorReporter/[^ ]+/add_info' "$work/install.log"; then
    fail_install "installer crashed (subiquity error report)"
  fi
  [ $((now - last_change)) -ge $((quiet_min * 60)) ] && fail_install "install.log silent for $quiet_min min"
  [ $((now - start)) -ge $((install_min * 60)) ] && fail_install "install did not finish in $install_min min"
done
wait "$qemu_pid" || { echo "vm-test: qemu exited with an error during install (see install.log)" >&2; exit 1; }

# The TPM state carries over: swtpm keeps running between the two boots.
echo "vm-test: first boot (up to $boot_min min)"
timeout "$((boot_min * 60))" qemu-system-x86_64 "${qemu_args[@]}" -serial "file:$work/boot.log" \
  || { echo "vm-test: first boot did not power off (see boot.log)" >&2; exit 1; }

python3 "$here/check-boot-report.py" "$work/boot.log"
