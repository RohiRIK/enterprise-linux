#!/usr/bin/env bash
# Remaster the official Ubuntu 26.04 LTS desktop ISO into an enterprise-linux
# installer: autoinstall.yaml at the ISO root, our payload under /el, and the
# original boot records untouched (Secure Boot keeps working through the
# stock shim and GRUB). No ISO blobs go into git.
#
#   image/build-iso.sh --base-iso ubuntu-26.04.1-desktop-amd64.iso
#                      [--sha256sums SHA256SUMS] [--profile default]
#                      [--deb out/el-eld_*.deb] [--out out/] [--timezone Asia/Jerusalem]
#                      [--unattended] [--test-identity] [--serial]
#
# --unattended   add `autoinstall` to the GRUB entry: installs without asking.
#                Without it the installer asks before it erases the disk.
# --test-identity  CI only: local account eltest / random password (printed),
#                powers off after install and reports on first boot.
# --serial       kernel console on ttyS0 too (CI logs).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
base_iso=""
sums=""
profile=default
deb=""
out="$repo/out"
timezone="Asia/Jerusalem"
unattended=0
test_identity=0
serial=0

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --base-iso) base_iso="${2:?}"; shift 2 ;;
    --sha256sums) sums="${2:?}"; shift 2 ;;
    --profile) profile="${2:?}"; shift 2 ;;
    --deb) deb="${2:?}"; shift 2 ;;
    --out) out="${2:?}"; shift 2 ;;
    --timezone) timezone="${2:?}"; shift 2 ;;
    --unattended) unattended=1; shift ;;
    --test-identity) test_identity=1; shift ;;
    --serial) serial=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "build-iso: unknown argument: $1" >&2; usage 2 ;;
  esac
done

die() { echo "build-iso: $*" >&2; exit 1; }
[ -r "$base_iso" ] || die "--base-iso is required and must be readable"
[ -f "$repo/catalog/profiles/$profile.yaml" ] || die "unknown profile '$profile' (catalog/profiles/)"
for tool in xorriso python3 openssl sha256sum; do
  command -v "$tool" >/dev/null || die "$tool not found"
done

iso_sha="$(sha256sum "$base_iso" | cut -d' ' -f1)"
if [ -n "$sums" ]; then
  grep -q "^$iso_sha [ *]$(basename "$base_iso")\$" "$sums" \
    || die "$(basename "$base_iso") does not match $sums"
fi
iso_label="$(xorriso -indev "$base_iso" -pvd_info 2>/dev/null | sed -n 's/^Volume Id *: *//p')"
case "$iso_label" in
  *26.04*) ;;
  *) die "base ISO volume id '$iso_label' is not Ubuntu 26.04" ;;
esac

[ -n "$deb" ] || deb="$("$repo/packaging/deb/build-eld-deb.sh" --out "$out")"
[ -r "$deb" ] || die "missing eld package $deb"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pay="$work/el"
mkdir -p "$pay/pool" "$pay/image"
for part in catalog desktop policies scripts security; do
  cp -a "$repo/$part" "$pay/"
done
cp -a "$here/late" "$here/uki" "$here/tests" "$pay/image/"
find "$pay" \( -name __pycache__ -o -name '*.pyc' \) -prune -exec rm -rf {} +
cp "$deb" "$pay/pool/"

# Per-build LUKS install key (see image/README.md "Install key").
openssl rand -base64 33 | tr -d '\n=' > "$pay/install.key"
install_key="$(cat "$pay/install.key")"

identity=""
interactive="identity"
late_args=""
shutdown=reboot
if [ "$test_identity" = 1 ]; then
  test_pw="$(openssl rand -base64 12)"
  hash="$(openssl passwd -6 "$test_pw")"
  identity="  identity:
    hostname: el-ci
    realname: EL test
    username: eltest
    password: \"$hash\""
  interactive=""
  late_args="--ci-report"
  shutdown=poweroff
  echo "build-iso: test identity eltest / $test_pw" >&2
fi

git_rev="$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown)"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml" | head -n1)"
python3 - "$pay/BUILD.json" <<PY
import json, sys
json.dump({"schema": "el.image.build/v1", "version": "$version", "git": "$git_rev",
           "profile": "$profile", "base_iso": "$(basename "$base_iso")",
           "base_iso_sha256": "$iso_sha", "base_iso_label": "$iso_label",
           "eld_package": "$(basename "$deb")", "test_image": bool($test_identity)},
          open(sys.argv[1], "w"), indent=2)
PY

python3 "$here/render-autoinstall.py" "$here/autoinstall/autoinstall.yaml.in" "$work/autoinstall.yaml" \
  INTERACTIVE="$interactive" TIMEZONE="$timezone" INSTALL_KEY="$install_key" \
  PROFILE="$profile" IDENTITY="$identity" LATE_ARGS="$late_args" SHUTDOWN="$shutdown"

xorriso -osirrox on -indev "$base_iso" -extract /boot/grub/grub.cfg "$work/grub.cfg" >/dev/null 2>&1 \
  || die "no /boot/grub/grub.cfg on the base ISO"
chmod u+w "$work/grub.cfg"
extra=""
[ "$unattended" = 1 ] && extra="$extra autoinstall"
[ "$serial" = 1 ] && extra="$extra console=tty0 console=ttyS0,115200"
python3 "$here/patch-grub.py" "$work/grub.cfg" "$extra"

mkdir -p "$out"
iso="$out/enterprise-linux-$version-$profile-amd64$( [ "$test_identity" = 1 ] && echo -ci ).iso"
rm -f "$iso"
xorriso -indev "$base_iso" -outdev "$iso" \
  -map "$pay" /el \
  -map "$work/autoinstall.yaml" /autoinstall.yaml \
  -map "$work/grub.cfg" /boot/grub/grub.cfg \
  -boot_image any replay >/dev/null 2>"$work/xorriso.log" \
  || { cat "$work/xorriso.log" >&2; die "xorriso failed"; }
(cd "$out" && sha256sum "$(basename "$iso")" > "$(basename "$iso").sha256")
echo "$iso"
