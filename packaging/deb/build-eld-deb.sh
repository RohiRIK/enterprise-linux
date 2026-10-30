#!/usr/bin/env bash
# Build the el-eld .deb (eld daemon + elctl CLI + unit + default config) for
# Ubuntu 26.04. Uses dpkg-deb only, so it runs on any Debian-family host.
#
#   packaging/deb/build-eld-deb.sh [--out DIR] [--version VER] [--no-build]
#
# --no-build packages the binaries already in target/release.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="$repo/out"
version=""
build=1

while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="${2:?--out needs a value}"; shift 2 ;;
    --version) version="${2:?--version needs a value}"; shift 2 ;;
    --no-build) build=0; shift ;;
    -h|--help) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$version" ]; then
  version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml" | head -n1)"
fi
arch="$(dpkg --print-architecture)"

if [ "$build" = 1 ]; then
  (cd "$repo" && cargo build --release --locked -p eld -p elctl)
fi
for bin in eld elctl; do
  [ -x "$repo/target/release/$bin" ] || { echo "error: target/release/$bin missing (run without --no-build)" >&2; exit 1; }
done

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
pkg="$stage/el-eld"

install -D -m 0755 "$repo/target/release/eld" "$pkg/usr/libexec/eld"
install -D -m 0755 "$repo/target/release/elctl" "$pkg/usr/bin/elctl"
install -D -m 0644 "$repo/dist/systemd/eld.service" "$pkg/usr/lib/systemd/system/eld.service"
install -D -m 0644 "$repo/dist/eld.json" "$pkg/etc/eld/eld.json"
install -D -m 0644 "$repo/LICENSE" "$pkg/usr/share/doc/el-eld/copyright"

mkdir -p "$pkg/DEBIAN"
for f in postinst prerm postrm conffiles; do
  install -m "$( [ "$f" = conffiles ] && echo 0644 || echo 0755 )" "$here/el-eld/DEBIAN/$f" "$pkg/DEBIAN/$f"
done
installed_kb="$(du -sk --exclude=DEBIAN "$pkg" | cut -f1)"
sed -e "s/@VERSION@/$version/" -e "s/@ARCH@/$arch/" -e "s/@SIZE@/$installed_kb/" \
  "$here/el-eld/DEBIAN/control.in" > "$pkg/DEBIAN/control"

mkdir -p "$out"
deb="$out/el-eld_${version}_${arch}.deb"
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$deb" >/dev/null
echo "$deb"
