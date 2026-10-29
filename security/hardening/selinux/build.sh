#!/bin/bash
# Build (and optionally install) the eld SELinux policy module.
# Needs: selinux-policy-devel (provides /usr/share/selinux/devel/Makefile).
# Usage: build.sh            -> builds eld.pp in a temp dir, prints its path
#        build.sh --install  -> also runs semodule -i and restorecon
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
devel_makefile=/usr/share/selinux/devel/Makefile

if [[ ! -f "$devel_makefile" ]]; then
    echo "error: $devel_makefile not found; install selinux-policy-devel" >&2
    exit 2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$here"/eld.te "$here"/eld.fc "$here"/eld.if "$work"/
make -C "$work" -f "$devel_makefile" eld.pp
out="${EL_SELINUX_OUT:-$here/eld.pp}"
cp "$work/eld.pp" "$out"
echo "built: $out"

if [[ "${1:-}" == "--install" ]]; then
    semodule -i "$out"
    restorecon -RFv /usr/libexec/eld /etc/el /var/lib/el /run/eld 2>/dev/null || true
    echo "installed eld module (domain is permissive until AVCs are reviewed)"
fi
