#!/usr/bin/env bash
# Install default apps and browser policies for one profile into a root fs.
#   desktop/apps/install-apps.sh --profile open-source|microsoft-365 --root DIR
# Called by desktop/install.sh. Installing the browser packages themselves is
# the job of the app bundles (catalog/), not this script.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="" profile=""
while [ $# -gt 0 ]; do
  case "$1" in
    --root) root="${2:?}"; shift 2 ;;
    --profile) profile="${2:?}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$root" ] || { echo "error: --root is required" >&2; exit 2; }
pdir="$here/profiles/$profile"
[ -n "$profile" ] && [ -d "$pdir" ] || {
  echo "error: unknown profile '$profile' (have: $(ls "$here/profiles" | tr '\n' ' '))" >&2; exit 2; }
root="${root%/}"

install -D -m 0644 "$pdir/mimeapps.list" "$root/etc/xdg/mimeapps.list"
install -D -m 0644 "$pdir/favorites.dconf" "$root/etc/dconf/db/enterprise-linux.d/20-favorites"

install -D -m 0644 "$here/browsers/firefox/policies.json" "$root/etc/firefox/policies/policies.json"
install -D -m 0644 "$here/browsers/chrome/enterprise-linux.json" "$root/etc/opt/chrome/policies/managed/enterprise-linux.json"
install -D -m 0644 "$here/browsers/edge/enterprise-linux.json" "$root/etc/opt/edge/policies/managed/enterprise-linux.json"
install -D -m 0644 "$here/browsers/chromium/enterprise-linux.json" "$root/etc/chromium/policies/managed/enterprise-linux.json"

# Profile overlays: edge-*.json / chrome-*.json land next to the baseline.
for f in "$pdir"/edge-*.json; do
  [ -e "$f" ] && install -D -m 0644 "$f" "$root/etc/opt/edge/policies/managed/$(basename "$f")"
done
for f in "$pdir"/chrome-*.json; do
  [ -e "$f" ] && install -D -m 0644 "$f" "$root/etc/opt/chrome/policies/managed/$(basename "$f")"
done
echo "installed apps profile '$profile' into ${root:-/}"
