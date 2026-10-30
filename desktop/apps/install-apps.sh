#!/usr/bin/env bash
# Install the dock favorites for one catalog profile into a root fs.
#   desktop/apps/install-apps.sh --profile <catalog profile> --root DIR
# Called by desktop/install.sh. Apps, browser policies and default apps
# (/etc/xdg/mimeapps.list) belong to scripts/apps/elapps; this script never
# writes them.
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
src="$here/favorites/$profile.dconf"
if [ -z "$profile" ] || [ ! -f "$src" ]; then
  echo "error: no dock favorites for profile '$profile' (see desktop/apps/favorites/)" >&2
  exit 2
fi
root="${root%/}"
install -D -m 0644 "$src" "$root/etc/dconf/db/enterprise-linux.d/20-favorites"
echo "installed dock favorites for profile '$profile' into ${root:-/}"
