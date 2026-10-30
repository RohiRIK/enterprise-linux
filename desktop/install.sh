#!/usr/bin/env bash
# Install the enterprise-linux GNOME desktop layer (dconf tiers, branding,
# default apps) into a root filesystem. Meant for the image build; it never
# touches the running system unless you pass --root / explicitly.
#
#   desktop/install.sh --root /path/to/rootfs [--profile <catalog profile>]
#                      [--branding desktop/branding/branding.conf]
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root=""
profile="default"
branding="$here/branding/branding.conf"

usage() {
  sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --root) root="${2:?--root needs a value}"; shift 2 ;;
    --profile) profile="${2:?--profile needs a value}"; shift 2 ;;
    --branding) branding="${2:?--branding needs a value}"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 2 ;;
  esac
done

[ -n "$root" ] || { echo "error: --root is required (use --root / for the live system)" >&2; exit 2; }
[ -f "$branding" ] || { echo "error: branding file not found: $branding" >&2; exit 2; }
root="${root%/}"

# Load KEY=VALUE pairs into BRAND_<KEY> environment variables for rendering.
# Values end up inside single-quoted GVariant strings, so reject quotes
# and backslashes.
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in ''|'#'*) continue ;; esac
  key="${line%%=*}"
  value="${line#*=}"
  if ! [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
    echo "error: bad branding key: $key" >&2; exit 1
  fi
  case "$value" in
    *"'"*|*'\'*) echo "error: $key must not contain ' or \\" >&2; exit 1 ;;
  esac
  export "BRAND_$key=$value"
done < "$branding"

# Copy a file, replacing @KEY@ with BRAND_KEY. Fails on any unknown marker.
render() {
  local src="$1" dst="$2"
  mkdir -p "$(dirname "$dst")"
  awk '
    {
      line = $0; out = ""
      while (match(line, /@[A-Z][A-Z0-9_]*@/)) {
        name = substr(line, RSTART + 1, RLENGTH - 2)
        if (!(("BRAND_" name) in ENVIRON)) {
          printf "error: %s: no branding value for @%s@\n", FILENAME, name > "/dev/stderr"
          exit 1
        }
        out = out substr(line, 1, RSTART - 1) ENVIRON["BRAND_" name]
        line = substr(line, RSTART + RLENGTH)
      }
      print out line
    }' "$src" > "$dst"
}

install_tree() {
  local src="$1" dst="$2" f rel
  while IFS= read -r -d '' f; do
    rel="${f#"$src"/}"
    render "$f" "$dst/$rel"
  done < <(find "$src" -type f -print0)
}

echo "==> dconf profiles and databases"
install_tree "$here/dconf/profile" "$root/etc/dconf/profile"
install_tree "$here/dconf/db/enterprise-linux.d" "$root/etc/dconf/db/enterprise-linux.d"
install_tree "$here/dconf/db/gdm.d" "$root/etc/dconf/db/gdm.d"

echo "==> branding"
install -D -m 0644 "$here/branding/wallpaper-light.svg" "$root/usr/share/backgrounds/enterprise-linux/wallpaper-light.svg"
install -D -m 0644 "$here/branding/wallpaper-dark.svg" "$root/usr/share/backgrounds/enterprise-linux/wallpaper-dark.svg"
install -D -m 0644 "$here/branding/logo.svg" "$root/usr/share/enterprise-linux/branding/logo.svg"
install -D -m 0644 "$here/branding/enterprise-linux-backgrounds.xml" \
  "$root/usr/share/gnome-background-properties/enterprise-linux-backgrounds.xml"
install -D -m 0644 "$branding" "$root/etc/enterprise-linux/branding.conf"

if [ -x "$here/apps/install-apps.sh" ]; then
  echo "==> dock favorites (profile: $profile)"
  "$here/apps/install-apps.sh" --profile "$profile" --root "${root:-/}"
else
  echo "warning: desktop/apps/install-apps.sh not found; skipping dock favorites" >&2
fi

echo "==> Workplace IT app"
"$here/workplace/install.sh" --root "${root:-/}"

if [ -z "$root" ] && command -v dconf >/dev/null 2>&1; then
  echo "==> dconf update"
  dconf update
else
  echo "note: run 'dconf update' inside the target system to compile the databases"
fi
