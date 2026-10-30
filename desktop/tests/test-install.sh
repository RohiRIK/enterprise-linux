#!/usr/bin/env bash
# End-to-end check: install both profiles into a temp root, compile the dconf
# databases, and confirm through gsettings that each tier behaves as designed.
# Needs: dconf-cli, gsettings (libglib2.0-bin) and gsettings-desktop-schemas
# + gnome-shell + gdm schemas installed on the host.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail=0

expect() { # schema key writable value
  local w v
  w="$(gsettings writable "$1" "$2")"
  v="$(gsettings get "$1" "$2")"
  if [ "$w" != "$3" ] || { [ -n "$4" ] && [ "$v" != "$4" ]; }; then
    echo "FAIL $1 $2: writable=$w (want $3) value=$v${4:+ (want $4)}"; fail=1
  else
    echo "ok   $1 $2 writable=$w"
  fi
}

for profile in default developer microsoft365 open-source; do
  root="$tmp/$profile"
  "$here/install.sh" --root "$root" --profile "$profile" >/dev/null
  dconf compile "$tmp/$profile.db" "$root/etc/dconf/db/enterprise-linux.d"
  dconf compile "$tmp/$profile-gdm.db" "$root/etc/dconf/db/gdm.d"
  export XDG_CONFIG_HOME="$tmp/config-$profile"
  printf 'user-db:user\nfile-db:%s\n' "$tmp/$profile.db" > "$tmp/profile"
  export DCONF_PROFILE="$tmp/profile"
  echo "== $profile: session"
  expect org.gnome.desktop.session idle-delay false "uint32 600"
  expect org.gnome.desktop.screensaver lock-enabled false true
  expect org.gnome.desktop.privacy usb-protection-level false "'lockscreen'"
  expect org.gnome.system.proxy mode false ""
  expect org.gnome.shell allow-extension-installation false false
  expect org.gnome.shell development-tools false false
  expect org.gnome.desktop.background picture-uri true \
    "'file:///usr/share/backgrounds/enterprise-linux/wallpaper-light.svg'"
  expect org.gnome.desktop.wm.preferences button-layout true "'appmenu:minimize,maximize,close'"
  expect org.gnome.desktop.interface color-scheme true ""
  expect org.gnome.desktop.a11y.applications screen-reader-enabled true ""
  case "$profile" in
    open-source) want="firefox-esr.desktop" ;;
    *) want="microsoft-edge.desktop" ;;
  esac
  if gsettings get org.gnome.shell favorite-apps | grep -q "'$want'"; then
    echo "ok   dock starts with $want"
  else
    echo "FAIL dock is missing $want"; fail=1
  fi
  # Browser policies and mimeapps.list belong to scripts/apps/elapps.
  for owned in etc/xdg/mimeapps.list etc/firefox etc/opt etc/chromium; do
    if [ -e "$root/$owned" ]; then echo "FAIL desktop layer wrote $owned (owned by elapps)"; fail=1; fi
  done

  printf 'user-db:user\nfile-db:%s\n' "$tmp/$profile-gdm.db" > "$tmp/profile"
  echo "== $profile: login screen"
  expect org.gnome.login-screen disable-user-list false true
  expect org.gnome.login-screen banner-message-enable false true
  if grep -rqE '@[A-Z][A-Z0-9_]*@' "$root/etc/dconf"; then
    echo "FAIL unrendered @TEMPLATE@ marker under /etc/dconf"; fail=1
  fi
done

exit "$fail"
