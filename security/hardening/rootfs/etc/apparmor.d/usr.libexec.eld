# AppArmor profile for eld, the enterprise-linux control daemon (layer 6).
# docs/CONTROL-API.md: eld runs confined, has no network listener, serves
# REST/JSON on /run/eld/api.sock and D-Bus org.enterpriselinux.Control1, and
# wraps native tools (cryptsetup, usbguard, flatpak, nft, apt) underneath.
#
# STATUS: draft for a daemon that does not exist yet. Written against
# AppArmor 4.0 (Ubuntu 24.04+). Not loaded-tested against a real eld; expect
# to tune it from complain-mode logs (aa-logprof) once eld exists.
#
# Design:
#  * eld itself never reads user home directories (helpdesk "cannot read user
#    files", PERMISSIONS.md §2) -> explicit deny.
#  * Native tools run in their own sibling profiles (Px -> eld-*) so a bug in
#    eld does not grant e.g. raw block-device access to the daemon itself.
#  * Package managers and flatpak need near-total system access by nature;
#    they transition with PUx (own profile if one is loaded, else unconfined).
#    That is a known gap to tighten later.

abi <abi/4.0>,

include <tunables/global>

profile eld /usr/libexec/eld {
  include <abstractions/base>
  include <abstractions/nameservice>
  include <abstractions/dbus-strict>

  # Drop privileges, manage file ownership in its own state, write audit records,
  # read peers' /proc entries for SO_PEERCRED identification.
  capability chown,
  capability dac_read_search,
  capability fowner,
  capability setgid,
  capability setuid,
  capability audit_write,
  capability kill,
  capability sys_ptrace,
  ptrace (read) peer=**,

  # Unix socket API (pathname socket -> file rules below govern the path)
  unix (create, bind, listen, accept, send, receive, getattr, getopt, setopt, shutdown) type=stream,

  # Own binary
  /usr/libexec/eld mr,

  # Configuration (policy documents, provider config) -- read only
  /etc/el/ r,
  /etc/el/** r,

  # State: last applied policy, cached role mappings, hardening manifest
  /var/lib/el/ rw,
  /var/lib/el/** rwk,

  # Runtime directory and API socket
  /run/eld/ rw,
  /run/eld/** rwk,
  /run/eld/api.sock rw,

  # Facts it reports
  @{PROC}/@{pid}/** r,
  @{PROC}/sys/kernel/** r,
  @{PROC}/sys/net/** r,
  @{PROC}/cmdline r,
  @{PROC}/mounts r,
  @{PROC}/modules r,
  /sys/firmware/efi/efivars/SecureBoot-* r,
  /sys/kernel/security/lockdown r,
  /sys/kernel/security/apparmor/profiles r,
  /sys/class/tpm/** r,
  /sys/devices/** r,
  /etc/os-release r,
  /usr/lib/os-release r,
  /etc/machine-id r,

  # Settings it renders (JIT sudo grants, polkit rules, usbguard rules,
  # dconf locks). Writes are limited to the drop-in locations we own.
  /etc/sudoers.d/ r,
  /etc/sudoers.d/50-el-* rw,
  /etc/polkit-1/rules.d/ r,
  /etc/polkit-1/rules.d/*-el-*.rules rw,
  /etc/usbguard/rules.d/ r,
  /etc/usbguard/rules.d/*-el-*.conf rw,
  /etc/dconf/db/local.d/ r,
  /etc/dconf/db/local.d/** rw,

  # D-Bus: own name, and talking to the system services it wraps
  dbus bind bus=system name=org.enterpriselinux.Control1,
  dbus receive bus=system path=/org/enterpriselinux/Control1{,/**},
  dbus send bus=system path=/org/enterpriselinux/Control1{,/**},
  dbus send bus=system peer=(name=org.freedesktop.DBus),
  dbus (send, receive) bus=system peer=(name=org.freedesktop.PolicyKit1),
  dbus (send, receive) bus=system peer=(name=org.freedesktop.systemd1),
  dbus (send, receive) bus=system peer=(name=org.freedesktop.login1),
  dbus (send, receive) bus=system peer=(name=org.freedesktop.NetworkManager),
  dbus (send, receive) bus=system peer=(name=org.freedesktop.UDisks2),
  dbus (send, receive) bus=system peer=(name=org.fedoraproject.FirewallD1),
  dbus (send, receive) bus=system peer=(name=org.usbguard1),
  dbus (send, receive) bus=system peer=(name=org.freedesktop.Flatpak.SystemHelper),

  # Native tools, each in its own sibling profile
  /usr/sbin/cryptsetup Px -> eld-cryptsetup,
  /usr/bin/systemd-cryptenroll Px -> eld-cryptsetup,
  /usr/bin/usbguard Px -> eld-usbguard-cli,
  /usr/sbin/nft Px -> eld-nft,
  /usr/bin/journalctl Px -> eld-journalctl,

  # Broad-access tools: TODO tighten (see header)
  /usr/bin/flatpak PUx,
  /usr/bin/apt-get PUx,
  /usr/bin/apt PUx,
  /usr/bin/fwupdmgr PUx,

  # Never read user data
  deny @{HOMEDIRS}/** rwklx,
  deny /root/** rwklx,

  # Never execute from writable locations
  deny /tmp/** x,
  deny /var/tmp/** x,
  deny /dev/shm/** x,

  include if exists <local/usr.libexec.eld>
}

profile eld-cryptsetup {
  include <abstractions/base>
  capability sys_admin,
  capability ipc_lock,
  capability dac_override,
  capability mknod,
  /usr/sbin/cryptsetup mr,
  /usr/bin/systemd-cryptenroll mr,
  /dev/mapper/ r,
  /dev/mapper/* rw,
  /dev/dm-* rw,
  /dev/nvme* rw,
  /dev/sd* rw,
  /dev/vd* rw,
  /dev/tpm* rw,
  /dev/tpmrm* rw,
  /run/cryptsetup/ rw,
  /run/cryptsetup/** rwk,
  /sys/devices/** r,
  /sys/class/** r,
  @{PROC}/@{pid}/** r,
  /etc/crypttab r,
  deny @{HOMEDIRS}/** rwklx,
}

profile eld-usbguard-cli {
  include <abstractions/base>
  /usr/bin/usbguard mr,
  # libqb IPC used by usbguard
  /dev/shm/qb-* rw,
  unix (connect, send, receive) type=stream,
  /etc/usbguard/ r,
  deny @{HOMEDIRS}/** rwklx,
}

profile eld-nft {
  include <abstractions/base>
  capability net_admin,
  network netlink raw,
  /usr/sbin/nft mr,
  /etc/nftables.conf r,
  /etc/nftables/ r,
  /etc/nftables/** r,
  deny @{HOMEDIRS}/** rwklx,
}

profile eld-journalctl {
  include <abstractions/base>
  /usr/bin/journalctl mr,
  /var/log/journal/ r,
  /var/log/journal/** r,
  /run/log/journal/ r,
  /run/log/journal/** r,
  /etc/machine-id r,
  deny @{HOMEDIRS}/** rwklx,
}
