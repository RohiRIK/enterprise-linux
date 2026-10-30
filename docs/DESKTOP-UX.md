# Desktop UX: a daily-use GUI with tiered customization

**Status:** design, with a first implementation in [`desktop/`](../desktop/README.md) (GNOME dconf tiers, branding, default apps, Workplace app skeleton). Not yet booted on a real image.  
**Date:** 2026-10-28  
**Related:** [CURATED-APPS.md](CURATED-APPS.md), [PERMISSIONS.md](PERMISSIONS.md), [CONTROL-API.md](CONTROL-API.md)

---

## 1. Goals

- An employee coming from Windows or macOS is productive on day one **without training**.
- Users can make the desktop *theirs* (wallpaper, dark mode, dock favorites, fonts) — **but not** change anything that affects security, compliance, or supportability.
- IT decides the fence; the user personalizes inside it. (ChromeOS model — see [research §5](RESEARCH-ENTERPRISE-DISTROS.md#5-immutable--image-based-desktops).)
- One friendly app for everything "IT": apps, status, help, admin requests.

---

## 2. Desktop environment

**Recommendation for discussion: GNOME** (on any substrate).

| | GNOME | KDE Plasma |
|---|---|---|
| Enterprise lockdown | **dconf system databases + locks**, mature, used by RHEL and Ubuntu | Kiosk framework (`[$i]` immutable keys), powerful but less used in enterprise |
| Default on candidates | RHEL, Ubuntu, Debian, Fedora | openSUSE, Fedora KDE |
| Familiar to Windows users | Needs a taskbar-style extension or Ubuntu's dock layout | Very Windows-like out of the box |
| Wayland / security | Mature Wayland, portals | Mature Wayland, portals |

Either works technically; GNOME aligns with the RHEL/Ubuntu substrates and their documented lockdown. We ship a **"familiar" layout**: bottom dock/taskbar, app menu, system tray, minimize/maximize buttons.

---

## 3. Customization tiers

Every desktop setting falls into exactly one tier. Tiers are enforced with dconf **locks** (or Plasma kiosk), driven by `desktop.*` policy in the Control API.

| Tier | Who can change it | Examples |
|---|---|---|
| **Locked (org)** | Only MDM policy | Screen lock timeout (max), lock on suspend, auto-update settings, firewall, encryption, Secure Boot, proxy/VPN, allowed extensions, login screen, telemetry, remote desktop on/off, USB policy, default browser (if org requires) |
| **Org default, user can change** | User, resettable by policy | Wallpaper, dock favorites, default apps (within catalog), keyboard layouts, notification settings |
| **User** | User | Dark/light mode, accent color, font size, scaling, mouse/touchpad, sounds, night light, accessibility, language (from allowed list), input methods |
| **Hidden** | Nobody in GUI | Developer/debug panels, things that make support impossible |

Settings in the **Locked** tier are shown greyed out with a short "Managed by your organization" note and a link to the IT app — users understand *why*, not just that they cannot.

Branding (wallpaper set, logo on login screen, accent color) is an org policy.

---

## 4. The IT app (working name "Company Portal" / "Workplace")

One first-party GTK/libadwaita app, a client of the [Control API](CONTROL-API.md). Tabs:

| Tab | What the user sees / does |
|---|---|
| **Home / Status** | Green/amber/red compliance tile: encrypted ✓, up to date ✓, Secure Boot ✓, EDR running ✓, last policy sync. Each failing item has a plain-language "Fix" button where possible. |
| **Apps** | Curated App Center: browse allowed bundles/apps, one-click install, "Request app" for apps that need approval ([CURATED-APPS.md](CURATED-APPS.md)) |
| **Updates** | What will update, when the next maintenance window is, "Restart now" / "Remind me" within the policy deferral limit |
| **Access** | Request temporary admin / extra role, with reason + duration ([PERMISSIONS.md §4](PERMISSIONS.md#4-just-in-time-jit-elevation)); see active grants and their expiry |
| **Devices** | Approve a new USB/Thunderbolt device (if policy allows user approval), printers, Bluetooth |
| **Help** | Contact IT, open a ticket with diagnostics bundle attached (`device.collect-logs`), start a remote-assist session the user must accept |
| **About** | Device name, serial, OS image version, who manages this device and what they can see (privacy transparency) |

Notifications from IT (`desktop.send-notification`) appear as normal desktop notifications with the org name.

---

## 5. First-boot / out-of-box experience

1. Language + keyboard + Wi-Fi (or wired).
2. **Org sign-in** (Entra / IdP with MFA) — this is what "enrolls" the device.
3. Policy, bundles, certificates, VPN pulled automatically; progress shown with plain steps.
4. Optional user choices the org allows (e.g. pick optional bundles, dark mode).
5. Short "what's managed here" privacy screen.
6. Desktop ready. Target: **under 15 minutes** from power-on to working desktop on a typical connection.

---

## 6. Accessibility, language, and RTL

- Accessibility available to every user regardless of lock tier (screen reader, zoom, high contrast, sticky keys).
- **Hebrew and other RTL languages** fully supported in shell and apps; fonts and input methods in locale packs. Org can restrict the list of UI languages but never remove accessibility.

---

## 7. Implementation

First cut lives in [`desktop/`](../desktop/README.md), GNOME only:

- Tiers map to files in `desktop/dconf/db/enterprise-linux.d/` (`00-` locked, `10-`/`20-`/`30-` org default, `90-` hidden); a validator enforces that user-tier and accessibility keys are never locked.
- Login screen branding in `desktop/dconf/db/gdm.d/`.
- Apps, browser policies and default apps come from the catalog profiles (`catalog/profiles/`, applied by `scripts/apps/elapps`). The desktop layer adds only the dock favorites for the same profile ([`desktop/apps/`](../desktop/apps/README.md)).
- The IT app skeleton, working name **Workplace**, in [`desktop/workplace/`](../desktop/workplace/README.md), on demo data until `eld` exists.

## 8. Open questions

1. GNOME (recommended) or KDE Plasma?
2. Name of the IT app?
3. Can users approve new USB devices themselves, or only helpdesk?
4. How much branding do orgs get (wallpaper only vs full theme)?
