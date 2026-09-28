# Distro comparison (substrate candidates)

**Status:** research / decision input — **no base locked**  
**Owner:** cto-max-grok  
**Date:** 2026-09-28  
**Product context:** Enterprise Linux = frozen core + strong SSO + strong MDM *support* + curated apps + locked automatic updates + controlled first-party marketplace (concept) + AI research track. Ubuntu-as-substrate was the earlier working assumption; this document re-opens the plate.

**Honesty rule:** nothing here is a “works with Intune/Jamf” badge. MDM columns describe *paths and fit*, not a certified integration we ship today.

---

## 1. Candidates

| ID | Candidate | What we mean |
|---|---|---|
| U | **Ubuntu 24.04 LTS** | Canonical Ubuntu, LTS pocket + optional Ubuntu Pro |
| RHEL | **Red Hat Enterprise Linux** | Subscription RHEL workstation/server SKUs |
| Rocky | **Rocky Linux** | RHEL-compatible rebuild (community) |
| Alma | **AlmaLinux** | RHEL-compatible rebuild (community) |
| Deb | **Debian** | Stable (not Testing/Sid) as frozen-core substrate |
| SUSE | **SUSE Linux Enterprise / openSUSE Leap** | SLE as paid; Leap as free freeze aligned with SLE |
| Custom | **Custom minimal frozen-core** | From-scratch or debootstrap/Yocto-style minimal root + our pins |

---

## 2. Axis definitions

| Axis | What “good” means for *this* product |
|---|---|
| **MDM strength** | Realistic path to org enroll / policy / inventory / remote actions (Intune-class, Jamf-class, or strong Linux natives: Landscape, Satellite/Insights, SUSE Manager, Fleet, etc.). Prefer vendors IT already bought. |
| **Enterprise stability / LTS** | Multi-year freeze, predictable ABI, clear major-upgrade train. |
| **Licensing cost** | $0 public rebuild vs paid subscription; legal clarity for redistribution of *our* image. |
| **Security posture** | Default hardenability (SELinux/AppArmor), security update quality/speed, FIPS/CIS *ecosystem* (not our certification claim). |
| **Automatic updates** | Mature unattended / guided security update tooling we can lock to policy. |
| **Locked / pre-configured image** | autoinstall/kickstart/Ignition/etc., reproducible CI→image, pin story. |
| **AI feature direction** | Neutrality: can we run local/offline inference, GPU drivers, and agent tooling without fighting the base? (Research fit — not “AI OS.”) |

---

## 3. Comparison matrix (qualitative)

Scale: **Strong / Adequate / Weak** for *org workstation product* fit. Judgments are architect opinion for Rohi’s thesis, not benchmarks.

| Candidate | MDM strength | Stability / LTS | Licensing cost | Security posture | Auto updates | Locked image fit | AI research fit |
|---|---|---|---|---|---|---|---|
| **Ubuntu 24.04 LTS** | **Adequate→Strong** via Landscape + growing Microsoft Linux management interest + Fleet/osquery-class agents; **not** “stock Ubuntu is enough” alone — product must add enroll hooks | **Strong** (LTS) | **Strong** (free); Ubuntu Pro optional $ | **Adequate→Strong** (AppArmor default; Pro adds ESM) | **Strong** (unattended-upgrades, well understood) | **Strong** (autoinstall + cloud-init; wide CI examples) | **Strong** (driver/GPU story, broad packages) |
| **RHEL** | **Strong** in Red Hat shops (Satellite, Insights, Ansible); Intune/third-party Linux agents often target RHEL family first | **Strong** | **Weak** for us as redistributor (subscription per seat; legal/process weight) | **Strong** (SELinux enforcing culture, certified ecosystems) | **Strong** (subscription manager, maintenance windows) | **Strong** (Image Builder, kickstart) but heavier pipeline | **Adequate** (supported GPUs via sub; more process) |
| **Rocky** | **Adequate→Strong** — same *technical* agent surface as RHEL family without RH support contract; MDM vendors that list “RHEL” often work, **verify per agent** | **Strong** (follows RHEL) | **Strong** ($0) | **Strong** (SELinux, RHEL-like) | **Strong** (dnf-automatic, etc.) | **Strong** (kickstart / same tooling patterns) | **Adequate** (similar to RHEL; fewer Canonical-style desktop niceties) |
| **Alma** | Same band as Rocky | **Strong** | **Strong** ($0) | **Strong** | **Strong** | **Strong** | **Adequate** |
| **Debian Stable** | **Weak→Adequate** — fewer first-class commercial MDM checkboxes; Fleet/custom agents doable | **Strong** (Stable) but slower package cadence | **Strong** ($0) | **Adequate→Strong** (AppArmor available; conservative) | **Adequate→Strong** (unattended-upgrades) | **Adequate→Strong** (preseed/FAI; less polished than Ubuntu autoinstall for desktops) | **Adequate** (stable packages lag; backports discipline required) |
| **SLE / Leap** | **Strong** in SUSE estates (SUSE Manager); outside that, **Adequate** | **Strong** (SLE); Leap tracks SLE | SLE **Weak** (paid); Leap **Strong** ($0) | **Strong** | **Strong** | **Strong** (AutoYaST, KIWI) | **Adequate** |
| **Custom minimal** | **Weak** day 1 — every MDM/agent path is DIY | **Unknown** (only as strong as our freeze process) | **Strong** ($0) but **high engineering cost** | **Unknown→Strong** if we invest | **Weak** until we build update train | **Strong** *if* we own the whole pipeline — that *is* the product cost | **Flexible** but we own drivers, glibc, CUDA pain |

---

## 4. Pros / cons by candidate

### Ubuntu 24.04 LTS

**Pros**
- Best laptop/desktop hardware and GPU convenience for a workstation wedge.
- Excellent locked-image story (autoinstall, cloud-init, easy Actions builders).
- Unattended security updates are boring and well documented — fits “automatic locked updates.”
- Large package set helps curated apps + AI experimentation without rebuilding the world.
- Landscape + Ubuntu Pro give a *native* management/security upsell path if Rohi wants Canonical-aligned MDM-ish control.

**Cons**
- Rohi’s pushback is valid: **stock** Ubuntu is not an MDM product. Intune/Jamf-class outcomes need **explicit agents, profiles, and hooks** we design — substrate alone does not deliver “strong MDM.”
- Not RHEL-compatible; some regulated buyers will bounce.
- AppArmor-centric (not SELinux-by-default), which some security teams discount.

**MDM how-it-still-works (if chosen later):** treat Ubuntu as plate; ship **enroll + compliance fact + policy agent slots** aimed at (pick with Rohi) Microsoft Intune Linux management path and/or Fleet/Landscape. Do not claim a badge until a named path is implemented and CLEAR’d.

---

### Red Hat Enterprise Linux

**Pros**
- Strongest “enterprise buyer already trusts this” story; Satellite/Insights/Ansible ecosystem.
- SELinux enforcing culture matches harden narrative.
- Commercial MDM/agents frequently list RHEL first.

**Cons**
- **Licensing and redistribution** fight a public MIT golden-image product unless every seat is subscribed and legalese is clean.
- Heavier process for a small team; workstation SKU complexity.
- Overkill if the wedge is “curated Linux laptop” not “RH shop standardization.”

---

### Rocky Linux / AlmaLinux

**Pros**
- RHEL-compatible **without** RH subscription — better fit for a public image product than RHEL itself.
- Same kickstart/Image Builder patterns; SELinux; dnf-automatic.
- Often the pragmatic answer when buyers say “must be RHEL-like” but will not fund RHEL seats for a side fleet.

**Cons**
- No Red Hat support contract (buyer risk; our docs must not imply RH support).
- Laptop polish and OEM enablement usually trail Ubuntu.
- Rocky vs Alma is mostly ecosystem/politics — pick one later if this family wins, do not ship both.

**Note:** Rocky and Alma are **close substitutes**. For decision-making, treat them as one “RHEL-compatible rebuild” lane unless a customer forces a brand.

---

### Debian Stable

**Pros**
- Pure frozen-core philosophy; $0; transparent.
- unattended-upgrades + strong packaging discipline.

**Cons**
- Weakest **checkbox MDM** story among paid-IT ecosystems.
- Desktop/laptop enablement and commercial agent docs skew Ubuntu/RHEL.
- Older libraries can slow AI/GPU experimentation unless backports are a first-class policy.

---

### SUSE Linux Enterprise / openSUSE Leap

**Pros**
- SUSE Manager is a real enterprise management plane.
- Leap gives a free SLE-aligned freeze; AutoYaST/KIWI are serious image tools.
- Strong security/update culture.

**Cons**
- Outside SUSE shops, hiring/docs/agent examples are thinner than Ubuntu/RHEL.
- SLE licensing cost if we need full SLE not Leap.
- Smaller community surface for “random laptop just works.”

---

### Custom minimal frozen-core

**Pros**
- Maximum control over pins, attack surface, and “locked ahead of time.”
- Can be shaped exactly around MDM agents + curated apps + AI runtime.

**Cons**
- **We become the distro vendor** (security backports, browser/CVE chase, GPU, printers).
- MDM strength starts at zero until we integrate agents ourselves.
- Highest schedule risk; conflicts with “concept → MVP in weeks” unless scope is tiny (kiosk), which this product is not.

---

## 5. Cross-cutting notes (MDM, updates, AI)

### MDM
- No candidate gives “strong MDM” with zero product work.
- **RHEL family** and **SUSE** win where the customer already standardized on Satellite / SUSE Manager.
- **Ubuntu** wins on laptop + build speed; MDM strength is **Adequate** until we add a named enroll path (Intune Linux and/or Fleet/Landscape). Rohi’s “stock Ubuntu insufficient” is about *stock*, not about “Ubuntu cannot be made MDM-ready.”
- **Custom** loses MDM unless MDM *is* the engineering centerpiece.

### Automatic locked updates
- All LTS/stable candidates can do policy-bound security updates.
- Differentiator is **our** image policy (on by default, reboot windows, no silent major upgrades) — substrate must not fight that. All listed except raw Arch-style rolling are fine; Custom must invent the train.

### AI research fit
- Prefer substrates with ordinary CUDA/ROCm/driver paths and recent libraries: **Ubuntu** leads; RHEL/Rocky/Alma adequate with more friction; Debian Stable lags; Custom flexible but costly.
- AI remains a **research track** — substrate choice should not assume a shipping model stack.

### Licensing for a public GitHub image product
- Friendliest: Ubuntu, Rocky, Alma, Debian, Leap.
- Hardest: RHEL (subscription entanglement).
- Custom: license is easy; maintenance is the cost.

---

## 6. What this document does *not* do

- **No substrate lock.** Decision waits on Rohi after reading this.
- **No Intune/Jamf certification claims.**
- **No ranking score that pretends to be objective.** The matrix is decision support for the product thesis in `docs/ARCHITECTURE.md`.

---

## 7. Suggested next step (process only)

1. Rohi marks must-have: **MDM vendor constraint** (Intune-class required day 1? RHEL-compatible required?) and **public image vs paid-only**.
2. Architect revises `ARCHITECTURE.md` decision summary to **one** substrate.
3. Joe SHIPs; Sam skims for leftover menu language and fake badges.

Until then, keep language as “substrate under comparison,” not “we are an Ubuntu product” or “we are a Rocky product.”
