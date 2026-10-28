# Feature ideas (concept backlog)

**Status: ideas only — not shipped.** This is a concept backlog, not a product claim, live capability, or committed roadmap. Every item below is explicitly an idea for investigation only.

## Honesty boundaries

- Enterprise Linux is a **Linux-only** product; there are no Windows-native clients.
- There are no live MDM, marketplace, or AI capabilities claimed here.
- There are no Intune/Jamf badges or certifications claimed here.
- This backlog introduces **no new dependencies**.
- The [AI-for-investigation research track](AI-RESEARCH.md) remains research-only, with no ship claim.

## Backlog

1. **IDEA — Admin GUI** *(not shipped)*: fleet workflows for enrollment, compliance, update rings, and an app allowlist.
2. **IDEA — Device trust** *(not shipped)*: TPM attestation and Secure Boot checks before SSO.
3. **IDEA — Air-gap / offline signed update packs** *(not shipped)*.
4. **IDEA — Break-glass local admin** *(not shipped)*: time-boxed access with auditing. Now designed in [PERMISSIONS.md](PERMISSIONS.md).
5. **IDEA — Policy-as-code lockdown profiles** *(not shipped)*. Policy format drafted in [CONTROL-API.md](CONTROL-API.md).
6. **IDEA — App sandbox defaults for curated apps** *(not shipped)*. See [CURATED-APPS.md](CURATED-APPS.md).
7. **IDEA — Secret escrow to an organization vault** *(not shipped)*. See [ENCRYPTION.md](ENCRYPTION.md).
8. **IDEA — Compliance export** *(not shipped)*: a CIS/SOC2 evidence pack.
9. **IDEA — Remote assist** *(not shipped)*: ticket-scoped support access.
10. **IDEA — AI-for-investigation research track** *(not shipped)*: research only; still no ship claim.

### Added 2026-10-28 (from enterprise distro research)

11. **IDEA — Network isolation response action** *(not shipped)*: EDR/MDM can put a device into "quarantine" firewall mode (only management + EDR endpoints reachable) through the Control API.
12. **IDEA — Device health score** *(not shipped)*: one number + reasons, computed locally from facts, shown in the IT app and sent to the MDM.
13. **IDEA — Lost-mode** *(not shipped)*: MDM sets a lock-screen message and blocks login until recovery; device keeps reporting location-less check-ins.
14. **IDEA — Drift report** *(not shipped)*: diff of `/etc` and installed packages vs the image manifest, as a fact (inspired by Insights drift).
15. **IDEA — Per-device SBOM + CVE fact** *(not shipped)*: MDM/EDR asks the device which CVEs apply instead of rescanning.
16. **IDEA — Developer containers by default** *(not shipped)*: power users get Toolbox/Distrobox so the host stays locked.
17. **IDEA — Shared / kiosk mode** *(not shipped)*: ephemeral sessions for frontline or lab devices; home wiped at logout.
18. **IDEA — Privacy transparency page** *(not shipped)*: the device shows the user exactly which data and actions the org has (Apple/Google MDM style).
19. **IDEA — Battery / energy policy** *(not shipped)*: power profiles and charge limits by policy for fleet battery health.
20. **IDEA — Signed configuration bundles** *(not shipped)*: policy documents signed by the org key; device rejects unsigned policy even from local root.
21. **IDEA — Release notes in the IT app** *(not shipped)*: users see what changed in the last update in plain language.
22. **IDEA — Ansible collection / Terraform-style provider** *(not shipped)*: fleet-as-code clients of the Control API.

Nothing in this file should be read as a live MDM, marketplace, AI, or Windows capability claim.
