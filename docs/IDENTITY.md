# Identity (strong SSO)

Stub. Headline pillar — see `docs/ARCHITECTURE.md` §5.2 and §8.

Path TBD after Rohi picks Entra-first (recommended) vs AD/sssd.

Do not claim a working join story until scripts and a verified VM path exist.

## Candidate building blocks (research, 2026-10)

| Option | What it is | Notes |
|---|---|---|
| **authd** (Canonical) | OIDC login broker for Entra ID / Google IAM with MFA + conditional access | Official in Ubuntu 26.04 LTS; Ubuntu-centric |
| **Himmelblau** | Open-source Entra ID + Intune client (PAM/NSS), multi-distro | Research maturity and support model |
| **SSSD + AD / IdM** | Classic Kerberos/LDAP join; Red Hat IdM adds HBAC + central sudo | Strong for AD/IdM shops; RHEL documents Entra login too |
| **Device certificates** | Issued at enrollment (SCEP/EST) for Wi-Fi/VPN and device trust | Needed regardless of login option |

## Requirements to carry into the ADR

- MFA and passwordless (FIDO2 / passkeys) at the login screen and for sudo.
- Offline login with cached credentials and a policy-defined grace period.
- Group claims feed the role model in [PERMISSIONS.md](PERMISSIONS.md).
- Conditional access: device compliance from the [Control API](CONTROL-API.md) must be visible to the IdP (via Intune or equivalent) so non-compliant devices lose M365 access.
