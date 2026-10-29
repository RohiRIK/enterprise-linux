# Managed browser policies

**Status:** design stage. These files are written and their syntax is checked
(valid JSON before rendering), but none of them has been loaded into a browser
on a released enterprise-linux image yet. Policy names come from the vendors'
published policy lists. Names marked *verify* below still need to be checked
against the browser version we freeze.

The `browsers` bundle (`catalog/bundles/browsers.yaml`: Edge, Chrome, Firefox ESR)
and the opt-in `browsers-extra` bundle (Chromium, Brave) install these files.
Each file is copied only when the browser was installed as a **native package**
(`appliesTo: [native]`). Flatpak builds of these browsers do not reliably read
host policy directories, so a Flatpak browser runs **unmanaged**. That is why
the bundle prefers native packages.

## Files

| File | Installed to | What it does |
|---|---|---|
| `chromium-common/10-baseline.json` | managed dir of Edge, Chrome, Chromium, Brave | Shared Chromium-family baseline: safe browsing, downloads, no password manager, no sync, no guest mode or extra profiles, telemetry off, extensions blocked, system DNS, Kerberos allowlist, homepage. |
| `edge/20-edge.json` | `/etc/opt/edge/policies/managed/` | Edge-only: work-account sign-in limited to the tenant, first-run, shopping, rewards, sidebar and news feed off, SmartScreen on. |
| `chrome/20-chrome.json` | `/etc/opt/chrome/policies/managed/` | Chrome-only: no Google sign-in, no promo tabs or labs, generative AI features off, Privacy Sandbox ad APIs off. |
| `chromium/20-chromium.json` | `/etc/chromium/policies/managed/` and, on apt, `/etc/chromium-browser/policies/managed/` (Ubuntu snap) | No browser sign-in, Privacy Sandbox ad APIs off. |
| `brave/20-brave.json` | `/etc/brave/policies/managed/` | Brave-only: rewards, wallet, VPN, AI chat (Leo), News, Talk, Tor windows, P3A, stats ping and Web Discovery off. |
| `firefox/policies.json` | `/etc/firefox/policies/policies.json` | Firefox equivalent of the baseline. |

### Managed directories

| Browser | Managed policy directory |
|---|---|
| Google Chrome | `/etc/opt/chrome/policies/managed/` |
| Microsoft Edge | `/etc/opt/edge/policies/managed/` |
| Chromium (Debian, Fedora, openSUSE) | `/etc/chromium/policies/managed/` |
| Chromium (Ubuntu snap) | `/etc/chromium-browser/policies/managed/` |
| Brave | `/etc/brave/policies/managed/` |
| Firefox / Firefox ESR | `/etc/firefox/policies/policies.json` (one file) |

Firefox notes:

- Mozilla supports `/etc/firefox/policies/policies.json` system-wide on Linux,
  and we write only that path.
- Some distro builds also read `<install dir>/distribution/policies.json`, for
  example `/usr/lib64/firefox/distribution/` on RHEL and Fedora, or
  `/usr/lib/firefox-esr/distribution/` on Debian. If a distro build ships its
  own `distribution/policies.json`, that file **takes precedence over** `/etc`.
  The installer should warn when it finds one. *verify per distro*

## How the files merge

**Chromium family.** The browser reads every `*.json` in the managed directory
and merges them. If two files set the same key, which one wins is not defined.
So:

- `10-baseline.json` and each `20-<browser>.json` have **disjoint keys**.
  `BrowserSignin` lives only in the overlays because Edge needs a different
  value from the others.
- Org overrides go in a new file, for example `30-org.json`, and must use keys
  that no other file sets. To change a baseline key, edit the baseline in the
  repo and bump the bundle version. Do not add a second file that sets the
  same key.
- List policies such as `ExtensionInstallAllowlist` are **not** merged across
  files by default. Keep each list in one file only.
- Another bundle may drop its own file into the same directory. For example,
  the Microsoft 365 bundle uses `WebAppInstallForceList` for the M365 PWAs.
  That file must also avoid every key used here.

**Firefox.** Firefox reads exactly **one** `policies.json`, and no merging
happens. Any other bundle that needs Firefox policy has to add its keys to
`firefox/policies.json` here. It must not write its own copy.

## Placeholders

The installer renders these from the profile's `settings:`. Every placeholder
sits **inside a JSON string**, so the files are valid JSON before rendering.

| Placeholder | Used in | Example | Empty value means |
|---|---|---|---|
| `{{ homepage }}` | `10-baseline.json` (`HomepageLocation`, `RestoreOnStartupURLs`), `firefox/policies.json` (`Homepage.URL`) | `https://www.office.com` | No managed homepage. |
| `{{ m365_tenant_domain }}` | `edge/20-edge.json` (`RestrictSigninToPattern`) | `contoso.com` | Edge sign-in not restricted to a tenant. |
| `{{ auth_server_allowlist }}` | `10-baseline.json` (`AuthServerAllowlist`), `firefox/policies.json` (`Authentication.SPNEGO`) | `*.corp.contoso.com` | No Kerberos/SPNEGO to any server. |

Every profile in `catalog/profiles/` defines all three, `""` by default.

**Rendering rule (required for correctness):** when a placeholder renders to
an empty string, the renderer must **remove** the value that holds it, not
leave an empty or partial string behind:

- An object member whose string value contains an empty placeholder is
  dropped. So `"RestrictSigninToPattern": ".*@{{ m365_tenant_domain }}"`
  with an empty domain removes the key entirely. Without this rule the value
  would be `".*@"`, and that would quietly allow any account.
- A list element whose string contains an empty placeholder is dropped. So
  `"RestoreOnStartupURLs": ["{{ homepage }}"]` becomes `[]`, and
  `"SPNEGO": ["{{ auth_server_allowlist }}"]` becomes `[]`.
- Values are JSON-escaped when inserted. Regex characters are **not**
  escaped. So `contoso.com` in the Edge pattern matches `contoso` + any
  character + `com`. This is acceptable for a sign-in restriction. An org
  that wants it exact can set `m365_tenant_domain: contoso\\.com`.
- After rendering, the result is parsed again as JSON before it is written.

When `homepage` is empty, `RestoreOnStartup: 4` ends up with an empty URL
list, and Chromium then opens the New Tab Page. That is acceptable.

On Firefox, `Authentication.SPNEGO` is joined with commas into
`network.negotiate-auth.trusted-uris`. A comma-separated
`auth_server_allowlist` therefore works in both browsers.

No list-valued placeholders are used. Lists (extension allowlists and
similar) stay static in the repo, as described below.

## Per-key rationale

### `chromium-common/10-baseline.json`

| Key | Value | Why |
|---|---|---|
| `SafeBrowsingProtectionLevel` | `1` (standard) | Phishing and malware protection on. We chose standard over enhanced (`2`) because enhanced sends visited URLs to Google in real time. Edge ignores this key and uses SmartScreen (see the Edge overlay). |
| `SafeBrowsingExtendedReportingEnabled` | `false` | Do not send page samples to Google. |
| `DownloadRestrictions` | `1` | Block downloads that Safe Browsing flags as dangerous. |
| `PromptForDownloadLocation` | `true` | The user chooses where files land. Pairs with `noexec` on `/home` (HARDENING #7). |
| `HttpsOnlyMode` | `force_balanced_enabled` | Upgrade to HTTPS and warn on sites that are usually HTTP, without breaking intranet HTTP hosts the way `force_enabled` would. *verify: the value needs Chrome ≥ 129. Edge does not use this key and uses `AutomaticHttpsDefault` instead.* |
| `PasswordManagerEnabled` | `false` | The org uses SSO and a central vault, so credentials should not live in browser profiles where infostealers find them. |
| `ImportSavedPasswords` | `false` | Same reason: nothing gets pulled in from another browser. |
| `AutofillCreditCardEnabled` | `false` | Card data stays out of the browser profile. |
| `PaymentMethodQueryEnabled` | `false` | Sites cannot probe for stored payment methods. |
| `SyncDisabled` | `true` | Profile data is not synced to a vendor cloud under a personal account. For Edge enterprise sync to the work tenant, an org can remove this from the baseline, which bumps the bundle version. |
| `BrowserGuestModeEnabled` | `false` | Guest windows bypass profile policy and audit. |
| `BrowserAddPersonEnabled` | `false` | No extra (personal) profiles. |
| `MetricsReportingEnabled` | `false` | No usage or crash statistics to the vendor. |
| `UrlKeyedAnonymizedDataCollectionEnabled` | `false` | No URL-keyed data collection. |
| `SpellCheckServiceEnabled` | `false` | Typed text is not sent to a cloud spell-checker. The local dictionary still works. |
| `UserFeedbackAllowed` | `false` | The feedback dialog can attach screenshots and page content. |
| `DefaultBrowserSettingEnabled` | `false` | The default browser is set by the profile (`/etc/xdg/mimeapps.list`), not by the browser nagging. |
| `BackgroundModeEnabled` | `false` | No browser processes after the last window closes. |
| `DeveloperToolsAvailability` | `0` | DevTools stay available, because web developers and support need them. They are blocked only on extensions force-installed by policy, so users cannot inspect or tamper with managed extensions. We chose `0` over `2` (block all) because blocking DevTools breaks normal support work and is not a real security boundary. |
| `ExtensionInstallBlocklist` | `["*"]` | Default deny for extensions. See *Allowing extensions*. |
| `BuiltInDnsClientEnabled` | `false` | Use the system resolver (systemd-resolved or nsswitch), so corporate DNS, split DNS and DNS filtering apply. |
| `DnsOverHttpsMode` | `"off"` | DoH would bypass corporate DNS and its filtering. |
| `AuthServerAllowlist` | `{{ auth_server_allowlist }}` | Hosts allowed to use Kerberos/SPNEGO integrated auth. Empty means none. |
| `HomepageLocation`, `HomepageIsNewTabPage`, `ShowHomeButton` | `{{ homepage }}`, `false`, `true` | Org homepage. |
| `RestoreOnStartup`, `RestoreOnStartupURLs` | `4`, `["{{ homepage }}"]` | Open the org homepage at startup. |

### `edge/20-edge.json`

| Key | Value | Why |
|---|---|---|
| `BrowserSignin` | `1` | Sign-in is allowed, because Entra ID conditional access and M365 SSO on Linux need the Edge profile signed in with the work account. |
| `RestrictSigninToPattern` | `.*@{{ m365_tenant_domain }}` | Only work accounts can sign in. The key is removed when the tenant is empty (see the rendering rule). |
| `HideFirstRunExperience` | `true` | No first-run wizard. |
| `DiagnosticData` | `0` | Required diagnostic data only. This is Edge's telemetry key; `MetricsReportingEnabled` is legacy in Edge. |
| `PersonalizationReportingEnabled` | `false` | Browsing data is not used for Microsoft personalization or ads. |
| `ShowRecommendationsEnabled` | `false` | No in-browser recommendations or notifications. |
| `EdgeShoppingAssistantEnabled` | `false` | No shopping and coupon features. |
| `EdgeCollectionsEnabled` | `false` | Collections content syncs to the Microsoft cloud. Off until there is a business need. |
| `EdgeFollowEnabled` | `false` | No creator-follow feed. |
| `ShowMicrosoftRewards` | `false` | No consumer rewards. |
| `NewTabPageContentEnabled` | `false` | No MSN news feed on the new tab page. |
| `HubsSidebarEnabled` | `false` | Sidebar (including the Copilot entry point) off. AI use is governed separately. |
| `SmartScreenEnabled`, `SmartScreenPuaEnabled` | `true`, `true` | Edge's equivalent of Safe Browsing, for phishing, malware and potentially unwanted apps. |
| `PreventSmartScreenPromptOverride`, `...ForFiles` | `true`, `true` | Users cannot click through SmartScreen warnings. |
| `AutomaticHttpsDefault` | `2` | Always upgrade navigations to HTTPS. This is Edge's form of `HttpsOnlyMode`. *verify value semantics on the frozen Edge version* |

Not here, on purpose: `WebAppInstallForceList`. The Microsoft 365 bundle owns
the M365 PWAs in its own file.

### `chrome/20-chrome.json`

| Key | Value | Why |
|---|---|---|
| `BrowserSignin` | `0` | No Google account sign-in in the browser. That stops personal accounts and sync. |
| `PromotionalTabsEnabled` | `false` | No promotional tabs. |
| `BrowserLabsEnabled` | `false` | No experimental features from the Labs menu. |
| `ShoppingListEnabled` | `false` | No price tracking. |
| `GenAiDefaultSettings` | `2` | Generative AI features off. Page content would go to Google under consumer terms. Orgs with a Gemini business agreement can lift this. *verify* |
| `PrivacySandboxPromptEnabled`, `...AdTopicsEnabled`, `...SiteEnabledAdsEnabled`, `...AdMeasurementEnabled` | `false` | No ad-interest APIs, and no prompt about them. |

### `chromium/20-chromium.json`

These keys are the same as the Chrome sign-in and Privacy Sandbox keys. A
distro Chromium build ignores any key it does not know.

### `brave/20-brave.json` (optional app)

| Key | Value | Why |
|---|---|---|
| `BrowserSignin` | `0` | Consistent with Chrome and Chromium. |
| `BraveRewardsDisabled` | `true` | No crypto rewards or ads program. |
| `BraveWalletDisabled` | `true` | No crypto wallet on corporate devices. |
| `BraveVPNDisabled` | `true` | No unmanaged consumer VPN. |
| `BraveAIChatEnabled` | `false` | No Leo AI chat. |
| `BraveNewsDisabled` | `true` | No news feed. *verify* |
| `BraveTalkDisabled` | `true` | No unmanaged video calls. *verify* |
| `BraveP3AEnabled`, `BraveStatsPingEnabled`, `BraveWebDiscoveryEnabled` | `false` | Brave telemetry and Web Discovery Project off. *verify* |
| `TorDisabled` | `true` | No Tor windows, which bypass corporate egress controls. |

Brave renames policies more often than other vendors. Re-check this file
against `brave://policy` on every frozen Brave version.

### `firefox/policies.json`

| Key | Why |
|---|---|
| `DisableTelemetry`, `DisableFirefoxStudies` | No telemetry and no Shield studies. |
| `DisablePocket`, `FirefoxHome` (sponsored and Pocket off, locked), `FirefoxSuggest` (sponsored off, locked) | No sponsored content. |
| `DisableFirefoxAccounts` | No Mozilla account or sync. This matches `SyncDisabled` and `BrowserSignin` on Chromium. |
| `DontCheckDefaultBrowser` | The default browser is set by the profile. |
| `DisableAppUpdate` | Updates come from the OS package (mirror), not Firefox's own updater. |
| `OverrideFirstRunPage`, `OverridePostUpdatePage` = `""` | No first-run or what's-new tabs. |
| `PasswordManagerEnabled` `false`, `OfferToSaveLogins` `false` | Same reason as for Chromium: SSO plus a central vault. |
| `AutofillCreditCardEnabled` `false` | Card data stays out of the profile. |
| `PromptForDownloadLocation` | The user chooses where files land. |
| `Homepage` (`{{ homepage }}`, locked, `StartPage: homepage-locked`) | Org homepage at startup. |
| `ExtensionSettings` `"*": blocked` | Default deny for extensions. See below. |
| `DNSOverHTTPS` disabled and locked | Use corporate DNS, like `DnsOverHttpsMode: off`. |
| `HttpsOnlyMode` `"enabled"` | HTTPS-Only on by default. Users can add per-site exceptions for intranet HTTP hosts. `force_enabled` would remove those exceptions. |
| `EnableTrackingProtection` (on, cryptomining and fingerprinting blocked, not locked) | Not locked, so users can turn it off for a site that breaks. |
| `Authentication.SPNEGO` = `[{{ auth_server_allowlist }}]`, `AllowNonFQDN` off, locked | Kerberos SSO only to allowlisted hosts. |
| `Certificates.ImportEnterpriseRoots` `true` | Harmless, but on Linux this key **does nothing**: it only reads the Windows and macOS OS stores. See *Not covered*. |
| `UserMessaging` (all off, `SkipOnboarding`, locked) | No onboarding, feature tours or recommendation popups. |

## Allowing extensions

**Chromium family.** Do not edit `10-baseline.json` for this. Add
`policies/browsers/<browser>/30-org-extensions.json` with a static list and
reference it from the bundle (or an org bundle):

```json
{ "ExtensionInstallAllowlist": ["cjpalhdlnbpafiamejdnhcphjbkeiagm"] }
```

To install an extension by force instead, use `ExtensionInstallForcelist`, or
`ExtensionSettings`. `ExtensionSettings` is a single dictionary, so it must
then live in only one file.

**Firefox.** Add an entry next to `"*"` in `ExtensionSettings`. For example,
for uBlock Origin:

```json
"uBlock0@raymondhill.net": {
  "installation_mode": "allowed"
}
```

Use `"force_installed"` with an `install_url` pointing at the mirrored `.xpi`
to install it by force.

## How to verify on a device

| Browser | Page | What to check |
|---|---|---|
| Chrome | `chrome://policy` | Every key is listed with source *Platform*, status *OK*, and no "unknown policy" errors. |
| Edge | `edge://policy` | Same. `edge://management` shows the browser as managed. |
| Chromium | `chrome://policy` | Same. On Ubuntu snap, check that `/etc/chromium-browser/policies/managed/` exists. |
| Brave | `brave://policy` | Same. Brave-specific keys must show *OK*, not *unknown*. |
| Firefox | `about:policies` | The *Active* tab lists the keys. The *Errors* tab must be empty. |

Also run `scripts/apps/elapps plan --profile <name>` before rendering, and check
that each rendered file still parses (`python3 -m json.tool <file>`).

## Not covered (yet)

- **Flatpak browsers** are installed without managed policy, as explained
  above.
- **Enterprise CA trust in Firefox on Linux.** `ImportEnterpriseRoots` does
  not apply on Linux. Options:
  - Load p11-kit-trust through the `SecurityDevices` policy. Its module path
    differs per family (`/usr/lib64/pkcs11/p11-kit-trust.so` on rpm,
    `/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so` on Debian/Ubuntu).
    That needs per-family rendering of `policies.json`.
  - Use `Certificates.Install` with the CA files.
  - RHEL and Fedora builds already use the system p11-kit store. *verify*
- **Chromium-family CA trust** uses the NSS user DB or the system store,
  depending on the version. It is handled by the PKI work in HARDENING, not
  here.
- **Proxy settings** (`ProxySettings`, Firefox `Proxy`). These are org- and
  network-specific; to be added with a placeholder when needed.
- **Conditional access and device compliance** for Edge on Linux. That needs
  the Microsoft Identity Broker and Intune, which are outside this bundle.
- **Extension allowlists.** None ship by default.
- **Per-user overrides.** These files are mandatory policy. We ship no
  `recommended/` policies.
- **Browser updates** come from the frozen vendor-repo mirror. How fast
  browser security updates reach that mirror is an open question in
  `CURATED-APPS.md`.
