# Secure At Work Authentication Assessment Toolkit

Read-only assessment toolkit for Microsoft Entra ID authentication configuration. Inventories the current (IST) state of a tenant via Microsoft Graph, compares it against the Secure At Work recommended (SOLL) configuration, and produces gap analysis, risk scoring, and remediation guidance.

See [specs/AI_Development_Specification_v1.0.md](specs/AI_Development_Specification_v1.0.md) for the full specification, or [docs/reading-the-report.md](docs/reading-the-report.md) for a plain-language walkthrough of what the assessment is and how to read its output (suitable to hand to a customer alongside a report). [docs/passkey-platform-compatibility.md](docs/passkey-platform-compatibility.md) is a standalone reference on which OS/browser/app combinations actually support passkeys, useful when planning a rollout regardless of whether you're using this toolkit. [docs/references.md](docs/references.md) is the source register: every rule and every substantive claim mapped to the Microsoft (or vendor) documentation backing it, with last-verified dates - the thing to reach for when a customer asks "says who?"

## Hard constraint

This toolkit is **read-only**. It must never create, modify, enable/disable, or delete any tenant object, policy, or authentication method registration.

## Repository structure

```
docs/               Project documentation (see docs/powershell-coding-notes.md)
specs/              Specifications driving development
config/baselines/   Named customer SOLL baseline presets (see "Customer baselines" below)
src/
  Invoke-SAWAssessment.ps1   Orchestrator: connect -> collect -> normalize -> evaluate -> report
  Invoke-SAWDriftReport.ps1  Compares two history/ snapshots for a tenant, renders a drift report
  Connect-SAWGraph.ps1       Module check + Microsoft Graph connection helper
  collector/         One Get-SAW*.ps1 (Graph read) + ConvertTo-SAWNormalized*.ps1 (derive
                      Category/Setting/State facts) pair per assessed category
  rules/             Secure At Work rule definitions (JSON, no logic), the rules engine,
                      Get-SAWBaselineOverrides.ps1 (customer baseline loader), and
                      Compare-SAWRuleResults.ps1 (drift comparison between two snapshots)
  dashboard/          Export-SAWHtmlReport.ps1 (flat table), Export-SAWDashboard.ps1
                      (Bootstrap/Chart.js dashboard, vendored locally under vendor/), and
                      Export-SAWDriftReport.ps1 (flat drift comparison report)
tests/              Pester tests, mirroring src/ (see tests/README.md - can't run locally
                    on this machine, see docs/powershell-coding-notes.md)
sampledata/raw/     Committed synthetic Graph response fixtures, used by -UseSampleData
                    and by the tests
schemas/            JSON schemas for normalized data and rules (not yet written)
reports/            Generated report output, namespaced per tenant + run (gitignored)
history/            Per-tenant, per-run JSON result snapshots for drift comparison (gitignored)
.github/workflows/  CI: runs Pester + PSScriptAnalyzer on push/PR
```

## Status

All 8 collectors from spec section 6 are implemented (Authentication Methods, Conditional
Access, Authentication Strengths, Registration, Temporary Access Pass, Passkeys, Sign-In
Analysis, Audit Logs), each with a Pester test file. The dashboard (spec section 9) and flat
HTML report both work, and the live-Graph path has been run successfully against a real
tenant. There are currently **30 rules** in `src/rules/` (AUDIT, AUTH, BOOT, CA, PASS, RCAMP, REG,
SIGNIN, SSPR, STR, TAP families) - every one of them mapped to the Microsoft Learn article backing
it in [docs/references.md](docs/references.md). Beyond the rules themselves, the dashboard has:

- **Four top-level assessment tabs**, split out to keep any single page from turning into one
  long scroll of unrelated content (originally all of this sat on a single "Assessment" tab):
  - **Overview** - SOLL baseline banner, upcoming Microsoft deadlines, the four status stat
    cards, the status/category charts, and the trend-over-time chart. Deliberately the
    default-active tab: Chart.js renders a canvas at 0x0 inside a Bootstrap tab pane that isn't
    shown yet, so anything chart-based has to live wherever loads active.
  - **Findings & Roadmap** - the Remediation Roadmap and the full Risk Findings &
    Recommendations list, grouped together since both answer "what's wrong and in what order to
    fix it."
  - **User Journeys** - the flow scenarios (What Users Can Expect: IST vs. SOLL) and the
    Security Info Registration user-triage roster, grouped since both describe what an actual
    person experiences, not tenant-wide configuration.
  - **Policy Inventory** - the Authentication Methods and Conditional Access policy inventories,
    plus the existing per-category "Detail by Category" sub-tabs, as the drill-down/reference
    material.
  - A fifth **"Reading This Report"** tab is added alongside these four whenever a reading guide
    is supplied (see below) - this is the one thing that stayed a separate tab from before.
- **Secure At Work branding**: the navbar, links, active tabs, and card styling use Secure At
  Work's own palette (primary blue `#0064da`, dark variant `#2b57a7`), sourced directly from
  `secureatwork.nl`'s computed CSS custom properties rather than guessed. Applied as CSS variable
  overrides on top of vendored Bootstrap 5.3 in [Export-SAWDashboard.ps1](src/dashboard/Export-SAWDashboard.ps1)
  (search for "Secure At Work brand palette"), not a fork of Bootstrap's CSS itself. Deliberately
  left alone: the green/yellow/red/grey traffic-light status colors (Bootstrap's
  success/warning/danger/secondary) - those are functional semantics the reader relies on to
  scan results quickly, not a place for brand color to compete for attention. No external font
  or asset dependency was added; the site's licensed display font isn't embeddable, so a system
  sans-serif stack (Helvetica Neue/Segoe UI first) approximates its grotesque feel instead.

- A **passkey dynamic migration opt-out check** (AUTH006), two **security info registration
  checks** on Conditional Access (CA004, CA005), and a check for **phishing-resistant strength
  required tenant-wide, not just for admins** (CA006) - see "Passkey rollout and lockout-risk
  checks" below

- A full **Conditional Access policy inventory** (every policy's name, state, targets, and
  grant controls in plain language - independent of the pass/fail CA checks)
- A **nudge forecast** (`ConvertTo-SAWNudgeForecast.ps1`) answering a question that's operational
  rather than technical: *who is about to get interrupted at sign-in, and have we told them?* An
  unannounced registration prompt is a help-desk spike and a trust problem. Forecasts four
  interrupts separately (the Microsoft-driven 2026-09-01 automatic passkey enablement, a passkey
  campaign, an Authenticator campaign, and the SSPR registration interrupt), plus the broken
  admin-SSPR case where a user is prompted and then told they can't register anything. Each count
  expands to the named users behind it, so the list goes straight into a comms tool. Also detects
  the tenant-wide suppressors Microsoft documents (attestation, AAGUID restrictions, self-service
  off, a blocking CA policy) and says so plainly when the campaign is configured but reaching
  nobody. Deliberately an over-estimate: the passkey nudge is evaluated per device-and-browser
  rather than per account, and several suppressors aren't visible through Graph, so the forecast
  reports *eligibility* rather than certainty.
  - It also cross-references the sign-in logs to separate **eligible** from **reachable**. A nudge
    is UI shown during an interactive sign-in, so a user who did no interactive sign-in in the
    collected window cannot be prompted by any campaign, however well configured. That group needs
    direct outreach rather than campaign tuning, and is the one most often misread as "users
    ignoring the prompt". Bounded honestly by Entra's own log retention (seven days on Free, 30 on
    P1/P2), so it always means "not within retention" rather than "never" - and a window longer
    than 30 days is capped, with the report saying so rather than implying coverage it can't have.
- A **FIDO2 key restrictions inventory** (`ConvertTo-SAWFido2KeyInventory.ps1`) answering the
  question PASS002's pass/fail check can't on its own: enforced against *which specific keys*?
  Graph only returns the raw AAGUIDs on the tenant's allow/block-list; this resolves each one to
  a human-readable key or provider name against a hand-maintained reference table, at two tiers
  of confidence:
  - **Vendor-confirmed** (Yubico, Feitian, SoloKeys, Microsoft Authenticator as a passkey
    provider): each checked against that vendor's own published page or repo. Feitian's own
    page actually disagreed with a secondary-source blog post found during research on at least
    two AAGUID/product-name pairings - exactly why it got cross-checked against Feitian's own
    page rather than trusted secondhand. Microsoft Authenticator's two AAGUIDs matter in
    practice since Entra's admin center offers "+ Add AAGUID > Microsoft Authenticator" as a
    one-click shortcut when building an allow-list.
  - **Community-sourced, lower confidence** (one Thales entry, IDPrime FIDO Bio): pulled from
    the passkeydeveloper/passkey-authenticator-aaguids project's `combined_aaguid.json`, not a
    page published by Thales itself - no equivalently clear Thales-direct AAGUID reference was
    found. Flagged as such in the resolved name itself, not just in code comments, so it's
    visible in the dashboard too.
  - **Researched but not found**: Google Titan Security Key. Checked Google's own product pages,
    FIDO Alliance discussion threads, and every AAGUID list that does cover the vendors above -
    no verifiable Google-published Titan AAGUID turned up anywhere. Left out rather than guessed
    at; a Titan AAGUID will show as "Unrecognized" like any other real gap, not silently
    misattributed to something else.

  Same "strong signal, not exhaustive proof" caveat throughout as PASS003's synced-passkey
  detection - an unrecognized AAGUID is reported as such, never silently dropped. Extending
  coverage further (Google Titan if a source ever turns up, other vendors entirely) is just more
  entries in `$knownFido2KeyAaguids`. Omitted from the dashboard entirely when key restrictions
  aren't enforced (nothing to list) or FIDO2 itself is tenant-wide disabled.
- A full **Authentication Methods policy inventory** (`ConvertTo-SAWAuthenticationMethodsInventory.ps1`)
  - every method's enabled/disabled state, who's included/excluded, and key settings in plain
  language - independent of the pass/fail checks. Target scoping is confirmed against Microsoft's
  own Graph API reference rather than guessed: `excludeTargets` is on the base
  `authenticationMethodConfiguration` type (common to all 8 methods), each method has its own
  typed `includeTargets`, and `all_users` is the well-known id for the built-in default target.
  No group/user display-name resolution is done (counts and the all_users/specific distinction
  only), to avoid an extra Graph call this toolkit doesn't otherwise need.
  - The inventory also carries two rows beyond the 8 method types, each genuinely three-state
  (Disabled / Enabled / **Microsoft managed**), not on/off: **Registration Campaign**
  (`registrationEnforcement.authenticationMethodsRegistrationCampaign` - what gets *nudged for
  registration*) and **System-Preferred Authentication** (`systemCredentialPreferences` - what
  gets *presented at sign-in* for a credential the user already has; a distinct setting from the
  campaign, easy to conflate). For both, Graph's `default` state maps to the admin center's
  "Microsoft managed" option - confirmed against
  [the registration campaign how-to](https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign)
  and [the System-Preferred concept article](https://learn.microsoft.com/entra/identity/authentication/concept-system-preferred-authentication).
  **When a row shows "Microsoft managed," it carries a distinct `bg-info` state badge plus a
  separate amber "Rollout timing not confirmed" badge** - the two are deliberately different
  colors/claims: the first says what's *configured*, the second flags that Microsoft's own docs
  describe "Microsoft managed" as an incrementally-rolled-out set of defaults on Microsoft's own
  batch schedule, not the tenant's. Microsoft announcing a start date (e.g. "gradually deployed...
  through August 2026") does not mean every tenant already has the new behavior by that date -
  this toolkit has no way to observe which batch a given tenant is in, so the Settings column's
  description for a Microsoft-managed row is labeled as Microsoft's stated *intent*, not a
  confirmed current fact, with the badge's tooltip spelling that out. Neither row is a rules-engine
  pass/fail finding, for the same reason. The per-user `systemPreferredAuthenticationMethod`
  Graph already returns is also passed through onto each roster entry (`SystemPreferredMethod`)
  as context, and the four **What Users Can Expect (IST vs. SOLL)** flows below fold
  System-Preferred Authentication's influence directly into the Bootstrap, Re-Registration, and
  CA-Gated scenarios - since it changes what a specific user actually sees, not just a setting.
- A per-user **Security Info Registration triage** (OK / Hunt / Remove, admins prioritized -
  who needs nudging toward a phishing-resistant method, and who has a phone-based fallback
  method that should be removed to close off a downgrade-attack path). Grouped into one
  collapsible section per bucket (native `<details>`, no extra JS) so "everyone in Hunt" can be
  worked through as a batch rather than scanning one long mixed table - Remove/Hunt/Guest start
  expanded (actionable), OK starts collapsed (nothing to do). Plus two badges layered on top of
  (not overriding) that bucketing:
  - **"Possible External Member"** for any user whose UPN has the `#EXT#` shape Microsoft
    auto-generates for B2B guest invitations but whose `userType` is Member, not Guest - likely a
    guest that was converted to Member, or provisioned as Member via cross-tenant sync. Still
    externally-sourced either way; flagged rather than silently indistinguishable from a genuine
    internal member. A UPN-shape heuristic, not authoritative - `userRegistrationDetails` has no
    stronger signal to confirm it, and it deliberately doesn't change the user's bucket (whether
    Microsoft's guest FIDO2 restriction still applies after a userType conversion isn't something
    this toolkit can determine from Graph data alone) - worth verifying with the customer.
  - **"WHfB-Only (Not Portable)"** for any user whose only phishing-resistant method is Windows
    Hello for Business, with no FIDO2 key or passkey alongside it. WHfB is bound to the specific
    device it was set up on - unlike FIDO2/passkeys, it can't be carried to a different machine,
    so a WHfB-only user has no working phishing-resistant credential off that one device. A real
    gap for admin accounts especially, since many admins don't do routine interactive sign-in on
    a managed device with their admin account at all.
  - **"Disabled by policy: \<method\>"** - stronger and more deterministic than "not recently
    used" below: `ConvertTo-SAWPolicyDisabledMethodRoster.ps1` cross-references each registered
    method against the tenant's own `authenticationMethodsPolicy` (already collected, no extra
    Graph call) and flags any registered method whose tenant-wide toggle is currently Disabled -
    that credential *cannot* be used to sign in anymore, not just "probably stale," so it's safe
    to clean up. `mobilePhone`/`alternateMobilePhone` map to both SMS and Voice (flagged if
    either is disabled, since registration data doesn't say which channel a user actually
    relies on); `officePhone` maps to Voice only. Windows Hello for Business is never flagged -
    there's no tenant-level toggle for it in `authenticationMethodsPolicy` at all (it's governed
    by device/WHfB policy, a different API), so there's nothing to check it against; passkey
    variants aren't mapped yet either, for the same "don't guess" reason.
  - **"Not recently used: \<method\>"** - registration alone only says a method is *registered*,
    not that it's actually usable. `ConvertTo-SAWMethodUsageRoster.ps1` cross-references
    registered methods against sign-in `authenticationDetails` over a wider window
    (`-MethodUsageDaysBack`, default 90 - independent of, and in addition to, the 7-day window
    the legacy-auth/device-code checks use) and flags any registered method with no successful
    sign-in step using it. Only a well-established subset of method types is evaluated (FIDO2,
    WHfB, TAP, SMS/voice, Authenticator push/OTP, email, certificate) - `methodsRegistered` and
    `authenticationDetails.authenticationMethod` are two different Graph vocabularies with no
    documented crosswalk, so a method type with no confident mapping (passkey variants, for now)
    is left unevaluated rather than risking a false "unused" claim. Pass `-MethodUsageDaysBack 0`
    to skip this check entirely - it's a second, separately-windowed call to `/auditLogs/signIns`,
    real extra Graph load worth being aware of on a very busy tenant.
- SSPR registration coverage, the authentication methods registration campaign's state/target,
  and a composite "phishing-resistant registration bootstrap available" check (self-service
  FIDO2 or TAP)
- **Admin SSPR exclusion check (SSPR002)** - `Get-SAWAuthorizationPolicy.ps1` reads
  `allowedToUseSSPR` on `/policies/authorizationPolicy`, a separate, easy-to-miss control from
  the SSPR settings above: by default, admin accounts get SSPR through their own built-in
  "two-gate" policy (two methods required, no security questions) independent of the tenant's
  general SSPR configuration for end users - so an admin showing `isSsprEnabled: true` while the
  general SSPR toggle looks "off" is expected, not a bug. `allowedToUseSSPR` is the real switch
  that turns admin SSPR off entirely, and Microsoft's own docs warn about a real trap: disabling
  it *without* also excluding admins from the user-facing SSPR policy leaves those admins stuck
  - still prompted to register, but shown a message that they can't register any methods.
  SSPR002 only fires (Red) when `allowedToUseSSPR` is explicitly `false` **and** at least one
  admin still shows `isSsprEnabled: true`; it's Grey (not applicable) whenever admin SSPR is
  enabled, the default. See
  [concept-sspr-policy#administrator-reset-policy-differences](https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy#administrator-reset-policy-differences).
- **Legacy MFA/SSPR policy migration check (AUTH007)** - reads `policyMigrationState` on the
  Authentication Methods Policy (already collected, no extra call). Microsoft announced
  deprecating the legacy per-user MFA policy and legacy SSPR policy back in March 2023, and
  since 2025-09-30 they can no longer be *edited* - but per Microsoft's own migration-states
  table, being unmanageable isn't the same as being *ignored*: both `premigration` and
  `migrationInProgress` mean those now-frozen legacy settings are still actively respected for
  who can register/use which method, only `migrationComplete` makes Entra ignore them entirely.
  A real blind spot for this toolkit specifically - a method shown Disabled in the Authentication
  Methods Policy Inventory can still be usable via the legacy policy, which lives on a different,
  older API this toolkit doesn't collect, so nothing here can see into it. High severity, Phase 1
  (fully reversible per Microsoft's own docs, so no rollout-risk reason to delay). See
  [concept-authentication-methods-manage#migration-between-policies](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods-manage#migration-between-policies).
- A composite "privileged access protection in place" check (compliant device OR a
  phishing-resistant auth strength required for admins - not a single hard-coded control)
- A **configurable, auto-detected customer SOLL baseline** (see below - hybrid vs. cloud-native
  is detected from the tenant itself, not just a manual flag) plus explicit **SOLL (Target) /
  IST (Current)** column labeling in both reports, with the active baseline's name shown in each
- A **synced (cloud-backed) passkeys** check (PASS003), detected by AAGUID against the FIDO2 key
  restrictions allow/block-list. Covers the full current contents of the community
  [passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids)
  list: dedicated password manager apps (Google Password Manager, iCloud Keychain / Apple
  Passwords, 1Password, Bitwarden, Dashlane, NordPass, Keeper, Sesame, Enpass, Samsung Pass,
  AliasVault, IDmelon) **and** browser-level platform credential stores (Chrome on Mac, Chromium
  Browser, Edge on Mac) - the latter aren't password manager apps, but the same custody concern
  applies, since a passkey saved there syncs via the user's Google/Microsoft account rather than
  staying device-bound. Windows Hello's AAGUIDs are the one deliberate exclusion from that source
  list: whether a given Windows Hello AAGUID is a per-device TPM-bound credential or a newer
  cloud-synced Windows passkey varies, and treating it as "synced" would false-flag legitimately
  device-bound credentials. Synced passkeys are still phishing-resistant, so the toolkit
  default is permissive (Expected Enabled, Low severity); a customer requiring device-bound-only
  passkeys can flip this in a baseline (`cloud-native-passwordless` does this as an example)
- **Multi-tenant, repeat-run-safe output** - reports and history snapshots are namespaced by
  tenant + run timestamp, so nothing overwrites a previous run - plus a **drift report**
  (`Invoke-SAWDriftReport.ps1`, see below) comparing any two runs of the same tenant to surface
  regressions/improvements and registration roster movement over time
- A **Remediation Roadmap** (see "From IST to SOLL" below) - not just a findings list, but an
  ordered, phased work plan showing what's safe to fix now versus what's blocked on an earlier
  phase still being open
- **"What Users Can Expect (IST vs. SOLL)"** (`ConvertTo-SAWRegistrationFlowScenarios.ps1`) -
  four real, Microsoft-documented end-to-end registration/authentication flows, each traced step
  by step and marked applicable/not-applicable against this tenant's actual collected settings.
  A single rule tells you whether one setting matches SOLL; this answers what an end user
  actually experiences when several settings interact. The four flows, each grounded in a cited
  Microsoft Learn article:
  - **New User Bootstrap** - first sign-in with a Temporary Access Pass through to a later
    registration-campaign nudge. Includes a documented limitation worth knowing: the forced
    Interrupt-mode redirect a TAP user can be routed into (when in scope for SSPR/MFA
    registration policy) doesn't currently support FIDO2 or phone sign-in registration - only
    outside that redirect can those be registered directly. Also traces a real cross-device
    bootstrap gap, confirmed against
    [how-to-register-passkey-authenticator](https://learn.microsoft.com/entra/identity/authentication/how-to-register-passkey-authenticator):
    if a user enters the TAP on a different device than the phone the passkey will live on
    (e.g. a laptop), registering "Passkey in Microsoft Authenticator" is genuinely supported
    cross-device - Microsoft's flow hands off to the phone via a QR code / app-open prompt -
    but the phone must independently complete its own sign-in and MFA inside the Authenticator
    app; it does not inherit the laptop's TAP session. Whether a brand-new user can actually
    complete that phone-side step is derived from two settings already collected: if TAP is
    enforced one-time-use (TAP001), the laptop-side TAP is consumed and there's nothing left
    for the phone - the only remaining path is Microsoft's Bluetooth-based "WebAuthn flow"
    fallback, which is explicitly documented as unavailable whenever FIDO2 attestation is
    enforced (PASS001). A tenant with both settings at their SOLL-recommended values
    simultaneously can leave a brand-new user with no way to complete this specific bootstrap
    path at all - WHfB (device-bound, no cross-device handoff needed) or a short-lived
    multi-use TAP scoped to onboarding are the practical alternatives, called out directly in
    TAP001's and PASS001's recommendation text.
  - **SSPR Eligibility & Two-Gate** - whether/how a standard user, and separately an admin
    (governed by its own built-in two-gate policy, independent of the general SSPR setting -
    see SSPR002), can register for and use self-service password reset.
  - **Existing User Re-Registration** - managing/refreshing security info after initial setup:
    manage-mode changes, the 5-minute MFA-freshness requirement for passkey changes, snooze
    mechanics, and optional periodic reconfirmation (`reconfirmationInDays`).
  - **CA-Gated Registration** - how an enabled Conditional Access policy scoped to "Register
    security information" changes all three flows above: registration campaign nudges are
    suppressed entirely for blocked users, and a TAP-only user can be fully locked out if the
    policy's authentication strength doesn't accept a TAP (cross-references CA004).
  Sourced from `how-to-mfa-registration-campaign`, `concept-registration-mfa-sspr-combined`,
  `howto-authentication-temporary-access-pass`, `concept-sspr-policy`, and
  `policy-all-users-security-info-registration` on Microsoft Learn.

Not yet built: Markdown/Excel/JSON report exports (spec section 14).

**Possible future work:**
- **Per-user legacy MFA state** (`perUserMfaState` - Disabled/Enabled/Enforced, via
  `GET /beta/users/{id}/authentication/requirements`). Not currently collected - unlike
  everything else in this toolkit, there's no bulk/report endpoint for it, only one Graph call
  per user, so it's a meaningfully more expensive collector than anything else here. Two possible
  angles if built: for a Conditional-Access-based tenant (this toolkit's assumed default), stray
  `Enabled`/`Enforced` users left over from before CA adoption are mostly a cleanup item (they
  force app-passwords for legacy protocols); for a tenant with no Conditional Access at all (Entra
  ID Free, no P1/P2), this is the *only* MFA enforcement mechanism that exists, and a gap here
  means no MFA requirement at all - something REG001/REG002 (registration, not enforcement)
  wouldn't catch. If built, scope to admins first (matching the "admins first" pattern used
  throughout the roster) rather than calling it for every user, to keep the added Graph cost down.
- **Device compatibility for passkeys** (OS version, browser, managed-vs-unmanaged, whether
  authentication happens directly on the device or cross-device). A real pre-enforcement gap:
  Passkey in Microsoft Authenticator requires Android 14+, while a syncable passkey via Google
  Password Manager reaches back to Android 9 - a tenant that only tests Authenticator can end up
  telling users to buy new phones unnecessarily. This data mostly lives in Intune/device
  compliance, not the Entra authentication surface this toolkit otherwise stays inside, so it's
  a bigger scope change than the other rules here, not just an extra Graph call. If ever built,
  it'd need its own collector pulling from `deviceManagement/managedDevices` (or Intune) rather
  than reusing any existing one, and should report inventory (what's actually out there) rather
  than a single pass/fail, since the "right" minimum OS version is a customer policy decision,
  not a fixed Microsoft baseline. The static half of this question - which OS/browser/app
  combinations support passkeys *at all*, regardless of any specific tenant's device fleet - is
  already written up in [docs/passkey-platform-compatibility.md](docs/passkey-platform-compatibility.md),
  since that part is the same for every tenant and doesn't need a collector to answer.
- **Staged Rollout state for federated tenants** (`GET /beta/policies/featureRolloutPolicies`).
  Not currently collected. Staged Rollout is the mechanism that moves a pilot group from federated
  to managed cloud authentication, and a tenant sitting in it has three constraints that change
  advice this toolkit already gives: SSPR with on-premises writeback isn't supported while it's
  enabled for a security group, Windows Hello for Business hybrid *certificate* trust (federation
  server as registration authority) and smartcard users aren't supported at all, and a user newly
  added to the rollout needs one more interactive sign-in through the old identity provider unless
  a TAP is issued, because Entra evaluates a TAP before it redirects to the federated IdP. That
  last point is a genuinely useful extension of the existing TAP bootstrap story (AUTH005, TAP001,
  TAP002, BOOT001) rather than a new one. Arguments against building it: this is Entra Connect
  territory rather than the authentication-methods surface the toolkit otherwise stays inside, it
  needs an additional Graph scope, and it's a deliberately temporary state that Microsoft says is
  "not designed to be a permanent configuration." A cheaper middle option is to surface it as an
  inventory row plus caveats on the SSPR rules when the tenant profile is Hybrid, rather than as a
  pass/fail rule. The documentation half is already written up in the blog and in
  [docs/references.md](docs/references.md).

## Customer baselines (SOLL)

SOLL (target state) is customer-specific: a hybrid tenant still tied to on-prem AD may
legitimately need passwords/SSPR for longer than a cloud-native, passwordless-only tenant, and
a severity that's right for one isn't necessarily right for the other. Rather than one
hard-coded "correct" Expected/Severity per rule, a baseline file overrides specific rules for
one customer profile without touching the rule JSON files themselves - see
[config/baselines/](config/baselines/) for the two starter presets
(`cloud-native-passwordless`, `hybrid-ad-passwords-required`) and their shape.

**Which one applies isn't just a manual choice** - `Get-SAWTenantProfile.ps1` reads
`organization.onPremisesSyncEnabled` via Graph (no extra permission needed, `Directory.Read.All`
already covers it) and auto-selects the matching preset whenever `-Baseline` is omitted:
`onPremisesSyncEnabled = true` (or `false`, meaning it *was* synced and may still have AD-era
artifacts) -> `hybrid-ad-passwords-required`; `null` (never synced) ->
`cloud-native-passwordless`. The detected profile is always shown
(`Detected tenant profile: ...`), and if you pass an explicit `-Baseline` that disagrees with
what was detected, you get a warning but your explicit choice still wins. Pass
`-SkipBaselineAutoDetection` to go back to "no baseline unless I say so."

```powershell
pwsh -File src/Invoke-SAWAssessment.ps1 -UseSampleData -Verbose
# auto-detects and picks a baseline; add -Baseline <name> to override, or
# -SkipBaselineAutoDetection for the old "no baseline by default" behavior
```

`-BaselineOverridePath <file>` layers a one-off, per-engagement override file (same shape) on
top of `-Baseline` for tweaks specific to a single customer, without needing a whole new named
preset.

**Entra Domain Services (proxy signal, not a rule):** the same collector also checks for a
group named `AAD DC Administrators`, which Microsoft's setup wizard automatically creates when
[Microsoft Entra Domain Services](https://learn.microsoft.com/entra/identity/domain-services/)
is enabled. Domain Services itself lives in Azure Resource Manager
(`Microsoft.AAD/domainServices`) - a different API, token audience, and permission model than
everything else this toolkit does - so this is the closest signal reachable through ordinary
Graph data, not a direct check. It means Domain Services was provisioned at some point, not
that it's still active today. When found, a caveated note appears in the console output and in
both reports' header - never as a rules-engine finding, since it's a hint to follow up on with
the customer, not a pass/fail.

## From IST to SOLL: the Remediation Roadmap

A findings list tells you *what's* wrong; it doesn't tell you *what order* to fix it in - and
order matters here. Enforcing "MFA for all users" via Conditional Access before registration
coverage is high enough risks locking out unregistered users. Chasing passkey registration
before a bootstrap method (self-service FIDO2 or TAP) exists gives users no way to act on the
ask. Removing a phone-based fallback before a stronger method is registered removes the only
factor a user has.

Every rule carries a `Phase` (1-5) and, where sequencing is a real rollout-safety concern
rather than just severity, a `DependsOn` list of RuleIDs that should be resolved first:

1. **Foundation & Visibility** - safe immediately, no dependencies (block legacy auth, enable
   Authenticator/FIDO2/TAP, audit log hygiene, TAP hardening)
2. **Enable Phishing-Resistant Capability** - needs FIDO2 enabled first (attestation, key
   restrictions, synced-passkey policy, phishing-resistant auth strength)
3. **Drive Registration Coverage** - needs a bootstrap path first (registration campaign,
   admin/overall MFA coverage, SSPR coverage)
4. **Retire Weak Fallback Methods** - don't remove SMS/Voice until coverage is high enough
5. **Enforce via Conditional Access** - enforcing MFA-for-all or privileged access protection
   before coverage is up risks lockouts

`ConvertTo-SAWRemediationRoadmap.ps1` groups the rules-engine results by phase and flags each
outstanding rule `Blocked = true` when one of its `DependsOn` rules is itself still Red/Yellow
(a Grey/not-applicable or already-Green dependency never blocks). The dashboard's
**Remediation Roadmap** section (right after the Overview, ahead of the flat findings list)
shows this directly: one card per phase with a completion count, and each still-open rule
tagged either safe to work on now or `Blocked - waiting on <RuleID>`.

## Passkey rollout and lockout-risk checks

Microsoft is retiring its own SMS/Voice authentication delivery on a fixed timeline
([Microsoft Learn](https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement)),
and the two dates use **different eligibility criteria** worth not conflating:

- **2026-09-01** - Microsoft auto-enables passkeys and flips the registration campaign to
  "Microsoft managed" (targeting passkeys) for every user currently *enabled for SMS or Voice in
  the authentication methods policy* - policy scope, not registration state. A user who already
  has a passkey/WHfB/other phishing-resistant method registered is not automatically exempt:
  Microsoft's own docs note such users "may still receive prompts to register passkeys on
  eligible devices" (the nudge is only suppressed per-device/browser where a qualifying local
  passkey is already present, not tenant-wide). Not blocking; AUTH006's opt-out defers it.
- **2027-02-01** - Microsoft-provided SMS/Voice delivery retires outright, with **no opt-out at
  all**. This date's population is narrower and different: only users whose **only** available
  MFA method is SMS/Voice (nothing else registered at all) get a mandatory, blocking passkey
  registration prompt. A user with SMS *and* Authenticator registered is unaffected by this
  specific date, even though they're still in scope for the broader 2026-09-01 rollout above.

- **AUTH006 - Passkey Dynamic Migration Not Opted Out.** The only tenant-level control over
  the *timing* of the first date is `authenticationMethodsPolicy.optOutSettings.
  passkeyDynamicMigration` - a field that only exists on the **beta** Graph endpoint (the one
  deliberate exception to this toolkit calling `v1.0` everywhere else). The collector fetches
  the whole beta object rather than `$select`ing just this field - confirmed against a real
  tenant that this endpoint rejects `$select` outright ("Query option 'Select' is not
  allowed"), unlike most Graph resources. Its semantics are easy to get backwards: setting it
  to `true` **opts the tenant OUT of - i.e. excludes it from** - the automatic 2026-09-01
  rollout while it prepares; left absent/`false` (the default), the rollout applies. Opting out
  never affects the 2027-02-01 date. Severity is Low because opting out is a legitimate,
  time-boxed choice - the recommendation is to verify
  there's an active plan behind it, not to treat opting out itself as a finding.
- **CA004 - Security Info Registration Reachable With Only A Temporary Access Pass.** A real
  lockout trap: once a user with no phishing-resistant method is nudged to register one
  (including via the automatic rollout above), a Temporary Access Pass is often their only way
  to bootstrap into the registration flow (see `BOOT001`). If an *enabled* Conditional Access
  policy gates `urn:user:registersecurityinfo` with a custom authentication strength whose
  `allowedCombinations` doesn't include `temporaryAccessPassOneTime`/
  `temporaryAccessPassMultiUse`, that user can never reach the page that would let them
  register a stronger method - they're locked out of self-service recovery entirely. A plain
  `mfa` builtin control doesn't trigger this (TAP generically satisfies it); only a custom
  strength without a TAP escape does.
- **CA005 - Security Info Registration Requires Strong Authentication.** The opposite gap from
  CA004: whether *any* enabled policy targets `urn:user:registersecurityinfo` at all, with at
  least a plain `mfa` control or an authentication strength. Conditional Access targeting is
  mutually exclusive between resources and user actions, confirmed against Microsoft's own
  [Target resources](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps)
  doc: a policy scoped to "All resources" never extends to this user action, it has to be
  targeted by its own explicit policy. Miss that, and a tenant whose baseline looks complete
  (legacy auth blocked, MFA for all users, admin protection) can still have zero Conditional
  Access control over the page where users register new authentication methods - reachable by
  anyone who's completed first-factor sign-in, MFA or not.
- **CA006 - Phishing-Resistant Authentication Strength Required For All Users.** A plain `mfa`
  builtin control (CA002) accepts whichever registered method the user has, which leaves an MFA
  downgrade attack open: an adversary-in-the-middle proxy can tell Entra the current browser
  doesn't support a passkey and fall back to a weaker method, and a plain `mfa` requirement has
  no way to object. Requiring a specific authentication strength for all users (not just admins,
  where CA003 already checks this) closes that fallback. Deliberately a separate, later-phase
  check from CA002: plain MFA for all users is a legitimate interim state while a tenant ramps
  up passkey adoption, not a failure in its own right.

**Upcoming Microsoft deadlines, with a countdown.** The dashboard's "Upcoming Microsoft
Deadlines" section (right after the SOLL baseline banner, before the Overview) surfaces every
known date above - plus others not tied to a specific rule, like the **2026-10-05** SSPR
enforcement (directory-sourced `mobilePhone`/`businessPhone`/`otherMails` stop working for SSPR
unless explicitly registered - see `SSPR001`'s recommendation text) and the **2026-11-09** SSPR
registration-campaign nudge (both dates re-verified 2026-08-06 against Microsoft's own doc,
updated 2026-08-04 - each moved once already from earlier recorded values of 2026-09-07 and
2026-08-06 respectively; Microsoft's wording no longer frames the nudge as strictly "ahead of"
the enforcement date now that the two have swapped relative order, so don't restate that
relationship without re-checking) - with a live "N days left" countdown computed
against the current date, color-coded by urgency (red inside 14 days, yellow inside 45,
grey once past). The list itself is [config/timeline-milestones.json](config/timeline-milestones.json),
a small, hand-maintained, sourced JSON file (same "rules are data" philosophy as everything
else here) - update it as Microsoft announces or moves dates; `Get-SAWTimelineMilestones.ps1`
just does the date math. Not every entry is checkable yet: the Message Center item for
"passwordless password change in My Sign-Ins" (~late October 2026) explicitly states its APIs
won't exist until release, so it's tracked here for awareness only, with no corresponding rule.

Where a milestone maps to a real population in this tenant, its card also shows **"N user(s)
impacted"**, and the two SMS/Voice dates deliberately use two different, separately-computed
metrics matching their different eligibility criteria above: `PhoneBasedMethodUsers` for
2026-09-01 (`HasDowngradeRiskMethod` in the roster - anyone with a phone-based method registered
at all, an upper-bound proxy for policy scope), and the narrower `SmsVoiceOnlyMfaUsers` for
2027-02-01 (`IsSmsVoiceOnlyMfa` in the roster - only users with *no other* method registered).
These two numbers are expected to differ, and usually will (the first is always >= the second) -
seeing them the same is a red flag that either everyone truly is SMS/Voice-only, or something's
off with registration data. Affected users also get a dedicated **"SMS/Voice-Only MFA"** badge
in the Security Info Registration Triage table below, distinct from the general phone-fallback
case already covered by the Remove bucket. The same "N user(s) impacted" treatment applies to
the SSPR deadlines too, showing how many SSPR-enabled users aren't yet SSPR-registered (a proxy
for "relying on directory-sourced contact info," since Graph doesn't expose whether a registered
method was explicit or directory-sourced) - the card's own label always states exactly what's
being counted. This
reuses data already collected for the registration/roster checks - no extra Graph calls. A
milestone with no matching data source (like the passwordless password change entry above)
simply omits the line rather than showing a fabricated "0 users impacted".

The SSPR-related milestones specifically go one step further: **"0 users impacted" and "not
applicable" are deliberately shown differently.** SSPR-enabled status is checked per user
(`isSsprEnabled` from `userRegistrationDetails` - there's no tenant-wide SSPR policy endpoint,
only this per-user effective state), so a user who doesn't have SSPR enabled is never counted as
impacted by the SSPR nudge/enforcement deadlines. But if literally no user in the tenant has SSPR
enabled at all, the card shows **"Not applicable - SSPR isn't enabled for any user in this
tenant"** instead of "0 users impacted" - the same zero would otherwise look identical whether it
means "fully compliant" or "doesn't apply here," which is a real difference worth keeping
visible. `Get-SAWTimelineMilestones.ps1`'s `-NotApplicableReasons` param (keyed the same way as
`-ImpactMetrics`) carries this distinction through and takes priority over any numeric count for
the same key.

## Usage

**Windows convenience wrapper:** double-click [run.cmd](run.cmd) (or run it from a terminal) for
a menu covering the common cases below - sample data, live tenant (default/specific tenant/install
modules/force reauth/device code), a drift report, or a custom argument passthrough. Requires
`pwsh` on PATH; it'll tell you if it isn't. Skip the menu entirely by passing arguments straight
through, e.g. `run.cmd -UseSampleData -Verbose` - anything after `run.cmd` goes directly to
`Invoke-SAWAssessment.ps1`, same as calling `pwsh -File src/Invoke-SAWAssessment.ps1` yourself.

Offline, against the bundled sample tenant fixtures (no Graph connection needed):

```powershell
pwsh -File src/Invoke-SAWAssessment.ps1 -UseSampleData -Verbose
```

Against a real tenant - `Invoke-SAWAssessment.ps1` connects for you (see
[Connect-SAWGraph.ps1](src/Connect-SAWGraph.ps1)): it checks that
`Microsoft.Graph.Authentication` is installed, imports it, and calls `Connect-MgGraph` with
the read-only scopes every collector needs, if there's no active connection with those scopes
already:

```powershell
pwsh -File src/Invoke-SAWAssessment.ps1 -Verbose
# or, to have it install the one required module for you if missing:
pwsh -File src/Invoke-SAWAssessment.ps1 -InstallMissingModules -Verbose
```

`Connect-MgGraph` opens its normal interactive/device-code sign-in - that part is yours to
complete, the script doesn't handle credentials itself. If you haven't run it against this
tenant before, consider trying a [Microsoft 365 Developer
Program](https://developer.microsoft.com/microsoft-365/dev-program) sandbox tenant first;
`Get-SAWSignInLogs`/`Get-SAWAuditLogs` scope their queries to the last 7 days by default
(`-DaysBack`) after an earlier real-tenant run hit Graph's request timeout querying those
endpoints unfiltered.

**A 401/403 from Graph almost always means a permissions problem, not a toolkit bug** -
`Invoke-SAWGraphRequest.ps1` (every collector routes through it) catches this and rethrows with
guidance instead of a raw HTTP error dump: either the signed-in account doesn't hold a role
Graph requires for that specific endpoint (having the delegated scope consented isn't always
enough by itself - Graph's own error names which roles would work; Global Reader or Security
Reader typically cover everything this toolkit reads), or - if that role is managed through
Privileged Identity Management (PIM) - it's *eligible* but wasn't *activated* before
`Connect-MgGraph` ran, so the issued token doesn't carry it. Activating the role fixes it, but
only after a fresh connection: run `Disconnect-MgGraph` and re-run the script, since an
already-issued token won't pick up a role activated after the fact.

Output lands in `reports/<tenant-slug>/<run-timestamp>/assessment-report.html` (flat table)
and `.../dashboard/index.html` (full dashboard - self-contained with its own `vendor/`
subfolder, so the whole `dashboard/` directory can be zipped up and handed to a client
without needing internet access to render). Pass `-ReportPath`/`-DashboardPath` explicitly to
pin a fixed location instead (e.g. for scripting/CI that always wants the latest run at a
known path).

**Both files carry an unmistakable "which environment, which point in time" banner** - a dark
bar right at the top with the tenant's display name, tenant ID, and the run's timestamp
(reformatted from the folder-naming `yyyyMMdd-HHmmss` to `yyyy-MM-dd HH:mm:ss`), and the same
information in the browser tab `<title>`. Useful with more than one report open at once -
different tenants, or repeat runs of the same one after a remediation round - since the tab bar
alone tells them apart without needing to hover or click in. Omitted entirely (no empty banner)
when tenant/timestamp weren't supplied, e.g. calling `Export-SAWDashboard.ps1`/
`Export-SAWHtmlReport.ps1` directly outside the orchestrator.

The dashboard also embeds [docs/reading-the-report.md](docs/reading-the-report.md) as its own
**"Reading This Report"** tab, alongside the four assessment tabs described above - so the explainer of
what IST/SOLL means and how to use the Remediation Roadmap travels with the dashboard file
itself, not as a separate doc someone has to remember to include. `ConvertTo-SAWMarkdownHtml.ps1`
does a small, deliberately scoped Markdown-to-HTML conversion (just what that one doc actually
uses - headers, lists, tables, bold/italic/code/links) rather than pulling in an external
Markdown library. If `docs/reading-the-report.md` is missing (e.g. a packaged distribution that
dropped `docs/`), the dashboard just renders without that tab - not a failed run.

## Multiple tenants and drift over time

Every run is namespaced by tenant and timestamp, so repeated runs - against the same tenant
or different ones - never overwrite each other. **Switching tenants in the same PowerShell
session:** pass `-TenantId <guid-or-domain>` on every run. Without it, an existing Graph
connection from an earlier run this session gets reused as-is - which is efficient when you
genuinely mean the same tenant, but silently wrong if you meant a different one (confirmed with
a real case: same account, PIM-active in both tenants, worked against tenant A, then quietly
kept using tenant A's connection - not tenant B's - on the very next run). `-TenantId` makes
`Connect-SAWGraph.ps1` detect that mismatch and reconnect to the tenant you actually asked for
instead.

**Just activated a role via PIM and still getting a 403?** Pass `-ForceReauth`. Even a correctly
tenant-matched connection can be a still-valid *cached* token that predates a role you activated
moments ago via PIM (including PIM for Groups) - `Connect-MgGraph` will happily reuse it rather
than authenticate fresh, so the activated role's claims never make it into the token the script
is using. `-ForceReauth` disconnects and reconnects unconditionally, scoped to this process only
(`-ContextScope Process`) so it can't pick up the shared, disk-persisted context another terminal
window populated earlier.

**`-ForceReauth` alone didn't fix it?** Also pass `-UseDeviceCode`. Confirmed against a real case:
a role was verifiably active - checked via a live `GET /me/transitiveMemberOf`, not just the PIM
UI - and a role-gated endpoint still 403'd even with `-ForceReauth`, but the identical call
succeeded immediately once signed in via OAuth device code flow instead of Windows' default Web
Account Manager (WAM) broker. WAM brokers tokens through its own OS-level cache (the Primary
Refresh Token), which lives outside both `Microsoft.Graph.Authentication`'s token cache and
`-ContextScope Process` - so `-ForceReauth` doesn't necessarily force a truly from-scratch token
on Windows. `-UseDeviceCode` prints a URL and one-time code; complete the sign-in in any browser.

- **Tenant identity** comes from `organization.id` via Graph (`Get-SAWTenantProfile.ps1`,
  already collected for baseline auto-detection - no extra permission needed).
  `ConvertTo-SAWTenantProfile.ps1` derives a filesystem-safe `Slug` from it (falling back to a
  sanitized `DisplayName` if `TenantId` is ever missing), used to namespace both
  `reports/<tenant-slug>/...` and `history/<tenant-slug>/...`.
- **Every run writes a JSON snapshot** to `history/<tenant-slug>/<run-timestamp>.json` (rule
  results, roster bucket counts, baseline name, tenant metadata) - opt out with
  `-SkipHistorySnapshot` for one-off runs you don't want counted in a tenant's drift history.

To see what changed between two runs of the same tenant, run `Invoke-SAWDriftReport.ps1`. By
default it picks the two most recent snapshots for a tenant slug:

```powershell
pwsh -File src/Invoke-SAWAssessment.ps1 -UseSampleData -Verbose   # run #1, writes a snapshot
# ... time passes, or the tenant configuration changes ...
pwsh -File src/Invoke-SAWAssessment.ps1 -UseSampleData -Verbose   # run #2, writes another snapshot

pwsh -File src/Invoke-SAWDriftReport.ps1 -TenantSlug <tenant-guid-or-slug> -Verbose
# or compare two specific snapshots directly:
pwsh -File src/Invoke-SAWDriftReport.ps1 -OldSnapshotPath history/<slug>/<older>.json -NewSnapshotPath history/<slug>/<newer>.json
```

The drift report (`reports/<tenant-slug>/drift/<old>-vs-<new>.html`) leads with **Regressions**
(status got worse - review first), then **Improvements**, then rules that became applicable or
not applicable (typically because a related feature was toggled), then any rule set changes
between the two toolkit versions used, then the Security Info Registration roster's bucket
deltas (e.g. how many users moved from Hunt into OK). Unchanged rules are summarized as a
count only, to keep the signal-to-noise ratio high on repeated runs.

**The dashboard itself also shows a lighter, at-a-glance trend** - no extra command needed.
Every dashboard has a "Trend Over Time" section (right after the Overview) plotting Green/
Yellow/Red/Grey counts across every run recorded for that tenant, built from the same
`history/<tenant-slug>/*.json` snapshots by `Get-SAWHistoryTrend.ps1`. With fewer than 2 runs
it shows a "not enough history yet" note instead of a chart. Use this for a quick read on
overall direction across many runs; use `Invoke-SAWDriftReport.ps1` when you need the detailed
rule-by-rule diff between two specific runs.

## Requirements

- PowerShell 7.4+ (`pwsh`, not Windows PowerShell / `powershell.exe`). If you run either
  entry-point script (`Invoke-SAWAssessment.ps1`, `Invoke-SAWDriftReport.ps1`) under the wrong
  host or an outdated `pwsh`, `Test-SAWPowerShellVersion.ps1` catches it before anything else
  runs and prints exactly what to do next - relaunch with `pwsh -File ...` if PowerShell 7 is
  already installed, or an install link/command if it isn't - rather than PowerShell's own
  generic `#Requires` error.
- `Microsoft.Graph.Authentication` - the only Graph SDK module this toolkit depends on. Every
  collector calls Graph via generic `Invoke-MgGraphRequest`/`Get-MgContext` rather than the
  typed per-resource cmdlets, so the heavier modules listed in spec section 5 (e.g.
  `Microsoft.Graph.Identity.SignIns`, `Microsoft.Graph.Users`) aren't actually needed.
- Delegated Graph permissions with **read-only** scopes: `Policy.Read.All`,
  `UserAuthenticationMethod.Read.All`, `Reports.Read.All`, `AuditLog.Read.All`,
  `Directory.Read.All` (the default set `Connect-SAWGraph.ps1` requests) — no write scopes
  should ever be requested.
