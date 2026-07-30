# Secure At Work Authentication Assessment Toolkit

Read-only assessment toolkit for Microsoft Entra ID authentication configuration. Inventories the current (IST) state of a tenant via Microsoft Graph, compares it against the Secure At Work recommended (SOLL) configuration, and produces gap analysis, risk scoring, and remediation guidance.

See [specs/AI_Development_Specification_v1.0.md](specs/AI_Development_Specification_v1.0.md) for the full specification.

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
tenant. Beyond the base 19 rules, the dashboard also has:

- A **passkey dynamic migration opt-out check** (AUTH006) and a **CA lockout check** (CA004) -
  see "Passkey rollout and lockout-risk checks" below

- A full **Conditional Access policy inventory** (every policy's name, state, targets, and
  grant controls in plain language - independent of the pass/fail CA checks)
- A per-user **Security Info Registration triage** (OK / Hunt / Remove, admins prioritized -
  who needs nudging toward a phishing-resistant method, and who has a phone-based fallback
  method that should be removed to close off a downgrade-attack path)
- SSPR registration coverage, the authentication methods registration campaign's state/target,
  and a composite "phishing-resistant registration bootstrap available" check (self-service
  FIDO2 or TAP)
- A composite "privileged access protection in place" check (compliant device OR a
  phishing-resistant auth strength required for admins - not a single hard-coded control)
- A **configurable, auto-detected customer SOLL baseline** (see below - hybrid vs. cloud-native
  is detected from the tenant itself, not just a manual flag) plus explicit **SOLL (Target) /
  IST (Current)** column labeling in both reports, with the active baseline's name shown in each
- A **synced (cloud-backed) passkeys** check (PASS003 - Google Password Manager, iCloud
  Keychain, 1Password, Bitwarden, and similar, detected by AAGUID against the FIDO2 key
  restrictions allow/block-list). Synced passkeys are still phishing-resistant, so the toolkit
  default is permissive (Expected Enabled, Low severity); a customer requiring device-bound-only
  passkeys can flip this in a baseline (`cloud-native-passwordless` does this as an example)
- **Multi-tenant, repeat-run-safe output** - reports and history snapshots are namespaced by
  tenant + run timestamp, so nothing overwrites a previous run - plus a **drift report**
  (`Invoke-SAWDriftReport.ps1`, see below) comparing any two runs of the same tenant to surface
  regressions/improvements and registration roster movement over time
- A **Remediation Roadmap** (see "From IST to SOLL" below) - not just a findings list, but an
  ordered, phased work plan showing what's safe to fix now versus what's blocked on an earlier
  phase still being open

Not yet built: Markdown/Excel/JSON report exports (spec section 14).

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
([Microsoft Learn](https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement)):
starting **2026-09-01**, Microsoft automatically enables passkeys for users currently enabled
for SMS or Voice and moves the registration campaign to "Microsoft managed"; on **2027-02-01**,
Microsoft-provided SMS/Voice delivery retires outright, with **no opt-out at all** for that
date.

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

## Usage

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

Output lands in `reports/<tenant-slug>/<run-timestamp>/assessment-report.html` (flat table)
and `.../dashboard/index.html` (full dashboard - self-contained with its own `vendor/`
subfolder, so the whole `dashboard/` directory can be zipped up and handed to a client
without needing internet access to render). Pass `-ReportPath`/`-DashboardPath` explicitly to
pin a fixed location instead (e.g. for scripting/CI that always wants the latest run at a
known path).

## Multiple tenants and drift over time

Every run is namespaced by tenant and timestamp, so repeated runs - against the same tenant
or different ones - never overwrite each other:

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

## Requirements

- PowerShell 7.4+
- `Microsoft.Graph.Authentication` - the only Graph SDK module this toolkit depends on. Every
  collector calls Graph via generic `Invoke-MgGraphRequest`/`Get-MgContext` rather than the
  typed per-resource cmdlets, so the heavier modules listed in spec section 5 (e.g.
  `Microsoft.Graph.Identity.SignIns`, `Microsoft.Graph.Users`) aren't actually needed.
- Delegated Graph permissions with **read-only** scopes: `Policy.Read.All`,
  `UserAuthenticationMethod.Read.All`, `Reports.Read.All`, `AuditLog.Read.All`,
  `Directory.Read.All` (the default set `Connect-SAWGraph.ps1` requests) — no write scopes
  should ever be requested.
