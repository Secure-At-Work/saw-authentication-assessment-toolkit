# Secure At Work Authentication Assessment Toolkit

Read-only assessment toolkit for Microsoft Entra ID authentication configuration. Inventories the current (IST) state of a tenant via Microsoft Graph, compares it against the Secure At Work recommended (SOLL) configuration, and produces gap analysis, risk scoring, and remediation guidance.

See [specs/AI_Development_Specification_v1.0.md](specs/AI_Development_Specification_v1.0.md) for the full specification, or [docs/reading-the-report.md](docs/reading-the-report.md) for a plain-language walkthrough of what the assessment is and how to read its output (suitable to hand to a customer alongside a report).

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

**Upcoming Microsoft deadlines, with a countdown.** The dashboard's "Upcoming Microsoft
Deadlines" section (right after the SOLL baseline banner, before the Overview) surfaces every
known date above - plus others not tied to a specific rule, like the **2026-09-07** SSPR
enforcement (directory-sourced `mobilePhone`/`businessPhone`/`otherMails` stop working for SSPR
unless explicitly registered - see `SSPR001`'s recommendation text) and the **2026-08-06** SSPR
registration-campaign nudge that precedes it - with a live "N days left" countdown computed
against the current date, color-coded by urgency (red inside 14 days, yellow inside 45,
grey once past). The list itself is [config/timeline-milestones.json](config/timeline-milestones.json),
a small, hand-maintained, sourced JSON file (same "rules are data" philosophy as everything
else here) - update it as Microsoft announces or moves dates; `Get-SAWTimelineMilestones.ps1`
just does the date math. Not every entry is checkable yet: the Message Center item for
"passwordless password change in My Sign-Ins" (~late October 2026) explicitly states its APIs
won't exist until release, so it's tracked here for awareness only, with no corresponding rule.

Where a milestone maps to a real population in this tenant, its card also shows **"N user(s)
impacted"** - e.g. how many users still have a phone-based method registered (relevant to both
the 2026-09-01 automatic passkey enablement and the 2027-02-01 SMS/Voice retirement), or how
many SSPR-enabled users aren't yet SSPR-registered (a proxy for "relying on directory-sourced
contact info," since Graph doesn't expose whether a registered method was explicit or
directory-sourced - the card's own label always states exactly what's being counted). This
reuses data already collected for the registration/roster checks - no extra Graph calls. A
milestone with no matching data source (like the passwordless password change entry above)
simply omits the line rather than showing a fabricated "0 users impacted".

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

The dashboard also embeds [docs/reading-the-report.md](docs/reading-the-report.md) as its own
**"Reading This Report"** tab, right alongside the **"Assessment"** tab - so the explainer of
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
