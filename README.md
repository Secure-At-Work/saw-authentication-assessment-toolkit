# Secure At Work Authentication Assessment Toolkit

Read-only assessment toolkit for Microsoft Entra ID authentication configuration. Inventories the current (IST) state of a tenant via Microsoft Graph, compares it against the Secure At Work recommended (SOLL) configuration, and produces gap analysis, risk scoring, and remediation guidance.

See [specs/AI_Development_Specification_v1.0.md](specs/AI_Development_Specification_v1.0.md) for the full specification, or [docs/reading-the-report.md](docs/reading-the-report.md) for a plain-language walkthrough of what the assessment is and how to read its output (suitable to hand to a customer alongside a report). [docs/passkey-platform-compatibility.md](docs/passkey-platform-compatibility.md) is a standalone reference on which OS/browser/app combinations actually support passkeys, useful when planning a rollout regardless of whether you're using this toolkit. [docs/references.md](docs/references.md) is the source register: every rule and every substantive claim mapped to the Microsoft (or vendor) documentation backing it, with last-verified dates - the thing to reach for when a customer asks "says who?"

## Hard constraint

This toolkit is **read-only**. It must never create, modify, enable/disable, or delete any tenant object, policy, or authentication method registration.

## Repository structure

```
run.cmd             Windows convenience wrapper - menu or direct argument passthrough (see Usage)
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
  dashboard/          Export-SAWDashboard.ps1 (Bootstrap/Chart.js dashboard, vendored
                      locally under vendor/) and
                      Export-SAWDriftReport.ps1 (flat drift comparison report)
tests/              Pester tests, mirroring src/ (see tests/README.md - can't run locally
                    on this machine, see docs/powershell-coding-notes.md)
sampledata/raw/     Committed synthetic Graph response fixtures, used by -UseSampleData
                    and by the tests
schemas/            JSON schemas for normalized data and rules (not yet written)
reports/            Generated report output, namespaced per tenant + run (gitignored)
history/            Per-tenant, per-run JSON result snapshots for drift comparison (gitignored)
```

No CI - this is a toolkit you clone and run yourself. `PSScriptAnalyzerSettings.psd1` at the repo
root documents the lint rules deliberately excluded (and why) if you run PSScriptAnalyzer locally.

## Status

All 8 collectors from spec section 6 are implemented (Authentication Methods, Conditional
Access, Authentication Strengths, Registration, Temporary Access Pass, Passkeys, Sign-In
Analysis, Audit Logs), each with a Pester test file. The dashboard (spec section 9) works, and
the live-Graph path has been run successfully against a real tenant. There are currently
**31 rules** in `src/rules/` (AUDIT, AUTH, BOOT, CA, PASS, RCAMP, REG, SIGNIN, SSPR, STR, TAP
families), every one mapped to the Microsoft Learn article backing it in
[docs/references.md](docs/references.md). Beyond the rules themselves, the dashboard has:

- **Four top-level assessment tabs** (Overview, Findings & Roadmap, User Journeys, Policy
  Inventory) plus a fifth "Reading This Report" tab, and Secure At Work branding (dark mode,
  print styles, WCAG AA-checked status colors)
- A full **Conditional Access** and **Authentication Methods** policy inventory (every policy's
  name, state, targets, and grant controls in plain language)
- A **nudge forecast** - who's about to be interrupted at sign-in by a registration campaign or
  the Microsoft-driven 2026-09-01 passkey rollout, cross-referenced against sign-in logs to
  separate eligible from reachable
- A **FIDO2 key restrictions inventory** resolving AAGUIDs to human-readable key/provider names
- A **Staged Rollout inventory** for tenants migrating from federated to cloud authentication
- A per-user **Security Info Registration triage** (OK / Hunt / Remove, admins prioritized),
  with badges for guest-conversion risk, WHfB-only (non-portable) credentials, policy-disabled
  methods, and methods registered but not recently used
- SSPR registration coverage, admin SSPR exclusion (SSPR002), and legacy MFA/SSPR policy
  migration status (AUTH007)
- A **configurable, auto-detected customer SOLL baseline** (see "Customer baselines" below) and
  a **synced (cloud-backed) passkeys** check (PASS003)
- **Multi-tenant, repeat-run-safe output**, namespaced by tenant + timestamp, plus a **drift
  report** comparing any two runs of the same tenant (see "Multiple tenants and drift" below)
- A **Remediation Roadmap** - an ordered, phased work plan, not just a findings list (see "From
  IST to SOLL" below)
- **"What Users Can Expect (IST vs. SOLL)"** - four real, Microsoft-documented end-to-end
  registration/authentication flows (New User Bootstrap, SSPR Eligibility & Two-Gate, Existing
  User Re-Registration, CA-Gated Registration), each traced step by step against this tenant's
  actual settings
- **Passkey rollout and lockout-risk checks** (AUTH006, CA004-CA006) tracking Microsoft's
  SMS/Voice retirement timeline and two Conditional-Access lockout traps around security info
  registration - see [docs/design-notes.md](docs/design-notes.md#passkey-rollout-and-lockout-risk-checks)

Not yet built: Markdown/Excel/JSON report exports (spec section 14).

**The full reasoning behind each of these** - sourcing, edge cases, deprecation handling
(`passkeyProfiles` vs. the deprecated `isAttestationEnforced`/`keyRestrictions`), and possible
future work - is in [docs/design-notes.md](docs/design-notes.md), kept separate from this README
so the getting-started path here stays short.

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

Tracks Microsoft's SMS/Voice retirement timeline (2026-09-01 automatic passkey rollout,
2027-02-01 hard cutoff) via AUTH006, plus two Conditional Access lockout traps around security
info registration (CA004, CA005) and a downgrade-attack gap (CA006). The dashboard's "Upcoming
Microsoft Deadlines" section surfaces these and other dated milestones
([config/timeline-milestones.json](config/timeline-milestones.json)) with a live countdown and,
where possible, an affected-user count. Full detail, sourcing, and the reasoning behind each
check: [docs/design-notes.md#passkey-rollout-and-lockout-risk-checks](docs/design-notes.md#passkey-rollout-and-lockout-risk-checks).

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

Output lands in `reports/<tenant-slug>/<run-timestamp>/dashboard/index.html`, shipping with its
own `vendor/` subfolder, so the whole `dashboard/` directory can be zipped up and handed to a
client without needing internet access to render. Pass `-DashboardPath` explicitly to pin a
fixed location instead (e.g. for scripting/CI that always wants the latest run at a known path).

A second, flat-table `assessment-report.html` used to be written alongside it and has been
removed. It predated the dashboard, and every section added afterwards (remediation roadmap,
nudge forecast, FIDO2 key inventory, Staged Rollout and its caveats) went into the dashboard
only - so it had stopped being a smaller view of the same answer and started being a different,
staler one. `-ReportPath` is gone with it.

**The report carries an unmistakable "which environment, which point in time" header** - the
tenant's display name as the page headline, plus tenant ID and the run's timestamp
(reformatted from the folder-naming `yyyyMMdd-HHmmss` to `yyyy-MM-dd HH:mm:ss`), and the same
information in the browser tab `<title>`. Useful with more than one report open at once -
different tenants, or repeat runs of the same one after a remediation round - since the tab bar
alone tells them apart without needing to hover or click in. Omitted entirely (no empty banner)
when tenant/timestamp weren't supplied, e.g. calling `Export-SAWDashboard.ps1` directly
outside the orchestrator.

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
  `Directory.Read.All`, `Policy.Read.HybridAuthentication` (the default set
  `Connect-SAWGraph.ps1` requests) — no write scopes should ever be requested.
  `Policy.Read.HybridAuthentication` is the odd one out and worth knowing about: it covers only
  the Staged Rollout inventory, and `Policy.Read.All` does **not** imply it. Microsoft's
  permissions table for `/policies/featureRolloutPolicies` lists it as the least-privileged
  option, with the only alternatives being write scopes this toolkit will never ask for. Adding
  it means one more admin consent the first time you run after upgrading.

  **Confirmed against a real tenant (2026-08-12): Entra can reject this exact scope outright**,
  failing the whole `Connect-MgGraph` call with `AADSTS70011: ... does not exist` — despite the
  scope name matching Microsoft's own documentation character for character (checked twice). That
  contradiction between documentation and the live token endpoint is unresolved. What
  `Connect-SAWGraph.ps1` does about it: catches that specific error and automatically retries once
  without this one scope, so a single tenant/app combination where it's rejected can no longer take
  the entire 30-rule assessment down over one optional inventory row. You'll see a warning when
  this happens; the Staged Rollout section then reports "not read" and everything else runs
  normally. You can also pass a `-Scopes` list without it yourself to skip the retry round-trip.

## License

MIT - see [LICENSE](LICENSE). Bootstrap and Chart.js, vendored locally under
`src/dashboard/vendor/` (see [NOTICE.md](src/dashboard/vendor/NOTICE.md)), are also MIT licensed.
