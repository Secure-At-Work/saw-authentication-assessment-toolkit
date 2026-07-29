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
  Connect-SAWGraph.ps1       Module check + Microsoft Graph connection helper
  collector/         One Get-SAW*.ps1 (Graph read) + ConvertTo-SAWNormalized*.ps1 (derive
                      Category/Setting/State facts) pair per assessed category
  rules/             Secure At Work rule definitions (JSON, no logic), the rules engine, and
                      Get-SAWBaselineOverrides.ps1 (customer baseline loader)
  dashboard/          Export-SAWHtmlReport.ps1 (flat table) and Export-SAWDashboard.ps1
                      (Bootstrap/Chart.js dashboard, vendored locally under vendor/)
tests/              Pester tests, mirroring src/ (see tests/README.md - can't run locally
                    on this machine, see docs/powershell-coding-notes.md)
sampledata/raw/     Committed synthetic Graph response fixtures, used by -UseSampleData
                    and by the tests
schemas/            JSON schemas for normalized data and rules (not yet written)
reports/            Generated report output (gitignored)
.github/workflows/  CI: runs Pester + PSScriptAnalyzer on push/PR
```

## Status

All 8 collectors from spec section 6 are implemented (Authentication Methods, Conditional
Access, Authentication Strengths, Registration, Temporary Access Pass, Passkeys, Sign-In
Analysis, Audit Logs), each with a Pester test file. The dashboard (spec section 9) and flat
HTML report both work, and the live-Graph path has been run successfully against a real
tenant. Beyond the base 19 rules, the dashboard also has:

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

Output lands in `reports/assessment-report.html` (flat table) and
`reports/dashboard/index.html` (full dashboard - self-contained with its own `vendor/`
subfolder, so the whole `reports/dashboard/` directory can be zipped up and handed to a
client without needing internet access to render).

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
