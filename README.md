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
Analysis, Audit Logs), each with a Pester test file, plus a per-user registration triage view
and a configurable customer SOLL baseline (see below). The dashboard (spec section 9) and flat
HTML report both work, and the live-Graph path has been run successfully against a real
tenant. Not yet built: Markdown/Excel/JSON report exports (spec section 14), and a full raw
Conditional Access policy inventory report (today's CA checks are derived pass/fail facts,
not a full policy listing).

## Customer baselines (SOLL)

SOLL (target state) is customer-specific: a hybrid tenant still tied to on-prem AD may
legitimately need passwords/SSPR for longer than a cloud-native, passwordless-only tenant, and
a severity that's right for one isn't necessarily right for the other. Rather than one
hard-coded "correct" Expected/Severity per rule, a baseline file overrides specific rules for
one customer profile without touching the rule JSON files themselves - see
[config/baselines/](config/baselines/) for the two starter presets
(`cloud-native-passwordless`, `hybrid-ad-passwords-required`) and their shape.

```powershell
pwsh -File src/Invoke-SAWAssessment.ps1 -UseSampleData -Baseline hybrid-ad-passwords-required -Verbose
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
