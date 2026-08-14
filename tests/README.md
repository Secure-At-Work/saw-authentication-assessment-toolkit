# Tests

Pester 5.x unit tests, mirroring `src/`:

```
tests/
  Test-SAWPowerShellVersion.Tests.ps1
  Invoke-SAWGraphRequest.Tests.ps1
  Connect-SAWGraph.Tests.ps1
  collector/
    Get-SAWAuthenticationMethods.Tests.ps1
    Get-SAWConditionalAccess.Tests.ps1
    Get-SAWAuthenticationStrengths.Tests.ps1
    Get-SAWRegistration.Tests.ps1
    Get-SAWTemporaryAccessPass.Tests.ps1
    Get-SAWPasskeys.Tests.ps1
    Get-SAWSignInLogs.Tests.ps1
    Get-SAWAuditLogs.Tests.ps1
    Get-SAWTenantProfile.Tests.ps1
    ConvertTo-SAWMethodUsageRoster.Tests.ps1
    ConvertTo-SAWPolicyDisabledMethodRoster.Tests.ps1
    ConvertTo-SAWAuthenticationMethodsInventory.Tests.ps1
    Get-SAWAuthorizationPolicy.Tests.ps1
  rules/
    Invoke-SAWRulesEngine.Tests.ps1
    Get-SAWBaselineOverrides.Tests.ps1
    Compare-SAWRuleResults.Tests.ps1
    ConvertTo-SAWRemediationRoadmap.Tests.ps1
    Get-SAWHistoryTrend.Tests.ps1
    Get-SAWTimelineMilestones.Tests.ps1
    ConvertTo-SAWRegistrationFlowScenarios.Tests.ps1
  dashboard/
    Export-SAWDashboard.Tests.ps1
    Export-SAWDriftReport.Tests.ps1
    ConvertTo-SAWMarkdownHtml.Tests.ps1
```

`Invoke-SAWAssessment.ps1` and `Invoke-SAWDriftReport.ps1` have no dedicated test file - they're
thin wiring over already-tested functions, verified end-to-end against sample data (and, where
relevant, a real tenant) instead. `Test-SAWPowerShellVersion.ps1`, `Invoke-SAWGraphRequest.ps1`,
and `Connect-SAWGraph.ps1` are the exceptions among top-level `src/` files: each has real,
mockable branching logic worth unit-testing on its own (module/connection checks, tenant-match
guarding, error-shape detection), not just orchestration.

Each collector test file covers both the collector and its paired normalizer (they're tested
together since they're always used together):

- **`-UseSampleData` path** — returns the bundled fixture under `sampledata/raw/`, throws on a
  missing file.
- **Live Graph path** — `Get-MgContext` and `Invoke-MgGraphRequest` are mocked (no real
  Microsoft.Graph module needed to run the tests): asserts the exact endpoint URI called, that
  pagination via `@odata.nextLink` is followed for list endpoints, and that it throws when not
  connected.
- **Normalizer logic** — the actual derivation/threshold logic, using small hand-built inputs
  rather than the full sample fixture, including edge cases (report-only Conditional Access
  policies don't count, Passkeys checks go Grey when FIDO2 is disabled tenant-wide, Registration
  coverage math, sign-in success vs. failure, audit log break-glass matching).

## Pester cannot run locally on this machine

This workstation enforces PowerShell **ConstrainedLanguage mode** (see
[../docs/powershell-coding-notes.md](../docs/powershell-coding-notes.md)), which blocks
`Add-Type` and dynamic type creation - both of which Pester's own engine depends on internally.
This isn't a test-authoring issue we can code around; Pester simply cannot execute here,
confirmed by running a trivial smoke test (`Should operator 'Be' is not registered`).

There's no CI running these - if your machine doesn't have this WDAC/CLM restriction, run them
yourself:

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -Force
Invoke-Pester -Path ./tests -Output Detailed
```

Target: >80% code coverage (spec section 18), using mocked Graph responses so tests never call
a real tenant.
