#Requires -Version 7.4
<#
.SYNOPSIS
    Compares two Invoke-SAWAssessment history snapshots for the same tenant and renders an
    HTML drift report showing what changed.
.DESCRIPTION
    Companion script to Invoke-SAWAssessment.ps1, which writes a JSON result snapshot to
    history/<tenant-slug>/<run-timestamp>.json on every run (unless -SkipHistorySnapshot was
    passed). This script picks two of those snapshots - by default the two most recent for a
    given tenant - diffs them with Compare-SAWRuleResults, and renders the result with
    Export-SAWDriftReport. Entirely offline/read-only: it only reads already-collected
    snapshot files, no Graph connection involved.
.PARAMETER TenantSlug
    The tenant slug (as used under history/<tenant-slug>/, e.g. the tenant's GUID) to
    auto-resolve the two most recent snapshots for. Required unless both -OldSnapshotPath and
    -NewSnapshotPath are given explicitly.
.PARAMETER HistoryPath
    Base directory to look under for <TenantSlug>'s snapshot files. Defaults to history/.
    Ignored when -OldSnapshotPath/-NewSnapshotPath are given.
.PARAMETER OldSnapshotPath
    Explicit path to the earlier snapshot JSON file, overriding auto-resolution via
    -TenantSlug. Must be paired with -NewSnapshotPath.
.PARAMETER NewSnapshotPath
    Explicit path to the later snapshot JSON file, overriding auto-resolution via -TenantSlug.
    Must be paired with -OldSnapshotPath.
.PARAMETER OutputPath
    Output path for the generated drift report. Defaults to
    reports/<tenant-slug>/drift/<old-timestamp>-vs-<new-timestamp>.html.
.PARAMETER OutputRoot
    Base directory for the default -OutputPath. Defaults to reports/. Ignored when -OutputPath
    is given explicitly.
.EXAMPLE
    pwsh -File src/Invoke-SAWDriftReport.ps1 -TenantSlug aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
.EXAMPLE
    pwsh -File src/Invoke-SAWDriftReport.ps1 -OldSnapshotPath history/contoso/20260101-000000.json -NewSnapshotPath history/contoso/20260201-000000.json
#>
[CmdletBinding()]
param(
    [string]$TenantSlug,

    [string]$HistoryPath = (Join-Path $PSScriptRoot '..' 'history'),

    [string]$OldSnapshotPath,

    [string]$NewSnapshotPath,

    [string]$OutputPath,

    [string]$OutputRoot = (Join-Path $PSScriptRoot '..' 'reports')
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'rules' 'Compare-SAWRuleResults.ps1')
. (Join-Path $PSScriptRoot 'dashboard' 'Export-SAWDriftReport.ps1')

$explicitPathsGiven = [bool]$OldSnapshotPath -or [bool]$NewSnapshotPath
if ($explicitPathsGiven -and (-not $OldSnapshotPath -or -not $NewSnapshotPath)) {
    throw '-OldSnapshotPath and -NewSnapshotPath must be given together.'
}

if (-not $explicitPathsGiven) {
    if (-not $TenantSlug) {
        throw 'Either -TenantSlug (to auto-resolve the two most recent snapshots), or both -OldSnapshotPath and -NewSnapshotPath, must be given.'
    }

    $tenantHistoryDirectory = Join-Path $HistoryPath $TenantSlug
    if (-not (Test-Path -Path $tenantHistoryDirectory)) {
        throw "No history found for tenant slug '$TenantSlug' at $tenantHistoryDirectory. Run Invoke-SAWAssessment.ps1 at least twice for this tenant first."
    }

    $snapshotFiles = Get-ChildItem -Path $tenantHistoryDirectory -Filter '*.json' -File | Sort-Object -Property Name
    if ($snapshotFiles.Count -lt 2) {
        throw "Found only $($snapshotFiles.Count) snapshot(s) for tenant slug '$TenantSlug' at $tenantHistoryDirectory - need at least 2 runs to compute drift. Run Invoke-SAWAssessment.ps1 again for this tenant, then retry."
    }

    $OldSnapshotPath = $snapshotFiles[-2].FullName
    $NewSnapshotPath = $snapshotFiles[-1].FullName
    Write-Verbose "Invoke-SAWDriftReport: auto-resolved OldSnapshotPath=$OldSnapshotPath, NewSnapshotPath=$NewSnapshotPath"
}

if (-not (Test-Path -Path $OldSnapshotPath)) {
    throw "Old snapshot not found: $OldSnapshotPath"
}
if (-not (Test-Path -Path $NewSnapshotPath)) {
    throw "New snapshot not found: $NewSnapshotPath"
}

Write-Verbose 'Invoke-SAWDriftReport: loading snapshots'
$oldSnapshot = Get-Content -Path $OldSnapshotPath -Raw | ConvertFrom-Json
$newSnapshot = Get-Content -Path $NewSnapshotPath -Raw | ConvertFrom-Json

Write-Verbose 'Invoke-SAWDriftReport: comparing snapshots'
$comparison = Compare-SAWRuleResults -OldSnapshot $oldSnapshot -NewSnapshot $newSnapshot -Verbose:$VerbosePreference

$tenantDisplayName = if ($newSnapshot.TenantDisplayName) { $newSnapshot.TenantDisplayName }
                     elseif ($oldSnapshot.TenantDisplayName) { $oldSnapshot.TenantDisplayName }
                     elseif ($TenantSlug) { $TenantSlug }
                     else { 'Unknown tenant' }

if (-not $OutputPath) {
    $resolvedTenantSlug = if ($TenantSlug) { $TenantSlug } else { $newSnapshot.TenantSlug }
    if (-not $resolvedTenantSlug) { $resolvedTenantSlug = 'unknown-tenant' }
    $OutputPath = Join-Path $OutputRoot $resolvedTenantSlug 'drift' "$($comparison.OldRunTimestamp)-vs-$($comparison.NewRunTimestamp).html"
}

Write-Verbose 'Invoke-SAWDriftReport: generating drift report'
$report = Export-SAWDriftReport -Comparison $comparison -TenantDisplayName $tenantDisplayName -OutputPath $OutputPath -Verbose:$VerbosePreference

Write-Host "Tenant: $tenantDisplayName"
Write-Host "Comparing $($comparison.OldRunTimestamp) -> $($comparison.NewRunTimestamp)"
Write-Host "Regressions: $($comparison.Regressions.Count)  Improvements: $($comparison.Improvements.Count)  Newly Applicable: $($comparison.NewlyApplicable.Count)  Newly Not Applicable: $($comparison.NewlyNotApplicable.Count)  New Checks: $($comparison.NewChecks.Count)  Removed Checks: $($comparison.RemovedChecks.Count)  Unchanged: $($comparison.Unchanged.Count)"
Write-Host ''
Write-Host "Drift report written to: $($report.FullName)"
