#Requires -Version 7.4
<#
.SYNOPSIS
    Runs the assessment vertical slice: collect -> normalize -> evaluate -> report,
    across every wired-up collector category.
.DESCRIPTION
    Wires together every collector/normalizer pair from spec section 6 - Authentication
    Methods, Conditional Access, Authentication Strengths, Registration, Temporary Access
    Pass, Passkeys, Sign-In Logs, and Audit Logs - with the shared Invoke-SAWRulesEngine,
    Export-SAWHtmlReport (flat table), and Export-SAWDashboard (multi-section Bootstrap/
    Chart.js dashboard). Read-only end to end; never modifies tenant configuration.
.PARAMETER UseSampleData
    Run against the bundled sample data instead of a live tenant. Requires no Graph connection
    and skips Connect-SAWGraph entirely.
.PARAMETER Scopes
    Graph delegated scopes to request when connecting to a live tenant. Defaults to the
    read-only scopes every collector needs. Ignored when -UseSampleData is set.
.PARAMETER InstallMissingModules
    Install Microsoft.Graph.Authentication for the current user if it isn't already
    installed. Ignored when -UseSampleData is set.
.PARAMETER RulesPath
    Directory containing rule *.json files. Defaults to src/rules.
.PARAMETER Baseline
    Name of a customer SOLL baseline preset under config/baselines/ (without the .json
    extension), e.g. 'hybrid-ad-passwords-required' or 'cloud-native-passwordless'. Optional -
    if omitted, the toolkit auto-detects whether the tenant is hybrid (synced with on-premises
    AD, via organization.onPremisesSyncEnabled) and picks the matching preset itself unless
    -SkipBaselineAutoDetection is set. If both -Baseline and detection disagree, a warning is
    shown but your explicit -Baseline always wins.
.PARAMETER SkipBaselineAutoDetection
    Disable auto-selecting a baseline from the detected tenant profile. With this set, omitting
    -Baseline means no customer-specific overrides at all (every rule exactly as authored) -
    the old default behavior, before auto-detection existed.
.PARAMETER BaselineOverridePath
    Path to a per-engagement override JSON file (same shape as a baseline preset), layered on
    top of -Baseline (explicit or auto-detected) for one-off tweaks specific to this
    engagement. Optional; can be used with or without -Baseline.
.PARAMETER ReportPath
    Output path for the generated flat HTML report. Defaults to
    <OutputRoot>/<tenant-slug>/<run-timestamp>/assessment-report.html so repeated runs (and
    runs against different tenants) never overwrite each other. Pass explicitly to pin a fixed
    location instead (e.g. for scripting/CI that always wants the latest run at a known path).
.PARAMETER DashboardPath
    Output path for the generated dashboard's index.html. Defaults to
    <OutputRoot>/<tenant-slug>/<run-timestamp>/dashboard/index.html (a vendor/ subfolder is
    created alongside it). Same override behavior as -ReportPath.
.PARAMETER OutputRoot
    Base directory under which per-tenant, per-run report/dashboard output is namespaced when
    -ReportPath/-DashboardPath are not explicitly given. Defaults to reports/.
.PARAMETER HistoryPath
    Base directory for persisted JSON result snapshots, one per run, used for drift comparison
    across runs (see Invoke-SAWDriftReport.ps1). Defaults to history/. Each snapshot lands at
    <HistoryPath>/<tenant-slug>/<run-timestamp>.json.
.PARAMETER SkipHistorySnapshot
    Skip writing the JSON history snapshot for this run. Use for one-off/exploratory runs you
    don't want counted in a tenant's drift history.
.EXAMPLE
    pwsh -File src/Invoke-SAWAssessment.ps1 -UseSampleData -Verbose
.EXAMPLE
    pwsh -File src/Invoke-SAWAssessment.ps1 -InstallMissingModules -Verbose
.EXAMPLE
    pwsh -File src/Invoke-SAWAssessment.ps1 -UseSampleData -Baseline hybrid-ad-passwords-required -Verbose
#>
[CmdletBinding()]
param(
    [switch]$UseSampleData,

    [string[]]$Scopes = @(
        'Policy.Read.All',
        'UserAuthenticationMethod.Read.All',
        'Reports.Read.All',
        'AuditLog.Read.All',
        'Directory.Read.All'
    ),

    [switch]$InstallMissingModules,

    [string]$RulesPath = (Join-Path $PSScriptRoot 'rules'),

    [string]$Baseline,

    [switch]$SkipBaselineAutoDetection,

    [string]$BaselineOverridePath,

    [string]$ReportPath,

    [string]$DashboardPath,

    [string]$OutputRoot = (Join-Path $PSScriptRoot '..' 'reports'),

    [string]$HistoryPath = (Join-Path $PSScriptRoot '..' 'history'),

    [switch]$SkipHistorySnapshot
)

$reportPathWasExplicit = $PSBoundParameters.ContainsKey('ReportPath')
$dashboardPathWasExplicit = $PSBoundParameters.ContainsKey('DashboardPath')

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Connect-SAWGraph.ps1')

. (Join-Path $PSScriptRoot 'collector' 'Get-SAWTenantProfile.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWTenantProfile.ps1')
. (Join-Path $PSScriptRoot 'collector' 'Get-SAWAuthenticationMethods.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedAuthenticationMethods.ps1')
. (Join-Path $PSScriptRoot 'collector' 'Get-SAWConditionalAccess.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedConditionalAccess.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWConditionalAccessInventory.ps1')
. (Join-Path $PSScriptRoot 'collector' 'Get-SAWAuthenticationStrengths.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedAuthenticationStrengths.ps1')
. (Join-Path $PSScriptRoot 'collector' 'Get-SAWRegistration.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedRegistration.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWUserRegistrationRoster.ps1')
. (Join-Path $PSScriptRoot 'collector' 'Get-SAWTemporaryAccessPass.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedTemporaryAccessPass.ps1')
. (Join-Path $PSScriptRoot 'collector' 'Get-SAWPasskeys.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedPasskeys.ps1')
. (Join-Path $PSScriptRoot 'collector' 'Get-SAWSignInLogs.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedSignInLogs.ps1')
. (Join-Path $PSScriptRoot 'collector' 'Get-SAWAuditLogs.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedAuditLogs.ps1')
. (Join-Path $PSScriptRoot 'rules' 'Get-SAWBaselineOverrides.ps1')
. (Join-Path $PSScriptRoot 'rules' 'Invoke-SAWRulesEngine.ps1')
. (Join-Path $PSScriptRoot 'dashboard' 'Export-SAWHtmlReport.ps1')
. (Join-Path $PSScriptRoot 'dashboard' 'Export-SAWDashboard.ps1')

if (-not $UseSampleData) {
    Write-Verbose 'Invoke-SAWAssessment: establishing Microsoft Graph connection'
    Connect-SAWGraph -Scopes $Scopes -InstallMissingModules:$InstallMissingModules -Verbose:$VerbosePreference | Out-Null
}

Write-Verbose 'Invoke-SAWAssessment: collecting tenant profile (hybrid vs. cloud-native detection)'
$tenantProfileRaw = Get-SAWTenantProfile -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$tenantProfile = $tenantProfileRaw | ConvertTo-SAWTenantProfile -Verbose:$VerbosePreference
Write-Host "Detected tenant profile: $($tenantProfile.HybridState) (organization.onPremisesSyncEnabled = $($tenantProfile.OnPremisesSyncEnabled))"

# Namespace output per tenant + per run so repeated runs (drift over time) and multiple
# tenants never collide or overwrite each other, unless the caller pinned an explicit path.
$runTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$tenantSlug = $tenantProfile.Slug
Write-Verbose "Invoke-SAWAssessment: tenant slug '$tenantSlug', run timestamp '$runTimestamp'"

if (-not $reportPathWasExplicit) {
    $ReportPath = Join-Path $OutputRoot $tenantSlug $runTimestamp 'assessment-report.html'
}
if (-not $dashboardPathWasExplicit) {
    $DashboardPath = Join-Path $OutputRoot $tenantSlug $runTimestamp 'dashboard' 'index.html'
}

$baselineWasExplicit = [bool]$Baseline
$autoDetectionNote = $null

if (-not $Baseline -and -not $SkipBaselineAutoDetection) {
    $Baseline = $tenantProfile.RecommendedBaseline
    $autoDetectionNote = "auto-detected from tenant profile ($($tenantProfile.HybridState))"
    Write-Host "No -Baseline specified - auto-selected '$Baseline' ($autoDetectionNote). Pass -SkipBaselineAutoDetection to disable this."
}
elseif ($baselineWasExplicit -and $Baseline -ne $tenantProfile.RecommendedBaseline -and -not $SkipBaselineAutoDetection) {
    Write-Warning "Baseline '$Baseline' was explicitly specified, but the tenant is detected as $($tenantProfile.HybridState) (recommended baseline: '$($tenantProfile.RecommendedBaseline)'). Your explicit -Baseline is being used - verify this is intentional."
}

$baselinePath = $null
if ($Baseline) {
    $baselinePath = Join-Path $PSScriptRoot '..' 'config' 'baselines' "$Baseline.json"
    if (-not (Test-Path -Path $baselinePath)) {
        $availableBaselines = Get-ChildItem -Path (Join-Path $PSScriptRoot '..' 'config' 'baselines') -Filter '*.json' -File |
            ForEach-Object { $_.BaseName }
        throw "Baseline preset '$Baseline' not found at $baselinePath. Available presets: $($availableBaselines -join ', ')"
    }
}

$baselineOverrides = Get-SAWBaselineOverrides -BaselinePath $baselinePath -OverridePath $BaselineOverridePath -Verbose:$VerbosePreference

$baselineDisplayName = 'Toolkit default (no customer-specific baseline applied)'
if ($baselinePath) {
    $baselineDisplayName = (Get-Content -Path $baselinePath -Raw | ConvertFrom-Json).name
    if ($autoDetectionNote) {
        $baselineDisplayName += " [$autoDetectionNote]"
    }
    if ($BaselineOverridePath) {
        $baselineDisplayName += ' + engagement override'
    }
}
elseif ($BaselineOverridePath) {
    $baselineDisplayName = 'Engagement override only (no named preset)'
}

$normalized = @()

Write-Verbose 'Invoke-SAWAssessment: collecting authentication methods policy'
$authRaw = Get-SAWAuthenticationMethods -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$normalized += $authRaw | ConvertTo-SAWNormalizedAuthenticationMethods -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: collecting conditional access policies'
$caRaw = Get-SAWConditionalAccess -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$normalized += $caRaw | ConvertTo-SAWNormalizedConditionalAccess -Verbose:$VerbosePreference
$caPolicyInventory = $caRaw | ConvertTo-SAWConditionalAccessInventory -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: collecting authentication strength policies'
$strengthsRaw = Get-SAWAuthenticationStrengths -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$normalized += $strengthsRaw | ConvertTo-SAWNormalizedAuthenticationStrengths -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: collecting user registration details'
$registrationRaw = Get-SAWRegistration -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$normalized += $registrationRaw | ConvertTo-SAWNormalizedRegistration -Verbose:$VerbosePreference
$userRoster = $registrationRaw | ConvertTo-SAWUserRegistrationRoster -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: collecting temporary access pass configuration'
$tapRaw = Get-SAWTemporaryAccessPass -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$normalized += $tapRaw | ConvertTo-SAWNormalizedTemporaryAccessPass -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: collecting FIDO2 (passkey) configuration'
$passkeysRaw = Get-SAWPasskeys -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$normalized += $passkeysRaw | ConvertTo-SAWNormalizedPasskeys -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: collecting sign-in logs'
$signInsRaw = Get-SAWSignInLogs -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$normalized += $signInsRaw | ConvertTo-SAWNormalizedSignInLogs -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: collecting directory audit logs'
$auditsRaw = Get-SAWAuditLogs -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$normalized += $auditsRaw | ConvertTo-SAWNormalizedAuditLogs -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: evaluating Secure At Work rules'
$results = Invoke-SAWRulesEngine -RulesPath $RulesPath -NormalizedData $normalized -BaselineOverrides $baselineOverrides -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: generating HTML report'
$report = Export-SAWHtmlReport -RuleResults $results -BaselineName $baselineDisplayName -OutputPath $ReportPath -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: generating dashboard'
$dashboard = Export-SAWDashboard -RuleResults $results -UserRoster $userRoster -CaPolicyInventory $caPolicyInventory -BaselineName $baselineDisplayName -OutputPath $DashboardPath -Verbose:$VerbosePreference

$snapshotPath = $null
if (-not $SkipHistorySnapshot) {
    Write-Verbose 'Invoke-SAWAssessment: writing history snapshot'

    $rosterCounts = @{ Remove = 0; Hunt = 0; 'Guest (FIDO2 Not Supported)' = 0; OK = 0 }
    $rosterAdminCounts = @{ Remove = 0; Hunt = 0; 'Guest (FIDO2 Not Supported)' = 0; OK = 0 }
    foreach ($u in $userRoster) {
        if ($rosterCounts.ContainsKey($u.Bucket)) {
            $rosterCounts[$u.Bucket]++
            if ($u.IsAdmin) { $rosterAdminCounts[$u.Bucket]++ }
        }
    }

    $snapshot = @{
        TenantId          = $tenantProfile.TenantId
        TenantSlug         = $tenantSlug
        TenantDisplayName  = $tenantProfile.DisplayName
        HybridState        = $tenantProfile.HybridState
        BaselineName       = $baselineDisplayName
        RunTimestamp       = $runTimestamp
        GeneratedAt        = (Get-Date).ToString('o')
        Results            = $results
        RosterCounts       = $rosterCounts
        RosterAdminCounts  = $rosterAdminCounts
    }

    $snapshotDirectory = Join-Path $HistoryPath $tenantSlug
    if (-not (Test-Path -Path $snapshotDirectory)) {
        New-Item -ItemType Directory -Force -Path $snapshotDirectory | Out-Null
    }
    $snapshotPath = Join-Path $snapshotDirectory "$runTimestamp.json"
    $snapshot | ConvertTo-Json -Depth 10 | Out-File -FilePath $snapshotPath -Encoding utf8
    Write-Verbose "Invoke-SAWAssessment: wrote history snapshot to $snapshotPath"
}

foreach ($result in $results) {
    Write-Host ("{0,-8} {1,-24} {2,-24} {3,-10} {4,-10} {5,-8} {6,-8}" -f `
        $result.RuleID, $result.Category, $result.Setting, $result.Expected, $result.Actual, $result.Severity, $result.Status)
}
Write-Host ''
Write-Host "Report written to: $($report.FullName)"
Write-Host "Dashboard written to: $($dashboard.FullName)"
if ($snapshotPath) {
    Write-Host "History snapshot written to: $snapshotPath"
}
