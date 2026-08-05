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
.PARAMETER TenantId
    Optional. The tenant (GUID or verified domain name) you intend to assess. Ignored when
    -UseSampleData is set. If a Microsoft Graph connection already exists from earlier in this
    session but belongs to a different tenant, passing this disconnects and reconnects to the
    requested tenant instead of silently reusing the wrong one - see Connect-SAWGraph.ps1. When
    running against more than one tenant in the same session, either pass this explicitly each
    time or run Disconnect-MgGraph yourself between runs.
.PARAMETER InstallMissingModules
    Install Microsoft.Graph.Authentication for the current user if it isn't already
    installed. Ignored when -UseSampleData is set.
.PARAMETER ForceReauth
    Always disconnect and re-authenticate fresh, even if an active connection already covers
    the requested tenant and scopes. Ignored when -UseSampleData is set. Use this if you just
    activated a role via PIM (including PIM for Groups) and still get a 403 on something that
    role should now cover - Connect-MgGraph can silently reuse a still-valid cached token that
    predates the activation. See Connect-SAWGraph.ps1.
.PARAMETER UseDeviceCode
    Sign in via OAuth device code flow (a URL + one-time code, completed in any browser) instead
    of Windows' Web Account Manager (WAM) broker. Ignored when -UseSampleData is set. Try this if
    -ForceReauth alone doesn't clear a persistent 403 on a role-gated endpoint - WAM brokers
    tokens through its own OS-level cache that -ForceReauth doesn't reach. See
    Connect-SAWGraph.ps1.
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
.PARAMETER MethodUsageDaysBack
    How many days of sign-in history to pull specifically for the "registered but not recently
    used" check (see ConvertTo-SAWMethodUsageRoster.ps1) - independent of, and in addition to,
    the sign-in log collection the legacy-auth/device-code checks already do (which stays at
    its own 7-day default). Defaults to 90, deliberately wider than that default: a method
    genuinely still in active use by an admin who signs in monthly would otherwise look
    abandoned under a 7-day window. This is a second, separately-windowed call to
    /auditLogs/signIns, not a reuse of the shorter one - real extra Graph load on top of
    everything else this toolkit already collects, worth being aware of on a very busy tenant.
    Pass 0 to skip this check entirely (no second sign-in log collection, roster ships without
    the unused-method flag).
.EXAMPLE
    pwsh -File src/Invoke-SAWAssessment.ps1 -UseSampleData -Verbose
.EXAMPLE
    pwsh -File src/Invoke-SAWAssessment.ps1 -InstallMissingModules -Verbose
.EXAMPLE
    pwsh -File src/Invoke-SAWAssessment.ps1 -UseSampleData -Baseline hybrid-ad-passwords-required -Verbose
.EXAMPLE
    # Assessing two different tenants in the same session - pass -TenantId each time so a
    # stale connection from the first tenant is never silently reused for the second.
    pwsh -File src/Invoke-SAWAssessment.ps1 -TenantId contoso.onmicrosoft.com -Verbose
    pwsh -File src/Invoke-SAWAssessment.ps1 -TenantId fabrikam.onmicrosoft.com -Verbose
.EXAMPLE
    # Just activated a role via PIM and still hitting a 403 - force a fresh, non-cached login.
    pwsh -File src/Invoke-SAWAssessment.ps1 -TenantId contoso.onmicrosoft.com -ForceReauth -Verbose
.EXAMPLE
    # -ForceReauth alone didn't clear it - also route around Windows' WAM broker.
    pwsh -File src/Invoke-SAWAssessment.ps1 -TenantId contoso.onmicrosoft.com -ForceReauth -UseDeviceCode -Verbose
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

    [string]$TenantId,

    [switch]$InstallMissingModules,

    [switch]$ForceReauth,

    [switch]$UseDeviceCode,

    # $RulesPath/$OutputRoot/$HistoryPath deliberately have NO default value expression here
    # (defaulted in the script body below instead, once execution is actually inside the
    # script). Windows PowerShell 5.1 leaves $PSScriptRoot empty specifically while evaluating
    # param-block default VALUES when the script is invoked via `-File` (confirmed against a
    # real 5.1 host - a longstanding, documented quirk) - a default like
    # `(Join-Path $PSScriptRoot 'rules')` here would throw before Test-SAWPowerShellVersion
    # below ever gets a chance to run, defeating the entire point of this check.
    [string]$RulesPath,

    [string]$Baseline,

    [switch]$SkipBaselineAutoDetection,

    [string]$BaselineOverridePath,

    [string]$ReportPath,

    [string]$DashboardPath,

    [string]$OutputRoot,

    [string]$HistoryPath,

    [switch]$SkipHistorySnapshot,

    [int]$MethodUsageDaysBack = 90
)

# Checked first, before anything else in this script (including the dot-sourcing below) - see
# Test-SAWPowerShellVersion.ps1 for why this replaces a plain #Requires -Version 7.4: that
# directive blocks the whole script before any of our own code runs, showing only PowerShell's
# generic version-mismatch message with no guidance on what to actually do about it. $PSScriptRoot
# is reliable here (script body), unlike in the param block default values above.
. (Join-Path $PSScriptRoot 'Test-SAWPowerShellVersion.ps1')
$powerShellVersionCheck = Test-SAWPowerShellVersion -ScriptPath $PSCommandPath
if (-not $powerShellVersionCheck.Satisfied) {
    Write-Host $powerShellVersionCheck.Message -ForegroundColor Red
    exit 1
}

if (-not $RulesPath) { $RulesPath = Join-Path $PSScriptRoot 'rules' }
if (-not $OutputRoot) { $OutputRoot = Join-Path (Join-Path $PSScriptRoot '..') 'reports' }
if (-not $HistoryPath) { $HistoryPath = Join-Path (Join-Path $PSScriptRoot '..') 'history' }

$reportPathWasExplicit = $PSBoundParameters.ContainsKey('ReportPath')
$dashboardPathWasExplicit = $PSBoundParameters.ContainsKey('DashboardPath')

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Connect-SAWGraph.ps1')
. (Join-Path $PSScriptRoot 'Invoke-SAWGraphRequest.ps1')

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
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWMethodUsageRoster.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWPolicyDisabledMethodRoster.ps1')
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
. (Join-Path $PSScriptRoot 'rules' 'ConvertTo-SAWRemediationRoadmap.ps1')
. (Join-Path $PSScriptRoot 'rules' 'Get-SAWHistoryTrend.ps1')
. (Join-Path $PSScriptRoot 'rules' 'Get-SAWTimelineMilestones.ps1')
. (Join-Path $PSScriptRoot 'dashboard' 'Export-SAWHtmlReport.ps1')
. (Join-Path $PSScriptRoot 'dashboard' 'Export-SAWDashboard.ps1')
. (Join-Path $PSScriptRoot 'dashboard' 'ConvertTo-SAWMarkdownHtml.ps1')

if (-not $UseSampleData) {
    Write-Verbose 'Invoke-SAWAssessment: establishing Microsoft Graph connection'
    Connect-SAWGraph -Scopes $Scopes -TenantId $TenantId -InstallMissingModules:$InstallMissingModules -ForceReauth:$ForceReauth -UseDeviceCode:$UseDeviceCode -Verbose:$VerbosePreference | Out-Null
}

Write-Verbose 'Invoke-SAWAssessment: collecting tenant profile (hybrid vs. cloud-native detection)'
$tenantProfileRaw = Get-SAWTenantProfile -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$tenantProfile = $tenantProfileRaw | ConvertTo-SAWTenantProfile -Verbose:$VerbosePreference
Write-Host "Detected tenant profile: $($tenantProfile.HybridState) (organization.onPremisesSyncEnabled = $($tenantProfile.OnPremisesSyncEnabled))"
if ($tenantProfile.DomainServicesDetected) {
    Write-Host "Possible Microsoft Entra Domain Services usage detected ('AAD DC Administrators' group found) - this is a proxy signal, not authoritative (Domain Services itself lives in Azure Resource Manager, out of reach for this toolkit's Graph-only scopes). Worth confirming with the customer."
}

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
# Cross-references registered methods against the tenant policy already collected above (no
# extra Graph call) - a registered method whose policy toggle is now Disabled cannot be used
# to sign in anymore, a stronger and more deterministic signal than "not recently used".
$userRoster = ConvertTo-SAWPolicyDisabledMethodRoster -Roster $userRoster -AuthenticationMethodsPolicy $authRaw -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: collecting temporary access pass configuration'
$tapRaw = Get-SAWTemporaryAccessPass -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$normalized += $tapRaw | ConvertTo-SAWNormalizedTemporaryAccessPass -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: collecting FIDO2 (passkey) configuration'
$passkeysRaw = Get-SAWPasskeys -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$normalized += $passkeysRaw | ConvertTo-SAWNormalizedPasskeys -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: collecting sign-in logs'
$signInsRaw = Get-SAWSignInLogs -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$normalized += $signInsRaw | ConvertTo-SAWNormalizedSignInLogs -Verbose:$VerbosePreference

if ($MethodUsageDaysBack -gt 0) {
    Write-Verbose "Invoke-SAWAssessment: collecting sign-in logs for the registered-but-unused-method check (-MethodUsageDaysBack $MethodUsageDaysBack, separate from the 7-day default above)"
    $methodUsageSignInsRaw = Get-SAWSignInLogs -UseSampleData:$UseSampleData -DaysBack $MethodUsageDaysBack -Verbose:$VerbosePreference
    $userRoster = ConvertTo-SAWMethodUsageRoster -Roster $userRoster -SignInLogs $methodUsageSignInsRaw -Verbose:$VerbosePreference
}
else {
    Write-Verbose 'Invoke-SAWAssessment: -MethodUsageDaysBack 0 - skipping the registered-but-unused-method check'
}

Write-Verbose 'Invoke-SAWAssessment: collecting directory audit logs'
$auditsRaw = Get-SAWAuditLogs -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$normalized += $auditsRaw | ConvertTo-SAWNormalizedAuditLogs -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: evaluating Secure At Work rules'
$results = Invoke-SAWRulesEngine -RulesPath $RulesPath -NormalizedData $normalized -BaselineOverrides $baselineOverrides -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: building remediation roadmap'
$roadmap = ConvertTo-SAWRemediationRoadmap -RuleResults $results -Verbose:$VerbosePreference

# History snapshot is written BEFORE report/dashboard generation (not after, as it might read
# more naturally) specifically so the current run is already on disk when Get-SAWHistoryTrend
# reads it below - otherwise the dashboard's trend chart would always lag one run behind.
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
        DomainServicesDetected = $tenantProfile.DomainServicesDetected
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

Write-Verbose 'Invoke-SAWAssessment: reading history trend for dashboard'
$trend = Get-SAWHistoryTrend -HistoryPath $HistoryPath -TenantSlug $tenantSlug -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: loading Microsoft rollout timeline'
# Reuses data already collected for the roster/registration checks above - no extra Graph
# calls. PhoneBasedMethodUsers matches the roster's own downgrade-risk detection exactly
# (mobilePhone/alternateMobilePhone/officePhone). SsprEnabledNotRegisteredUsers is a proxy for
# "relying on directory-sourced contact info" (see ImpactMetricLabel in the JSON for the
# caveat) - Graph's per-user isSsprRegistered doesn't distinguish an explicitly-registered
# method from a directory-sourced one, so this is an upper bound, not an exact count.
$phoneBasedMethodUsers = @($userRoster | Where-Object { $_.HasDowngradeRiskMethod }).Count
$ssprEnabledUsersTotal = 0
$ssprEnabledNotRegisteredUsers = 0
foreach ($u in @($registrationRaw.value)) {
    if ($u.isSsprEnabled) {
        $ssprEnabledUsersTotal++
        if (-not $u.isSsprRegistered) { $ssprEnabledNotRegisteredUsers++ }
    }
}
$impactMetrics = @{
    PhoneBasedMethodUsers         = $phoneBasedMethodUsers
    SsprEnabledNotRegisteredUsers = $ssprEnabledNotRegisteredUsers
}
# SSPR-enabled-for-nobody is a distinct state from "everyone who's enabled is already
# registered" - both would otherwise show as "0 users impacted", which reads identically
# whether it means "fully compliant" or "doesn't apply to this tenant at all".
$notApplicableReasons = @{}
if ($ssprEnabledUsersTotal -eq 0) {
    $notApplicableReasons['SsprEnabledNotRegisteredUsers'] = "SSPR isn't enabled for any user in this tenant"
}
$timelineMilestones = Get-SAWTimelineMilestones -ImpactMetrics $impactMetrics -NotApplicableReasons $notApplicableReasons -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: generating HTML report'
$report = Export-SAWHtmlReport -RuleResults $results -TenantDisplayName $tenantProfile.DisplayName -TenantId $tenantProfile.TenantId -RunTimestamp $runTimestamp -BaselineName $baselineDisplayName -DomainServicesDetected $tenantProfile.DomainServicesDetected -OutputPath $ReportPath -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: generating dashboard'
# Embeds docs/reading-the-report.md as a "Reading This Report" tab so the explainer travels
# with the dashboard file itself (e.g. when the dashboard/ folder is zipped and handed to a
# customer, per README). Missing file (e.g. a packaged distribution that dropped docs/) just
# means no guide tab, not a failed run - Export-SAWDashboard.ps1 falls back to its pre-existing
# single-page layout whenever -ReadingGuideHtml is empty.
$readingGuideHtml = ''
$readingGuidePath = Join-Path $PSScriptRoot '..' 'docs' 'reading-the-report.md'
if (Test-Path -Path $readingGuidePath) {
    $readingGuideMarkdown = Get-Content -Path $readingGuidePath -Raw
    $readingGuideHtml = ConvertTo-SAWMarkdownHtml -Markdown $readingGuideMarkdown -Verbose:$VerbosePreference
}
else {
    Write-Verbose "Invoke-SAWAssessment: no reading guide found at $readingGuidePath - dashboard will render without the 'Reading This Report' tab"
}

$dashboard = Export-SAWDashboard -RuleResults $results -TenantDisplayName $tenantProfile.DisplayName -TenantId $tenantProfile.TenantId -RunTimestamp $runTimestamp -UserRoster $userRoster -MethodUsageDaysBack $MethodUsageDaysBack -CaPolicyInventory $caPolicyInventory -Roadmap $roadmap -Trend $trend -TimelineMilestones $timelineMilestones -ReadingGuideHtml $readingGuideHtml -BaselineName $baselineDisplayName -DomainServicesDetected $tenantProfile.DomainServicesDetected -OutputPath $DashboardPath -Verbose:$VerbosePreference

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
