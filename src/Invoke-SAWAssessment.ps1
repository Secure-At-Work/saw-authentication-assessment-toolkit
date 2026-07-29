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
.PARAMETER ReportPath
    Output path for the generated flat HTML report. Defaults to reports/assessment-report.html.
.PARAMETER DashboardPath
    Output path for the generated dashboard's index.html. Defaults to
    reports/dashboard/index.html (a vendor/ subfolder is created alongside it).
.EXAMPLE
    pwsh -File src/Invoke-SAWAssessment.ps1 -UseSampleData -Verbose
.EXAMPLE
    pwsh -File src/Invoke-SAWAssessment.ps1 -InstallMissingModules -Verbose
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

    [string]$ReportPath = (Join-Path $PSScriptRoot '..' 'reports' 'assessment-report.html'),

    [string]$DashboardPath = (Join-Path $PSScriptRoot '..' 'reports' 'dashboard' 'index.html')
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Connect-SAWGraph.ps1')

. (Join-Path $PSScriptRoot 'collector' 'Get-SAWAuthenticationMethods.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedAuthenticationMethods.ps1')
. (Join-Path $PSScriptRoot 'collector' 'Get-SAWConditionalAccess.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedConditionalAccess.ps1')
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
. (Join-Path $PSScriptRoot 'rules' 'Invoke-SAWRulesEngine.ps1')
. (Join-Path $PSScriptRoot 'dashboard' 'Export-SAWHtmlReport.ps1')
. (Join-Path $PSScriptRoot 'dashboard' 'Export-SAWDashboard.ps1')

if (-not $UseSampleData) {
    Write-Verbose 'Invoke-SAWAssessment: establishing Microsoft Graph connection'
    Connect-SAWGraph -Scopes $Scopes -InstallMissingModules:$InstallMissingModules -Verbose:$VerbosePreference | Out-Null
}

$normalized = @()

Write-Verbose 'Invoke-SAWAssessment: collecting authentication methods policy'
$authRaw = Get-SAWAuthenticationMethods -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$normalized += $authRaw | ConvertTo-SAWNormalizedAuthenticationMethods -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: collecting conditional access policies'
$caRaw = Get-SAWConditionalAccess -UseSampleData:$UseSampleData -Verbose:$VerbosePreference
$normalized += $caRaw | ConvertTo-SAWNormalizedConditionalAccess -Verbose:$VerbosePreference

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
$results = Invoke-SAWRulesEngine -RulesPath $RulesPath -NormalizedData $normalized -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: generating HTML report'
$report = Export-SAWHtmlReport -RuleResults $results -OutputPath $ReportPath -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: generating dashboard'
$dashboard = Export-SAWDashboard -RuleResults $results -UserRoster $userRoster -OutputPath $DashboardPath -Verbose:$VerbosePreference

foreach ($result in $results) {
    Write-Host ("{0,-8} {1,-24} {2,-24} {3,-10} {4,-10} {5,-8} {6,-8}" -f `
        $result.RuleID, $result.Category, $result.Setting, $result.Expected, $result.Actual, $result.Severity, $result.Status)
}
Write-Host ''
Write-Host "Report written to: $($report.FullName)"
Write-Host "Dashboard written to: $($dashboard.FullName)"
