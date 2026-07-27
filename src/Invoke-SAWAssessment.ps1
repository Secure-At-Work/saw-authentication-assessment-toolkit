#Requires -Version 7.4
<#
.SYNOPSIS
    Runs the assessment vertical slice: collect -> normalize -> evaluate -> report,
    across every wired-up collector category.
.DESCRIPTION
    Wires together each collector/normalizer pair (currently Authentication Methods,
    Conditional Access, Authentication Strengths, and Registration) with the shared
    Invoke-SAWRulesEngine and Export-SAWHtmlReport. Read-only end to end; never modifies
    tenant configuration.
.PARAMETER UseSampleData
    Run against the bundled sample data instead of a live tenant. Requires no Graph connection.
.PARAMETER RulesPath
    Directory containing rule *.json files. Defaults to src/rules.
.PARAMETER ReportPath
    Output path for the generated HTML report. Defaults to reports/assessment-report.html.
.EXAMPLE
    pwsh -File src/Invoke-SAWAssessment.ps1 -UseSampleData -Verbose
#>
[CmdletBinding()]
param(
    [switch]$UseSampleData,

    [string]$RulesPath = (Join-Path $PSScriptRoot 'rules'),

    [string]$ReportPath = (Join-Path $PSScriptRoot '..' 'reports' 'assessment-report.html')
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'collector' 'Get-SAWAuthenticationMethods.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedAuthenticationMethods.ps1')
. (Join-Path $PSScriptRoot 'collector' 'Get-SAWConditionalAccess.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedConditionalAccess.ps1')
. (Join-Path $PSScriptRoot 'collector' 'Get-SAWAuthenticationStrengths.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedAuthenticationStrengths.ps1')
. (Join-Path $PSScriptRoot 'collector' 'Get-SAWRegistration.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedRegistration.ps1')
. (Join-Path $PSScriptRoot 'rules' 'Invoke-SAWRulesEngine.ps1')
. (Join-Path $PSScriptRoot 'dashboard' 'Export-SAWHtmlReport.ps1')

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

Write-Verbose 'Invoke-SAWAssessment: evaluating Secure At Work rules'
$results = Invoke-SAWRulesEngine -RulesPath $RulesPath -NormalizedData $normalized -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: generating HTML report'
$report = Export-SAWHtmlReport -RuleResults $results -OutputPath $ReportPath -Verbose:$VerbosePreference

foreach ($result in $results) {
    Write-Host ("{0,-8} {1,-24} {2,-24} {3,-10} {4,-10} {5,-8} {6,-8}" -f `
        $result.RuleID, $result.Category, $result.Setting, $result.Expected, $result.Actual, $result.Severity, $result.Status)
}
Write-Host ''
Write-Host "Report written to: $($report.FullName)"
