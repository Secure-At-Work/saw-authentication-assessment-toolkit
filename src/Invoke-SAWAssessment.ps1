#Requires -Version 7.4
<#
.SYNOPSIS
    Runs the Authentication Methods vertical slice: collect -> normalize -> evaluate -> report.
.DESCRIPTION
    Wires together Get-SAWAuthenticationMethods, ConvertTo-SAWNormalizedAuthenticationMethods,
    Invoke-SAWRulesEngine, and Export-SAWHtmlReport. Read-only end to end; never modifies
    tenant configuration.
.PARAMETER UseSampleData
    Run against the bundled sample data instead of a live tenant. Requires no Graph connection.
.PARAMETER RulesPath
    Directory containing rule *.json files. Defaults to src/rules.
.PARAMETER ReportPath
    Output path for the generated HTML report. Defaults to reports/authentication-methods-report.html.
.EXAMPLE
    pwsh -File src/Invoke-SAWAssessment.ps1 -UseSampleData -Verbose
#>
[CmdletBinding()]
param(
    [switch]$UseSampleData,

    [string]$RulesPath = (Join-Path $PSScriptRoot 'rules'),

    [string]$ReportPath = (Join-Path $PSScriptRoot '..' 'reports' 'authentication-methods-report.html')
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'collector' 'Get-SAWAuthenticationMethods.ps1')
. (Join-Path $PSScriptRoot 'collector' 'ConvertTo-SAWNormalizedAuthenticationMethods.ps1')
. (Join-Path $PSScriptRoot 'rules' 'Invoke-SAWRulesEngine.ps1')
. (Join-Path $PSScriptRoot 'dashboard' 'Export-SAWHtmlReport.ps1')

Write-Verbose 'Invoke-SAWAssessment: collecting authentication methods policy'
$raw = Get-SAWAuthenticationMethods -UseSampleData:$UseSampleData -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: normalizing collected data'
$normalized = $raw | ConvertTo-SAWNormalizedAuthenticationMethods -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: evaluating Secure At Work rules'
$results = Invoke-SAWRulesEngine -RulesPath $RulesPath -NormalizedData $normalized -Verbose:$VerbosePreference

Write-Verbose 'Invoke-SAWAssessment: generating HTML report'
$report = Export-SAWHtmlReport -RuleResults $results -OutputPath $ReportPath -Verbose:$VerbosePreference

foreach ($result in $results) {
    Write-Host ("{0,-8} {1,-24} {2,-10} {3,-10} {4,-8} {5,-8}" -f `
        $result.RuleID, $result.Setting, $result.Expected, $result.Actual, $result.Severity, $result.Status)
}
Write-Host ''
Write-Host "Report written to: $($report.FullName)"
