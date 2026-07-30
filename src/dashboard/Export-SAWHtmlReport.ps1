function Export-SAWHtmlReport {
    <#
    .SYNOPSIS
        Renders rules engine results into a static HTML report.
    .DESCRIPTION
        Minimal, dependency-free HTML report (no Bootstrap/Chart.js yet - that lands with
        the full dashboard). Color-codes each row per the Green/Yellow/Red/Grey
        convention in spec section 10.
    .PARAMETER RuleResults
        Output of Invoke-SAWRulesEngine.
    .PARAMETER BaselineName
        Display name of the customer SOLL baseline that produced these results (typically a
        baseline preset's "name" field), shown in the report header for traceability. Defaults
        to a label indicating no customer-specific baseline was applied.
    .PARAMETER DomainServicesDetected
        Whether Get-SAWTenantProfile found an "AAD DC Administrators" group (a proxy signal
        for Microsoft Entra Domain Services - see ConvertTo-SAWTenantProfile.ps1). When true, a
        caveated note is shown in the report header.
    .PARAMETER OutputPath
        File path to write the HTML report to. Parent directory is created if missing.
    .OUTPUTS
        System.IO.FileInfo
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$RuleResults,

        [string]$BaselineName = 'Toolkit default (no customer-specific baseline applied)',

        [bool]$DomainServicesDetected = $false,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $statusColors = @{
        Green  = '#2e7d32'
        Yellow = '#f9a825'
        Red    = '#c62828'
        Grey   = '#9e9e9e'
    }

    function ConvertTo-SAWHtmlEncoded([string]$Text) {
        if ([string]::IsNullOrEmpty($Text)) { return '' }
        $Text = $Text -replace '&', '&amp;'
        $Text = $Text -replace '<', '&lt;'
        $Text = $Text -replace '>', '&gt;'
        $Text = $Text -replace '"', '&quot;'
        $Text = $Text -replace "'", '&#39;'
        return $Text
    }

    $rows = foreach ($r in $RuleResults) {
        $color = $statusColors[$r.Status]
        if (-not $color) { $color = '#9e9e9e' }
        @"
      <tr>
        <td>$(ConvertTo-SAWHtmlEncoded $r.RuleID)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $r.Category)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $r.Setting)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $r.Expected)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $r.Actual)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $r.Severity)</td>
        <td style="background-color:$color;color:#fff;font-weight:600;text-align:center;">$(ConvertTo-SAWHtmlEncoded $r.Status)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $r.Recommendation)</td>
      </tr>
"@
    }

    $categories = @()
    foreach ($r in $RuleResults) {
        if ($r.Category -and ($categories -notcontains $r.Category)) {
            $categories += $r.Category
        }
    }
    $categoriesText = ConvertTo-SAWHtmlEncoded ($categories -join ', ')

    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $rowsHtml = $rows -join "`n"

    $domainServicesNote = ''
    if ($DomainServicesDetected) {
        $domainServicesNote = '<br>Possible Microsoft Entra Domain Services usage detected (&quot;AAD DC Administrators&quot; group found) - a proxy signal, not authoritative. Worth confirming with the customer.'
    }

    $html = @"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secure At Work Authentication Assessment Report</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 2rem; color: #212121; }
    h1 { margin-bottom: 0; }
    .meta { color: #616161; margin-bottom: 1.5rem; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #e0e0e0; padding: 0.5rem 0.75rem; text-align: left; font-size: 0.9rem; vertical-align: top; }
    th { background-color: #263238; color: #fff; }
    tr:nth-child(even) { background-color: #fafafa; }
  </style>
</head>
<body>
  <h1>Secure At Work Authentication Assessment Report</h1>
  <p class="meta">Generated $generated &middot; Categories: $categoriesText &middot; Read-only assessment, no tenant changes made.<br>SOLL baseline: $(ConvertTo-SAWHtmlEncoded $BaselineName)<br>SOLL = target state for this customer. IST = what was actually observed in the tenant.$domainServicesNote</p>
  <table>
    <thead>
      <tr>
        <th>Rule ID</th>
        <th>Category</th>
        <th>Setting</th>
        <th>SOLL (Target)</th>
        <th>IST (Current)</th>
        <th>Severity</th>
        <th>Status</th>
        <th>Recommendation</th>
      </tr>
    </thead>
    <tbody>
$rowsHtml
    </tbody>
  </table>
</body>
</html>
"@

    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if ($outputDirectory -and -not (Test-Path -Path $outputDirectory)) {
        New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    }

    $html | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Verbose "Export-SAWHtmlReport: wrote report to $OutputPath"
    Get-Item -Path $OutputPath
}
