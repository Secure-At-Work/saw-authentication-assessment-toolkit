function Export-SAWDriftReport {
    <#
    .SYNOPSIS
        Renders a Compare-SAWRuleResults comparison into a static HTML drift report.
    .DESCRIPTION
        Minimal, dependency-free HTML report (no Bootstrap/Chart.js, self-contained single
        file, so it can be emailed on its own) for comparing two assessment runs of
        the same tenant. Regressions are shown first (they're what an assessor needs to act on
        immediately), then improvements, then applicability changes and rule-set changes, then
        the roster bucket deltas. Unchanged rules are summarized as a count only - showing all
        of them would bury the signal this report exists to surface.
    .PARAMETER Comparison
        Output of Compare-SAWRuleResults.
    .PARAMETER TenantDisplayName
        Display name of the tenant being compared, shown in the report header.
    .PARAMETER OutputPath
        File path to write the HTML report to. Parent directory is created if missing.
    .OUTPUTS
        System.IO.FileInfo
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Comparison,

        [string]$TenantDisplayName = 'Unknown tenant',

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

    function ConvertTo-SAWStatusBadge([string]$Status) {
        if (-not $Status) { return '<span style="color:#9e9e9e;">(none)</span>' }
        $color = $statusColors[$Status]
        if (-not $color) { $color = '#9e9e9e' }
        return "<span style=""background-color:$color;color:#fff;font-weight:600;padding:0.1rem 0.5rem;border-radius:3px;"">$(ConvertTo-SAWHtmlEncoded $Status)</span>"
    }

    function ConvertTo-SAWChangeRowsHtml([object[]]$Changes, [bool]$ShowTransition) {
        $rows = foreach ($c in $Changes) {
            $transitionCell = if ($ShowTransition) {
                "<td>$(ConvertTo-SAWStatusBadge $c.OldStatus) &rarr; $(ConvertTo-SAWStatusBadge $c.NewStatus)</td>"
            }
            else {
                "<td>$(ConvertTo-SAWStatusBadge $c.NewStatus)</td>"
            }
@"
      <tr>
        <td>$(ConvertTo-SAWHtmlEncoded $c.RuleID)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $c.Category)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $c.Setting)</td>
        $transitionCell
        <td>$(ConvertTo-SAWHtmlEncoded $c.OldActual) &rarr; $(ConvertTo-SAWHtmlEncoded $c.NewActual)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $c.Severity)</td>
      </tr>
"@
        }
        return ($rows -join "`n")
    }

    function New-SAWChangeSection([string]$Title, [string]$Description, [object[]]$Changes, [bool]$ShowTransition = $true) {
        if (-not $Changes -or $Changes.Count -eq 0) {
            return "<h2>$(ConvertTo-SAWHtmlEncoded $Title) (0)</h2><p class=`"meta`">None.</p>"
        }
        $rowsHtml = ConvertTo-SAWChangeRowsHtml -Changes $Changes -ShowTransition $ShowTransition
@"
  <h2>$(ConvertTo-SAWHtmlEncoded $Title) ($($Changes.Count))</h2>
  <p class="meta">$(ConvertTo-SAWHtmlEncoded $Description)</p>
  <table>
    <thead>
      <tr>
        <th>Rule ID</th>
        <th>Category</th>
        <th>Setting</th>
        <th>Status</th>
        <th>IST (Old &rarr; New)</th>
        <th>Severity</th>
      </tr>
    </thead>
    <tbody>
$rowsHtml
    </tbody>
  </table>
"@
    }

    $regressionsHtml = New-SAWChangeSection -Title 'Regressions' `
        -Description 'Got worse since the previous run - review first.' `
        -Changes $Comparison.Regressions

    $improvementsHtml = New-SAWChangeSection -Title 'Improvements' `
        -Description 'Got better since the previous run.' `
        -Changes $Comparison.Improvements

    $newlyApplicableHtml = New-SAWChangeSection -Title 'Newly Applicable' `
        -Description 'Now produce a real result where they were previously Grey (not applicable / no data) - typically because a related feature was just enabled.' `
        -Changes $Comparison.NewlyApplicable

    $newlyNotApplicableHtml = New-SAWChangeSection -Title 'Newly Not Applicable' `
        -Description 'Went back to Grey (not applicable / no data) - typically because a related feature was disabled, or a baseline override changed.' `
        -Changes $Comparison.NewlyNotApplicable

    $newChecksHtml = New-SAWChangeSection -Title 'New Checks' `
        -Description 'Rules that did not exist in the previous run (toolkit updated between runs).' `
        -Changes $Comparison.NewChecks -ShowTransition $false

    $removedChecksHtml = New-SAWChangeSection -Title 'Removed Checks' `
        -Description 'Rules that existed in the previous run but not this one (toolkit updated between runs).' `
        -Changes $Comparison.RemovedChecks -ShowTransition $false

    $rosterRowsHtml = ''
    if ($Comparison.RosterDelta) {
        $rosterRows = foreach ($r in $Comparison.RosterDelta) {
            $deltaText = if ($r.Delta -gt 0) { "+$($r.Delta)" } else { "$($r.Delta)" }
            $deltaColor = if ($r.Delta -gt 0 -and $r.Bucket -in @('Remove', 'Hunt')) { '#c62828' }
                          elseif ($r.Delta -lt 0 -and $r.Bucket -in @('Remove', 'Hunt')) { '#2e7d32' }
                          elseif ($r.Delta -gt 0 -and $r.Bucket -eq 'OK') { '#2e7d32' }
                          elseif ($r.Delta -lt 0 -and $r.Bucket -eq 'OK') { '#c62828' }
                          else { '#616161' }
@"
      <tr>
        <td>$(ConvertTo-SAWHtmlEncoded $r.Bucket)</td>
        <td>$($r.Old)</td>
        <td>$($r.New)</td>
        <td style="color:$deltaColor;font-weight:600;">$deltaText</td>
      </tr>
"@
        }
        $rosterRowsHtml = $rosterRows -join "`n"
    }
    $rosterHtml = if ($Comparison.RosterDelta) {
@"
  <h2>Security Info Registration Roster Delta</h2>
  <table>
    <thead>
      <tr><th>Bucket</th><th>Old Count</th><th>New Count</th><th>Delta</th></tr>
    </thead>
    <tbody>
$rosterRowsHtml
    </tbody>
  </table>
"@
    }
    else {
        '<h2>Security Info Registration Roster Delta</h2><p class="meta">Not available for this comparison (one or both snapshots have no roster data).</p>'
    }

    $unchangedCount = if ($Comparison.Unchanged) { $Comparison.Unchanged.Count } else { 0 }
    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $html = @"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secure At Work Authentication Assessment - Drift Report</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 2rem; color: #212121; }
    h1 { margin-bottom: 0; }
    h2 { margin-top: 2rem; border-bottom: 2px solid #eceff1; padding-bottom: 0.25rem; }
    .meta { color: #616161; margin-bottom: 1rem; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 0.5rem; }
    th, td { border: 1px solid #e0e0e0; padding: 0.5rem 0.75rem; text-align: left; font-size: 0.9rem; vertical-align: top; }
    th { background-color: #263238; color: #fff; }
    tr:nth-child(even) { background-color: #fafafa; }
  </style>
</head>
<body>
  <h1>Secure At Work Authentication Assessment - Drift Report</h1>
  <p class="meta">
    Tenant: $(ConvertTo-SAWHtmlEncoded $TenantDisplayName)<br>
    Comparing run <strong>$(ConvertTo-SAWHtmlEncoded $Comparison.OldRunTimestamp)</strong> &rarr; <strong>$(ConvertTo-SAWHtmlEncoded $Comparison.NewRunTimestamp)</strong><br>
    Generated $generated &middot; Read-only comparison, no tenant changes made.<br>
    $unchangedCount rule(s) unchanged between the two runs (not listed below).
  </p>
$regressionsHtml
$improvementsHtml
$newlyApplicableHtml
$newlyNotApplicableHtml
$newChecksHtml
$removedChecksHtml
$rosterHtml
</body>
</html>
"@

    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if ($outputDirectory -and -not (Test-Path -Path $outputDirectory)) {
        New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    }

    $html | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Verbose "Export-SAWDriftReport: wrote drift report to $OutputPath"
    Get-Item -Path $OutputPath
}
