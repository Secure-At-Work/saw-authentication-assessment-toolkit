function Export-SAWDashboard {
    <#
    .SYNOPSIS
        Renders rules engine results into the full Secure At Work dashboard (spec section 9).
    .DESCRIPTION
        Unlike Export-SAWHtmlReport (a single flat table), this produces a multi-section
        Bootstrap/Chart.js dashboard: an Overview with status/category charts, a prioritized
        Risk Findings & Recommendations list, and per-category detail tabs. Both the flat
        report and the dashboard are legitimate outputs per the spec section 3 architecture
        diagram (Rules Engine -> Dashboard, HTML Report, ...).

        Bootstrap and Chart.js are vendored locally under src/dashboard/vendor/ (no CDN
        reference) per spec section 5 ("Everything runs locally"). This function copies that
        vendor/ folder next to the generated index.html so the whole output directory is
        self-contained and portable - it can be zipped up and opened offline.

        Sections not yet backed by a dedicated collector (Guests, a standalone Break Glass
        view, OATH, Certificate Authentication as their own tabs) are intentionally omitted
        rather than rendered empty; SMS and Voice currently appear as individual settings
        within the Authentication Methods tab, since that's where they're actually collected.
    .PARAMETER RuleResults
        Output of Invoke-SAWRulesEngine.
    .PARAMETER UserRoster
        Optional output of ConvertTo-SAWUserRegistrationRoster (one hashtable per user, with
        Bucket = OK/Hunt/Remove). When supplied, renders a "Security Info Registration - User
        Triage" section: who's fine, who needs hunting down to register a phishing-resistant
        method, and who has a downgrade-risk fallback method to remove - already sorted
        Remove > Hunt > OK, admins first within each bucket. Omitted entirely if empty/absent.
    .PARAMETER CaPolicyInventory
        Optional output of ConvertTo-SAWConditionalAccessInventory (one hashtable per CA
        policy). When supplied, renders a "Conditional Access Policy Inventory" section
        listing every policy's name, state, targets, and grant controls - independent of the
        handful of synthetic pass/fail CA checks in the rules engine. Omitted entirely if
        empty/absent.
    .PARAMETER Roadmap
        Optional output of ConvertTo-SAWRemediationRoadmap (one hashtable per phase). When
        supplied, renders a "Remediation Roadmap" section right after the Overview - the
        answer to "what do I fix, in what order" rather than just a flat findings list: each
        phase shows its completion state, and each outstanding rule within it shows whether
        it's safe to work on now or Blocked on an earlier phase's rule still being open.
        Omitted entirely if empty/absent.
    .PARAMETER BaselineName
        Display name of the customer SOLL baseline that produced these results (typically a
        baseline preset's "name" field), shown in the navbar and Overview for traceability.
        Defaults to a label indicating no customer-specific baseline was applied.
    .PARAMETER DomainServicesDetected
        Whether Get-SAWTenantProfile found an "AAD DC Administrators" group (a proxy signal
        for Microsoft Entra Domain Services - see ConvertTo-SAWTenantProfile.ps1). When true, a
        caveated note is shown in the top banner alongside the baseline name.
    .PARAMETER OutputPath
        File path to write index.html to (e.g. reports/dashboard/index.html). A vendor/
        subfolder is created alongside it. Parent directory is created if missing.
    .OUTPUTS
        System.IO.FileInfo
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$RuleResults,

        [AllowEmptyCollection()]
        [object[]]$UserRoster = @(),

        [AllowEmptyCollection()]
        [object[]]$CaPolicyInventory = @(),

        [AllowEmptyCollection()]
        [object[]]$Roadmap = @(),

        [string]$BaselineName = 'Toolkit default (no customer-specific baseline applied)',

        [bool]$DomainServicesDetected = $false,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $statusBadgeClass = @{
        Green  = 'bg-success'
        Yellow = 'bg-warning text-dark'
        Red    = 'bg-danger'
        Grey   = 'bg-secondary'
    }
    $severityRank = @{
        High   = 0
        Medium = 1
        Low    = 2
    }

    function ConvertTo-SAWHtmlEncoded {
        param([string]$Text)
        if ([string]::IsNullOrEmpty($Text)) { return '' }
        $Text = $Text -replace '&', '&amp;'
        $Text = $Text -replace '<', '&lt;'
        $Text = $Text -replace '>', '&gt;'
        $Text = $Text -replace '"', '&quot;'
        $Text = $Text -replace "'", '&#39;'
        return $Text
    }

    function ConvertTo-SAWSlug {
        param([string]$Text)
        return ($Text -replace '[^a-zA-Z0-9]', '')
    }

    # --- Overview counts ---
    $counts = @{ Green = 0; Yellow = 0; Red = 0; Grey = 0 }
    foreach ($r in $RuleResults) {
        if ($counts.ContainsKey($r.Status)) { $counts[$r.Status]++ }
    }

    # --- Distinct categories, first-seen order ---
    $categories = @()
    foreach ($r in $RuleResults) {
        if ($r.Category -and ($categories -notcontains $r.Category)) {
            $categories += $r.Category
        }
    }

    # --- Per-category chart series ---
    $categoryRedCounts = @()
    $categoryYellowCounts = @()
    $categoryGreenCounts = @()
    foreach ($cat in $categories) {
        $rowsForCat = $RuleResults | Where-Object { $_.Category -eq $cat }
        $red = 0; $yellow = 0; $green = 0
        foreach ($r in $rowsForCat) {
            if ($r.Status -eq 'Red') { $red++ }
            elseif ($r.Status -eq 'Yellow') { $yellow++ }
            elseif ($r.Status -eq 'Green') { $green++ }
        }
        $categoryRedCounts += $red
        $categoryYellowCounts += $yellow
        $categoryGreenCounts += $green
    }

    $statusChartLabelsJson = @('Green', 'Yellow', 'Red', 'Grey') | ConvertTo-Json -Compress
    $statusChartDataJson = @($counts.Green, $counts.Yellow, $counts.Red, $counts.Grey) | ConvertTo-Json -Compress
    $categoryLabelsJson = @($categories) | ConvertTo-Json -Compress
    $categoryRedJson = @($categoryRedCounts) | ConvertTo-Json -Compress
    $categoryYellowJson = @($categoryYellowCounts) | ConvertTo-Json -Compress
    $categoryGreenJson = @($categoryGreenCounts) | ConvertTo-Json -Compress

    # --- Nav pills + per-category detail tables ---
    $navItems = @()
    $tabPanes = @()
    $isFirst = $true
    foreach ($cat in $categories) {
        $slug = ConvertTo-SAWSlug $cat
        $navActiveClass = if ($isFirst) { ' active' } else { '' }
        $paneActiveClass = if ($isFirst) { ' show active' } else { '' }
        $ariaSelected = if ($isFirst) { 'true' } else { 'false' }

        $navItems += @"
      <li class="nav-item" role="presentation">
        <button class="nav-link$navActiveClass" id="tab-$slug" data-bs-toggle="pill" data-bs-target="#pane-$slug" type="button" role="tab" aria-controls="pane-$slug" aria-selected="$ariaSelected">$(ConvertTo-SAWHtmlEncoded $cat)</button>
      </li>
"@

        $rowsForCat = $RuleResults | Where-Object { $_.Category -eq $cat }
        $bodyRows = foreach ($r in $rowsForCat) {
            $badgeClass = $statusBadgeClass[$r.Status]
            if (-not $badgeClass) { $badgeClass = 'bg-secondary' }
            @"
              <tr>
                <td>$(ConvertTo-SAWHtmlEncoded $r.RuleID)</td>
                <td>$(ConvertTo-SAWHtmlEncoded $r.Setting)</td>
                <td>$(ConvertTo-SAWHtmlEncoded $r.Expected)</td>
                <td>$(ConvertTo-SAWHtmlEncoded $r.Actual)</td>
                <td>$(ConvertTo-SAWHtmlEncoded $r.Severity)</td>
                <td><span class="badge $badgeClass">$(ConvertTo-SAWHtmlEncoded $r.Status)</span></td>
                <td>$(ConvertTo-SAWHtmlEncoded $r.Recommendation)</td>
              </tr>
"@
        }

        $tabPanes += @"
      <div class="tab-pane fade$paneActiveClass" id="pane-$slug" role="tabpanel" aria-labelledby="tab-$slug">
        <div class="table-responsive">
          <table class="table table-striped table-hover align-middle">
            <thead>
              <tr><th>Rule</th><th>Setting</th><th>SOLL (Target)</th><th>IST (Current)</th><th>Severity</th><th>Status</th><th>Recommendation</th></tr>
            </thead>
            <tbody>
$($bodyRows -join "`n")
            </tbody>
          </table>
        </div>
      </div>
"@
        $isFirst = $false
    }

    # --- Risk findings / recommendations: non-Green, non-Grey, sorted by severity then RuleID ---
    $findings = $RuleResults | Where-Object { $_.Status -ne 'Green' -and $_.Status -ne 'Grey' }
    $findingsSorted = $findings | Sort-Object -Property `
        { if ($severityRank.ContainsKey($_.Severity)) { $severityRank[$_.Severity] } else { 99 } }, `
        { $_.RuleID }

    $findingsHtml = foreach ($f in $findingsSorted) {
        $badgeClass = $statusBadgeClass[$f.Status]
        if (-not $badgeClass) { $badgeClass = 'bg-secondary' }
        @"
        <div class="list-group-item">
          <div class="d-flex flex-wrap align-items-center gap-2 mb-1">
            <span class="badge $badgeClass">$(ConvertTo-SAWHtmlEncoded $f.Status)</span>
            <strong>$(ConvertTo-SAWHtmlEncoded $f.RuleID)</strong>
            <span class="text-body-secondary">$(ConvertTo-SAWHtmlEncoded $f.Category) / $(ConvertTo-SAWHtmlEncoded $f.Setting)</span>
            <span class="badge bg-light text-dark border">$(ConvertTo-SAWHtmlEncoded $f.Severity)</span>
          </div>
          <p class="mb-0 text-body-secondary">$(ConvertTo-SAWHtmlEncoded $f.Recommendation)</p>
        </div>
"@
    }
    if ($findingsSorted.Count -eq 0) {
        $findingsHtml = '<div class="list-group-item text-body-secondary">No open findings - every evaluated setting matches the Secure At Work baseline.</div>'
    }

    # --- User registration triage (OK / Hunt / Remove / Guest) ---
    $rosterBadgeClass = @{
        Remove                        = 'bg-danger'
        Hunt                          = 'bg-warning text-dark'
        'Guest (FIDO2 Not Supported)' = 'bg-secondary'
        OK                            = 'bg-success'
    }
    $rosterCounts = @{ Remove = 0; Hunt = 0; 'Guest (FIDO2 Not Supported)' = 0; OK = 0 }
    $rosterAdminCounts = @{ Remove = 0; Hunt = 0; 'Guest (FIDO2 Not Supported)' = 0; OK = 0 }
    foreach ($u in $UserRoster) {
        if ($rosterCounts.ContainsKey($u.Bucket)) {
            $rosterCounts[$u.Bucket]++
            if ($u.IsAdmin) { $rosterAdminCounts[$u.Bucket]++ }
        }
    }

    $rosterRowsHtml = foreach ($u in $UserRoster) {
        $badgeClass = $rosterBadgeClass[$u.Bucket]
        if (-not $badgeClass) { $badgeClass = 'bg-secondary' }
        $adminBadge = ''
        if ($u.IsAdmin) { $adminBadge = ' <span class="badge bg-dark">Admin</span>' }
        @"
      <tr>
        <td><span class="badge $badgeClass">$(ConvertTo-SAWHtmlEncoded $u.Bucket)</span></td>
        <td>$(ConvertTo-SAWHtmlEncoded $u.DisplayName)$adminBadge</td>
        <td>$(ConvertTo-SAWHtmlEncoded $u.UserPrincipalName)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $u.MethodsRegistered)</td>
      </tr>
"@
    }

    $rosterSectionHtml = ''
    if ($UserRoster.Count -gt 0) {
        $rosterSectionHtml = @"
  <h2 class="h4 mb-3">Security Info Registration - User Triage</h2>
  <div class="row g-3 mb-3">
    <div class="col-sm-6 col-lg-3">
      <div class="card stat-card red h-100"><div class="card-body">
        <div class="text-uppercase text-body-secondary small">Remove weak fallback ($($rosterAdminCounts.Remove) admin)</div>
        <div class="fs-2 fw-bold">$($rosterCounts.Remove)</div>
        <div class="text-body-secondary small">Has a phishing-resistant method AND a phone-based fallback still registered - the fallback enables a downgrade attack. Start with admins.</div>
      </div></div>
    </div>
    <div class="col-sm-6 col-lg-3">
      <div class="card stat-card yellow h-100"><div class="card-body">
        <div class="text-uppercase text-body-secondary small">Hunt for registration ($($rosterAdminCounts.Hunt) admin)</div>
        <div class="fs-2 fw-bold">$($rosterCounts.Hunt)</div>
        <div class="text-body-secondary small">No phishing-resistant method registered yet - target these users with the registration campaign. Start with admins.</div>
      </div></div>
    </div>
    <div class="col-sm-6 col-lg-3">
      <div class="card stat-card grey h-100"><div class="card-body">
        <div class="text-uppercase text-body-secondary small">Guests (FIDO2 not supported)</div>
        <div class="fs-2 fw-bold">$($rosterCounts.'Guest (FIDO2 Not Supported)')</div>
        <div class="text-body-secondary small">Guest/B2B users can't register FIDO2/passkeys in Entra yet (Microsoft: planned end of 2026) - not an actionable gap, just tracked for awareness.</div>
      </div></div>
    </div>
    <div class="col-sm-6 col-lg-3">
      <div class="card stat-card green h-100"><div class="card-body">
        <div class="text-uppercase text-body-secondary small">OK ($($rosterAdminCounts.OK) admin)</div>
        <div class="fs-2 fw-bold">$($rosterCounts.OK)</div>
        <div class="text-body-secondary small">Phishing-resistant method registered, no weak fallback in place. No action needed.</div>
      </div></div>
    </div>
  </div>
  <div class="table-responsive mb-4">
    <table class="table table-striped table-hover align-middle">
      <thead>
        <tr><th>Bucket</th><th>User</th><th>UPN</th><th>Methods Registered</th></tr>
      </thead>
      <tbody>
$($rosterRowsHtml -join "`n")
      </tbody>
    </table>
  </div>
"@
    }

    # --- Conditional Access policy inventory ---
    $caStateBadgeClass = @{
        'Enabled'                = 'bg-success'
        'Enabled (report-only)' = 'bg-warning text-dark'
        'Disabled'               = 'bg-secondary'
    }

    $caInventoryRowsHtml = foreach ($p in $CaPolicyInventory) {
        $badgeClass = $caStateBadgeClass[$p.State]
        if (-not $badgeClass) { $badgeClass = 'bg-secondary' }
        $registrationBadge = ''
        if ($p.TargetsSecurityInfoRegistration) {
            $registrationBadge = ' <span class="badge bg-info text-dark">Security Info Registration</span>'
        }
        @"
      <tr>
        <td>$(ConvertTo-SAWHtmlEncoded $p.DisplayName)$registrationBadge</td>
        <td><span class="badge $badgeClass">$(ConvertTo-SAWHtmlEncoded $p.State)</span></td>
        <td>$(ConvertTo-SAWHtmlEncoded $p.UserTargetSummary)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $p.AppTargetSummary)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $p.GrantControlsSummary)</td>
      </tr>
"@
    }

    $caInventorySectionHtml = ''
    if ($CaPolicyInventory.Count -gt 0) {
        $caInventorySectionHtml = @"
  <h2 class="h4 mb-3">Conditional Access Policy Inventory</h2>
  <p class="text-body-secondary small">Every policy as configured in the tenant, independent of the synthetic pass/fail checks above.</p>
  <div class="table-responsive mb-4">
    <table class="table table-striped table-hover align-middle">
      <thead>
        <tr><th>Policy</th><th>State</th><th>Users/Roles</th><th>Apps/Actions</th><th>Grant Controls</th></tr>
      </thead>
      <tbody>
$($caInventoryRowsHtml -join "`n")
      </tbody>
    </table>
  </div>
"@
    }

    # --- Remediation Roadmap (IST -> SOLL phased work plan) ---
    $roadmapSectionHtml = ''
    if ($Roadmap.Count -gt 0) {
        $phaseCardsHtml = foreach ($phase in $Roadmap) {
            $headerBadge = if ($phase.IsComplete) {
                '<span class="badge bg-success">Complete</span>'
            }
            else {
                "<span class=""badge bg-secondary"">$($phase.OutstandingCount) outstanding</span>"
            }

            $outstandingItemsHtml = foreach ($o in $phase.OutstandingRules) {
                $badgeClass = $statusBadgeClass[$o.Status]
                if (-not $badgeClass) { $badgeClass = 'bg-secondary' }
                $blockedHtml = ''
                if ($o.Blocked) {
                    $blockedHtml = " <span class=""badge bg-dark"">Blocked - waiting on $(ConvertTo-SAWHtmlEncoded (($o.BlockedBy) -join ', '))</span>"
                }
                @"
          <div class="list-group-item">
            <div class="d-flex flex-wrap align-items-center gap-2 mb-1">
              <span class="badge $badgeClass">$(ConvertTo-SAWHtmlEncoded $o.Status)</span>
              <strong>$(ConvertTo-SAWHtmlEncoded $o.RuleID)</strong>
              <span class="text-body-secondary">$(ConvertTo-SAWHtmlEncoded $o.Category) / $(ConvertTo-SAWHtmlEncoded $o.Setting)</span>
              <span class="badge bg-light text-dark border">$(ConvertTo-SAWHtmlEncoded $o.Severity)</span>$blockedHtml
            </div>
            <p class="mb-0 text-body-secondary">$(ConvertTo-SAWHtmlEncoded $o.Recommendation)</p>
          </div>
"@
            }
            if ($phase.OutstandingRules.Count -eq 0) {
                $outstandingItemsHtml = '<div class="list-group-item text-body-secondary">All rules in this phase are already Green or not applicable.</div>'
            }

            @"
      <div class="card mb-3">
        <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
          <strong>$(ConvertTo-SAWHtmlEncoded $phase.PhaseName)</strong>
          <span class="d-flex align-items-center gap-2">
            <span class="text-body-secondary small">$($phase.CompletedCount)/$($phase.TotalCount) complete$(if ($phase.NotApplicableCount -gt 0) { " &middot; $($phase.NotApplicableCount) N/A" })</span>
            $headerBadge
          </span>
        </div>
        <div class="list-group list-group-flush">
$($outstandingItemsHtml -join "`n")
        </div>
      </div>
"@
        }

        $roadmapSectionHtml = @"
  <h2 class="h4 mb-3">Remediation Roadmap</h2>
  <p class="text-body-secondary small">The IST -&gt; SOLL work plan, in order. Each phase should generally be worked before the next; a <span class="badge bg-dark">Blocked</span> item is waiting on a rule from an earlier phase and should not be tackled out of order, even where technically possible, since doing so can carry real rollout risk (e.g. account lockouts).</p>
$($phaseCardsHtml -join "`n")
"@
    }

    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $totalRules = $RuleResults.Count

    $html = @"
<!doctype html>
<html lang="en" data-bs-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure At Work - Authentication Assessment Dashboard</title>
<link rel="stylesheet" href="vendor/bootstrap/bootstrap.min.css">
<style>
  body { padding-bottom: 3rem; }
  .navbar-brand { font-weight: 600; }
  .stat-card { border-left: 4px solid; }
  .stat-card.green { border-left-color: #198754; }
  .stat-card.yellow { border-left-color: #ffc107; }
  .stat-card.red { border-left-color: #dc3545; }
  .stat-card.grey { border-left-color: #6c757d; }
</style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
  <div class="container-fluid">
    <span class="navbar-brand">Secure At Work &middot; Authentication Assessment Dashboard</span>
    <span class="navbar-text text-white-50">Generated $generated &middot; $totalRules checks &middot; Read-only assessment, no tenant changes made</span>
  </div>
</nav>
<div class="container-fluid">

  <div class="alert alert-secondary d-flex flex-wrap gap-3 align-items-center mb-4" role="alert">
    <div><strong>SOLL baseline:</strong> $(ConvertTo-SAWHtmlEncoded $BaselineName)</div>
    <div class="text-body-secondary">SOLL = target state for this customer &middot; IST = what was actually observed in the tenant</div>
  </div>
$(if ($DomainServicesDetected) {
@"
  <div class="alert alert-warning d-flex flex-wrap gap-3 align-items-center mb-4" role="alert">
    <div><strong>Possible Microsoft Entra Domain Services usage detected</strong> (an "AAD DC Administrators" group was found in the directory) - a proxy signal, not authoritative. Domain Services itself is managed via Azure Resource Manager, outside this Graph-only toolkit's reach. Worth confirming with the customer.</div>
  </div>
"@
})

  <h2 class="h4 mb-3">Overview</h2>
  <div class="row g-3 mb-4">
    <div class="col-sm-6 col-lg-3">
      <div class="card stat-card green h-100"><div class="card-body">
        <div class="text-uppercase text-body-secondary small">Green</div>
        <div class="fs-2 fw-bold">$($counts.Green)</div>
      </div></div>
    </div>
    <div class="col-sm-6 col-lg-3">
      <div class="card stat-card yellow h-100"><div class="card-body">
        <div class="text-uppercase text-body-secondary small">Yellow</div>
        <div class="fs-2 fw-bold">$($counts.Yellow)</div>
      </div></div>
    </div>
    <div class="col-sm-6 col-lg-3">
      <div class="card stat-card red h-100"><div class="card-body">
        <div class="text-uppercase text-body-secondary small">Red</div>
        <div class="fs-2 fw-bold">$($counts.Red)</div>
      </div></div>
    </div>
    <div class="col-sm-6 col-lg-3">
      <div class="card stat-card grey h-100"><div class="card-body">
        <div class="text-uppercase text-body-secondary small">Grey / N/A</div>
        <div class="fs-2 fw-bold">$($counts.Grey)</div>
      </div></div>
    </div>
  </div>

  <div class="row mb-4 g-3">
    <div class="col-lg-5">
      <div class="card h-100"><div class="card-body">
        <h3 class="h6">Findings by Status</h3>
        <canvas id="statusChart" height="220"></canvas>
      </div></div>
    </div>
    <div class="col-lg-7">
      <div class="card h-100"><div class="card-body">
        <h3 class="h6">Findings by Category</h3>
        <canvas id="categoryChart" height="220"></canvas>
      </div></div>
    </div>
  </div>

$roadmapSectionHtml
  <h2 class="h4 mb-3">Risk Findings &amp; Recommendations</h2>
  <div class="list-group mb-4">
$($findingsHtml -join "`n")
  </div>

$rosterSectionHtml
$caInventorySectionHtml
  <h2 class="h4 mb-3">Detail by Category</h2>
  <ul class="nav nav-pills mb-3" role="tablist">
$($navItems -join "`n")
  </ul>
  <div class="tab-content">
$($tabPanes -join "`n")
  </div>

  <p class="text-body-secondary small mt-5">
    Categories not yet backed by a dedicated collector (Guests, a standalone Break Glass view,
    OATH, Certificate Authentication) aren't shown as separate tabs here. SMS and Voice
    currently appear as individual settings under Authentication Methods, since that's where
    they're actually collected.
  </p>
</div>

<script src="vendor/bootstrap/bootstrap.bundle.min.js"></script>
<script src="vendor/chartjs/chart.umd.min.js"></script>
<script>
  new Chart(document.getElementById('statusChart'), {
    type: 'doughnut',
    data: {
      labels: $statusChartLabelsJson,
      datasets: [{
        data: $statusChartDataJson,
        backgroundColor: ['#198754', '#ffc107', '#dc3545', '#6c757d']
      }]
    },
    options: { plugins: { legend: { position: 'bottom' } } }
  });

  new Chart(document.getElementById('categoryChart'), {
    type: 'bar',
    data: {
      labels: $categoryLabelsJson,
      datasets: [
        { label: 'Red', data: $categoryRedJson, backgroundColor: '#dc3545' },
        { label: 'Yellow', data: $categoryYellowJson, backgroundColor: '#ffc107' },
        { label: 'Green', data: $categoryGreenJson, backgroundColor: '#198754' }
      ]
    },
    options: {
      responsive: true,
      scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } },
      plugins: { legend: { position: 'bottom' } }
    }
  });
</script>
</body>
</html>
"@

    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if ($outputDirectory -and -not (Test-Path -Path $outputDirectory)) {
        New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    }

    $vendorSource = Join-Path $PSScriptRoot 'vendor'
    $vendorDestination = Join-Path $outputDirectory 'vendor'
    Copy-Item -Path $vendorSource -Destination $vendorDestination -Recurse -Force

    $html | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Verbose "Export-SAWDashboard: wrote dashboard to $OutputPath (vendor assets copied to $vendorDestination)"
    Get-Item -Path $OutputPath
}
