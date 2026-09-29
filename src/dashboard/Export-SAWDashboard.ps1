function Export-SAWDashboard {
    <#
    .SYNOPSIS
        Renders rules engine results into the full Secure At Work dashboard (spec section 9).
    .DESCRIPTION
        The single HTML output of an assessment run: a multi-section Bootstrap/Chart.js
        dashboard with an Overview carrying status/category charts, a prioritized Risk Findings
        & Recommendations list, a remediation roadmap, user-journey detail, and policy
        inventories.

        There used to be a second, flat-table renderer alongside this one
        (Export-SAWHtmlReport.ps1), kept from before this dashboard existed. It was removed once
        it started actively misleading rather than merely duplicating: every section added after
        it (roadmap, nudge forecast, FIDO2 key inventory, Staged Rollout and its caveats) landed
        here only, so the flat report would show e.g. SSPR001 red with no sign that Staged
        Rollout qualifies that finding for the tenant in question. One renderer means one answer.

        Bootstrap and Chart.js are vendored locally under src/dashboard/vendor/ (no CDN
        reference) per spec section 5 ("Everything runs locally"). This function copies that
        vendor/ folder next to the generated index.html so the whole output directory is
        self-contained and portable - it can be zipped up and opened offline. The Secure At Work
        logo under src/dashboard/branding/ is copied the same way, alongside vendor/ rather than
        inside it since it isn't a third-party library.

        Sections not yet backed by a dedicated collector (Guests, a standalone Break Glass
        view, OATH, Certificate Authentication as their own tabs) are intentionally omitted
        rather than rendered empty; SMS and Voice currently appear as individual settings
        within the Authentication Methods tab, since that's where they're actually collected.
    .PARAMETER RuleResults
        Output of Invoke-SAWRulesEngine.
    .PARAMETER UserRoster
        Optional output of ConvertTo-SAWUserRegistrationRoster, optionally further enriched by
        ConvertTo-SAWMethodUsageRoster (one hashtable per user, with Bucket = OK/Hunt/Remove).
        When supplied, renders a "Security Info Registration - User Triage" section: who's fine,
        who needs hunting down to register a phishing-resistant method, and who has a
        downgrade-risk fallback method to remove - already sorted Remove > Hunt > OK, admins
        first within each bucket. Omitted entirely if empty/absent. If entries carry
        HasUnusedRegisteredMethod/UnusedRegisteredMethods (from ConvertTo-SAWMethodUsageRoster),
        a "Not recently used" badge is also shown per flagged registered method.
    .PARAMETER MethodUsageDaysBack
        The lookback window (in days) used when the caller computed HasUnusedRegisteredMethod -
        shown in the section note so the "recently used" claim states its own window rather than
        being vague about it. Purely cosmetic here (this function does no date math itself);
        should match whatever -DaysBack was actually passed to the Get-SAWSignInLogs call that
        fed ConvertTo-SAWMethodUsageRoster. Defaults to 90 to match that function's own default.
    .PARAMETER AuthMethodsInventory
        Optional output of ConvertTo-SAWAuthenticationMethodsInventory (one hashtable per
        authentication method type). When supplied, renders an "Authentication Methods Policy
        Inventory" section listing every method's enabled/disabled state, who's included/
        excluded (counts only - no group/user name resolution, to avoid an extra Graph call),
        and key settings in plain language - independent of the pass/fail checks in the rules
        engine. Omitted entirely if empty/absent.
    .PARAMETER CaPolicyInventory
        Optional output of ConvertTo-SAWConditionalAccessInventory (one hashtable per CA
        policy). When supplied, renders a "Conditional Access Policy Inventory" section
        listing every policy's name, state, targets, and grant controls - independent of the
        handful of synthetic pass/fail CA checks in the rules engine. Omitted entirely if
        empty/absent.
    .PARAMETER Fido2KeyInventory
        Optional output of ConvertTo-SAWFido2KeyInventory (a single hashtable, not one per
        anything). When supplied and key restrictions are enforced, renders a "FIDO2 Key
        Restrictions" section resolving the tenant's raw allow/block-listed AAGUIDs into
        human-readable key/provider names - the answer to "which keys are actually allowed"
        that Graph's raw GUIDs don't give you on their own. Omitted entirely if absent or if
        key restrictions aren't enforced (nothing to list).
    .PARAMETER NudgeForecast
        Optional output of ConvertTo-SAWNudgeForecast (a hashtable with Users and Summary). When
        supplied, renders a "Who Will Be Nudged" section on the User Journeys tab: per-interrupt
        counts, the named users behind each count, and any tenant-wide suppressor that means the
        real answer is "nobody". This exists for communication planning - the population that needs
        telling before a prompt appears, not after. Omitted entirely if absent.
    .PARAMETER Roadmap
        Optional output of ConvertTo-SAWRemediationRoadmap (one hashtable per phase). When
        supplied, renders a "Remediation Roadmap" section right after the Overview - the
        answer to "what do I fix, in what order" rather than just a flat findings list: each
        phase shows its completion state, and each outstanding rule within it shows whether
        it's safe to work on now or Blocked on an earlier phase's rule still being open.
        Omitted entirely if empty/absent.
    .PARAMETER TenantDisplayName
        The assessed tenant's display name (typically Get-SAWTenantProfile's .DisplayName).
        Shown, together with -TenantId and -RunTimestamp, in a banner at the very top of the
        page and in the browser tab title - so it's unmistakable which environment and point in
        time a given report/dashboard is for, especially with several open at once (different
        tenants, or repeat runs of the same one). Omitted entirely from the banner if empty.
    .PARAMETER TenantId
        The assessed tenant's GUID (typically Get-SAWTenantProfile's .TenantId). Shown alongside
        -TenantDisplayName in the banner. Omitted entirely if empty.
    .PARAMETER RunTimestamp
        This run's timestamp in the same yyyyMMdd-HHmmss form used to namespace report/history
        output (e.g. "20260805-140901"), reformatted for display as "2026-08-05 14:09:01" in the
        banner. A value that doesn't match that exact shape is shown as-is rather than dropped,
        so a caller passing something else still gets useful (if unformatted) output instead of
        silence. Omitted entirely from the banner if empty.
    .PARAMETER BaselineName
        Display name of the customer SOLL baseline that produced these results (typically a
        baseline preset's "name" field), shown in the navbar and Overview for traceability.
        Defaults to a label indicating no customer-specific baseline was applied.
    .PARAMETER DomainServicesDetected
        Whether Get-SAWTenantProfile found an "AAD DC Administrators" group (a proxy signal
        for Microsoft Entra Domain Services - see ConvertTo-SAWTenantProfile.ps1). When true, a
        caveated note is shown in the top banner alongside the baseline name.
    .PARAMETER Trend
        Optional output of Get-SAWHistoryTrend (one hashtable per historical run for this
        tenant, ascending by RunTimestamp). When supplied with 2 or more runs, renders a "Trend
        Over Time" section (a line chart of Green/Yellow/Red/Grey counts across every run, plus
        a small per-run table) right after the Overview - the lighter, at-a-glance counterpart
        to Invoke-SAWDriftReport.ps1's detailed two-run diff. With 0 or 1 runs, shows a "not
        enough history yet" note instead of a chart. Omitted entirely if not supplied at all.
    .PARAMETER TimelineMilestones
        Optional output of Get-SAWTimelineMilestones (hand-maintained, sourced Microsoft
        rollout dates - see config/timeline-milestones.json). When supplied, renders an
        "Upcoming Microsoft Deadlines" section near the top of the dashboard - before the
        Overview, since these are external, time-driven items independent of this run's
        findings - showing each milestone's date, days remaining (or "N days ago" once past),
        description, and a link to its source. Color-coded by urgency (<=14 days = red,
        <=45 days = yellow, further out or already past = neutral). Omitted entirely if
        empty/absent.
    .PARAMETER FlowScenarios
        Optional output of ConvertTo-SAWRegistrationFlowScenarios (one hashtable per documented
        flow, each with a Steps array). When supplied, renders a "What Users Can Expect (IST vs.
        SOLL)" section: real, Microsoft-sourced end-to-end flows (new-user TAP bootstrap, SSPR
        eligibility, existing-user re-registration, CA-gated registration), each step marked
        applicable or not against this tenant's actual collected settings. Answers "what will an
        end user actually experience" rather than a single setting's pass/fail state. Omitted
        entirely if empty/absent.
    .PARAMETER ReadingGuideHtml
        Optional pre-rendered HTML fragment (e.g. docs/reading-the-report.md run through
        ConvertTo-SAWMarkdownHtml.ps1 by the caller) explaining what the assessment is and how
        to read it. When supplied (non-empty), the whole dashboard is wrapped in two top-level
        tabs - "Assessment" (everything below, unchanged) and "Reading This Report" (this HTML,
        rendered as-is) - so the explainer travels with the dashboard file itself rather than
        needing a separate doc alongside it. When omitted (the default), the dashboard renders
        exactly as before with no tab wrapper at all, for full backward compatibility.

        This function does not read the .md file or do any Markdown conversion itself - it just
        renders whatever HTML it's given, same as every other optional section here receives
        already-derived data rather than a file path.
    .PARAMETER OutputPath
        File path to write index.html to (e.g. reports/dashboard/index.html). vendor/ and
        branding/ subfolders are created alongside it. Parent directory is created if missing.
    .OUTPUTS
        System.IO.FileInfo
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$RuleResults,

        [string]$TenantDisplayName = '',

        [string]$TenantId = '',

        [string]$RunTimestamp = '',

        [AllowEmptyCollection()]
        [object[]]$UserRoster = @(),

        [int]$MethodUsageDaysBack = 90,

        [AllowEmptyCollection()]
        [object[]]$AuthMethodsInventory = @(),

        [AllowEmptyCollection()]
        [object[]]$CaPolicyInventory = @(),

        [object]$Fido2KeyInventory = $null,

        [object]$NudgeForecast = $null,

        # Null for a cloud-native tenant, where Staged Rollout cannot apply and the orchestrator
        # deliberately doesn't call for it. Distinct from an inventory whose .IsAvailable is
        # $false, which means "this tenant could have it, but we couldn't read it".
        [AllowNull()]
        [object]$StagedRolloutInventory = $null,

        [AllowEmptyCollection()]
        [object[]]$Roadmap = @(),

        [string]$BaselineName = 'Toolkit default (no customer-specific baseline applied)',

        [bool]$DomainServicesDetected = $false,

        [AllowNull()]
        [object[]]$Trend = $null,

        [AllowEmptyCollection()]
        [object[]]$TimelineMilestones = @(),

        [AllowEmptyCollection()]
        [object[]]$FlowScenarios = @(),

        [string]$ReadingGuideHtml = '',

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

    # --- Trend over time (optional - Get-SAWHistoryTrend output) ---
    $trendSectionHtml = ''
    $trendScriptHtml = ''
    if ($null -ne $Trend) {
        if (@($Trend).Count -lt 2) {
            $trendSectionHtml = @"
  <h2 class="h4 mb-3">Trend Over Time</h2>
  <p class="text-body-secondary small mb-4">Not enough history yet for this tenant to show a trend - at least 2 runs are needed. Run this assessment again later to start building one.</p>
"@
        }
        else {
            $trendLabelsJson = @($Trend | ForEach-Object { $_.RunTimestamp }) | ConvertTo-Json -Compress
            $trendGreenJson = @($Trend | ForEach-Object { $_.Counts.Green }) | ConvertTo-Json -Compress
            $trendYellowJson = @($Trend | ForEach-Object { $_.Counts.Yellow }) | ConvertTo-Json -Compress
            $trendRedJson = @($Trend | ForEach-Object { $_.Counts.Red }) | ConvertTo-Json -Compress
            $trendGreyJson = @($Trend | ForEach-Object { $_.Counts.Grey }) | ConvertTo-Json -Compress

            $trendRowsHtml = foreach ($t in $Trend) {
                @"
      <tr>
        <td><strong class="saw-trend-run">$(ConvertTo-SAWHtmlEncoded $t.RunTimestamp)</strong><small class="saw-trend-baseline">$(ConvertTo-SAWHtmlEncoded $t.BaselineName)</small></td>
        <td><div class="saw-trend-counts"><span class="badge bg-success" title="Green">$($t.Counts.Green)</span><span class="badge bg-warning text-dark" title="Yellow">$($t.Counts.Yellow)</span><span class="badge bg-danger" title="Red">$($t.Counts.Red)</span><span class="badge bg-secondary" title="Grey">$($t.Counts.Grey)</span></div></td>
      </tr>
"@
            }

            $trendSectionHtml = @"
  <section class="saw-section saw-trend-section">
    <div class="saw-section-heading"><div><h2>Trend over time</h2><p>$(@($Trend).Count) runs · status counts by assessment date</p></div><a href="Invoke-SAWDriftReport.ps1" class="small">Compare two runs</a></div>
    <div class="saw-trend-grid">
      <div class="saw-trend-chart-panel"><canvas id="trendChart" height="300"></canvas></div>
      <div class="saw-trend-history-panel">
        <table class="table table-sm align-middle mb-0 saw-trend-table">
          <thead><tr><th>Run and baseline</th><th>G / Y / R / Grey</th></tr></thead>
          <tbody>
$($trendRowsHtml -join "`n")
          </tbody>
        </table>
      </div>
    </div>
  </section>
"@

            $trendScriptHtml = @"
  new Chart(document.getElementById('trendChart'), {
    type: 'line',
    data: {
      labels: $trendLabelsJson,
      datasets: [
        { label: 'Green', data: $trendGreenJson, borderColor: '#198754', backgroundColor: '#198754', tension: 0.2 },
        { label: 'Yellow', data: $trendYellowJson, borderColor: '#ffc107', backgroundColor: '#ffc107', tension: 0.2 },
        { label: 'Red', data: $trendRedJson, borderColor: '#dc3545', backgroundColor: '#dc3545', tension: 0.2 },
        { label: 'Grey', data: $trendGreyJson, borderColor: '#6c757d', backgroundColor: '#6c757d', tension: 0.2 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { autoSkip: true, maxTicksLimit: 8, minRotation: 0, maxRotation: 0 } },
        y: { beginAtZero: true, ticks: { precision: 0 } }
      },
      plugins: { legend: { position: 'bottom' } }
    }
  });
"@
        }
    }
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

    function ConvertTo-SAWRosterRowHtml {
        param($User)
        $adminBadge = ''
        if ($User.IsAdmin) { $adminBadge = ' <span class="badge bg-dark">Admin</span>' }
        $externalMemberBadge = ''
        if ($User.IsPossibleExternalMember) {
            $externalMemberBadge = ' <span class="badge bg-info text-dark" title="UPN contains &quot;#EXT#&quot; (Microsoft''s auto-generated shape for a B2B guest invitation) but userType is Member, not Guest - likely a guest converted to Member, or provisioned as Member via cross-tenant sync. Still externally-sourced; not authoritative, see docs/reading-the-report.md.">Possible External Member</span>'
        }
        $whfbOnlyBadge = ''
        if ($User.IsWhfbOnly) {
            $whfbOnlyBadge = ' <span class="badge bg-warning text-dark" title="Windows Hello for Business is bound to the specific device it was set up on - it cannot be carried to a different machine like a FIDO2 key or passkey can. This user''s only phishing-resistant method is WHfB, so they have no working phishing-resistant credential off that one device. Especially worth checking for admin accounts that don''t do routine interactive sign-in on a managed device.">WHfB-Only (Not Portable)</span>'
        }
        $smsVoiceOnlyBadge = ''
        if ($User.IsSmsVoiceOnlyMfa) {
            $smsVoiceOnlyBadge = ' <span class="badge bg-danger" title="SMS/Voice is this user''s ONLY registered MFA method - nothing else at all. This is exactly the population Microsoft''s 2027-02-01 SMS/Voice retirement blocks with a mandatory, no-opt-out passkey registration prompt (see Upcoming Microsoft Deadlines). Narrower than the general phone-based-fallback badge below: a user with SMS AND another method is not in this population.">SMS/Voice-Only MFA</span>'
        }
        $unusedMethodsHtml = ''
        if ($User.HasUnusedRegisteredMethod) {
            $unusedMethodsHtml = " <span class=""badge bg-danger"" title=""Registered, but not observed as used in any successful sign-in step in the analysis window. Could mean the device/method is no longer available, the user relies on something else day to day, or the registration is simply stale - worth checking rather than assuming either way. Only a well-established subset of method types is evaluated for this, see docs/reading-the-report.md."">Not recently used: $(ConvertTo-SAWHtmlEncoded $User.UnusedRegisteredMethods)</span>"
        }
        $policyDisabledMethodsHtml = ''
        if ($User.HasPolicyDisabledMethod) {
            $policyDisabledMethodsHtml = " <span class=""badge bg-dark"" title=""Registered, but the tenant's authentication methods policy currently has this method type Disabled - this credential cannot be used to sign in anymore, not just unused. Safe to clean up. Windows Hello for Business and passkey variants aren't evaluated here (no tenant policy toggle exists for WHfB; passkey isn't mapped yet), see docs/reading-the-report.md."">Disabled by policy: $(ConvertTo-SAWHtmlEncoded $User.PolicyDisabledMethods)</span>"
        }
        $systemPreferredDisplay = if ($User.SystemPreferredMethod) { $User.SystemPreferredMethod } else { '-' }
        return @"
      <tr>
        <td>$(ConvertTo-SAWHtmlEncoded $User.DisplayName)$adminBadge$externalMemberBadge$whfbOnlyBadge$smsVoiceOnlyBadge</td>
        <td>$(ConvertTo-SAWHtmlEncoded $User.UserPrincipalName)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $User.MethodsRegistered)$unusedMethodsHtml$policyDisabledMethodsHtml</td>
        <td class="text-body-secondary small" title="What System-Preferred Authentication would currently present first at sign-in for this user, if that tenant-wide setting is active - see the Authentication Methods Policy Inventory section. Doesn't affect this user's OK/Hunt/Remove bucket.">$(ConvertTo-SAWHtmlEncoded $systemPreferredDisplay)</td>
      </tr>
"@
    }

    # Buckets shown as their own collapsible section (native <details>, no extra Bootstrap JS
    # wiring needed) rather than one flat table with a Bucket column - the point of grouping is
    # to work through "everyone in Hunt" as a batch, not scan a mixed list row by row. Remove/
    # Hunt/Guest start expanded (actionable); OK starts collapsed (nothing to do, just noise
    # otherwise). Order matches the existing bucket-rank sort (Remove > Hunt > Guest > OK).
    $rosterBucketOrder = @('Remove', 'Hunt', 'Guest (FIDO2 Not Supported)', 'OK')
    $rosterBucketDescriptions = @{
        Remove                        = 'Has a phishing-resistant method AND a phone-based fallback still registered - the fallback enables a downgrade attack. Start with admins.'
        Hunt                          = 'No phishing-resistant method registered yet - target these users with the registration campaign. Start with admins.'
        'Guest (FIDO2 Not Supported)' = "Guest/B2B users can't register FIDO2/passkeys in Entra yet (Microsoft: planned end of 2026) - not an actionable gap, just tracked for awareness."
        OK                            = 'Phishing-resistant method registered, no weak fallback in place. No action needed.'
    }

    $rosterSectionsHtml = foreach ($bucket in $rosterBucketOrder) {
        $usersInBucket = @($UserRoster | Where-Object { $_.Bucket -eq $bucket })
        if ($usersInBucket.Count -eq 0) { continue }

        $badgeClass = $rosterBadgeClass[$bucket]
        if (-not $badgeClass) { $badgeClass = 'bg-secondary' }
        $adminCount = @($usersInBucket | Where-Object { $_.IsAdmin }).Count
        $openAttr = if ($bucket -eq 'OK') { '' } else { ' open' }
        $bucketRowsHtml = ($usersInBucket | ForEach-Object { ConvertTo-SAWRosterRowHtml -User $_ }) -join "`n"

        @"
  <details class="card mb-3"$openAttr>
    <summary class="card-header" style="cursor: pointer;">
      <span class="badge $badgeClass">$(ConvertTo-SAWHtmlEncoded $bucket)</span>
      <strong>$($usersInBucket.Count)</strong> user$(if ($usersInBucket.Count -ne 1) { 's' }) ($adminCount admin)
      <span class="text-body-secondary small">- $(ConvertTo-SAWHtmlEncoded $rosterBucketDescriptions[$bucket])</span>
    </summary>
    <div class="table-responsive">
      <table class="table table-striped table-hover align-middle mb-0">
        <thead>
          <tr><th>User</th><th>UPN</th><th>Methods Registered</th><th>System-Preferred</th></tr>
        </thead>
        <tbody>
$bucketRowsHtml
        </tbody>
      </table>
    </div>
  </details>
"@
    }

    $possibleExternalMemberCount = @($UserRoster | Where-Object { $_.IsPossibleExternalMember }).Count
    $externalMemberNoteHtml = ''
    if ($possibleExternalMemberCount -gt 0) {
        $plural = if ($possibleExternalMemberCount -eq 1) { '' } else { 's' }
        $externalMemberNoteHtml = @"
  <p class="text-body-secondary small"><span class="badge bg-info text-dark">Possible External Member</span> ($possibleExternalMemberCount user$plural below) - UPN has the "#EXT#" shape Microsoft auto-generates for B2B guest invitations, but userType is Member rather than Guest. Likely a guest that was converted to Member, or provisioned as Member via cross-tenant sync - either way still externally-sourced. A UPN-shape heuristic, not authoritative (Graph's registration data has no stronger signal to confirm it) - worth verifying with the customer.</p>
"@
    }

    $whfbOnlyCount = @($UserRoster | Where-Object { $_.IsWhfbOnly }).Count
    $whfbOnlyNoteHtml = ''
    if ($whfbOnlyCount -gt 0) {
        $plural = if ($whfbOnlyCount -eq 1) { '' } else { 's' }
        $whfbOnlyNoteHtml = @"
  <p class="text-body-secondary small"><span class="badge bg-warning text-dark">WHfB-Only (Not Portable)</span> ($whfbOnlyCount user$plural below) - Windows Hello for Business is bound to the device it was set up on, unlike a FIDO2 key or passkey. Relying on WHfB alone is a real gap for admin accounts especially, since many admins don't do routine interactive sign-in on a managed device with their admin account at all - worth confirming these users actually have a working phishing-resistant option off their primary device.</p>
"@
    }

    $smsVoiceOnlyCount = @($UserRoster | Where-Object { $_.IsSmsVoiceOnlyMfa }).Count
    $smsVoiceOnlyNoteHtml = ''
    if ($smsVoiceOnlyCount -gt 0) {
        $plural = if ($smsVoiceOnlyCount -eq 1) { '' } else { 's' }
        $smsVoiceOnlyNoteHtml = @"
  <p class="text-body-secondary small"><span class="badge bg-danger">SMS/Voice-Only MFA</span> ($smsVoiceOnlyCount user$plural below) - SMS/Voice is this user's ONLY registered MFA method, nothing else. This is exactly the population Microsoft's 2027-02-01 SMS/Voice retirement blocks with a mandatory, no-opt-out passkey registration prompt (see Upcoming Microsoft Deadlines) - narrower than the general phone-based-fallback case, since a user with SMS plus another method is unaffected by that specific date.</p>
"@
    }

    $unusedMethodCount = @($UserRoster | Where-Object { $_.HasUnusedRegisteredMethod }).Count
    $unusedMethodNoteHtml = ''
    if ($unusedMethodCount -gt 0) {
        $plural = if ($unusedMethodCount -eq 1) { '' } else { 's' }
        $unusedMethodNoteHtml = @"
  <p class="text-body-secondary small"><span class="badge bg-danger">Not recently used</span> ($unusedMethodCount user$plural below) - a registered method with no successful sign-in using it in the last $MethodUsageDaysBack day(s) <em>as far as the logs go back</em>. Entra retains sign-in logs for seven days on Entra ID Free and 30 days on P1/P2, so if a longer window was requested this badge really reflects whatever was actually retained, not the full requested period. Could mean the device/method is no longer available, the user relies on something else day to day, or the registration is simply stale - not a confirmed problem on its own, but worth checking rather than assuming either way. Only a well-established subset of method types is evaluated (see docs/reading-the-report.md); an absent method type isn't necessarily fine, it just wasn't checked.</p>
"@
    }

    $policyDisabledMethodCount = @($UserRoster | Where-Object { $_.HasPolicyDisabledMethod }).Count
    $policyDisabledMethodNoteHtml = ''
    if ($policyDisabledMethodCount -gt 0) {
        $plural = if ($policyDisabledMethodCount -eq 1) { '' } else { 's' }
        $policyDisabledMethodNoteHtml = @"
  <p class="text-body-secondary small"><span class="badge bg-dark">Disabled by policy</span> ($policyDisabledMethodCount user$plural below) - a registered method whose tenant-wide authentication methods policy toggle is currently Disabled. Unlike "Not recently used" above, this isn't a proxy - the credential structurally cannot be used to sign in anymore, so it's safe to clean up. Windows Hello for Business and passkey variants aren't evaluated here (no tenant policy toggle exists for WHfB; passkey isn't mapped yet), see docs/reading-the-report.md.</p>
"@
    }

    $rosterSectionHtml = ''
    if ($UserRoster.Count -gt 0) {
        $rosterSectionHtml = @"
  <h2 class="h4 mb-3">Security Info Registration - User Triage</h2>
$externalMemberNoteHtml
$whfbOnlyNoteHtml
$smsVoiceOnlyNoteHtml
$unusedMethodNoteHtml
$policyDisabledMethodNoteHtml
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
$($rosterSectionsHtml -join "`n")
"@
    }

    # --- Authentication methods policy inventory ---
    $authMethodStateBadgeClass = @{
        'Enabled'                          = 'bg-success'
        'Disabled'                         = 'bg-secondary'
        'Enabled (second factor only)'     = 'bg-success'
        'Microsoft managed'                = 'bg-info text-dark'
    }

    $rolloutNoteCount = @($AuthMethodsInventory | Where-Object { $_.RolloutNote }).Count

    $authMethodsInventoryRowsHtml = foreach ($m in $AuthMethodsInventory) {
        $badgeClass = $authMethodStateBadgeClass[$m.State]
        if (-not $badgeClass) { $badgeClass = 'bg-secondary' }
        $rolloutBadge = ''
        if ($m.RolloutNote) {
            $rolloutBadge = " <span class=""badge bg-warning text-dark"" title=""$(ConvertTo-SAWHtmlEncoded $m.RolloutNote)"">Rollout timing not confirmed</span>"
        }
        @"
      <tr>
        <td>$(ConvertTo-SAWHtmlEncoded $m.Setting)</td>
        <td><span class="badge $badgeClass">$(ConvertTo-SAWHtmlEncoded $m.State)</span>$rolloutBadge</td>
        <td>$(ConvertTo-SAWHtmlEncoded $m.TargetSummary)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $m.SettingsSummary)</td>
      </tr>
"@
    }

    $rolloutNoteExplainerHtml = ''
    if ($rolloutNoteCount -gt 0) {
        $plural = if ($rolloutNoteCount -eq 1) { '' } else { 's' }
        $rolloutNoteExplainerHtml = @"
  <p class="text-body-secondary small"><span class="badge bg-warning text-dark">Rollout timing not confirmed</span> ($rolloutNoteCount row$plural below) - this setting is at Microsoft's "Microsoft managed" state. Microsoft communicating a start date for a Microsoft-managed behavior change is not the same as every tenant already having it: tenants are migrated in batches on Microsoft's own schedule, invisible to this toolkit. The Settings column describes Microsoft's stated <em>intent</em> for this state, not a confirmed current fact for this specific tenant - hover the badge for detail, and re-check the admin center directly if the exact current behavior matters right now.</p>
"@
    }

    $authMethodsInventorySectionHtml = ''
    if ($AuthMethodsInventory.Count -gt 0) {
        $authMethodsInventorySectionHtml = @"
  <h2 class="h4 mb-3">Authentication Methods Policy Inventory</h2>
  <p class="text-body-secondary small">Every method as configured tenant-wide, independent of the pass/fail checks above. "Included" shows who can register/use the method (no group/user names resolved, to avoid an extra Graph call - counts only); "Excluded" is folded into that same column when present.</p>
$rolloutNoteExplainerHtml
  <div class="table-responsive mb-4">
    <table class="table table-striped table-hover align-middle">
      <thead>
        <tr><th>Method</th><th>State</th><th>Included / Excluded</th><th>Settings</th></tr>
      </thead>
      <tbody>
$($authMethodsInventoryRowsHtml -join "`n")
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

    # --- Staged Rollout: federated-to-managed migration state, and what it qualifies ---
    # Inventory only, never a pass/fail: Staged Rollout is a temporary migration state, so
    # "enabled" is neither good nor bad on its own. Three display states, kept distinct on
    # purpose, because collapsing them would each time turn a different unknown into a false
    # "no": not rendered at all (cloud-native tenant, cannot apply), couldn't read it (scope
    # missing), and read it (with or without policies).
    $stagedRolloutSectionHtml = ''
    if ($StagedRolloutInventory) {
        if (-not $StagedRolloutInventory.IsAvailable) {
            $stagedRolloutSectionHtml = @"
  <h2 class="h4 mb-3">Staged Rollout (Federated to Managed Authentication)</h2>
  <div class="alert alert-secondary" role="alert">
    <strong>Not read.</strong> $(ConvertTo-SAWHtmlEncoded $StagedRolloutInventory.UnavailableReason)
  </div>
"@
        }
        else {
            $stagedRolloutRowsHtml = foreach ($p in $StagedRolloutInventory.Policies) {
                $enabledBadge = if ($p.IsEnabled) {
                    '<span class="badge bg-primary">Enabled</span>'
                }
                else {
                    '<span class="badge bg-secondary">Disabled</span>'
                }
                $featureCell = if ($p.FeatureRecognized) {
                    ConvertTo-SAWHtmlEncoded $p.FeatureLabel
                }
                else {
                    "$(ConvertTo-SAWHtmlEncoded $p.FeatureLabel) <span class=""badge bg-warning text-dark"">Newer than this toolkit</span>"
                }
                $scopeCell = if ($p.AppliesToOrganization) {
                    '<span class="badge bg-warning text-dark">Entire organization</span>'
                }
                elseif ($p.GroupCount -gt 0) {
                    ConvertTo-SAWHtmlEncoded ($p.GroupNames -join ', ')
                }
                else {
                    '<span class="text-body-secondary">No groups targeted</span>'
                }
                @"
      <tr>
        <td>$featureCell</td>
        <td>$(ConvertTo-SAWHtmlEncoded $p.DisplayName)</td>
        <td>$enabledBadge</td>
        <td>$scopeCell</td>
      </tr>
"@
            }

            $stagedRolloutTableHtml = ''
            if ($StagedRolloutInventory.Policies.Count -gt 0) {
                $stagedRolloutTableHtml = @"
  <div class="table-responsive mb-4">
    <table class="table table-striped table-hover align-middle">
      <thead>
        <tr><th>Feature</th><th>Policy</th><th>State</th><th>Applies to</th></tr>
      </thead>
      <tbody>
$($stagedRolloutRowsHtml -join "`n")
      </tbody>
    </table>
  </div>
"@
            }

            $stagedRolloutCaveatsHtml = ''
            if ($StagedRolloutInventory.Caveats.Count -gt 0) {
                $caveatItemsHtml = foreach ($c in $StagedRolloutInventory.Caveats) {
                    @"
    <li class="mb-3">
      <strong>$(ConvertTo-SAWHtmlEncoded $c.Heading)</strong><br>
      $(ConvertTo-SAWHtmlEncoded $c.Detail)<br>
      <span class="text-body-secondary small">Qualifies: $(ConvertTo-SAWHtmlEncoded $c.AffectsRules)</span>
    </li>
"@
                }
                $stagedRolloutCaveatsHtml = @"
  <div class="alert alert-warning" role="alert">
    <h3 class="h6">Because Staged Rollout is active, some findings elsewhere in this report are qualified</h3>
    <p class="small mb-2">These aren't failures. They're places where the standard recommendation doesn't fully apply while the tenant is mid-migration, and following it anyway would produce a result that looks right and isn't.</p>
    <ul class="mb-0 small">
$($caveatItemsHtml -join "`n")
    </ul>
  </div>
"@
            }

            $stagedRolloutSectionHtml = @"
  <h2 class="h4 mb-3">Staged Rollout (Federated to Managed Authentication)</h2>
  <p class="text-body-secondary small">Staged Rollout moves a pilot group from federated sign-in (AD FS or a third-party identity provider) to Microsoft Entra, ahead of converting the whole domain. It's reported here as inventory rather than as a pass or fail, because Microsoft designs it as a temporary testing state rather than a configuration with a correct value. Group targeting is capped at 10 groups per feature, and nested and dynamic groups aren't supported.</p>
  <p class="small">$(ConvertTo-SAWHtmlEncoded $StagedRolloutInventory.Summary)</p>
$stagedRolloutTableHtml
$stagedRolloutCaveatsHtml
"@
        }
    }

    # --- FIDO2 key restrictions: which specific keys/providers are allowed ---
    $fido2KeyRowsHtml = foreach ($k in $Fido2KeyInventory.AllowedKeys) {
        $recognizedBadge = if ($k.Recognized) {
            '<span class="badge bg-success">Recognized</span>'
        }
        else {
            '<span class="badge bg-warning text-dark">Unrecognized</span>'
        }
      $managedCampaignBadge = if ($k.IsManagedCampaignQualifyingProvider) {
        '<span class="badge bg-success">Qualifying provider</span>'
      }
      else {
        '<span class="badge bg-secondary">Other</span>'
      }
        @"
      <tr>
      <td>$(ConvertTo-SAWHtmlEncoded $k.ProfileName)</td>
        <td><code>$(ConvertTo-SAWHtmlEncoded $k.Aaguid)</code></td>
        <td>$(ConvertTo-SAWHtmlEncoded $k.KnownName)</td>
      <td>$(ConvertTo-SAWHtmlEncoded $k.PasskeyType)</td>
      <td>$recognizedBadge $managedCampaignBadge</td>
      </tr>
"@
    }

    $fido2KeyInventorySectionHtml = ''
    if ($Fido2KeyInventory -and $Fido2KeyInventory.IsEnforced) {
        $fido2KeyInventorySectionHtml = @"
  <h2 class="h4 mb-3">FIDO2 Key Restrictions</h2>
  <p class="text-body-secondary small">$(ConvertTo-SAWHtmlEncoded $Fido2KeyInventory.EnforcementSummary) $(ConvertTo-SAWHtmlEncoded $Fido2KeyInventory.ProfileTypeGuidance) AAGUIDs are resolved against a hand-maintained reference list; an unrecognized AAGUID is a real key/provider this toolkit's reference list doesn't yet cover, not necessarily a problem. Check the FIDO Alliance Metadata Service or the vendor directly for anything unrecognized. Microsoft-managed nudge eligibility applies only to allow-list restrictions; block-lists do not participate in that check.</p>
  <div class="table-responsive mb-4">
    <table class="table table-striped table-hover align-middle">
      <thead>
        <tr><th>Passkey profile</th><th>AAGUID</th><th>Key / Provider</th><th>Profile type</th><th>Reference</th></tr>
      </thead>
      <tbody>
$($fido2KeyRowsHtml -join "`n")
      </tbody>
    </table>
  </div>
"@
    }

    # --- Who Will Be Nudged (communication planning) ---
    $nudgeSectionHtml = ''
    if ($NudgeForecast -and $NudgeForecast.Summary) {
        $ns = $NudgeForecast.Summary

        $nudgeGroups = @(
            @{ Key = 'NudgeAutoPasskeySept2026'; Title = 'Automatic passkey enablement (2026-09-01)'; Count = $ns.AutoPasskeySept2026Count
               Note = 'Microsoft-driven, arrives whether or not this tenant configures its own campaign. Users enabled for SMS/Voice are auto-enabled for passkeys and nudged on their next MFA sign-in, with unlimited snoozes by default. Highest communication priority, because the date is not in your control.' }
            @{ Key = 'NudgePasskeyCampaign'; Title = 'Registration campaign - passkey'; Count = $ns.PasskeyCampaignPotentialCount
               Note = 'Nudged after completing MFA, if in campaign scope and without a passkey on that device/browser.'
               ScopeSensitive = $true }
            @{ Key = 'NudgeAuthenticatorCampaign'; Title = 'Registration campaign - Microsoft Authenticator'; Count = $ns.AuthenticatorCampaignCount
               Note = 'Nudged after completing MFA, if in campaign scope and Authenticator push is not set up.'
               ScopeSensitive = $true }
            @{ Key = 'NudgeSsprRegistration'; Title = 'SSPR registration interrupt'; Count = $ns.SsprRegistrationCount
               Note = 'SSPR-enabled but not registered. Skippable indefinitely unless MFA registration is also enforced, so this is a recurring nag rather than a one-off.' }
            @{ Key = 'NudgeSsprBrokenForAdmin'; Title = 'Broken: admin prompted but cannot register'; Count = $ns.SsprBrokenForAdminCount
               Note = 'Admin SSPR is disabled tenant-wide while these admins are still in scope for the user SSPR policy. They are interrupted to register and then told no methods can be registered. See SSPR002.' }
        )

        $nudgeCardsHtml = foreach ($g in $nudgeGroups) {
            if ($g.Count -eq 0) { continue }
            $affected = if ($g.Key -eq 'NudgePasskeyCampaign') {
              @($NudgeForecast.Users | Where-Object { $_[$g.Key] -or $_.NudgePasskeyCampaignUncertain })
            }
            else {
              @($NudgeForecast.Users | Where-Object { $_[$g.Key] })
            }
            $isBroken = $g.Key -eq 'NudgeSsprBrokenForAdmin'
            $badgeClass = if ($isBroken) { 'bg-danger' } else { 'bg-warning text-dark' }

            # A campaign-driven count (passkey/Authenticator) is computed WITHOUT resolving group
            # membership - this toolkit avoids the extra per-group Graph call, so when the campaign
            # targets specific groups rather than "All users" there is no way to tell which of the
            # users below are actually in scope. Without this, the card silently implies "these N
            # people will be nudged" when the honest claim is "up to N people, tenant-wide, meet
            # the method/policy conditions" - the gap between those two readings is exactly what
            # made a 33,546-user count on a group-scoped campaign look like a bug report rather than
            # an upper bound. $ns.CampaignScopeUncertain already carries this fact (computed in
            # ConvertTo-SAWNudgeForecast.ps1); it previously only reached a generic footer caveat at
            # the bottom of the whole section, disconnected from the specific number it qualifies.
            $scopeUncertainForThisCard = [bool]$g.ScopeSensitive -and $ns.CampaignScopeUncertain
            $profileScopeUncertainForThisCard = $g.Key -eq 'NudgePasskeyCampaign' -and $ns.PasskeyProfileEligibilityUnknownCount -gt 0
            $confirmedCount = if ($g.Key -eq 'NudgePasskeyCampaign') { $ns.PasskeyCampaignCount } else { $g.Count }
            $countLabel = if ($scopeUncertainForThisCard) { "up to $($g.Count)" } elseif ($profileScopeUncertainForThisCard) { "$confirmedCount confirmed; up to $($g.Count)" } else { "$($g.Count)" }
            $scopeWarningHtml = ''
            if ($scopeUncertainForThisCard -and $ns.CampaignScopeUncertainReason -eq 'msft-managed-rollout') {
                $scopeWarningHtml = @"
      <div class="alert alert-warning small mb-3" role="alert">
        <strong>Scope uncertain.</strong> This campaign is Microsoft managed with no custom
        include/exclude targets configured, so there is no target group to look up - see the
        <strong>"Rollout timing not confirmed"</strong> badge on the Registration Campaign row in
        the <strong>Policy Inventory</strong> tab for the same underlying fact. Microsoft
        documents this state as an incremental, per-tenant rollout on Microsoft's own batch
        schedule, not something this toolkit can observe - the effective population moves from
        SMS/Voice users only to all MFA-capable users, and this tenant may still be on the prior
        default, mid-transition, or already on the new one. The count and list below assume the
        broader population (all MFA-capable users) as the safer upper bound; the true number
        currently nudged may be smaller if this tenant hasn't reached that stage yet.
      </div>
"@
            }

            $profileScopeWarningHtml = ''
            if ($profileScopeUncertainForThisCard) {
                $profileScopeWarningHtml = @"
      <div class="alert alert-warning small mb-3" role="alert">
        <strong>Passkey profile eligibility partly unknown.</strong>
        $($ns.PasskeyProfileEligibilityUnknownCount) user(s) have unresolved profile assignments.
        The list below contains confirmed eligible users; the badge shows the potential upper bound.
        Check the FIDO2 target groups if a group membership lookup was unavailable.
      </div>
"@
            }
            elseif ($scopeUncertainForThisCard) {
                $scopeWarningHtml = @"
      <div class="alert alert-warning small mb-3" role="alert">
        <strong>Scope uncertain.</strong> This campaign targets specific group(s) rather than
        "All users," and group membership isn't resolved from Graph (it would need an extra call
        per group). The count and list below include <strong>every user tenant-wide</strong> who
        meets the method/policy conditions, not only those actually in the target group(s) - so
        this is an upper bound, and the true number nudged is very likely smaller. Check the
        campaign's target group(s) under Authentication methods &gt; Registration campaign in the
        admin center to narrow this down.
      </div>
"@
            }

            $userRowsHtml = foreach ($u in $affected) {
                $adminBadge = if ($u.IsAdmin) { ' <span class="badge bg-dark">Admin</span>' } else { '' }
                    $eligibilityCell = if ($u.NudgePasskeyCampaignUncertain) { '<span class="badge bg-warning text-dark">Profile assignment unknown</span>' } else { '<span class="badge bg-success">Eligible</span>' }
                @"
        <tr>
          <td>$(ConvertTo-SAWHtmlEncoded $u.DisplayName)$adminBadge</td>
          <td class="text-body-secondary small">$(ConvertTo-SAWHtmlEncoded $u.UserPrincipalName)</td>
          <td class="text-body-secondary small">$(ConvertTo-SAWHtmlEncoded $u.MethodsRegistered)</td>
              $(if ($g.Key -eq 'NudgePasskeyCampaign') { "<td>$eligibilityCell</td>" })
        </tr>
"@
            }

            @"
  <div class="card mb-3">
    <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
      <strong>$(ConvertTo-SAWHtmlEncoded $g.Title)</strong>
      <span class="badge $badgeClass">$countLabel user$(if ($g.Count -ne 1) { 's' })</span>
    </div>
    <div class="card-body">
      <p class="text-body-secondary small mb-3">$(ConvertTo-SAWHtmlEncoded $g.Note)</p>
$scopeWarningHtml
$profileScopeWarningHtml
      <details>
        <summary class="small">Show the $($g.Count) affected user$(if ($g.Count -ne 1) { 's' })</summary>
        <div class="table-responsive mt-2">
          <table class="table table-sm table-striped align-middle">
            <thead><tr><th>User</th><th>UPN</th><th>Methods registered</th>$(if ($g.Key -eq 'NudgePasskeyCampaign') { '<th>Profile eligibility</th>' })</tr></thead>
            <tbody>
$($userRowsHtml -join "`n")
            </tbody>
          </table>
        </div>
      </details>
    </div>
  </div>
"@
        }

        # Eligible but structurally unreachable: the group most often misread as "users ignoring
        # the prompt" when they are simply never shown one.
        $unreachableHtml = ''
        if ($ns.ReachabilityAvailable -and $ns.UnreachableInWindowCount -gt 0) {
            $unreachable = @($NudgeForecast.Users | Where-Object { $_.NudgeUnreachableInWindow })
            $unreachableRowsHtml = foreach ($u in $unreachable) {
                $adminBadge = if ($u.IsAdmin) { ' <span class="badge bg-dark">Admin</span>' } else { '' }
                @"
        <tr>
          <td>$(ConvertTo-SAWHtmlEncoded $u.DisplayName)$adminBadge</td>
          <td class="text-body-secondary small">$(ConvertTo-SAWHtmlEncoded $u.UserPrincipalName)</td>
          <td class="text-body-secondary small">$(ConvertTo-SAWHtmlEncoded $u.MethodsRegistered)</td>
        </tr>
"@
            }
            $unreachableHtml = @"
  <div class="card mb-3 border-danger">
    <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
      <strong>Eligible, but a campaign cannot reach them</strong>
      <span class="badge bg-danger">$($ns.UnreachableInWindowCount) user$(if ($ns.UnreachableInWindowCount -ne 1) { 's' })</span>
    </div>
    <div class="card-body">
      <p class="text-body-secondary small mb-3">These users are forecast to be nudged, but did no
      <strong>interactive</strong> sign-in in the last $($ns.SignInWindowDays) day(s). A nudge is UI shown during an
      interactive sign-in, so a campaign has no opportunity to prompt them: token refreshes, single
      sign-on on a joined device, and opening a second Office app on an already-signed-in machine
      all happen without any interruption. Reaching this group needs direct outreach (email, service
      desk, manager) rather than a firmer campaign. Note the window is bounded by Entra's own log
      retention (seven days on Free, 30 on P1/P2), so this means "not within retention", not
      "never".</p>
      <details>
        <summary class="small">Show the $($ns.UnreachableInWindowCount) affected user$(if ($ns.UnreachableInWindowCount -ne 1) { 's' })</summary>
        <div class="table-responsive mt-2">
          <table class="table table-sm table-striped align-middle">
            <thead><tr><th>User</th><th>UPN</th><th>Methods registered</th></tr></thead>
            <tbody>
$($unreachableRowsHtml -join "`n")
            </tbody>
          </table>
        </div>
      </details>
    </div>
  </div>
"@
        }

        $suppressorHtml = ''
        if ($ns.Suppressors.Count -gt 0) {
            $suppressorItems = ($ns.Suppressors | ForEach-Object { "      <li>$(ConvertTo-SAWHtmlEncoded $_)</li>" }) -join "`n"
            $suppressorHtml = @"
  <div class="alert alert-warning" role="alert">
    <strong>The registration campaign currently reaches nobody.</strong> Microsoft documents the
    following as suppressing the nudge, and this tenant has at least one in place:
    <ul class="mb-2 mt-2">
$suppressorItems
    </ul>
    <span class="small">The campaign can therefore look correctly configured while silently
    nudging no one. Note this does <em>not</em> suppress the 2026-09-01 automatic enablement, which
    is driven by Microsoft rather than by this campaign.</span>
  </div>
"@
        }

        $caveatItems = ($ns.Caveats | ForEach-Object { "    <li>$(ConvertTo-SAWHtmlEncoded $_)</li>" }) -join "`n"

        $nudgeSectionHtml = @"
  <h2 class="h4 mb-3">Who Will Be Nudged (Communication Planning)</h2>
  <p class="text-body-secondary small">Which users are <em>eligible</em> to be interrupted with a
  registration prompt, and why. The purpose is to have told them first: an unannounced interrupt at
  sign-in is a help-desk call and a trust problem, not a technical failure. Campaign state read from
  the tenant: <strong>$(ConvertTo-SAWHtmlEncoded $ns.CampaignState)</strong>.</p>
$suppressorHtml
$unreachableHtml
$(if (@($nudgeCardsHtml).Count -eq 0) {
    '  <p class="text-body-secondary">No users are currently forecast to be nudged by any of the modeled interrupts.</p>'
} else {
    ($nudgeCardsHtml -join "`n")
})
  <div class="alert alert-secondary small" role="alert">
    <strong>Read these counts as a planning estimate, not a guarantee.</strong>
    <ul class="mb-0 mt-2">
$caveatItems
    </ul>
  </div>
"@
    }

    # --- Remediation Roadmap (IST -> SOLL phased work plan) ---
    $roadmapSectionHtml = ''
    if ($Roadmap.Count -gt 0) {
      $firstIncompletePhase = $Roadmap | Where-Object { -not $_.IsComplete } | Select-Object -First 1
      $metroStopsHtml = foreach ($phase in $Roadmap) {
        if ($phase.IsComplete) {
          $metroState = 'complete'
          $metroLabel = 'Complete'
          $metroIcon = '&#10003;'
        }
        elseif ($firstIncompletePhase -eq $phase) {
          $metroState = 'current'
          $metroLabel = 'In progress'
          $metroIcon = '&bull;'
        }
        else {
          $metroState = 'waiting'
          $metroLabel = 'Waiting'
          $metroIcon = '&rarr;'
        }

        $phaseNumber = if ($null -ne $phase.Phase) { $phase.Phase } else { '-' }
        @"
      <div class="saw-metro-stop $metroState">
        <div class="saw-metro-marker" aria-hidden="true">$metroIcon</div>
        <div class="saw-metro-label"><strong>$(ConvertTo-SAWHtmlEncoded $phase.PhaseName)</strong><span>$metroLabel &middot; $($phase.CompletedCount)/$($phase.TotalCount)</span></div>
      </div>
"@
      }

      $completedPhaseCount = @($Roadmap | Where-Object { $_.IsComplete }).Count
      $currentPhaseName = if ($firstIncompletePhase) { $firstIncompletePhase.PhaseName } else { 'Target state reached' }
      $metroSummary = if ($firstIncompletePhase) {
        "$completedPhaseCount of $($Roadmap.Count) phases complete. Current focus: $(ConvertTo-SAWHtmlEncoded $currentPhaseName)."
      }
      else {
        "All $($Roadmap.Count) phases are complete or not applicable. This tenant matches its measured SOLL."
      }

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
  <div class="card mb-4 saw-metro-card">
    <div class="card-body">
      <div class="d-flex flex-wrap justify-content-between align-items-start gap-2 mb-3">
        <div><h3 class="h5 mb-1">IST &rarr; SOLL journey</h3><p class="text-body-secondary small mb-0">$(ConvertTo-SAWHtmlEncoded $metroSummary)</p></div>
        <span class="badge bg-light text-dark border">$completedPhaseCount/$($Roadmap.Count) stations complete</span>
      </div>
      <div class="saw-metro-line" role="list" aria-label="IST to SOLL phases">
$($metroStopsHtml -join "`n")
      </div>
    </div>
  </div>
$($phaseCardsHtml -join "`n")
"@
    }

    # --- Upcoming Microsoft deadlines (optional - Get-SAWTimelineMilestones output) ---
    $timelineSectionHtml = ''
    if (@($TimelineMilestones).Count -gt 0) {
        $timelineCardsHtml = foreach ($m in $TimelineMilestones) {
            $urgencyClass = 'saw-deadline-future'
            $daysLabel = "$($m.DaysRemaining) day(s) left"
            if ($m.IsPast) {
                $urgencyClass = 'saw-deadline-past'
                # -$m.DaysRemaining (unary minus), not [Math]::Abs - static calls on
                # System.Math are blocked under this machine's ConstrainedLanguage mode.
                # Safe here since IsPast guarantees DaysRemaining is negative.
                $daysLabel = "$(-$m.DaysRemaining) day(s) ago"
            }
            elseif ($m.DaysRemaining -eq 0) {
                $daysLabel = 'Today'
                $urgencyClass = 'saw-deadline-now'
            }
            elseif ($m.DaysRemaining -le 14) {
                $urgencyClass = 'saw-deadline-soon'
            }
            elseif ($m.DaysRemaining -le 45) {
                $urgencyClass = 'saw-deadline-near'
            }

            $relatedBadgesHtml = ''
            if (@($m.RelatedRuleIDs).Count -gt 0) {
                $relatedBadgesHtml = ($m.RelatedRuleIDs | ForEach-Object { "<span class=""badge bg-light text-dark border"">$(ConvertTo-SAWHtmlEncoded $_)</span>" }) -join ' '
            }

            $sourceLinkHtml = ''
            if ($m.SourceUrl) {
                $sourceLinkHtml = "<a href=""$(ConvertTo-SAWHtmlEncoded $m.SourceUrl)"" target=""_blank"" rel=""noopener noreferrer"" class=""small"">Source</a>"
            }

            # UsersImpacted is nullable by design (Get-SAWTimelineMilestones.ps1) - a milestone
            # with no ImpactMetric (no rule/data source exists yet, e.g. passwordless password
            # change) or no -ImpactMetrics supplied (e.g. -UseSampleData without registration
            # data) omits this line entirely rather than showing a fabricated "0 users impacted".
            # NotApplicableReason is a distinct third state from both of those: the metric WAS
            # computed, but the underlying feature doesn't apply to this tenant at all (e.g. SSPR
            # isn't enabled for anyone) - "0 users impacted" would otherwise look identical to
            # "fully compliant," which is a real difference worth keeping visible.
            $impactHtml = ''
            if ($m.NotApplicableReason) {
                $impactHtml = "<div class=""small fw-semibold mb-1 text-body-secondary"">Not applicable - $(ConvertTo-SAWHtmlEncoded $m.NotApplicableReason)</div>"
            }
            elseif ($null -ne $m.UsersImpacted) {
                $impactLabel = if ($m.ImpactMetricLabel) { " ($(ConvertTo-SAWHtmlEncoded $m.ImpactMetricLabel))" } else { '' }
                $impactHtml = "<div class=""small fw-semibold mb-1"">$($m.UsersImpacted) user(s) impacted$impactLabel</div>"
            }

            @"
      <li class="saw-deadline-row $urgencyClass">
        <time class="saw-deadline-date">$(ConvertTo-SAWHtmlEncoded $m.Date)<span>$daysLabel</span></time>
        <div class="saw-deadline-main"><strong>$(ConvertTo-SAWHtmlEncoded $m.Title)</strong><p>$(ConvertTo-SAWHtmlEncoded $m.Description)</p><div class="saw-deadline-rules">$relatedBadgesHtml</div></div>
        <div class="saw-deadline-impact">$impactHtml $sourceLinkHtml</div>
      </li>
"@
        }

        $timelineSectionHtml = @"
  <section class="saw-section saw-deadlines">
    <div class="saw-section-heading"><div><h2>Microsoft timeline</h2><p>Published Entra milestones relevant to this tenant</p></div><span class="saw-section-note">Verify source dates before planning changes</span></div>
    <ul class="saw-deadline-list">
$($timelineCardsHtml -join "`n")
    </ul>
  </section>
"@
    }

    # --- What Users Can Expect: IST vs. SOLL flow scenarios (optional -
    # ConvertTo-SAWRegistrationFlowScenarios output) ---
    $flowScenariosSectionHtml = ''
    if (@($FlowScenarios).Count -gt 0) {
        $flowCardsHtml = foreach ($flow in $FlowScenarios) {
            $applicableBadge = if ($flow.Applicable) {
                '<span class="badge bg-success">Applies to this tenant</span>'
            }
            else {
                '<span class="badge bg-secondary">Not applicable today</span>'
            }

            $stepsHtml = foreach ($step in $flow.Steps) {
                # 'unknown' is a distinct third state from $null: $null means a fixed Microsoft
                # mechanic with nothing tenant-configurable to check. 'unknown' means the opposite
                # - it IS tenant-conditioned, but this toolkit has no Graph-readable way to observe
                # it (e.g. a legacy setting with no modern API equivalent found so far) - collapsing
                # the two into one badge would misrepresent a real gap as an immutable fact.
                $stepBadge = switch ($step.Applies) {
                    $true { '<span class="badge bg-success">IST: happens today</span>' }
                    $false { '<span class="badge bg-secondary">IST: does not happen today</span>' }
                    'unknown' { '<span class="badge bg-warning text-dark">Unknown - verify directly</span>' }
                    default { '<span class="badge bg-light text-dark border">Fixed Microsoft behavior</span>' }
                }
                @"
          <li class="list-group-item">
            <div class="d-flex flex-wrap align-items-start gap-2 mb-1">
              $stepBadge
              <span>$(ConvertTo-SAWHtmlEncoded $step.Step)</span>
            </div>
            <p class="mb-0 text-body-secondary small">$(ConvertTo-SAWHtmlEncoded $step.Detail)</p>
          </li>
"@
            }

            @"
      <div class="card mb-3">
        <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
          <div><strong>$(ConvertTo-SAWHtmlEncoded $flow.Category)</strong> - $(ConvertTo-SAWHtmlEncoded $flow.Title)</div>
          $applicableBadge
        </div>
        <div class="card-body">
          <p class="small mb-1"><strong>IST (today):</strong> $(ConvertTo-SAWHtmlEncoded $flow.ISTSummary)</p>
          <p class="small mb-3"><strong>SOLL (target):</strong> $(ConvertTo-SAWHtmlEncoded $flow.SOLLSummary)</p>
          <ol class="list-group list-group-numbered list-group-flush mb-2">
$($stepsHtml -join "`n")
          </ol>
          <a href="$(ConvertTo-SAWHtmlEncoded $flow.SourceUrl)" target="_blank" rel="noopener noreferrer" class="small">Source</a>
        </div>
      </div>
"@
        }

        $flowScenariosSectionHtml = @"
  <h2 class="h4 mb-3">What Users Can Expect (IST vs. SOLL)</h2>
  <p class="text-body-secondary small">Four real, Microsoft-documented end-to-end flows - not single-setting checks. Each step is marked against this tenant's actual collected settings: whether it happens today (IST), or is a fixed Microsoft behavior included for context. Read alongside the Remediation Roadmap above to see how a fix to one setting changes what an end user actually experiences.</p>
$($flowCardsHtml -join "`n")
"@
    }

    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $totalRules = $RuleResults.Count

    # --- Environment/point-in-time banner (tenant + run timestamp) ---
    # Regex reformat rather than [datetime]::ParseExact - static method calls on non-core types
    # are blocked under this machine's ConstrainedLanguage mode (see
    # docs/powershell-coding-notes.md), and RunTimestamp's shape is fixed and known (produced by
    # Get-Date -Format 'yyyyMMdd-HHmmss' in Invoke-SAWAssessment.ps1), so a plain regex is both
    # safer and simpler than parsing it as a real datetime just to reformat it.
    $runTimestampDisplay = $RunTimestamp
    if ($RunTimestamp -match '^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})$') {
        $runTimestampDisplay = "$($Matches[1])-$($Matches[2])-$($Matches[3]) $($Matches[4]):$($Matches[5]):$($Matches[6])"
    }

    $titleTenantSuffix = ''
    if ($TenantDisplayName) { $titleTenantSuffix += " - $(ConvertTo-SAWHtmlEncoded $TenantDisplayName)" }
    if ($RunTimestamp) { $titleTenantSuffix += " - $(ConvertTo-SAWHtmlEncoded $runTimestampDisplay)" }

    # The tenant is the report headline, with the product identity retained in the compact masthead.
    $heroTitle = if ($TenantDisplayName) {
        ConvertTo-SAWHtmlEncoded $TenantDisplayName
    }
    else {
        'Authentication Assessment'
    }

    # One headline number in the hero: how many checks are not currently at the target state.
    # Deliberately counts Red + Yellow and excludes Grey, since Grey means "not applicable to
    # this tenant" rather than "unresolved", and rolling it in would inflate the number with
    # items nobody can act on.
    $openFindings = $counts.Red + $counts.Yellow
    $heroScoreChipHtml = if ($totalRules -gt 0) {
        $openLabel = if ($openFindings -eq 1) { 'finding open' } else { 'findings open' }
        "      <span class=""saw-chip"" title=""Red plus Yellow. Grey items are not applicable to this tenant and are excluded.""><strong>$openFindings</strong> $openLabel</span>"
    }
    else {
        ''
    }

    $priorityActionRows = foreach ($finding in @($findingsSorted | Select-Object -First 3)) {
      $statusClass = if ($finding.Status -eq 'Red') { 'saw-status-red' } else { 'saw-status-amber' }
      "<li class=""saw-priority-row""><span class=""$statusClass"">$(ConvertTo-SAWHtmlEncoded $finding.Status)</span><div><strong>$(ConvertTo-SAWHtmlEncoded $finding.Setting)</strong><p>$(ConvertTo-SAWHtmlEncoded $finding.Recommendation)</p></div><span class=""saw-rule-id"">$(ConvertTo-SAWHtmlEncoded $finding.RuleID)</span></li>"
    }
    if (@($priorityActionRows).Count -eq 0) {
      $priorityActionRows = '<li class="saw-empty-state">No open findings. Every evaluated setting meets the selected baseline.</li>'
    }

    $envBannerHtml = ''
    if ($TenantDisplayName -or $TenantId -or $RunTimestamp) {
        $tenantLineHtml = ''
        if ($TenantDisplayName -or $TenantId) {
            $tenantIdHtml = if ($TenantId) { " <small>$(ConvertTo-SAWHtmlEncoded $TenantId)</small>" } else { '' }
            $tenantLineHtml = "<div class=""saw-context-item""><span>Tenant</span><strong>$(ConvertTo-SAWHtmlEncoded $TenantDisplayName)</strong>$tenantIdHtml</div>"
        }
        $runLineHtml = ''
        if ($RunTimestamp) {
            $runLineHtml = "<div class=""saw-context-item""><span>Assessed</span><strong>$(ConvertTo-SAWHtmlEncoded $runTimestampDisplay)</strong></div>"
        }
        $envBannerHtml = @"
  <div class="saw-report-context">
    $tenantLineHtml
    $runLineHtml
  </div>
"@
    }

    # --- Top-level tabs ---
      # Group the existing report fragments into four reader tasks. Overview remains active so the
      # Chart.js canvases measure correctly at initial render; the implementation plan and findings
      # share one section, rather than competing as separate destinations.
    $overviewPaneHtml = @"
  <div class="saw-baseline-strip">
    <strong>SOLL baseline</strong><span>$(ConvertTo-SAWHtmlEncoded $BaselineName)</span>
    <span class="saw-baseline-explainer">Target state for this customer · IST is the observed tenant configuration</span>
  </div>
$(if ($DomainServicesDetected) {
@"
  <div class="alert alert-warning d-flex flex-wrap gap-3 align-items-center mb-3" role="alert">
    <div><strong>Possible Microsoft Entra Domain Services usage detected.</strong> An "AAD DC Administrators" group was found. This is a proxy signal, not an authoritative service check; confirm with the customer.</div>
  </div>
"@
})
  <section class="saw-summary-band" aria-label="Assessment summary">
    <div class="saw-open-count"><span>Open findings</span><strong>$openFindings</strong><small>Red and Yellow · Grey excluded</small></div>
    <div class="saw-summary-metrics">
      <div class="saw-summary-metric saw-summary-red"><span>Red</span><strong>$($counts.Red)</strong></div>
      <div class="saw-summary-metric saw-summary-amber"><span>Yellow</span><strong>$($counts.Yellow)</strong></div>
      <div class="saw-summary-metric saw-summary-green"><span>Green</span><strong>$($counts.Green)</strong></div>
      <div class="saw-summary-metric saw-summary-gray"><span>Grey</span><strong>$($counts.Grey)</strong></div>
    </div>
    <div class="saw-status-distribution" role="img" aria-label="$($counts.Red) Red, $($counts.Yellow) Yellow, $($counts.Green) Green, $($counts.Grey) Grey">
      <span class="saw-distribution-red" style="flex-grow: $($counts.Red)"></span><span class="saw-distribution-amber" style="flex-grow: $($counts.Yellow)"></span><span class="saw-distribution-green" style="flex-grow: $($counts.Green)"></span><span class="saw-distribution-gray" style="flex-grow: $($counts.Grey)"></span>
    </div>
  </section>

  <div class="saw-overview-grid">
    <section class="saw-overview-charts">
      <div class="saw-section-heading"><div><h2>Assessment at a glance</h2><p>$totalRules checks across authentication, registration, and access policy</p></div></div>
      <div class="saw-chart-grid">
        <div class="saw-chart-panel"><h3>By status</h3><canvas id="statusChart" height="190"></canvas></div>
        <div class="saw-chart-panel"><h3>By category</h3><canvas id="categoryChart" height="190"></canvas></div>
      </div>
    </section>
    <section class="saw-priority-panel">
      <div class="saw-section-heading"><div><h2>Address first</h2><p>Highest-severity open findings</p></div></div>
      <ol class="saw-priority-list">
$($priorityActionRows -join "`n")
      </ol>
      <a class="saw-inline-link" href="#pane-plan-findings" data-bs-toggle="tab" data-bs-target="#pane-plan-findings" role="tab">View plan and all findings</a>
    </section>
  </div>

$timelineSectionHtml
$trendSectionHtml
"@

    $findingsRoadmapPaneHtml = @"
$roadmapSectionHtml
  <h2 class="h4 mb-3">Risk Findings &amp; Recommendations</h2>
  <div class="saw-plan list-group mb-4">
$($findingsHtml -join "`n")
  </div>
"@

    $userJourneysPaneHtml = @"
$nudgeSectionHtml
$flowScenariosSectionHtml
$rosterSectionHtml
"@

    $implementationPlanPaneHtml = @"
  <div class="alert alert-primary d-flex flex-wrap gap-3 align-items-center mb-4" role="alert">
    <div><strong>Purpose:</strong> move from this assessment to a controlled authentication improvement pilot.</div>
    <div class="text-body-secondary">Complete each gate before moving to the next step. This plan does not apply tenant changes.</div>
  </div>
  <h2 class="h4 mb-3">Step-by-Step Implementation Plan</h2>
  <div class="list-group mb-4">
    <div class="list-group-item">
      <div class="d-flex gap-3"><span class="badge text-bg-primary rounded-pill align-self-start">1</span><div><h3 class="h6 mb-1">Confirm scope and ownership</h3><p class="mb-1">Confirm the tenant, change window, business owner, technical operator, service desk contact, pilot review date, and rollback deadline.</p><small class="text-body-secondary"><strong>Gate:</strong> owner, window, and rollback contact are recorded.</small></div></div>
    </div>
    <div class="list-group-item">
      <div class="d-flex gap-3"><span class="badge text-bg-primary rounded-pill align-self-start">2</span><div><h3 class="h6 mb-1">Resolve the target state</h3><p class="mb-1">Use the SOLL baseline and the findings below to decide which authentication methods, registration paths, and Conditional Access controls are safe to change first.</p><small class="text-body-secondary"><strong>Gate:</strong> no unresolved bootstrap or lockout risk blocks the proposed pilot.</small></div></div>
    </div>
    <div class="list-group-item">
      <div class="d-flex gap-3"><span class="badge text-bg-primary rounded-pill align-self-start">3</span><div><h3 class="h6 mb-1">Prepare groups and configuration</h3><p class="mb-1">Create or review the allowlist and exception group names in <code>config/config.json</code>. Keep break-glass accounts outside the pilot population.</p><small class="text-body-secondary"><strong>Evidence:</strong> approved group names, object IDs, membership owner, and exception criteria.</small></div></div>
    </div>
    <div class="list-group-item">
      <div class="d-flex gap-3"><span class="badge text-bg-primary rounded-pill align-self-start">4</span><div><h3 class="h6 mb-1">Capture the current state</h3><p class="mb-1">Run this assessment and record the dashboard, history snapshot, current authentication method policy, group membership, and affected-user counts.</p><small class="text-body-secondary"><strong>Gate:</strong> the baseline evidence is stored with the change record.</small></div></div>
    </div>
    <div class="list-group-item">
      <div class="d-flex gap-3"><span class="badge text-bg-primary rounded-pill align-self-start">5</span><div><h3 class="h6 mb-1">Generate and review the dry run</h3><p class="mb-1">Run <code>Invoke-SAWSmsFreezePilot.ps1 -ConfigPath ./config/config.json -DryRun -Verbose</code> when piloting SMS/Voice restriction. Check allowed, exception, and excluded users line by line.</p><small class="text-body-secondary"><strong>Gate:</strong> zero unexpected users, names, or policy targets; no live change has occurred.</small></div></div>
    </div>
    <div class="list-group-item">
      <div class="d-flex gap-3"><span class="badge text-bg-primary rounded-pill align-self-start">6</span><div><h3 class="h6 mb-1">Approve a small pilot wave</h3><p class="mb-1">Select a representative, supportable group. Exclude break-glass accounts and high-risk users unless their replacement method has been tested and explicitly approved.</p><small class="text-body-secondary"><strong>Evidence:</strong> approved pilot roster, exception list, and change approval.</small></div></div>
    </div>
    <div class="list-group-item">
      <div class="d-flex gap-3"><span class="badge text-bg-primary rounded-pill align-self-start">7</span><div><h3 class="h6 mb-1">Apply the controlled change</h3><p class="mb-1">Run the pilot command with <code>-Apply</code> only after approval. Record group IDs, policy response, request IDs, operator, and timestamp.</p><small class="text-body-secondary"><strong>Gate:</strong> the applied policy targets only the approved group and the exception path is understood.</small></div></div>
    </div>
    <div class="list-group-item">
      <div class="d-flex gap-3"><span class="badge text-bg-primary rounded-pill align-self-start">8</span><div><h3 class="h6 mb-1">Verify immediately</h3><p class="mb-1">Check the policy and group memberships in Graph and the Entra admin center. Test an approved user, a controlled negative case, and the recovery path.</p><small class="text-body-secondary"><strong>Gate:</strong> approved users can authenticate, blocked users cannot newly use the restricted method, and recovery access works.</small></div></div>
    </div>
    <div class="list-group-item">
      <div class="d-flex gap-3"><span class="badge text-bg-primary rounded-pill align-self-start">9</span><div><h3 class="h6 mb-1">Monitor the pilot</h3><p class="mb-1">During the agreed window, review sign-in and audit logs, registration changes, group drift, help-desk tickets, and unexpected authentication failures.</p><small class="text-body-secondary"><strong>Gate:</strong> no unresolved critical lockouts, unexplained failures, or membership drift.</small></div></div>
    </div>
    <div class="list-group-item">
      <div class="d-flex gap-3"><span class="badge text-bg-primary rounded-pill align-self-start">10</span><div><h3 class="h6 mb-1">Close, roll back, or expand</h3><p class="mb-1">At the review date, either document success and repeat the sequence for the next wave, or restore the recorded pre-change policy and retest all recovery paths.</p><small class="text-body-secondary"><strong>Evidence:</strong> outcome, incidents, exceptions, rollback decision, next wave owner, and next review date.</small></div></div>
    </div>
  </div>
  <div class="alert alert-warning mb-0" role="alert">
    <strong>Change safety:</strong> this dashboard is evidence and guidance. The assessment flow is read-only. The SMS/Voice pilot script changes the tenant only when <code>-Apply</code> is explicitly supplied.
  </div>
"@

    $policyInventoryPaneHtml = @"
$authMethodsInventorySectionHtml
$fido2KeyInventorySectionHtml
$caInventorySectionHtml
$stagedRolloutSectionHtml
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
"@

    $readingGuideNavHtml = ''
    $readingGuidePaneHtml = ''
    if ($ReadingGuideHtml) {
        $readingGuideNavHtml = @"
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-reading-guide" data-bs-toggle="tab" data-bs-target="#pane-reading-guide" type="button" role="tab" aria-controls="pane-reading-guide" aria-selected="false">Reading This Report</button>
    </li>
"@
        $readingGuidePaneHtml = @"
    <div class="tab-pane fade" id="pane-reading-guide" role="tabpanel" aria-labelledby="tab-reading-guide">
      <div class="reading-guide-content">
$ReadingGuideHtml
      </div>
    </div>
"@
    }

    $mainContentHtml = @"
  <div class="saw-tabs-sticky mb-4">
  <ul class="nav nav-tabs saw-main-tabs" role="tablist">
    <li class="nav-item" role="presentation">
      <button class="nav-link active" id="tab-overview" data-bs-toggle="tab" data-bs-target="#pane-overview" type="button" role="tab" aria-controls="pane-overview" aria-selected="true">Overview</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-plan-findings" data-bs-toggle="tab" data-bs-target="#pane-plan-findings" type="button" role="tab" aria-controls="pane-plan-findings" aria-selected="false">Plan &amp; Findings</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-user-journeys" data-bs-toggle="tab" data-bs-target="#pane-user-journeys" type="button" role="tab" aria-controls="pane-user-journeys" aria-selected="false">User Journeys</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-policy-inventory" data-bs-toggle="tab" data-bs-target="#pane-policy-inventory" type="button" role="tab" aria-controls="pane-policy-inventory" aria-selected="false">Policy Inventory</button>
    </li>
$readingGuideNavHtml
  </ul>
  </div>
  <div class="tab-content">
    <div class="tab-pane fade show active" id="pane-overview" role="tabpanel" aria-labelledby="tab-overview">
$overviewPaneHtml
    </div>
    <div class="tab-pane fade" id="pane-plan-findings" role="tabpanel" aria-labelledby="tab-plan-findings">
      <section id="section-implementation-plan">
  $implementationPlanPaneHtml
      </section>
      <section id="section-findings-roadmap">
$findingsRoadmapPaneHtml
      </section>
    </div>
    <div class="tab-pane fade" id="pane-user-journeys" role="tabpanel" aria-labelledby="tab-user-journeys">
$userJourneysPaneHtml
    </div>
    <div class="tab-pane fade" id="pane-policy-inventory" role="tabpanel" aria-labelledby="tab-policy-inventory">
$policyInventoryPaneHtml
    </div>
$readingGuidePaneHtml
  </div>
"@

    $html = @"
<!doctype html>
<html lang="en" data-bs-theme="light">
<script>
  /* Resolve the saved theme before first paint; otherwise follow the OS preference. */
  (function () {
    var root = document.documentElement;
    var dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    try {
      var savedTheme = window.localStorage.getItem('saw-dashboard-theme');
      if (savedTheme === 'dark') { dark = true; }
      else if (savedTheme === 'light') { dark = false; }
    } catch (e) { /* use the OS preference */ }
    window.sawDashboardDark = dark;
    function setTheme(isDark) {
      root.setAttribute('data-saw-theme', isDark ? 'dark' : 'light');
      root.setAttribute('data-bs-theme', isDark ? 'dark' : 'light');
    }
    setTheme(dark);
    window.addEventListener('beforeprint', function () { setTheme(false); });
    window.addEventListener('afterprint', function () { setTheme(window.sawDashboardDark); });
  })();
</script>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure At Work - Authentication Assessment Dashboard$titleTenantSuffix</title>
<link rel="stylesheet" href="vendor/bootstrap/bootstrap.min.css">
<style>
  /*
    Secure At Work's licensed display/text font isn't embeddable here without a license, so
    this toolkit avoids CDN font dependencies on principle (same reason Bootstrap/Chart.js
    are vendored locally, not pulled from a CDN). The report uses an accessible teal/navy
    accent with traffic-light status colors reserved for assessment meaning.

    Traffic-light status colors (green/yellow/red/grey - Bootstrap's success/warning/
    danger/secondary) are deliberately left as Bootstrap defaults, not rebranded: they're
    functional semantics the reader relies on, not a place for brand color.
  */
  :root {
    --saw-primary: #087e9a;
    --saw-primary-dark: #075a70;
    --saw-primary-light: #e4f2f5;
    --saw-bg: #ffffff;
    --saw-ink: #18252f;
    --saw-heading: #18252f;
    --saw-muted: #5d6c77;
    --saw-border: #d9e0e4;
    --saw-card-header: #f7f9fa;
    --saw-green: #198754;  --saw-green-bg: #e7f4ed;  --saw-green-ink: #10633d;
    --saw-yellow: #e0a800; --saw-yellow-bg: #fdf4dd; --saw-yellow-ink: #7a5600;
    --saw-red: #dc3545;    --saw-red-bg: #fdebed;    --saw-red-ink: #a71d2a;
    --saw-grey: #6c757d;   --saw-grey-bg: #eef1f5;   --saw-grey-ink: #4a5462;
    --bs-primary: var(--saw-primary);
    --bs-primary-rgb: 8, 126, 154;
    --bs-link-color: var(--saw-primary);
    --bs-link-color-rgb: 8, 126, 154;
    --bs-link-hover-color: var(--saw-primary-dark);
    --bs-link-hover-color-rgb: 7, 90, 112;
    --bs-body-font-family: -apple-system, "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
    --bs-border-radius: 0.25rem;
    --bs-border-radius-sm: 0.2rem;
    --bs-border-radius-lg: 0.35rem;
  }
  .saw-metro-card { background: linear-gradient(135deg, var(--saw-primary-light), #ffffff 62%); }
  .saw-metro-line { display: flex; align-items: flex-start; gap: 0; overflow-x: auto; padding: 0.25rem 0 0.5rem; }
  .saw-metro-stop { position: relative; flex: 1 1 0; min-width: 150px; text-align: center; }
  .saw-metro-stop:not(:last-child)::after { content: ''; position: absolute; top: 1rem; left: 50%; width: 100%; height: 0.25rem; background: var(--saw-grey); z-index: 0; }
  .saw-metro-marker { position: relative; z-index: 1; display: grid; place-items: center; width: 2rem; height: 2rem; margin: 0 auto 0.5rem; border: 0.25rem solid #fff; border-radius: 50%; background: var(--saw-grey); color: #fff; font-weight: 700; box-shadow: 0 0 0 2px var(--saw-grey); }
  .saw-metro-label { display: grid; gap: 0.15rem; color: var(--saw-heading); font-size: 0.85rem; }
  .saw-metro-label span { color: var(--saw-muted); font-size: 0.75rem; }
  .saw-metro-stop.complete .saw-metro-marker { background: var(--saw-green); box-shadow: 0 0 0 2px var(--saw-green); }
  .saw-metro-stop.complete:not(:last-child)::after { background: var(--saw-green); }
  .saw-metro-stop.current .saw-metro-marker { background: var(--saw-primary); box-shadow: 0 0 0 2px var(--saw-primary); }
  .saw-metro-stop.current .saw-metro-label strong { color: var(--saw-primary-dark); }
  @media (max-width: 575.98px) {
    .saw-metro-line { display: grid; gap: 0.75rem; overflow-x: visible; }
    .saw-metro-stop { display: grid; grid-template-columns: 2rem 1fr; min-width: 0; text-align: left; align-items: center; column-gap: 0.75rem; }
    .saw-metro-stop:not(:last-child)::after { top: 2rem; left: 0.875rem; width: 0.25rem; height: calc(100% + 0.75rem); }
    .saw-metro-marker { margin: 0; }
  }
  body {
    padding-bottom: 4rem;
    background-color: var(--saw-bg);
    color: var(--saw-ink);
    -webkit-font-smoothing: antialiased;
  }
  a { color: var(--saw-primary); text-underline-offset: 0.15em; }
  a:hover { color: var(--saw-primary-dark); }

  /* Type scale. Headings are tightened and slightly darker than body text so section
     boundaries read at a glance when scrolling a long report. */
  h1, h2, h3, h4, h5, h6 { letter-spacing: 0; color: var(--saw-heading); }
  h2.h4 { font-weight: 650; }
  .lead-sm { font-size: 0.9375rem; line-height: 1.6; }

  /* --- Cards ------------------------------------------------------------------ */
  .card {
    border-color: var(--saw-border);
    box-shadow: none;
    transition: border-color 0.16s ease, background-color 0.16s ease;
  }
  .card-header { font-weight: 600; background-color: var(--saw-card-header); border-bottom-color: var(--saw-border); }
  details.card > summary.card-header:hover { background-color: var(--saw-primary-light); }

  /* --- KPI tiles ---------------------------------------------------------------
     Previously a 4px left border. Now a top accent plus a tinted, tabular-figure
     numeral, so the four tiles scan as a set and the numbers line up. */
  .stat-card { position: relative; overflow: hidden; border-top: 3px solid transparent; }
  .stat-card:hover { border-color: var(--saw-primary); }
  .stat-card .stat-label {
    text-transform: uppercase; letter-spacing: 0.06em;
    font-size: 0.7rem; font-weight: 650; color: var(--saw-muted);
  }
  .stat-card .stat-value {
    font-size: 2.35rem; font-weight: 700; line-height: 1.1;
    font-variant-numeric: tabular-nums; letter-spacing: 0;
  }
  .stat-card.green  { border-top-color: var(--saw-green); }
  .stat-card.yellow { border-top-color: var(--saw-yellow); }
  .stat-card.red    { border-top-color: var(--saw-red); }
  .stat-card.grey   { border-top-color: var(--saw-grey); }
  .stat-card.green  .stat-value { color: var(--saw-green); }
  .stat-card.yellow .stat-value { color: var(--saw-yellow-ink); }
  .stat-card.red    .stat-value { color: var(--saw-red); }
  .stat-card.grey   .stat-value { color: var(--saw-grey); }

  /* --- Navigation --------------------------------------------------------------
     Sticky, because several panes are long tables and losing the tab bar halfway
     down means scrolling back to the top to change view. */
  .saw-tabs-sticky {
    position: sticky; top: 0; z-index: 1020;
    background-color: var(--saw-bg);
    padding-top: 0.35rem;
    box-shadow: 0 6px 12px -10px rgba(16, 24, 40, 0.5);
  }
  .nav-tabs { border-bottom-color: var(--saw-border); }
  .nav-tabs .nav-link { color: var(--saw-muted); font-weight: 550; border: none; border-bottom: 2px solid transparent; padding-left: 0; padding-right: 1.25rem; }
  .nav-tabs .nav-link:hover { color: var(--saw-primary); border-bottom-color: var(--saw-border); }
  .nav-tabs .nav-link.active { color: var(--saw-primary); background: transparent; border-bottom: 2px solid var(--saw-primary); }
  .nav-tabs .tab-index { color: var(--saw-muted); font-size: 0.68rem; letter-spacing: 0.08em; margin-right: 0.35rem; }
  .nav-tabs .nav-link.active .tab-index { color: var(--saw-primary); }
  .nav-pills .nav-link { color: var(--saw-muted); font-weight: 550; }
  .nav-pills .nav-link.active, .nav-pills .show > .nav-link { background-color: var(--saw-primary); color: #fff; }

  /* --- Tables ------------------------------------------------------------------
     Column headers become quiet micro-labels and the heavy zebra striping goes, so
     the coloured status badges are the only strong signal in the grid. */
  .table { --bs-table-border-color: var(--saw-border); }
  .table > thead > tr > th {
    text-transform: uppercase; letter-spacing: 0.05em;
    font-size: 0.7rem; font-weight: 650; color: var(--saw-muted);
    border-bottom: 1px solid var(--saw-border); white-space: nowrap;
  }
  .table > tbody > tr > td { vertical-align: middle; }
  .table-striped > tbody > tr:nth-of-type(odd) > * { --bs-table-accent-bg: transparent; background-color: transparent; }
  .table-hover > tbody > tr:hover > * { background-color: var(--saw-primary-light); }
  .table-responsive { border-radius: var(--bs-border-radius); }
  .table-responsive > .table { margin-bottom: 0; }

  /* --- Badges ------------------------------------------------------------------
     Bootstrap's solid warning/secondary badges are visually louder than the finding
     they label. These are tinted pills: same semantics, far less shouting. */
  .badge { font-weight: 600; letter-spacing: 0.01em; border-radius: 999px; padding: 0.34em 0.68em; }
  .badge.bg-success { background-color: var(--saw-green-bg) !important; color: var(--saw-green-ink) !important; }
  .badge.bg-warning { background-color: var(--saw-yellow-bg) !important; color: var(--saw-yellow-ink) !important; }
  .badge.bg-danger  { background-color: var(--saw-red-bg) !important;   color: var(--saw-red-ink) !important; }
  .badge.bg-secondary { background-color: var(--saw-grey-bg) !important; color: var(--saw-grey-ink) !important; }
  .badge.bg-primary { background-color: var(--saw-primary-light) !important; color: var(--saw-primary-dark) !important; }

  /* --- Alerts ------------------------------------------------------------------ */
  .alert { border: 1px solid var(--saw-border); border-left-width: 4px; }
  .alert-warning { border-left-color: var(--saw-yellow); }
  .alert-danger { border-left-color: var(--saw-red); }
  .alert-secondary { border-left-color: var(--saw-primary); background-color: var(--saw-primary-light); }

  /* --- Implementation plan ---------------------------------------------------- */
  .saw-plan { border-left: 1px solid var(--saw-border); border-radius: 0; }
  .saw-plan .list-group-item { border: 0; border-bottom: 1px solid var(--saw-border); border-radius: 0; background: transparent; padding: 1.35rem 1rem 1.35rem 1.5rem; }
  .saw-plan .list-group-item:last-child { border-bottom: 0; }
  .saw-plan .badge { display: inline-grid; place-items: center; min-width: 2rem; height: 2rem; border-radius: 0.2rem; font-variant-numeric: tabular-nums; background: linear-gradient(135deg, var(--saw-primary), var(--saw-primary-dark)) !important; color: #fff !important; }
  .saw-plan h3 { font-size: 1rem; font-weight: 700; }
  .saw-plan p { color: var(--saw-ink); max-width: 70rem; }

  code { color: var(--saw-primary-dark); background-color: var(--saw-primary-light); padding: 0.1em 0.35em; border-radius: 0.3rem; }

  .reading-guide-content { max-width: 900px; }
  .reading-guide-content h1 { margin-top: 0.5rem; margin-bottom: 1rem; }
  .reading-guide-content h2 { margin-top: 2rem; margin-bottom: 0.75rem; }
  .reading-guide-content h3 { margin-top: 1.5rem; margin-bottom: 0.5rem; }
  .reading-guide-content table { margin: 1rem 0; }

  /* --- Dark mode ---------------------------------------------------------------
     The toggle selects explicit color themes; the OS preference supplies the initial state. */
  html[data-saw-theme="dark"] {
    --saw-bg: #0f1520;
    --saw-ink: #e6e9ef;
    --saw-heading: #f4f6fa;
    --saw-muted: #98a3b5;
    --saw-border: rgba(255, 255, 255, 0.10);
    --saw-card-header: rgba(255, 255, 255, 0.03);
    --saw-primary: #5aa4ff;
    --saw-primary-dark: #8dc0ff;
    --saw-primary-light: rgba(90, 164, 255, 0.13);
    --saw-green-bg: rgba(45, 190, 120, 0.16); --saw-green-ink: #63d9a0;
    --saw-yellow-bg: rgba(240, 180, 40, 0.16); --saw-yellow-ink: #f0c257;
    --saw-red-bg: rgba(240, 90, 100, 0.16);   --saw-red-ink: #ff8b93;
    --saw-grey-bg: rgba(160, 170, 185, 0.16); --saw-grey-ink: #aab3c2;
  }
  html[data-saw-theme="dark"] .card { box-shadow: 0 1px 2px rgba(0,0,0,0.35), 0 8px 24px rgba(0,0,0,0.30); }

  /* --- Print -------------------------------------------------------------------
     Consultants hand these over as PDFs. Show every tab pane rather than only the
     active one, drop shadows and interactive chrome, and avoid breaking a card
     across pages. */
  @media print {
    body { background: #fff; padding-bottom: 0; }
    .saw-tabs-sticky, .nav-tabs, .nav-pills { display: none !important; }
    .tab-pane { display: block !important; opacity: 1 !important; }
    .card { box-shadow: none; break-inside: avoid; }
    .table-responsive { overflow: visible !important; }
    a[href^="http"]::after { content: " (" attr(href) ")"; font-size: 0.7em; word-break: break-all; }
  }

  /* --- Assessment report shell ----------------------------------------------- */
  body { padding-bottom: 0; background: var(--saw-bg); }
  .saw-appbar { position: sticky; top: 0; z-index: 1030; background: var(--saw-bg); border-bottom: 1px solid var(--saw-border); }
  .saw-appbar-inner { display: flex; align-items: center; justify-content: space-between; gap: 1.5rem; width: min(100%, 1480px); min-height: 58px; margin: 0 auto; padding: 0 1.75rem; }
  .saw-brand-lockup, .saw-appbar-actions { display: flex; align-items: center; gap: 0.8rem; }
  .saw-brand-lockup { min-width: 0; color: var(--saw-ink); font-size: 0.82rem; font-weight: 650; }
  .saw-brand-lockup img { display: block; width: 98px; height: auto; }
  .saw-brand-divider { height: 1.4rem; border-left: 1px solid var(--saw-border); }
  .saw-readonly-label { color: var(--saw-muted); font-size: 0.72rem; }
  .saw-mode-toggle { min-height: 2rem; border: 1px solid var(--saw-border); border-radius: 4px; padding: 0.25rem 0.65rem; background: var(--saw-bg); color: var(--saw-ink); font-size: 0.75rem; font-weight: 600; cursor: pointer; }
  .saw-mode-toggle:hover { border-color: var(--saw-primary); color: var(--saw-primary-dark); }
  .saw-report-page { width: min(100%, 1480px); margin: 0 auto; padding: 1.5rem 2rem 3rem; }
  .saw-report-heading { display: flex; align-items: flex-end; justify-content: space-between; gap: 1.25rem; margin-bottom: 1.2rem; }
  .saw-report-heading h1 { max-width: 45rem; margin: 0; color: var(--saw-heading); font-size: 1.8rem; line-height: 1.2; font-weight: 700; }
  .saw-report-eyebrow { margin: 0 0 0.25rem; color: var(--saw-primary-dark); font-size: 0.68rem; font-weight: 700; text-transform: uppercase; }
  .saw-report-heading-meta { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 0.6rem 1.4rem; }
  .saw-report-context { display: flex; flex-wrap: wrap; gap: 0.55rem 1.1rem; }
  .saw-context-item { display: grid; gap: 0.08rem; min-width: 7rem; }
  .saw-context-item > span { color: var(--saw-muted); font-size: 0.65rem; font-weight: 650; text-transform: uppercase; }
  .saw-context-item strong { color: var(--saw-ink); font-size: 0.78rem; font-weight: 650; }
  .saw-context-item small { color: var(--saw-muted); font-size: 0.65rem; }
  .saw-report-page .saw-tabs-sticky { top: 58px; z-index: 1020; margin-bottom: 1.25rem !important; padding-top: 0; background: var(--saw-bg); box-shadow: 0 2px 3px rgba(24, 37, 47, 0.04); }
  .saw-main-tabs { display: flex; gap: 0.2rem; border-bottom: 1px solid var(--saw-border); }
  .saw-main-tabs .nav-link { min-height: 2.8rem; padding: 0.75rem 1rem; color: var(--saw-muted); font-size: 0.82rem; font-weight: 600; white-space: nowrap; }
  .saw-main-tabs .nav-link.active { color: var(--saw-primary-dark); border-bottom: 2px solid var(--saw-primary); }
  .saw-main-tabs .nav-link:focus-visible, .saw-mode-toggle:focus-visible { outline: 2px solid var(--saw-primary); outline-offset: 2px; }
  .saw-report-page .tab-content { min-width: 0; }
  .saw-baseline-strip { display: flex; flex-wrap: wrap; align-items: center; gap: 0.3rem 1rem; margin-bottom: 1.1rem; padding: 0.7rem 0.9rem; border-left: 3px solid var(--saw-primary); background: var(--saw-primary-light); color: var(--saw-ink); font-size: 0.78rem; }
  .saw-baseline-strip strong { font-weight: 700; }
  .saw-baseline-explainer { color: var(--saw-muted); }
  .saw-summary-band { display: grid; grid-template-columns: minmax(150px, 0.75fr) minmax(0, 2fr) minmax(150px, 1.25fr); align-items: center; margin-bottom: 1.25rem; padding: 0.8rem 0; border-top: 1px solid var(--saw-border); border-bottom: 1px solid var(--saw-border); }
  .saw-open-count { display: grid; grid-template-columns: auto auto; align-items: center; column-gap: 0.7rem; padding: 0 1rem 0 0; border-right: 1px solid var(--saw-border); }
  .saw-open-count span { color: var(--saw-muted); font-size: 0.74rem; font-weight: 650; }
  .saw-open-count strong { grid-column: 2; grid-row: 1 / span 2; color: var(--saw-red); font-size: 1.85rem; line-height: 1; font-variant-numeric: tabular-nums; }
  .saw-open-count small { color: var(--saw-muted); font-size: 0.65rem; }
  .saw-summary-metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); padding: 0 1.2rem; }
  .saw-summary-metric { display: flex; align-items: baseline; justify-content: center; gap: 0.45rem; border-right: 1px solid var(--saw-border); }
  .saw-summary-metric:last-child { border-right: 0; }
  .saw-summary-metric span { color: var(--saw-muted); font-size: 0.7rem; font-weight: 600; }
  .saw-summary-metric strong { font-size: 1rem; font-variant-numeric: tabular-nums; }
  .saw-summary-red strong { color: var(--saw-red); }
  .saw-summary-amber strong { color: var(--saw-yellow-ink); }
  .saw-summary-green strong { color: var(--saw-green); }
  .saw-summary-gray strong { color: var(--saw-grey); }
  .saw-status-distribution { display: flex; height: 0.55rem; gap: 2px; overflow: hidden; border-radius: 2px; background: var(--saw-grey-bg); }
  .saw-status-distribution span { min-width: 0; }
  .saw-distribution-red { background: var(--saw-red); }
  .saw-distribution-amber { background: var(--saw-yellow); }
  .saw-distribution-green { background: var(--saw-green); }
  .saw-distribution-gray { background: var(--saw-grey); }
  .saw-overview-grid { display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(320px, 0.9fr); gap: 1.3rem; align-items: start; }
  .saw-overview-charts, .saw-priority-panel { min-width: 0; }
  .saw-section-heading { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; margin-bottom: 0.7rem; }
  .saw-section-heading h2 { margin: 0; color: var(--saw-heading); font-size: 1rem; font-weight: 700; }
  .saw-section-heading p, .saw-section-note { margin: 0; color: var(--saw-muted); font-size: 0.7rem; }
  .saw-chart-grid { display: grid; grid-template-columns: minmax(0, 0.8fr) minmax(0, 1.2fr); gap: 1rem; }
  .saw-chart-panel { min-width: 0; padding-top: 0.65rem; border-top: 1px solid var(--saw-border); }
  .saw-chart-panel h3 { margin: 0 0 0.3rem; color: var(--saw-muted); font-size: 0.72rem; font-weight: 650; }
  .saw-priority-panel { padding: 0.1rem 0 0 1.15rem; border-left: 1px solid var(--saw-border); }
  .saw-priority-list { margin: 0; padding: 0; list-style: none; }
  .saw-priority-row { display: grid; grid-template-columns: 3.3rem minmax(0, 1fr) auto; min-width: 0; align-items: start; gap: 0.6rem; padding: 0.65rem 0; border-top: 1px solid var(--saw-border); }
  .saw-priority-row > div { min-width: 0; }
  .saw-priority-row > span:first-child { font-size: 0.65rem; font-weight: 700; text-transform: uppercase; }
  .saw-status-red { color: var(--saw-red-ink); }
  .saw-status-amber { color: var(--saw-yellow-ink); }
  .saw-priority-row strong { display: block; color: var(--saw-ink); font-size: 0.78rem; line-height: 1.35; }
  .saw-priority-row p { margin: 0.2rem 0 0; color: var(--saw-muted); font-size: 0.68rem; line-height: 1.45; overflow-wrap: anywhere; }
  .saw-rule-id { color: var(--saw-primary-dark); font-size: 0.68rem; font-weight: 700; white-space: nowrap; }
  .saw-empty-state { padding: 0.8rem 0; color: var(--saw-muted); font-size: 0.78rem; }
  .saw-inline-link { display: inline-block; margin-top: 0.65rem; color: var(--saw-primary-dark); font-size: 0.72rem; font-weight: 650; }
  .saw-section { margin-top: 1.7rem; }
  .saw-deadlines { padding-top: 0.15rem; }
  .saw-deadline-list { margin: 0; padding: 0; list-style: none; border-top: 1px solid var(--saw-border); }
  .saw-deadline-row { display: grid; grid-template-columns: 8.2rem minmax(0, 1fr) minmax(11rem, 0.55fr); gap: 1rem; align-items: start; padding: 0.8rem 0.3rem; border-bottom: 1px solid var(--saw-border); }
  .saw-deadline-date { color: var(--saw-ink); font-size: 0.75rem; font-weight: 650; font-variant-numeric: tabular-nums; }
  .saw-deadline-date span { display: block; margin-top: 0.15rem; color: var(--saw-muted); font-size: 0.65rem; font-weight: 500; }
  .saw-deadline-main strong { color: var(--saw-ink); font-size: 0.78rem; font-weight: 650; }
  .saw-deadline-main p { margin: 0.2rem 0 0.35rem; color: var(--saw-muted); font-size: 0.69rem; line-height: 1.45; }
  .saw-deadline-rules .badge { margin-right: 0.2rem; font-size: 0.6rem; }
  .saw-deadline-impact { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 0.45rem; color: var(--saw-muted); font-size: 0.68rem; text-align: right; }
  .saw-deadline-critical .saw-deadline-date, .saw-deadline-soon .saw-deadline-date { color: var(--saw-red-ink); }
  .saw-deadline-near .saw-deadline-date { color: var(--saw-yellow-ink); }
  .saw-trend-grid { display: grid; grid-template-columns: minmax(0, 1.6fr) minmax(340px, 1fr); gap: 1rem; align-items: stretch; }
  .saw-trend-chart-panel, .saw-trend-history-panel { min-width: 0; height: 25rem; border: 1px solid var(--saw-border); border-radius: 4px; background: var(--saw-bg); }
  .saw-trend-chart-panel { position: relative; padding: 0.8rem; }
  .saw-trend-chart-panel canvas { width: 100% !important; height: 100% !important; }
  .saw-trend-history-panel { overflow: auto; }
  .saw-trend-table { width: 100%; table-layout: fixed; }
  .saw-trend-table th:first-child, .saw-trend-table td:first-child { width: 62%; }
  .saw-trend-table th:last-child, .saw-trend-table td:last-child { width: 38%; }
  .saw-trend-table th { position: sticky; top: 0; z-index: 1; background: var(--saw-bg); }
  .saw-trend-run { display: block; color: var(--saw-ink); font-size: 0.7rem; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
  .saw-trend-baseline { display: block; margin-top: 0.15rem; color: var(--saw-muted); font-size: 0.64rem; line-height: 1.35; overflow-wrap: anywhere; }
  .saw-trend-counts { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.2rem; }
  .saw-trend-counts .badge { display: block; min-width: 0; padding: 0.32em 0.1em; text-align: center; font-size: 0.65rem; }
  .saw-report-page .card { border-radius: 4px; box-shadow: none; }
  .saw-report-page .list-group-item { border-color: var(--saw-border); background: var(--saw-bg); }
  .saw-plan, .saw-plan .list-group-item { min-width: 0; }
  .saw-plan p, .saw-plan code { overflow-wrap: anywhere; }
  .saw-report-footer { width: min(100%, 1480px); margin: 1rem auto 0; padding: 1.4rem 2rem 0; border-top: 1px solid var(--saw-border); }
  html[data-saw-theme="dark"] .saw-appbar { background: var(--saw-bg); }
  @media (max-width: 900px) {
    .saw-report-page { padding-right: 1.25rem; padding-left: 1.25rem; }
    .saw-overview-grid { grid-template-columns: 1fr; }
    .saw-trend-grid { grid-template-columns: 1fr; }
    .saw-trend-chart-panel { height: 22rem; }
    .saw-trend-history-panel { height: 20rem; }
    .saw-priority-panel { padding: 1rem 0 0; border-top: 1px solid var(--saw-border); border-left: 0; }
    .saw-report-heading-meta { justify-content: flex-start; }
  }
  @media (max-width: 620px) {
    .saw-appbar-inner { min-height: 50px; padding: 0 0.8rem; }
    .saw-brand-lockup img { width: 82px; }
    .saw-brand-lockup { font-size: 0; }
    .saw-brand-divider, .saw-readonly-label { display: none; }
    .saw-appbar-actions { gap: 0.4rem; }
    .saw-mode-toggle { font-size: 0.67rem; padding: 0.2rem 0.45rem; }
    .saw-report-page { padding: 1.1rem 0.85rem 2rem; }
    .saw-report-heading { display: block; margin-bottom: 0.8rem; }
    .saw-report-heading h1 { font-size: 1.45rem; }
    .saw-report-heading-meta { justify-content: flex-start; gap: 0.4rem 0.8rem; margin-top: 0.7rem; }
    .saw-context-item { min-width: 0; }
    .saw-report-context { gap: 0.4rem 0.8rem; }
    .saw-tabs-sticky { top: 50px; }
    .saw-main-tabs { overflow-x: auto; flex-wrap: nowrap; }
    .saw-main-tabs .nav-link { min-height: 2.55rem; padding: 0.65rem 0.7rem; font-size: 0.7rem; }
    .saw-summary-band { grid-template-columns: minmax(0, 1fr) minmax(7rem, 0.8fr); row-gap: 0.65rem; padding: 0.65rem 0; }
    .saw-open-count { grid-row: span 2; }
    .saw-summary-metrics { grid-template-columns: repeat(2, 1fr); gap: 0.35rem 0.2rem; padding: 0; }
    .saw-summary-metric { justify-content: flex-start; border: 0; }
    .saw-status-distribution { grid-column: 2; grid-row: 2; }
    .saw-chart-grid { grid-template-columns: 1fr; }
    .saw-chart-panel canvas { max-height: 190px; }
    .saw-trend-chart-panel { height: 18rem; }
    .saw-trend-history-panel { height: 16rem; }
    .saw-deadline-row { grid-template-columns: 5.7rem minmax(0, 1fr); gap: 0.6rem; }
    .saw-deadline-impact { grid-column: 2; justify-content: flex-start; text-align: left; }
    .saw-section-heading { align-items: flex-start; }
    .saw-section-note { display: none; }
    .saw-report-footer { padding: 1rem 0.85rem 0; }
  }
  @media print {
    body { background: #fff; }
    .saw-appbar { position: static; }
    .saw-appbar-actions, .saw-tabs-sticky { display: none !important; }
    .saw-report-page { width: 100%; padding: 0.5rem; }
    .saw-priority-panel { border-left: 1px solid #d9e0e4; }
    .saw-report-footer { padding-right: 0.5rem; padding-left: 0.5rem; }
  }
</style>
</head>
<body>
<header class="saw-appbar">
  <div class="saw-appbar-inner">
    <div class="saw-brand-lockup">
      <img src="branding/secure-at-work-logo.png" alt="Secure At Work" width="2869" height="918">
      <span class="saw-brand-divider" aria-hidden="true"></span>
      <span>Authentication assessment</span>
    </div>
    <div class="saw-appbar-actions">
      <span class="saw-readonly-label">Read-only assessment</span>
      <button class="saw-mode-toggle" id="saw-theme-toggle" type="button" aria-pressed="false">Dark mode</button>
    </div>
  </div>
</header>
<main class="saw-report-page">
  <header class="saw-report-heading">
    <div><p class="saw-report-eyebrow">Microsoft Entra ID · Assessment report</p><h1>$heroTitle</h1></div>
    <div class="saw-report-heading-meta">
$envBannerHtml
      <div class="saw-context-item"><span>SOLL baseline</span><strong>$(ConvertTo-SAWHtmlEncoded $BaselineName)</strong></div>
    </div>
  </header>
$mainContentHtml

<footer class="saw-report-footer">
  <p class="text-body-secondary small mb-2"><strong>Sources.</strong> Every behavioral claim in this
  report traces to a published source rather than to this toolkit's own opinion. Primary sources are
  Microsoft Learn and the Microsoft Graph API reference; changes announced but not yet documented
  cite Microsoft 365 Message Center posts via
  <a href="https://mc.merill.net" rel="noopener noreferrer" target="_blank">mc.merill.net</a>, the
  community mirror maintained by Merill Fernando, so they stay checkable by anyone.</p>
  <p class="text-body-secondary small mb-2"><strong>With thanks to</strong>
  <a href="https://ourcloudnetwork.com/microsoft-entra-just-made-passwordless-mfa-registration-easier/" rel="noopener noreferrer" target="_blank">ourcloudnetwork.com</a>
  for surfacing the passwordless-registration changes,
  <a href="https://www.youtube.com/watch?v=3MC0Hoc8GuA" rel="noopener noreferrer" target="_blank">Ru Campbell at Threatscape</a>
  for the passkey deployment pitfalls that prompted several checks here, the
  <a href="https://github.com/passkeydeveloper/passkey-authenticator-aaguids" rel="noopener noreferrer" target="_blank">passkey-authenticator-aaguids</a>
  project, and the published AAGUID references from
  <a href="https://support.yubico.com/hc/en-us/articles/360016648959-YubiKey-hardware-FIDO2-AAGUIDs" rel="noopener noreferrer" target="_blank">Yubico</a>,
  <a href="https://fido.ftsafe.com/products/" rel="noopener noreferrer" target="_blank">Feitian</a> and
  <a href="https://docs.solokeys.dev/metadata-statements/" rel="noopener noreferrer" target="_blank">SoloKeys</a>.
  Built with <a href="https://getbootstrap.com/" rel="noopener noreferrer" target="_blank">Bootstrap</a>
  and <a href="https://www.chartjs.org/" rel="noopener noreferrer" target="_blank">Chart.js</a>,
  bundled locally so this file opens without internet access.</p>
  <p class="text-body-secondary small mb-0">The full rule-by-rule source mapping, with the date each
  was last verified against the live page, travels with this report in
  <code>docs/references.md</code>$(if ($ReadingGuideHtml) { ' and is summarised on the <strong>Reading This Report</strong> tab' }).</p>
</footer>
</main>

<script src="vendor/bootstrap/bootstrap.bundle.min.js"></script>
<script src="vendor/chartjs/chart.umd.min.js"></script>
<script>
  (function () {
    var root = document.documentElement;
    var toggle = document.getElementById('saw-theme-toggle');
    var dark = root.getAttribute('data-saw-theme') === 'dark';
    function applyTheme() {
      root.setAttribute('data-saw-theme', dark ? 'dark' : 'light');
      root.setAttribute('data-bs-theme', dark ? 'dark' : 'light');
      window.sawDashboardDark = dark;
      toggle.setAttribute('aria-pressed', dark ? 'true' : 'false');
      toggle.textContent = dark ? 'Normal mode' : 'Dark mode';
      if (window.Chart) {
        var chartColor = getComputedStyle(document.body).getPropertyValue('color') || '#191919';
        var chartBorderColor = getComputedStyle(root).getPropertyValue('--saw-border').trim() || 'rgba(16,24,40,0.09)';
        Chart.defaults.color = chartColor;
        Chart.defaults.borderColor = chartBorderColor;
        Object.keys(Chart.instances).forEach(function (id) {
          Chart.instances[id].options.color = chartColor;
          Chart.instances[id].options.borderColor = chartBorderColor;
          Chart.instances[id].update();
        });
      }
    }
    toggle.addEventListener('click', function () {
      dark = !dark;
      try { window.localStorage.setItem('saw-dashboard-theme', dark ? 'dark' : 'light'); } catch (e) { /* optional preference */ }
      applyTheme();
    });
    applyTheme();
  }());

  /* Chart.js draws legends and axis ticks in a fixed dark grey, which disappears against the
     dark theme. Read the resolved body colour instead so both themes stay legible. */
  Chart.defaults.color = getComputedStyle(document.body).getPropertyValue('color') || '#191919';
  Chart.defaults.borderColor = getComputedStyle(document.documentElement).getPropertyValue('--saw-border').trim() || 'rgba(16,24,40,0.09)';
  Chart.defaults.font.family = getComputedStyle(document.body).getPropertyValue('font-family');

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
$trendScriptHtml
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

    # Secure At Work's own logo, not a third-party library, so it lives next to vendor/ rather
    # than inside it - same "copy alongside the generated index.html" pattern either way, so the
    # report stays a self-contained directory with no absolute-path or CDN dependency.
    $brandingSource = Join-Path $PSScriptRoot 'branding'
    $brandingDestination = Join-Path $outputDirectory 'branding'
    Copy-Item -Path $brandingSource -Destination $brandingDestination -Recurse -Force

    $html | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Verbose "Export-SAWDashboard: wrote dashboard to $OutputPath (vendor assets copied to $vendorDestination, branding assets copied to $brandingDestination)"
    Get-Item -Path $OutputPath
}
