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
        self-contained and portable - it can be zipped up and opened offline.

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
        <td>$(ConvertTo-SAWHtmlEncoded $t.RunTimestamp)</td>
        <td>$(ConvertTo-SAWHtmlEncoded $t.BaselineName)</td>
        <td><span class="badge bg-success">$($t.Counts.Green)</span> <span class="badge bg-warning text-dark">$($t.Counts.Yellow)</span> <span class="badge bg-danger">$($t.Counts.Red)</span> <span class="badge bg-secondary">$($t.Counts.Grey)</span></td>
      </tr>
"@
            }

            $trendSectionHtml = @"
  <h2 class="h4 mb-3">Trend Over Time</h2>
  <p class="text-body-secondary small">$(@($Trend).Count) runs for this tenant. The lighter, at-a-glance counterpart to the detailed two-run drift report (<code>Invoke-SAWDriftReport.ps1</code>).</p>
  <div class="row mb-4 g-3">
    <div class="col-lg-8">
      <div class="card h-100"><div class="card-body">
        <canvas id="trendChart" height="220"></canvas>
      </div></div>
    </div>
    <div class="col-lg-4">
      <div class="card h-100"><div class="card-body">
        <div class="table-responsive" style="max-height: 300px;">
          <table class="table table-sm table-striped align-middle mb-0">
            <thead><tr><th>Run</th><th>Baseline</th><th>G/Y/R/Grey</th></tr></thead>
            <tbody>
$($trendRowsHtml -join "`n")
            </tbody>
          </table>
        </div>
      </div></div>
    </div>
  </div>
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
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
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
        @"
      <tr>
        <td><code>$(ConvertTo-SAWHtmlEncoded $k.Aaguid)</code></td>
        <td>$(ConvertTo-SAWHtmlEncoded $k.KnownName)</td>
        <td>$recognizedBadge</td>
      </tr>
"@
    }

    $fido2KeyInventorySectionHtml = ''
    if ($Fido2KeyInventory -and $Fido2KeyInventory.IsEnforced) {
        $fido2KeyInventorySectionHtml = @"
  <h2 class="h4 mb-3">FIDO2 Key Restrictions</h2>
  <p class="text-body-secondary small">$(ConvertTo-SAWHtmlEncoded $Fido2KeyInventory.EnforcementSummary) AAGUIDs are resolved against a hand-maintained reference list (Yubico hardware keys, confirmed against Yubico's own published AAGUID table, plus common synced-passkey providers) - an unrecognized AAGUID is a real key/provider this toolkit's reference list doesn't yet cover, not necessarily a problem. Check the FIDO Alliance Metadata Service or the vendor directly for anything unrecognized.</p>
  <div class="table-responsive mb-4">
    <table class="table table-striped table-hover align-middle">
      <thead>
        <tr><th>AAGUID</th><th>Key / Provider</th><th></th></tr>
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
            @{ Key = 'NudgePasskeyCampaign'; Title = 'Registration campaign - passkey'; Count = $ns.PasskeyCampaignCount
               Note = 'Nudged after completing MFA, if in campaign scope and without a passkey on that device/browser.' }
            @{ Key = 'NudgeAuthenticatorCampaign'; Title = 'Registration campaign - Microsoft Authenticator'; Count = $ns.AuthenticatorCampaignCount
               Note = 'Nudged after completing MFA, if in campaign scope and Authenticator push is not set up.' }
            @{ Key = 'NudgeSsprRegistration'; Title = 'SSPR registration interrupt'; Count = $ns.SsprRegistrationCount
               Note = 'SSPR-enabled but not registered. Skippable indefinitely unless MFA registration is also enforced, so this is a recurring nag rather than a one-off.' }
            @{ Key = 'NudgeSsprBrokenForAdmin'; Title = 'Broken: admin prompted but cannot register'; Count = $ns.SsprBrokenForAdminCount
               Note = 'Admin SSPR is disabled tenant-wide while these admins are still in scope for the user SSPR policy. They are interrupted to register and then told no methods can be registered. See SSPR002.' }
        )

        $nudgeCardsHtml = foreach ($g in $nudgeGroups) {
            if ($g.Count -eq 0) { continue }
            $affected = @($NudgeForecast.Users | Where-Object { $_[$g.Key] })
            $isBroken = $g.Key -eq 'NudgeSsprBrokenForAdmin'
            $badgeClass = if ($isBroken) { 'bg-danger' } else { 'bg-warning text-dark' }

            $userRowsHtml = foreach ($u in $affected) {
                $adminBadge = if ($u.IsAdmin) { ' <span class="badge bg-dark">Admin</span>' } else { '' }
                @"
        <tr>
          <td>$(ConvertTo-SAWHtmlEncoded $u.DisplayName)$adminBadge</td>
          <td class="text-body-secondary small">$(ConvertTo-SAWHtmlEncoded $u.UserPrincipalName)</td>
          <td class="text-body-secondary small">$(ConvertTo-SAWHtmlEncoded $u.MethodsRegistered)</td>
        </tr>
"@
            }

            @"
  <div class="card mb-3">
    <div class="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
      <strong>$(ConvertTo-SAWHtmlEncoded $g.Title)</strong>
      <span class="badge $badgeClass">$($g.Count) user$(if ($g.Count -ne 1) { 's' })</span>
    </div>
    <div class="card-body">
      <p class="text-body-secondary small mb-3">$(ConvertTo-SAWHtmlEncoded $g.Note)</p>
      <details>
        <summary class="small">Show the $($g.Count) affected user$(if ($g.Count -ne 1) { 's' })</summary>
        <div class="table-responsive mt-2">
          <table class="table table-sm table-striped align-middle">
            <thead><tr><th>User</th><th>UPN</th><th>Methods registered</th></tr></thead>
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

    # --- Upcoming Microsoft deadlines (optional - Get-SAWTimelineMilestones output) ---
    $timelineSectionHtml = ''
    if (@($TimelineMilestones).Count -gt 0) {
        $timelineCardsHtml = foreach ($m in $TimelineMilestones) {
            $urgencyClass = 'border-info'
            $daysLabel = "$($m.DaysRemaining) day(s) left"
            if ($m.IsPast) {
                $urgencyClass = 'border-secondary'
                # -$m.DaysRemaining (unary minus), not [Math]::Abs - static calls on
                # System.Math are blocked under this machine's ConstrainedLanguage mode.
                # Safe here since IsPast guarantees DaysRemaining is negative.
                $daysLabel = "$(-$m.DaysRemaining) day(s) ago"
            }
            elseif ($m.DaysRemaining -eq 0) {
                $daysLabel = 'Today'
                $urgencyClass = 'border-danger'
            }
            elseif ($m.DaysRemaining -le 14) {
                $urgencyClass = 'border-danger'
            }
            elseif ($m.DaysRemaining -le 45) {
                $urgencyClass = 'border-warning'
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
      <div class="col-md-6 col-lg-4">
        <div class="card h-100 $urgencyClass" style="border-left-width: 4px;"><div class="card-body">
          <div class="d-flex justify-content-between align-items-start gap-2 mb-1">
            <strong>$(ConvertTo-SAWHtmlEncoded $m.Title)</strong>
            <span class="badge bg-dark">$daysLabel</span>
          </div>
          <div class="text-body-secondary small mb-2">$(ConvertTo-SAWHtmlEncoded $m.Date) &middot; $relatedBadgesHtml</div>
          $impactHtml
          <p class="small mb-1">$(ConvertTo-SAWHtmlEncoded $m.Description)</p>
          $sourceLinkHtml
        </div></div>
      </div>
"@
        }

        $timelineSectionHtml = @"
  <h2 class="h4 mb-3">Upcoming Microsoft Deadlines</h2>
  <p class="text-body-secondary small">Hand-maintained, sourced list of known Microsoft-driven Entra rollout dates relevant to the checks above - not tenant-specific findings. Verify against the linked source before treating a date as final.</p>
  <div class="row g-3 mb-4">
$($timelineCardsHtml -join "`n")
  </div>
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
                $stepBadge = switch ($step.Applies) {
                    $true { '<span class="badge bg-success">IST: happens today</span>' }
                    $false { '<span class="badge bg-secondary">IST: does not happen today</span>' }
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

    # The tenant name is the headline in the hero, because a consultant with several of these
    # open needs to tell them apart at a glance, and the product name is already in the brand
    # line above it. Falls back to the product name when no tenant was resolved (sample data,
    # or a profile call that came back empty).
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

    $envBannerHtml = ''
    if ($TenantDisplayName -or $TenantId -or $RunTimestamp) {
        $tenantLineHtml = ''
        if ($TenantDisplayName -or $TenantId) {
            $tenantIdHtml = if ($TenantId) { " <span class=""text-white-50"">($(ConvertTo-SAWHtmlEncoded $TenantId))</span>" } else { '' }
            $tenantLineHtml = "<div><strong>Tenant:</strong> $(ConvertTo-SAWHtmlEncoded $TenantDisplayName)$tenantIdHtml</div>"
        }
        $runLineHtml = ''
        if ($RunTimestamp) {
            $runLineHtml = "<div><strong>Assessed:</strong> $(ConvertTo-SAWHtmlEncoded $runTimestampDisplay)</div>"
        }
        $envBannerHtml = @"
  <div class="alert alert-dark d-flex flex-wrap justify-content-between align-items-center gap-3 mb-3" role="alert">
    $tenantLineHtml
    $runLineHtml
  </div>
"@
    }

    # --- Top-level tabs ---
    # Splits what used to be one long "Assessment" scroll into four purpose-grouped tabs, plus
    # Reading This Report when a guide was supplied. Overview is deliberately the default-active
    # tab: Chart.js renders a canvas at 0x0 if it's inside a Bootstrap tab-pane that isn't shown
    # yet, so the two charts (and the trend chart) have to live on whichever pane loads active.
    $overviewPaneHtml = @"
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

$timelineSectionHtml
  <h2 class="h4 mb-3">Overview</h2>
  <div class="row g-3 mb-4">
    <div class="col-6 col-lg-3">
      <div class="card stat-card red h-100"><div class="card-body">
        <div class="stat-label">Red</div>
        <div class="stat-value">$($counts.Red)</div>
        <div class="small text-body-secondary">Below target, act first</div>
      </div></div>
    </div>
    <div class="col-6 col-lg-3">
      <div class="card stat-card yellow h-100"><div class="card-body">
        <div class="stat-label">Yellow</div>
        <div class="stat-value">$($counts.Yellow)</div>
        <div class="small text-body-secondary">Below target, lower severity</div>
      </div></div>
    </div>
    <div class="col-6 col-lg-3">
      <div class="card stat-card green h-100"><div class="card-body">
        <div class="stat-label">Green</div>
        <div class="stat-value">$($counts.Green)</div>
        <div class="small text-body-secondary">At target state</div>
      </div></div>
    </div>
    <div class="col-6 col-lg-3">
      <div class="card stat-card grey h-100"><div class="card-body">
        <div class="stat-label">Grey</div>
        <div class="stat-value">$($counts.Grey)</div>
        <div class="small text-body-secondary">Not applicable here</div>
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

$trendSectionHtml
"@

    $findingsRoadmapPaneHtml = @"
$roadmapSectionHtml
  <h2 class="h4 mb-3">Risk Findings &amp; Recommendations</h2>
  <div class="list-group mb-4">
$($findingsHtml -join "`n")
  </div>
"@

    $userJourneysPaneHtml = @"
$nudgeSectionHtml
$flowScenariosSectionHtml
$rosterSectionHtml
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
  <ul class="nav nav-tabs" role="tablist">
    <li class="nav-item" role="presentation">
      <button class="nav-link active" id="tab-overview" data-bs-toggle="tab" data-bs-target="#pane-overview" type="button" role="tab" aria-controls="pane-overview" aria-selected="true">Overview</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="tab-findings-roadmap" data-bs-toggle="tab" data-bs-target="#pane-findings-roadmap" type="button" role="tab" aria-controls="pane-findings-roadmap" aria-selected="false">Findings &amp; Roadmap</button>
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
    <div class="tab-pane fade" id="pane-findings-roadmap" role="tabpanel" aria-labelledby="tab-findings-roadmap">
$findingsRoadmapPaneHtml
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
  /* Set the Bootstrap theme before first paint, so a dark-mode reader never sees a white
     flash. Deliberately follows the OS setting only: this report is a deliverable that gets
     opened once and handed on, so a manual toggle would be state nobody asked to manage.
     Printing always forces light, because these get exported to PDF. */
  (function () {
    try {
      var dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      document.documentElement.setAttribute('data-bs-theme', dark ? 'dark' : 'light');
      window.addEventListener('beforeprint', function () { document.documentElement.setAttribute('data-bs-theme', 'light'); });
      window.addEventListener('afterprint', function () { document.documentElement.setAttribute('data-bs-theme', dark ? 'dark' : 'light'); });
    } catch (e) { /* leave the light default in place */ }
  })();
</script>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure At Work - Authentication Assessment Dashboard$titleTenantSuffix</title>
<link rel="stylesheet" href="vendor/bootstrap/bootstrap.min.css">
<style>
  /*
    Secure At Work brand palette, sourced from secureatwork.nl's own computed styles
    (WordPress theme --wp--preset--color--primary-* custom properties): primary blue
    #0064da, dark variant #2b57a7, very light tint #eff5fe/#f9fbff. Neue Haas Grotesk
    (the site's licensed display/text font) isn't embeddable here without a license and
    this toolkit avoids CDN font dependencies on principle (same reason Bootstrap/Chart.js
    are vendored locally, not pulled from a CDN) - the system sans-serif stack below leans
    on Helvetica Neue/Segoe UI ahead of the generic fallback for a similar grotesque feel.

    Traffic-light status colors (green/yellow/red/grey - Bootstrap's success/warning/
    danger/secondary) are deliberately left as Bootstrap defaults, not rebranded: they're
    functional semantics the reader relies on, not a place for brand color.
  */
  :root {
    --saw-primary: #0064da;
    --saw-primary-dark: #2b57a7;
    --saw-primary-light: #eff5fe;
    --saw-bg: #f9fbff;
    --saw-ink: #191919;
    --saw-heading: #0d1b2a;
    --saw-muted: #5c6b7f;
    --saw-border: rgba(16, 24, 40, 0.09);
    --saw-card-header: #fbfcfe;
    --saw-hero-from: #2b57a7;
    --saw-hero-mid: #0064da;
    --saw-hero-to: #2f8ae8;

    /* Status colours. Kept as traffic-light semantics rather than brand colour, but
       split into an accent (borders, tile rules) and a bg/ink pair for tinted badges,
       because solid amber on white fails contrast at badge size. Ink values are
       darkened until they pass WCAG AA against their own tint. */
    --saw-green: #198754;  --saw-green-bg: #e7f4ed;  --saw-green-ink: #10633d;
    --saw-yellow: #e0a800; --saw-yellow-bg: #fdf4dd; --saw-yellow-ink: #7a5600;
    --saw-red: #dc3545;    --saw-red-bg: #fdebed;    --saw-red-ink: #a71d2a;
    --saw-grey: #6c757d;   --saw-grey-bg: #eef1f5;   --saw-grey-ink: #4a5462;

    --bs-primary: var(--saw-primary);
    --bs-primary-rgb: 0, 100, 218;
    --bs-link-color: var(--saw-primary);
    --bs-link-color-rgb: 0, 100, 218;
    --bs-link-hover-color: var(--saw-primary-dark);
    --bs-link-hover-color-rgb: 43, 87, 167;
    --bs-body-font-family: -apple-system, "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
    --bs-border-radius: 0.6rem;
    --bs-border-radius-sm: 0.4rem;
    --bs-border-radius-lg: 0.75rem;
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
  h1, h2, h3, h4, h5, h6 { letter-spacing: -0.018em; color: var(--saw-heading); }
  h2.h4 { font-weight: 650; }
  .lead-sm { font-size: 0.9375rem; line-height: 1.6; }

  /* --- Hero -------------------------------------------------------------------
     Replaces a flat navbar strip. The tenant name is the thing a consultant running
     several assessments needs to identify a file by, so it is the largest element. */
  .saw-hero {
    /* Deliberately its own colour pair rather than reusing --saw-primary: dark mode lightens
       the primary blue for text contrast, which would wash the hero out to near-white. */
    background: linear-gradient(135deg, var(--saw-hero-from) 0%, var(--saw-hero-mid) 55%, var(--saw-hero-to) 100%);
    color: #fff;
    padding: 1.75rem 0 1.5rem;
    margin-bottom: 1.75rem;
    box-shadow: 0 8px 28px rgba(0, 60, 130, 0.18);
  }
  .saw-hero a { color: #fff; }
  .saw-hero-brand {
    display: inline-flex; align-items: center; gap: 0.5rem;
    font-weight: 700; letter-spacing: 0.02em; text-transform: uppercase;
    font-size: 0.78rem; opacity: 0.92; margin-bottom: 0.65rem;
  }
  .saw-hero-title { font-weight: 700; font-size: clamp(1.35rem, 2.4vw, 1.9rem); margin: 0; color: #fff; }
  .saw-hero-sub { opacity: 0.85; font-size: 0.875rem; margin: 0.35rem 0 0; }
  .saw-hero-meta { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.9rem; }
  .saw-chip {
    display: inline-flex; align-items: center; gap: 0.35rem;
    background: rgba(255, 255, 255, 0.14);
    border: 1px solid rgba(255, 255, 255, 0.22);
    border-radius: 999px; padding: 0.2rem 0.7rem;
    font-size: 0.78rem; white-space: nowrap;
  }
  .saw-chip strong { font-weight: 600; }
  .navbar-mark { flex: none; }

  /* --- Cards ------------------------------------------------------------------ */
  .card {
    border-color: var(--saw-border);
    box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04), 0 6px 20px rgba(16, 24, 40, 0.05);
    transition: box-shadow 0.16s ease, transform 0.16s ease;
  }
  .card-header { font-weight: 600; background-color: var(--saw-card-header); border-bottom-color: var(--saw-border); }
  details.card > summary.card-header:hover { background-color: var(--saw-primary-light); }

  /* --- KPI tiles ---------------------------------------------------------------
     Previously a 4px left border. Now a top accent plus a tinted, tabular-figure
     numeral, so the four tiles scan as a set and the numbers line up. */
  .stat-card { position: relative; overflow: hidden; border-top: 3px solid transparent; }
  .stat-card:hover { transform: translateY(-2px); box-shadow: 0 2px 4px rgba(16,24,40,0.05), 0 12px 28px rgba(16,24,40,0.10); }
  .stat-card .stat-label {
    text-transform: uppercase; letter-spacing: 0.06em;
    font-size: 0.7rem; font-weight: 650; color: var(--saw-muted);
  }
  .stat-card .stat-value {
    font-size: 2.35rem; font-weight: 700; line-height: 1.1;
    font-variant-numeric: tabular-nums; letter-spacing: -0.03em;
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
  .nav-tabs .nav-link { color: var(--saw-muted); font-weight: 550; border: none; border-bottom: 2px solid transparent; }
  .nav-tabs .nav-link:hover { color: var(--saw-primary); border-bottom-color: var(--saw-border); }
  .nav-tabs .nav-link.active { color: var(--saw-primary); background: transparent; border-bottom: 2px solid var(--saw-primary); }
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

  code { color: var(--saw-primary-dark); background-color: var(--saw-primary-light); padding: 0.1em 0.35em; border-radius: 0.3rem; }

  .reading-guide-content { max-width: 900px; }
  .reading-guide-content h1 { margin-top: 0.5rem; margin-bottom: 1rem; }
  .reading-guide-content h2 { margin-top: 2rem; margin-bottom: 0.75rem; }
  .reading-guide-content h3 { margin-top: 1.5rem; margin-bottom: 0.5rem; }
  .reading-guide-content table { margin: 1rem 0; }

  /* --- Dark mode ---------------------------------------------------------------
     Follows the reader's OS setting. Bootstrap 5.3 already themes its own components
     from data-bs-theme, which the inline script below flips; these variables cover
     the custom surfaces above. */
  @media (prefers-color-scheme: dark) {
    :root {
      --saw-bg: #0f1520;
      --saw-ink: #e6e9ef;
      --saw-heading: #f4f6fa;
      --saw-muted: #98a3b5;
      --saw-border: rgba(255, 255, 255, 0.10);
      --saw-card-header: rgba(255, 255, 255, 0.03);
      --saw-primary: #5aa4ff;
      --saw-primary-dark: #8dc0ff;
      --saw-primary-light: rgba(90, 164, 255, 0.13);
      /* Hero stays deep in dark mode; only slightly desaturated so it doesn't glow. */
      --saw-hero-from: #16305e;
      --saw-hero-mid: #10457f;
      --saw-hero-to: #1b5c9e;
      --saw-green-bg: rgba(45, 190, 120, 0.16); --saw-green-ink: #63d9a0;
      --saw-yellow-bg: rgba(240, 180, 40, 0.16); --saw-yellow-ink: #f0c257;
      --saw-red-bg: rgba(240, 90, 100, 0.16);   --saw-red-ink: #ff8b93;
      --saw-grey-bg: rgba(160, 170, 185, 0.16); --saw-grey-ink: #aab3c2;
    }
    .card { box-shadow: 0 1px 2px rgba(0,0,0,0.35), 0 8px 24px rgba(0,0,0,0.30); }
    .saw-hero { box-shadow: 0 8px 28px rgba(0, 0, 0, 0.45); }
  }

  /* --- Print -------------------------------------------------------------------
     Consultants hand these over as PDFs. Show every tab pane rather than only the
     active one, drop shadows and interactive chrome, and avoid breaking a card
     across pages. */
  @media print {
    body { background: #fff; padding-bottom: 0; }
    .saw-hero { background: var(--saw-primary-dark) !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; box-shadow: none; }
    .saw-tabs-sticky, .nav-tabs, .nav-pills { display: none !important; }
    .tab-pane { display: block !important; opacity: 1 !important; }
    .card { box-shadow: none; break-inside: avoid; }
    .table-responsive { overflow: visible !important; }
    a[href^="http"]::after { content: " (" attr(href) ")"; font-size: 0.7em; word-break: break-all; }
  }
</style>
</head>
<body>
<header class="saw-hero">
  <div class="container-fluid">
    <div class="saw-hero-brand">
      <svg class="navbar-mark" width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <path d="M12 2L4 5.5V11C4 16.2 7.4 20.9 12 22C16.6 20.9 20 16.2 20 11V5.5L12 2Z" fill="white" fill-opacity="0.18"/>
        <path d="M12 2L4 5.5V11C4 16.2 7.4 20.9 12 22C16.6 20.9 20 16.2 20 11V5.5L12 2Z" stroke="white" stroke-width="1.4" stroke-linejoin="round"/>
        <path d="M8.5 12.2L10.8 14.5L15.5 9.5" stroke="white" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      Secure At Work
    </div>
    <h1 class="saw-hero-title">$heroTitle</h1>
    <p class="saw-hero-sub">Entra ID Authentication Assessment &middot; IST versus SOLL</p>
    <div class="saw-hero-meta">
      <span class="saw-chip">Generated <strong>$generated</strong></span>
      <span class="saw-chip"><strong>$totalRules</strong> checks</span>
$heroScoreChipHtml
      <span class="saw-chip" title="This toolkit only ever issues HTTP GET requests.">Read-only &middot; no tenant changes made</span>
    </div>
  </div>
</header>
<div class="container-fluid">

$envBannerHtml
$mainContentHtml
</div>

<footer class="container-fluid mt-5 pt-4 border-top">
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

<script src="vendor/bootstrap/bootstrap.bundle.min.js"></script>
<script src="vendor/chartjs/chart.umd.min.js"></script>
<script>
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

    $html | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Verbose "Export-SAWDashboard: wrote dashboard to $OutputPath (vendor assets copied to $vendorDestination)"
    Get-Item -Path $OutputPath
}
