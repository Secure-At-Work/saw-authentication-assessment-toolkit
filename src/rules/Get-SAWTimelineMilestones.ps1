function Get-SAWTimelineMilestones {
    <#
    .SYNOPSIS
        Loads the hand-maintained Microsoft rollout timeline and computes how many days remain
        (or have elapsed) until each milestone, relative to a given reference date.
    .DESCRIPTION
        Pure data shaping, no Graph calls - reads config/timeline-milestones.json (a static,
        hand-sourced list of known Microsoft-driven Entra authentication rollout dates, e.g.
        the 2026-09-07 SSPR enforcement or the 2027-02-01 SMS/Voice retirement) and annotates
        each entry with DaysRemaining and IsPast, sorted ascending by Date so the nearest
        deadline is always first.

        -ReferenceDate defaults to today but is a parameter (not read from Get-Date internally)
        specifically so this is deterministically testable - a hand-authored deadline list is
        exactly the kind of thing that silently goes stale, so the "how many days left" math
        needs to be verifiable against a fixed date, not whatever day the test happens to run.

        A milestone can optionally declare an ImpactMetric key (e.g. "PhoneBasedMethodUsers") in
        the JSON - if -ImpactMetrics contains a matching key, that milestone's UsersImpacted gets
        set to the corresponding count, alongside the milestone's own ImpactMetricLabel
        explaining what's being counted. This function only does the lookup; the actual counting
        happens in the caller (Invoke-SAWAssessment.ps1, against $userRoster/$registrationRaw)
        since that's tenant data this function has no business collecting itself. A milestone
        with no ImpactMetric (e.g. "passwordless password change" - no rule, no data source
        exists yet) or one whose key isn't in -ImpactMetrics simply gets UsersImpacted = $null,
        which the dashboard renders as "not computable" rather than a fabricated 0.

        -NotApplicableReasons covers a different case from "not computable": the metric WAS
        computed, but the underlying feature doesn't apply to this tenant at all - e.g. SSPR
        isn't enabled for any user, so the SSPR-enforcement deadlines are moot regardless of
        what the raw count says. Without this, "0 users impacted" would read identically whether
        it means "fully compliant" or "doesn't apply here," which is a real difference worth
        keeping distinct. When a milestone's ImpactMetric key is present in
        -NotApplicableReasons, that reason wins over any numeric value in -ImpactMetrics -
        NotApplicableReason gets set and UsersImpacted stays $null.
    .PARAMETER MilestonesPath
        Path to the timeline milestones JSON file. Defaults to config/timeline-milestones.json.
    .PARAMETER ReferenceDate
        The "today" to compute DaysRemaining against. Defaults to the current date (time
        component ignored - both dates are compared at midnight).
    .PARAMETER ImpactMetrics
        Optional hashtable of pre-computed impact counts, keyed by the ImpactMetric name a
        milestone declares in the JSON (e.g. @{ PhoneBasedMethodUsers = 12 }). Omit entirely for
        an impact-free view (every milestone's UsersImpacted is $null) - e.g. under
        -UseSampleData or when registration data wasn't collected for some other reason.
    .PARAMETER NotApplicableReasons
        Optional hashtable, keyed the same way as -ImpactMetrics, whose value is a short reason
        string shown instead of a count (e.g. @{ SsprEnabledNotRegisteredUsers = "SSPR isn't
        enabled for any user in this tenant" }). Takes priority over -ImpactMetrics for the same
        key - a milestone flagged not-applicable never shows a numeric "impacted" count.
    .OUTPUTS
        Hashtable[] - one per milestone, ascending by Date, each with Date, Title, Description,
        RelatedRuleIDs, SourceUrl, DaysRemaining (negative if in the past), IsPast, UsersImpacted
        (nullable), ImpactMetricLabel (nullable), NotApplicableReason (nullable).
    #>
    [CmdletBinding()]
    param(
        [string]$MilestonesPath = (Join-Path $PSScriptRoot '..' '..' 'config' 'timeline-milestones.json'),

        [datetime]$ReferenceDate = (Get-Date),

        [hashtable]$ImpactMetrics = @{},

        [hashtable]$NotApplicableReasons = @{}
    )

    if (-not (Test-Path -Path $MilestonesPath)) {
        Write-Verbose "Get-SAWTimelineMilestones: no milestones file found at $MilestonesPath"
        return , @()
    }

    $data = Get-Content -Path $MilestonesPath -Raw | ConvertFrom-Json
    $today = $ReferenceDate.Date

    $milestones = foreach ($m in @($data.milestones)) {
        $milestoneDate = [datetime]$m.Date
        $daysRemaining = ($milestoneDate.Date - $today).Days

        $usersImpacted = $null
        $notApplicableReason = $null
        if ($m.ImpactMetric -and $NotApplicableReasons.ContainsKey($m.ImpactMetric)) {
            $notApplicableReason = $NotApplicableReasons[$m.ImpactMetric]
        }
        elseif ($m.ImpactMetric -and $ImpactMetrics.ContainsKey($m.ImpactMetric)) {
            $usersImpacted = $ImpactMetrics[$m.ImpactMetric]
        }

        @{
            Date                = $m.Date
            Title               = $m.Title
            Description         = $m.Description
            RelatedRuleIDs      = @($m.RelatedRuleIDs)
            SourceUrl           = $m.SourceUrl
            DaysRemaining       = $daysRemaining
            IsPast              = ($daysRemaining -lt 0)
            UsersImpacted       = $usersImpacted
            ImpactMetricLabel   = $m.ImpactMetricLabel
            NotApplicableReason = $notApplicableReason
        }
    }

    $milestones = @($milestones | Sort-Object -Property { [datetime]$_.Date })
    Write-Verbose "Get-SAWTimelineMilestones: $($milestones.Count) milestone(s) loaded, reference date $($today.ToString('yyyy-MM-dd'))"

    , $milestones
}
