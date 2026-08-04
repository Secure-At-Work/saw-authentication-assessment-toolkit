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
    .PARAMETER MilestonesPath
        Path to the timeline milestones JSON file. Defaults to config/timeline-milestones.json.
    .PARAMETER ReferenceDate
        The "today" to compute DaysRemaining against. Defaults to the current date (time
        component ignored - both dates are compared at midnight).
    .OUTPUTS
        Hashtable[] - one per milestone, ascending by Date, each with Date, Title, Description,
        RelatedRuleIDs, SourceUrl, DaysRemaining (negative if in the past), IsPast.
    #>
    [CmdletBinding()]
    param(
        [string]$MilestonesPath = (Join-Path $PSScriptRoot '..' '..' 'config' 'timeline-milestones.json'),

        [datetime]$ReferenceDate = (Get-Date)
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

        @{
            Date            = $m.Date
            Title           = $m.Title
            Description     = $m.Description
            RelatedRuleIDs  = @($m.RelatedRuleIDs)
            SourceUrl       = $m.SourceUrl
            DaysRemaining   = $daysRemaining
            IsPast          = ($daysRemaining -lt 0)
        }
    }

    $milestones = @($milestones | Sort-Object -Property { [datetime]$_.Date })
    Write-Verbose "Get-SAWTimelineMilestones: $($milestones.Count) milestone(s) loaded, reference date $($today.ToString('yyyy-MM-dd'))"

    , $milestones
}
