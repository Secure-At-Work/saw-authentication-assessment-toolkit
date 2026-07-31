function Get-SAWHistoryTrend {
    <#
    .SYNOPSIS
        Reads every history snapshot for a tenant and summarizes it into a small, ordered
        trend series for the dashboard.
    .DESCRIPTION
        Companion to Invoke-SAWDriftReport.ps1 - that script diffs exactly two snapshots in
        detail (regressions, blocked-by, roster bucket deltas); this one is the lighter "at a
        glance, across every run" counterpart rendered directly in the dashboard, so an
        assessor doesn't have to leave the report to see whether things are trending the right
        way.

        Reads every history/<TenantSlug>/*.json snapshot file (as written by
        Invoke-SAWAssessment.ps1), sorted ascending by filename - safe because the run
        timestamp format (yyyyMMdd-HHmmss) sorts lexically in chronological order, same
        assumption Invoke-SAWDriftReport.ps1 already relies on. For each snapshot, extracts
        just the Green/Yellow/Red/Grey status counts and roster bucket counts - not the full
        rule-by-rule detail, since a multi-run trend chart is about overall direction, not
        individual findings.

        Never touches the tenant - pure read of already-collected local snapshot files. Missing
        or empty history is not an error: returns an empty array so callers can render a "not
        enough history yet" note instead of failing.
    .PARAMETER HistoryPath
        Base directory snapshots live under (matches Invoke-SAWAssessment.ps1's -HistoryPath).
    .PARAMETER TenantSlug
        The tenant slug (subfolder under -HistoryPath) to build the trend for.
    .OUTPUTS
        Hashtable[] - one per run, ascending by RunTimestamp, each with RunTimestamp,
        GeneratedAt, BaselineName, Counts (Green/Yellow/Red/Grey), RosterCounts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HistoryPath,

        [Parameter(Mandatory)]
        [string]$TenantSlug
    )

    $tenantHistoryDirectory = Join-Path $HistoryPath $TenantSlug
    if (-not (Test-Path -Path $tenantHistoryDirectory)) {
        Write-Verbose "Get-SAWHistoryTrend: no history directory for tenant slug '$TenantSlug' at $tenantHistoryDirectory"
        return , @()
    }

    $snapshotFiles = Get-ChildItem -Path $tenantHistoryDirectory -Filter '*.json' -File | Sort-Object -Property Name

    $trend = foreach ($file in $snapshotFiles) {
        $snapshot = $null
        try {
            $snapshot = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        }
        catch {
            Write-Verbose "Get-SAWHistoryTrend: skipping unreadable/invalid snapshot $($file.FullName): $_"
            continue
        }

        $counts = @{ Green = 0; Yellow = 0; Red = 0; Grey = 0 }
        foreach ($result in @($snapshot.Results)) {
            if ($counts.ContainsKey($result.Status)) { $counts[$result.Status]++ }
        }

        $rosterCounts = @{ Remove = 0; Hunt = 0; 'Guest (FIDO2 Not Supported)' = 0; OK = 0 }
        foreach ($bucket in @($rosterCounts.Keys)) {
            if ($snapshot.RosterCounts.$bucket) { $rosterCounts[$bucket] = [int]$snapshot.RosterCounts.$bucket }
        }

        @{
            RunTimestamp = $snapshot.RunTimestamp
            GeneratedAt  = $snapshot.GeneratedAt
            BaselineName = $snapshot.BaselineName
            Counts       = $counts
            RosterCounts = $rosterCounts
        }
    }

    $trend = @($trend)
    Write-Verbose "Get-SAWHistoryTrend: $($trend.Count) snapshot(s) found for tenant slug '$TenantSlug'"

    , $trend
}
