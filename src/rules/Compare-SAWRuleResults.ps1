function Compare-SAWRuleResults {
    <#
    .SYNOPSIS
        Diffs two Invoke-SAWAssessment history snapshots for the same tenant to surface drift.
    .DESCRIPTION
        Pure comparison, no Graph calls - takes two snapshot objects (as written by
        Invoke-SAWAssessment.ps1 to history/<tenant-slug>/<timestamp>.json, or the equivalent
        in-memory shape) and reports what changed between them per RuleID, plus roster bucket
        deltas. Never touches the tenant; only compares already-collected data.

        Per-rule classification (OldSnapshot -> NewSnapshot):
          - 'New Check'            - RuleID exists in NewSnapshot but not OldSnapshot (a rule
                                      was added to the toolkit between runs).
          - 'Removed Check'        - RuleID exists in OldSnapshot but not NewSnapshot (a rule
                                      was removed/renamed between runs).
          - 'Regressed'            - Status got worse (Green -> Yellow/Red, or Yellow -> Red).
          - 'Improved'             - Status got better (Red -> Yellow/Green, or Yellow -> Green).
          - 'Became Applicable'    - Status went from Grey (no data / not applicable) to a real
                                      Green/Yellow/Red result - e.g. FIDO2 just got enabled, so
                                      PASS001-003 now actually evaluate. Surfaced separately from
                                      Regressed/Improved since Grey has no severity ranking of
                                      its own to compare against.
          - 'Became Not Applicable'- The reverse: a real result went back to Grey (e.g. a
                                      feature was disabled, or a baseline override marked it
                                      NotApplicable).
          - 'Unchanged'            - Same Status in both snapshots (including Grey -> Grey).

        Status severity ranking used for Regressed/Improved: Green (best) < Yellow < Red
        (worst). Grey is deliberately excluded from this ranking (see 'Became
        Applicable'/'Became Not Applicable' above) rather than treated as, say, "worse than
        Red" or "better than Green" - neither framing is meaningful for a not-applicable result.
    .PARAMETER OldSnapshot
        The earlier snapshot (object with a .Results array of RuleID/Category/Setting/Status/
        Actual/Expected, and optional .RosterCounts/.RosterAdminCounts hashtables).
    .PARAMETER NewSnapshot
        The later snapshot, same shape as -OldSnapshot.
    .OUTPUTS
        Hashtable with RuleChanges (all), Regressions, Improvements, NewlyApplicable,
        NewlyNotApplicable, NewChecks, RemovedChecks, Unchanged (all subsets of RuleChanges),
        and RosterDelta (per-bucket Old/New/Delta counts, only present when both snapshots
        carry RosterCounts).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$OldSnapshot,

        [Parameter(Mandatory)]
        [object]$NewSnapshot
    )

    $statusRank = @{ Green = 0; Yellow = 1; Red = 2 }

    $oldResults = @{}
    foreach ($r in @($OldSnapshot.Results)) { $oldResults[$r.RuleID] = $r }

    $newResults = @{}
    foreach ($r in @($NewSnapshot.Results)) { $newResults[$r.RuleID] = $r }

    $allRuleIds = @()
    foreach ($id in $oldResults.Keys) { if ($allRuleIds -notcontains $id) { $allRuleIds += $id } }
    foreach ($id in $newResults.Keys) { if ($allRuleIds -notcontains $id) { $allRuleIds += $id } }
    $allRuleIds = $allRuleIds | Sort-Object

    $ruleChanges = foreach ($ruleId in $allRuleIds) {
        $old = $oldResults[$ruleId]
        $new = $newResults[$ruleId]

        if (-not $old) {
            $changeType = 'New Check'
        }
        elseif (-not $new) {
            $changeType = 'Removed Check'
        }
        elseif ($old.Status -eq $new.Status) {
            $changeType = 'Unchanged'
        }
        elseif ($old.Status -eq 'Grey') {
            $changeType = 'Became Applicable'
        }
        elseif ($new.Status -eq 'Grey') {
            $changeType = 'Became Not Applicable'
        }
        elseif ($statusRank.ContainsKey($old.Status) -and $statusRank.ContainsKey($new.Status)) {
            if ($statusRank[$new.Status] -gt $statusRank[$old.Status]) { $changeType = 'Regressed' }
            elseif ($statusRank[$new.Status] -lt $statusRank[$old.Status]) { $changeType = 'Improved' }
            else { $changeType = 'Unchanged' }
        }
        else {
            $changeType = 'Unchanged'
        }

        $reference = if ($new) { $new } else { $old }

        @{
            RuleID     = $ruleId
            Category   = $reference.Category
            Setting    = $reference.Setting
            OldStatus  = if ($old) { $old.Status } else { $null }
            NewStatus  = if ($new) { $new.Status } else { $null }
            OldActual  = if ($old) { $old.Actual } else { $null }
            NewActual  = if ($new) { $new.Actual } else { $null }
            Expected   = if ($new) { $new.Expected } else { $old.Expected }
            Severity   = if ($new) { $new.Severity } else { $old.Severity }
            ChangeType = $changeType
        }
    }

    $rosterDelta = $null
    if ($OldSnapshot.RosterCounts -and $NewSnapshot.RosterCounts) {
        # Dot-property access (.$bucket) works uniformly whether RosterCounts is a raw
        # hashtable (in-memory, e.g. called directly from Invoke-SAWAssessment) or a
        # PSCustomObject (round-tripped through ConvertFrom-Json when read back from a
        # history/*.json file) - PowerShell resolves hashtable keys via member-access
        # notation the same way it resolves NoteProperty names. A missing bucket key
        # resolves to $null, which [int] casts to 0.
        $buckets = @('Remove', 'Hunt', 'Guest (FIDO2 Not Supported)', 'OK')
        $rosterDelta = foreach ($bucket in $buckets) {
            $oldCount = [int]$OldSnapshot.RosterCounts.$bucket
            $newCount = [int]$NewSnapshot.RosterCounts.$bucket

            @{
                Bucket = $bucket
                Old    = $oldCount
                New    = $newCount
                Delta  = ($newCount - $oldCount)
            }
        }
    }

    Write-Verbose "Compare-SAWRuleResults: $($ruleChanges.Count) rule(s) compared - $((@($ruleChanges | Where-Object { $_.ChangeType -eq 'Regressed' })).Count) regressed, $((@($ruleChanges | Where-Object { $_.ChangeType -eq 'Improved' })).Count) improved"

    @{
        OldRunTimestamp     = $OldSnapshot.RunTimestamp
        NewRunTimestamp     = $NewSnapshot.RunTimestamp
        RuleChanges         = $ruleChanges
        Regressions         = @($ruleChanges | Where-Object { $_.ChangeType -eq 'Regressed' })
        Improvements        = @($ruleChanges | Where-Object { $_.ChangeType -eq 'Improved' })
        NewlyApplicable     = @($ruleChanges | Where-Object { $_.ChangeType -eq 'Became Applicable' })
        NewlyNotApplicable  = @($ruleChanges | Where-Object { $_.ChangeType -eq 'Became Not Applicable' })
        NewChecks           = @($ruleChanges | Where-Object { $_.ChangeType -eq 'New Check' })
        RemovedChecks       = @($ruleChanges | Where-Object { $_.ChangeType -eq 'Removed Check' })
        Unchanged           = @($ruleChanges | Where-Object { $_.ChangeType -eq 'Unchanged' })
        RosterDelta         = $rosterDelta
    }
}
