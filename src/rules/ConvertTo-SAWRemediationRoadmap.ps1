function ConvertTo-SAWRemediationRoadmap {
    <#
    .SYNOPSIS
        Groups Invoke-SAWRulesEngine results into an ordered, phased IST -> SOLL remediation
        path.
    .DESCRIPTION
        This is a separate data product from the rules engine's flat result list (like the CA
        policy inventory or the user registration roster) - it doesn't evaluate anything new,
        it re-groups already-evaluated results by the Phase/PhaseName/DependsOn metadata each
        rule now carries (see the rule *.json files and Invoke-SAWRulesEngine.ps1) into
        something an assessor can hand to a customer as a work plan, not just a findings list.

        For each distinct Phase present in -RuleResults, produces a summary (total rules,
        how many are already Green, how many are Grey/not applicable, and the still-outstanding
        Red/Yellow ones) plus, per outstanding rule, whether it's currently Blocked - true if
        any RuleID in its DependsOn list is itself still Red/Yellow (not yet Green) in this same
        result set. A rule with no unmet dependencies is safe to work on now; a Blocked rule
        should wait, even if fixing it directly is technically possible, because doing so out of
        order carries real risk (e.g. enforcing CA002 - MFA for all users - before REG002 -
        registration coverage - is high enough risks locking out unregistered users).

        Rules with no Phase (a rule authored without one, or a caller passing hand-built
        fixtures) are grouped under a trailing 'Unphased' bucket (Phase = $null) rather than
        dropped, so nothing silently disappears from the roadmap. Phases sort ascending, with
        Unphased always last.
    .PARAMETER RuleResults
        Output of Invoke-SAWRulesEngine (RuleID/Category/Setting/Expected/Actual/Severity/
        Status/Recommendation/Phase/PhaseName/DependsOn).
    .OUTPUTS
        Hashtable[] - one per phase, ordered ascending by Phase (Unphased last), each with
        Phase, PhaseName, TotalCount, CompletedCount, NotApplicableCount, OutstandingCount,
        IsComplete, and OutstandingRules (RuleID/Category/Setting/Status/Severity/
        Recommendation/Blocked/BlockedBy, sorted Severity then RuleID).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$RuleResults
    )

    $severityRank = @{ High = 0; Medium = 1; Low = 2 }

    $statusByRuleId = @{}
    foreach ($r in $RuleResults) { $statusByRuleId[$r.RuleID] = $r.Status }

    function Test-SAWDependencyUnmet {
        param([string]$DependencyRuleId)
        if (-not $statusByRuleId.ContainsKey($DependencyRuleId)) { return $false }
        $depStatus = $statusByRuleId[$DependencyRuleId]
        return ($depStatus -eq 'Red' -or $depStatus -eq 'Yellow')
    }

    # --- Group into phases, preserving a stable identity for the "Unphased" fallback bucket ---
    $phaseGroups = @{}
    $phaseOrder = @()
    foreach ($r in $RuleResults) {
        $phaseKey = if ($null -ne $r.Phase) { $r.Phase } else { 'Unphased' }
        if (-not $phaseGroups.ContainsKey($phaseKey)) {
            $phaseGroups[$phaseKey] = @()
            $phaseOrder += $phaseKey
        }
        $phaseGroups[$phaseKey] += $r
    }

    $orderedPhaseKeys = $phaseOrder | Sort-Object -Property `
        { if ($_ -eq 'Unphased') { [int]::MaxValue } else { [int]$_ } }

    $roadmap = foreach ($phaseKey in $orderedPhaseKeys) {
        $rulesInPhase = $phaseGroups[$phaseKey]

        $completed = @($rulesInPhase | Where-Object { $_.Status -eq 'Green' })
        $notApplicable = @($rulesInPhase | Where-Object { $_.Status -eq 'Grey' })
        $outstanding = @($rulesInPhase | Where-Object { $_.Status -eq 'Red' -or $_.Status -eq 'Yellow' })

        $outstandingSorted = $outstanding | Sort-Object -Property `
            { if ($severityRank.ContainsKey($_.Severity)) { $severityRank[$_.Severity] } else { 99 } }, `
            { $_.RuleID }

        $outstandingRoadmapEntries = foreach ($rule in $outstandingSorted) {
            $unmetDependencies = @()
            foreach ($dep in @($rule.DependsOn)) {
                if (Test-SAWDependencyUnmet -DependencyRuleId $dep) { $unmetDependencies += $dep }
            }

            @{
                RuleID         = $rule.RuleID
                Category       = $rule.Category
                Setting        = $rule.Setting
                Status         = $rule.Status
                Severity       = $rule.Severity
                Recommendation = $rule.Recommendation
                Blocked        = ($unmetDependencies.Count -gt 0)
                BlockedBy      = $unmetDependencies
            }
        }

        $phaseName = if ($phaseKey -eq 'Unphased') { 'Unphased' } else { $rulesInPhase[0].PhaseName }
        if (-not $phaseName) { $phaseName = "Phase $phaseKey" }

        @{
            Phase               = if ($phaseKey -eq 'Unphased') { $null } else { $phaseKey }
            PhaseName           = $phaseName
            TotalCount          = $rulesInPhase.Count
            CompletedCount      = $completed.Count
            NotApplicableCount  = $notApplicable.Count
            OutstandingCount    = $outstanding.Count
            IsComplete          = ($outstanding.Count -eq 0)
            OutstandingRules    = @($outstandingRoadmapEntries)
        }
    }

    $roadmap = @($roadmap)
    Write-Verbose "ConvertTo-SAWRemediationRoadmap: $($roadmap.Count) phase(s) built from $($RuleResults.Count) rule result(s)"

    # The comma operator forces PowerShell to write $roadmap to the output pipeline as a
    # single array object rather than enumerating it - without this, a result with exactly
    # one phase group unwraps into the bare phase hashtable, and callers doing $result[0] or
    # $result.Count would silently operate on that hashtable's own indexer/key-count instead
    # (a classic PowerShell footgun, caught here by manual verification before this was
    # discovered to matter).
    , $roadmap
}
