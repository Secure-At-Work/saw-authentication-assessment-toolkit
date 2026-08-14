@{
    # Rules excluded deliberately, not by oversight - see the comment above each one.
    ExcludeRules = @(
        # Every collector/normalizer name here (Get-SAWAuditLogs, ConvertTo-SAWNormalizedSignInLogs,
        # etc.) is deliberately plural: each one returns or represents a collection, and the plural
        # noun is the accurate name for that collection (matching the Graph resource it wraps, e.g.
        # auditLogs, signIns). Singularizing ~14 public function names at this point would break
        # every caller, test, and doc reference for a style preference with no functional benefit.
        'PSUseSingularNouns',

        # Write-Host is used only in entry-point/orchestrator scripts (Invoke-SAWAssessment.ps1,
        # Invoke-SAWDriftReport.ps1, Connect-SAWGraph.ps1) for human-facing console banners and
        # -ForegroundColor status output, never in library functions that return data. That's
        # exactly Write-Host's intended use; Write-Output would pollute the pipeline and
        # Write-Information can't carry color.
        'PSAvoidUsingWriteHost',

        # Single false positive: New-SAWChangeSection (src/dashboard/Export-SAWDriftReport.ps1) is
        # a private nested function that builds an HTML string - it doesn't touch system state, the
        # "New-" verb is only for naming consistency with this file's other section builders.
        # PSScriptAnalyzer does not honour [SuppressMessageAttribute] for this specific rule
        # (verified locally - the attribute is silently ignored on both nested and top-level
        # functions, unlike every other rule), so this has to be excluded project-wide instead of
        # suppressed at the one call site.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
