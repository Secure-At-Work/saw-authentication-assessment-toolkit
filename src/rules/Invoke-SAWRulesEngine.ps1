function Invoke-SAWRulesEngine {
    <#
    .SYNOPSIS
        Evaluates normalized collector data against Secure At Work rule definitions.
    .DESCRIPTION
        Loads every *.json rule file from -RulesPath (rules contain no PowerShell logic,
        per spec section 8) and compares each rule's Expected value against the matching
        normalized setting. Never touches the tenant - pure comparison of already-collected data.

        -BaselineOverrides (see Get-SAWBaselineOverrides) lets a customer-specific SOLL
        baseline adjust a rule's Expected/Severity, or mark it NotApplicable entirely, without
        editing the rule JSON files themselves - the shipped rules stay the toolkit's
        out-of-the-box defaults; a baseline is a diff on top of them for one engagement.

        Status mapping (spec section 10):
          Green  - Actual matches Expected (after any baseline override).
          Red    - Actual differs from Expected and the effective Severity is High.
          Yellow - Actual differs from Expected and the effective Severity is Medium/Low.
          Grey   - No normalized data was collected for this rule's Category/Setting, OR the
                   baseline marks it NotApplicable for this customer.
    .PARAMETER RulesPath
        Directory containing rule *.json files.
    .PARAMETER NormalizedData
        Normalized objects produced by a collector's normalizer (Category/Setting/State).
    .PARAMETER BaselineOverrides
        Optional hashtable from Get-SAWBaselineOverrides, keyed by RuleID. Defaults to no
        overrides (every rule evaluates exactly as authored).
    .OUTPUTS
        Hashtable[]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RulesPath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$NormalizedData,

        [hashtable]$BaselineOverrides = @{}
    )

    if (-not (Test-Path -Path $RulesPath)) {
        throw "Rules path not found: $RulesPath"
    }

    $rules = Get-ChildItem -Path $RulesPath -Filter '*.json' -File |
        ForEach-Object { Get-Content -Path $_.FullName -Raw | ConvertFrom-Json }

    Write-Verbose "Invoke-SAWRulesEngine: loaded $($rules.Count) rule(s) from $RulesPath"

    foreach ($rule in $rules) {
        $expected = $rule.Expected
        $severity = $rule.Severity
        $notApplicable = $false
        $baselineNote = $null

        if ($BaselineOverrides.ContainsKey($rule.RuleID)) {
            $override = $BaselineOverrides[$rule.RuleID]
            if ($override.ContainsKey('Expected')) { $expected = $override.Expected }
            if ($override.ContainsKey('Severity')) { $severity = $override.Severity }
            if ($override.ContainsKey('NotApplicable')) { $notApplicable = [bool]$override.NotApplicable }
            if ($override.ContainsKey('Note')) { $baselineNote = $override.Note }
            Write-Verbose "Invoke-SAWRulesEngine: $($rule.RuleID) - baseline override applied (Expected=$expected, Severity=$severity, NotApplicable=$notApplicable)"
        }

        $recommendation = $rule.Recommendation
        if ($baselineNote) {
            $recommendation = "$recommendation (Baseline note: $baselineNote)"
        }

        if ($notApplicable) {
            @{
                RuleID         = $rule.RuleID
                Category       = $rule.Category
                Setting        = $rule.Setting
                Expected       = $expected
                Actual         = $null
                Severity       = $severity
                Status         = 'Grey'
                Recommendation = $recommendation
            }
            continue
        }

        $match = $NormalizedData |
            Where-Object { $_.Category -eq $rule.Category -and $_.Setting -eq $rule.Setting } |
            Select-Object -First 1

        if (-not $match) {
            Write-Verbose "Invoke-SAWRulesEngine: $($rule.RuleID) - no normalized data for '$($rule.Category)/$($rule.Setting)', marking Grey"
            @{
                RuleID         = $rule.RuleID
                Category       = $rule.Category
                Setting        = $rule.Setting
                Expected       = $expected
                Actual         = $null
                Severity       = $severity
                Status         = 'Grey'
                Recommendation = $recommendation
            }
            continue
        }

        if ($match.State -eq $expected) {
            $status = 'Green'
        }
        elseif ($severity -eq 'High') {
            $status = 'Red'
        }
        else {
            $status = 'Yellow'
        }

        @{
            RuleID         = $rule.RuleID
            Category       = $rule.Category
            Setting        = $rule.Setting
            Expected       = $expected
            Actual         = $match.State
            Severity       = $severity
            Status         = $status
            Recommendation = $recommendation
        }
    }
}
