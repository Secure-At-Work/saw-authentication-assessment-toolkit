function Invoke-SAWRulesEngine {
    <#
    .SYNOPSIS
        Evaluates normalized collector data against Secure At Work rule definitions.
    .DESCRIPTION
        Loads every *.json rule file from -RulesPath (rules contain no PowerShell logic,
        per spec section 8) and compares each rule's Expected value against the matching
        normalized setting. Never touches the tenant - pure comparison of already-collected data.

        Status mapping (spec section 10):
          Green  - Actual matches Expected.
          Red    - Actual differs from Expected and the rule Severity is High (security issue).
          Yellow - Actual differs from Expected and the rule Severity is Medium/Low (differs, not a hard issue).
          Grey   - No normalized data was collected for this rule's Category/Setting (not applicable).
    .PARAMETER RulesPath
        Directory containing rule *.json files.
    .PARAMETER NormalizedData
        Normalized objects produced by a collector's normalizer (Category/Setting/State).
    .OUTPUTS
        Hashtable[]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RulesPath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$NormalizedData
    )

    if (-not (Test-Path -Path $RulesPath)) {
        throw "Rules path not found: $RulesPath"
    }

    $rules = Get-ChildItem -Path $RulesPath -Filter '*.json' -File |
        ForEach-Object { Get-Content -Path $_.FullName -Raw | ConvertFrom-Json }

    Write-Verbose "Invoke-SAWRulesEngine: loaded $($rules.Count) rule(s) from $RulesPath"

    foreach ($rule in $rules) {
        $match = $NormalizedData |
            Where-Object { $_.Category -eq $rule.Category -and $_.Setting -eq $rule.Setting } |
            Select-Object -First 1

        if (-not $match) {
            Write-Verbose "Invoke-SAWRulesEngine: $($rule.RuleID) - no normalized data for '$($rule.Category)/$($rule.Setting)', marking Grey"
            @{
                RuleID         = $rule.RuleID
                Category       = $rule.Category
                Setting        = $rule.Setting
                Expected       = $rule.Expected
                Actual         = $null
                Severity       = $rule.Severity
                Status         = 'Grey'
                Recommendation = $rule.Recommendation
            }
            continue
        }

        if ($match.State -eq $rule.Expected) {
            $status = 'Green'
        }
        elseif ($rule.Severity -eq 'High') {
            $status = 'Red'
        }
        else {
            $status = 'Yellow'
        }

        @{
            RuleID         = $rule.RuleID
            Category       = $rule.Category
            Setting        = $rule.Setting
            Expected       = $rule.Expected
            Actual         = $match.State
            Severity       = $rule.Severity
            Status         = $status
            Recommendation = $rule.Recommendation
        }
    }
}
