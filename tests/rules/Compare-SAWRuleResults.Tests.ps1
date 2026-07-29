BeforeAll {
    . "$PSScriptRoot/../../src/rules/Compare-SAWRuleResults.ps1"

    function New-SAWTestResult {
        param($RuleID, $Status, $Actual = 'x', $Expected = 'x', $Category = 'Cat', $Setting = 'Set', $Severity = 'High')
        @{ RuleID = $RuleID; Status = $Status; Actual = $Actual; Expected = $Expected; Category = $Category; Setting = $Setting; Severity = $Severity }
    }
}

Describe 'Compare-SAWRuleResults' {
    Context 'status transitions' {
        It 'classifies Red -> Green as Improved' {
            $old = @{ Results = @((New-SAWTestResult -RuleID 'A' -Status 'Red')) }
            $new = @{ Results = @((New-SAWTestResult -RuleID 'A' -Status 'Green')) }

            $diff = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

            $diff.Improvements.Count | Should -Be 1
            $diff.Improvements[0].RuleID | Should -Be 'A'
            $diff.Regressions.Count | Should -Be 0
        }

        It 'classifies Green -> Red as Regressed' {
            $old = @{ Results = @((New-SAWTestResult -RuleID 'A' -Status 'Green')) }
            $new = @{ Results = @((New-SAWTestResult -RuleID 'A' -Status 'Red')) }

            $diff = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

            $diff.Regressions.Count | Should -Be 1
            $diff.Regressions[0].RuleID | Should -Be 'A'
        }

        It 'classifies Yellow -> Red as Regressed (not just Green comparisons)' {
            $old = @{ Results = @((New-SAWTestResult -RuleID 'A' -Status 'Yellow')) }
            $new = @{ Results = @((New-SAWTestResult -RuleID 'A' -Status 'Red')) }

            $diff = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

            $diff.Regressions.Count | Should -Be 1
        }

        It 'classifies an unchanged status as Unchanged' {
            $old = @{ Results = @((New-SAWTestResult -RuleID 'A' -Status 'Green')) }
            $new = @{ Results = @((New-SAWTestResult -RuleID 'A' -Status 'Green')) }

            $diff = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

            $diff.Unchanged.Count | Should -Be 1
            $diff.Regressions.Count | Should -Be 0
            $diff.Improvements.Count | Should -Be 0
        }
    }

    Context 'Grey (not applicable) transitions' {
        It 'classifies Grey -> Green as Became Applicable, not Improved' {
            $old = @{ Results = @((New-SAWTestResult -RuleID 'A' -Status 'Grey')) }
            $new = @{ Results = @((New-SAWTestResult -RuleID 'A' -Status 'Green')) }

            $diff = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

            $diff.NewlyApplicable.Count | Should -Be 1
            $diff.Improvements.Count | Should -Be 0
        }

        It 'classifies Red -> Grey as Became Not Applicable, not Improved' {
            $old = @{ Results = @((New-SAWTestResult -RuleID 'A' -Status 'Red')) }
            $new = @{ Results = @((New-SAWTestResult -RuleID 'A' -Status 'Grey')) }

            $diff = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

            $diff.NewlyNotApplicable.Count | Should -Be 1
            $diff.Improvements.Count | Should -Be 0
            $diff.Regressions.Count | Should -Be 0
        }

        It 'classifies Grey -> Grey as Unchanged' {
            $old = @{ Results = @((New-SAWTestResult -RuleID 'A' -Status 'Grey')) }
            $new = @{ Results = @((New-SAWTestResult -RuleID 'A' -Status 'Grey')) }

            $diff = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

            $diff.Unchanged.Count | Should -Be 1
        }
    }

    Context 'rule set changes between runs' {
        It 'classifies a RuleID only present in NewSnapshot as New Check' {
            $old = @{ Results = @() }
            $new = @{ Results = @((New-SAWTestResult -RuleID 'NEWRULE' -Status 'Yellow')) }

            $diff = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

            $diff.NewChecks.Count | Should -Be 1
            $diff.NewChecks[0].RuleID | Should -Be 'NEWRULE'
        }

        It 'classifies a RuleID only present in OldSnapshot as Removed Check' {
            $old = @{ Results = @((New-SAWTestResult -RuleID 'GONE' -Status 'Green')) }
            $new = @{ Results = @() }

            $diff = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

            $diff.RemovedChecks.Count | Should -Be 1
            $diff.RemovedChecks[0].RuleID | Should -Be 'GONE'
        }
    }

    Context 'roster deltas' {
        It 'computes per-bucket Old/New/Delta when both snapshots carry RosterCounts' {
            $old = @{ Results = @(); RosterCounts = @{ Remove = 2; Hunt = 5; 'Guest (FIDO2 Not Supported)' = 1; OK = 1 } }
            $new = @{ Results = @(); RosterCounts = @{ Remove = 0; Hunt = 3; 'Guest (FIDO2 Not Supported)' = 1; OK = 5 } }

            $diff = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

            $removeDelta = $diff.RosterDelta | Where-Object { $_.Bucket -eq 'Remove' }
            $removeDelta.Old | Should -Be 2
            $removeDelta.New | Should -Be 0
            $removeDelta.Delta | Should -Be -2

            $okDelta = $diff.RosterDelta | Where-Object { $_.Bucket -eq 'OK' }
            $okDelta.Delta | Should -Be 4
        }

        It 'leaves RosterDelta null when RosterCounts is missing from either snapshot' {
            $old = @{ Results = @() }
            $new = @{ Results = @() }

            $diff = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

            $diff.RosterDelta | Should -BeNullOrEmpty
        }
    }

    Context 'JSON round-tripped snapshots' {
        It 'still detects status transitions and roster deltas after ConvertTo-Json/ConvertFrom-Json' {
            $old = @{
                Results      = @((New-SAWTestResult -RuleID 'A' -Status 'Red'))
                RosterCounts = @{ Remove = 2; Hunt = 5; 'Guest (FIDO2 Not Supported)' = 1; OK = 1 }
            }
            $new = @{
                Results      = @((New-SAWTestResult -RuleID 'A' -Status 'Green'))
                RosterCounts = @{ Remove = 0; Hunt = 3; 'Guest (FIDO2 Not Supported)' = 1; OK = 5 }
            }
            $oldJson = $old | ConvertTo-Json -Depth 10 | ConvertFrom-Json
            $newJson = $new | ConvertTo-Json -Depth 10 | ConvertFrom-Json

            $diff = Compare-SAWRuleResults -OldSnapshot $oldJson -NewSnapshot $newJson

            $diff.Improvements.Count | Should -Be 1
            $removeDelta = $diff.RosterDelta | Where-Object { $_.Bucket -eq 'Remove' }
            $removeDelta.Old | Should -Be 2
            $removeDelta.New | Should -Be 0
        }
    }
}
