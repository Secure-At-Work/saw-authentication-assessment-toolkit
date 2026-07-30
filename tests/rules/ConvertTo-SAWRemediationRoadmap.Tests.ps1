BeforeAll {
    . "$PSScriptRoot/../../src/rules/ConvertTo-SAWRemediationRoadmap.ps1"

    function New-SAWTestRuleResult {
        param($RuleID, $Status, $Severity = 'High', $Phase = 1, $PhaseName = 'P1', $DependsOn = @())
        @{ RuleID = $RuleID; Category = 'Cat'; Setting = 'Set'; Status = $Status; Severity = $Severity; Recommendation = 'Fix it'; Phase = $Phase; PhaseName = $PhaseName; DependsOn = $DependsOn }
    }
}

Describe 'ConvertTo-SAWRemediationRoadmap' {
    It 'returns an empty array for empty input' {
        $roadmap = ConvertTo-SAWRemediationRoadmap -RuleResults @()

        , $roadmap | Should -Not -BeNullOrEmpty -Because 'the array wrapper itself should exist'
        $roadmap.Count | Should -Be 0
    }

    It 'always returns an array, even when only one phase group is produced' {
        $results = @((New-SAWTestRuleResult -RuleID 'D' -Status 'Red' -Phase 1))

        $roadmap = ConvertTo-SAWRemediationRoadmap -RuleResults $results

        $roadmap.GetType().IsArray | Should -BeTrue
        $roadmap.Count | Should -Be 1
        $roadmap[0].Phase | Should -Be 1
    }

    It 'groups rules into distinct phases and sorts them ascending' {
        $results = @(
            (New-SAWTestRuleResult -RuleID 'A' -Status 'Green' -Phase 2 -PhaseName 'Second')
            (New-SAWTestRuleResult -RuleID 'B' -Status 'Red' -Phase 1 -PhaseName 'First')
        )

        $roadmap = ConvertTo-SAWRemediationRoadmap -RuleResults $results

        $roadmap.Count | Should -Be 2
        $roadmap[0].Phase | Should -Be 1
        $roadmap[0].PhaseName | Should -Be 'First'
        $roadmap[1].Phase | Should -Be 2
        $roadmap[1].PhaseName | Should -Be 'Second'
    }

    It 'computes CompletedCount/NotApplicableCount/OutstandingCount per phase correctly' {
        $results = @(
            (New-SAWTestRuleResult -RuleID 'A' -Status 'Green' -Phase 1)
            (New-SAWTestRuleResult -RuleID 'B' -Status 'Red' -Phase 1)
            (New-SAWTestRuleResult -RuleID 'C' -Status 'Grey' -Phase 1)
            (New-SAWTestRuleResult -RuleID 'D' -Status 'Yellow' -Phase 1)
        )

        $roadmap = ConvertTo-SAWRemediationRoadmap -RuleResults $results

        $roadmap[0].TotalCount | Should -Be 4
        $roadmap[0].CompletedCount | Should -Be 1
        $roadmap[0].NotApplicableCount | Should -Be 1
        $roadmap[0].OutstandingCount | Should -Be 2
        $roadmap[0].IsComplete | Should -BeFalse
    }

    It 'marks a phase IsComplete when nothing is Red or Yellow' {
        $results = @(
            (New-SAWTestRuleResult -RuleID 'A' -Status 'Green' -Phase 1)
            (New-SAWTestRuleResult -RuleID 'B' -Status 'Grey' -Phase 1)
        )

        $roadmap = ConvertTo-SAWRemediationRoadmap -RuleResults $results

        $roadmap[0].IsComplete | Should -BeTrue
        $roadmap[0].OutstandingRules.Count | Should -Be 0
    }

    It 'sorts OutstandingRules by severity then RuleID' {
        $results = @(
            (New-SAWTestRuleResult -RuleID 'Z' -Status 'Red' -Severity 'Low' -Phase 1)
            (New-SAWTestRuleResult -RuleID 'A' -Status 'Red' -Severity 'High' -Phase 1)
            (New-SAWTestRuleResult -RuleID 'M' -Status 'Red' -Severity 'Medium' -Phase 1)
            (New-SAWTestRuleResult -RuleID 'B' -Status 'Red' -Severity 'High' -Phase 1)
        )

        $roadmap = ConvertTo-SAWRemediationRoadmap -RuleResults $results

        ($roadmap[0].OutstandingRules | ForEach-Object { $_.RuleID }) -join ',' | Should -Be 'A,B,M,Z'
    }

    Context 'Blocked / BlockedBy' {
        It 'marks a rule Blocked when a DependsOn rule is still Red' {
            $results = @(
                (New-SAWTestRuleResult -RuleID 'B' -Status 'Red' -Phase 1)
                (New-SAWTestRuleResult -RuleID 'D' -Status 'Yellow' -Phase 2 -DependsOn @('B'))
            )

            $roadmap = ConvertTo-SAWRemediationRoadmap -RuleResults $results

            $phase2 = $roadmap | Where-Object { $_.Phase -eq 2 }
            $dEntry = $phase2.OutstandingRules[0]
            $dEntry.Blocked | Should -BeTrue
            $dEntry.BlockedBy | Should -Be @('B')
        }

        It 'marks a rule not Blocked once its DependsOn rule is Green' {
            $results = @(
                (New-SAWTestRuleResult -RuleID 'B' -Status 'Green' -Phase 1)
                (New-SAWTestRuleResult -RuleID 'D' -Status 'Yellow' -Phase 2 -DependsOn @('B'))
            )

            $roadmap = ConvertTo-SAWRemediationRoadmap -RuleResults $results

            $phase2 = $roadmap | Where-Object { $_.Phase -eq 2 }
            $phase2.OutstandingRules[0].Blocked | Should -BeFalse
        }

        It 'does not treat a Grey (not applicable) dependency as blocking' {
            $results = @(
                (New-SAWTestRuleResult -RuleID 'B' -Status 'Grey' -Phase 1)
                (New-SAWTestRuleResult -RuleID 'D' -Status 'Red' -Phase 2 -DependsOn @('B'))
            )

            $roadmap = ConvertTo-SAWRemediationRoadmap -RuleResults $results

            $phase2 = $roadmap | Where-Object { $_.Phase -eq 2 }
            $phase2.OutstandingRules[0].Blocked | Should -BeFalse
        }

        It 'does not block on a DependsOn RuleID that is not present in the result set' {
            $results = @((New-SAWTestRuleResult -RuleID 'D' -Status 'Red' -Phase 1 -DependsOn @('NOPE')))

            $roadmap = ConvertTo-SAWRemediationRoadmap -RuleResults $results

            $roadmap[0].OutstandingRules[0].Blocked | Should -BeFalse
        }
    }

    It 'groups rules with no Phase into a trailing Unphased bucket' {
        $results = @(
            (New-SAWTestRuleResult -RuleID 'A' -Status 'Red' -Phase 1 -PhaseName 'Foundation')
            (New-SAWTestRuleResult -RuleID 'X' -Status 'Red' -Phase $null -PhaseName $null)
        )

        $roadmap = ConvertTo-SAWRemediationRoadmap -RuleResults $results

        $roadmap.Count | Should -Be 2
        $roadmap[0].Phase | Should -Be 1
        $roadmap[-1].Phase | Should -BeNullOrEmpty
        $roadmap[-1].PhaseName | Should -Be 'Unphased'
    }
}
