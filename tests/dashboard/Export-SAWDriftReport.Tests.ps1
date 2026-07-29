BeforeAll {
    . "$PSScriptRoot/../../src/rules/Compare-SAWRuleResults.ps1"
    . "$PSScriptRoot/../../src/dashboard/Export-SAWDriftReport.ps1"

    function New-SAWTestResult {
        param($RuleID, $Status, $Actual = 'x', $Expected = 'x', $Category = 'Cat', $Setting = 'Set', $Severity = 'High')
        @{ RuleID = $RuleID; Status = $Status; Actual = $Actual; Expected = $Expected; Category = $Category; Setting = $Setting; Severity = $Severity }
    }
}

Describe 'Export-SAWDriftReport' {
    It 'creates the output file' {
        $outputPath = Join-Path $TestDrive 'drift.html'
        $old = @{ RunTimestamp = 't1'; Results = @() }
        $new = @{ RunTimestamp = 't2'; Results = @() }
        $comparison = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

        Export-SAWDriftReport -Comparison $comparison -OutputPath $outputPath | Out-Null

        Test-Path $outputPath | Should -BeTrue
    }

    It 'creates the parent directory if it does not exist' {
        $outputPath = Join-Path $TestDrive 'nested\deeper\drift.html'
        $old = @{ RunTimestamp = 't1'; Results = @() }
        $new = @{ RunTimestamp = 't2'; Results = @() }
        $comparison = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

        Export-SAWDriftReport -Comparison $comparison -OutputPath $outputPath | Out-Null

        Test-Path $outputPath | Should -BeTrue
    }

    It 'shows the tenant display name and both run timestamps' {
        $outputPath = Join-Path $TestDrive 'header.html'
        $old = @{ RunTimestamp = '20260101-000000'; Results = @() }
        $new = @{ RunTimestamp = '20260201-000000'; Results = @() }
        $comparison = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

        Export-SAWDriftReport -Comparison $comparison -TenantDisplayName 'Contoso Ltd' -OutputPath $outputPath | Out-Null

        $content = Get-Content -Path $outputPath -Raw
        $content | Should -Match 'Contoso Ltd'
        $content | Should -Match '20260101-000000'
        $content | Should -Match '20260201-000000'
    }

    It 'lists a regression with its RuleID and shows a nonzero Regressions count' {
        $outputPath = Join-Path $TestDrive 'regression.html'
        $old = @{ RunTimestamp = 't1'; Results = @((New-SAWTestResult -RuleID 'CA002' -Status 'Green')) }
        $new = @{ RunTimestamp = 't2'; Results = @((New-SAWTestResult -RuleID 'CA002' -Status 'Red')) }
        $comparison = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

        Export-SAWDriftReport -Comparison $comparison -OutputPath $outputPath | Out-Null

        $content = Get-Content -Path $outputPath -Raw
        $content | Should -Match 'Regressions \(1\)'
        $content | Should -Match 'CA002'
    }

    It 'reports zero for every change category when nothing changed' {
        $outputPath = Join-Path $TestDrive 'nochange.html'
        $old = @{ RunTimestamp = 't1'; Results = @((New-SAWTestResult -RuleID 'A' -Status 'Green')) }
        $new = @{ RunTimestamp = 't2'; Results = @((New-SAWTestResult -RuleID 'A' -Status 'Green')) }
        $comparison = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

        Export-SAWDriftReport -Comparison $comparison -OutputPath $outputPath | Out-Null

        $content = Get-Content -Path $outputPath -Raw
        $content | Should -Match 'Regressions \(0\)'
        $content | Should -Match 'Improvements \(0\)'
        $content | Should -Match '1 rule\(s\) unchanged'
    }

    It 'renders the roster delta table when both snapshots carry RosterCounts' {
        $outputPath = Join-Path $TestDrive 'roster.html'
        $old = @{ RunTimestamp = 't1'; Results = @(); RosterCounts = @{ Remove = 2; Hunt = 5; 'Guest (FIDO2 Not Supported)' = 1; OK = 1 } }
        $new = @{ RunTimestamp = 't2'; Results = @(); RosterCounts = @{ Remove = 0; Hunt = 3; 'Guest (FIDO2 Not Supported)' = 1; OK = 5 } }
        $comparison = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

        Export-SAWDriftReport -Comparison $comparison -OutputPath $outputPath | Out-Null

        $content = Get-Content -Path $outputPath -Raw
        $content | Should -Match '<td>Remove</td>'
        $content | Should -Match '-2'
    }

    It 'notes roster data is unavailable when RosterCounts is missing' {
        $outputPath = Join-Path $TestDrive 'noroster.html'
        $old = @{ RunTimestamp = 't1'; Results = @() }
        $new = @{ RunTimestamp = 't2'; Results = @() }
        $comparison = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

        Export-SAWDriftReport -Comparison $comparison -OutputPath $outputPath | Out-Null

        $content = Get-Content -Path $outputPath -Raw
        $content | Should -Match 'Not available for this comparison'
    }

    It 'produces a valid HTML shell even with an empty comparison' {
        $outputPath = Join-Path $TestDrive 'empty.html'
        $old = @{ RunTimestamp = 't1'; Results = @() }
        $new = @{ RunTimestamp = 't2'; Results = @() }
        $comparison = Compare-SAWRuleResults -OldSnapshot $old -NewSnapshot $new

        Export-SAWDriftReport -Comparison $comparison -OutputPath $outputPath | Out-Null

        $content = Get-Content -Path $outputPath -Raw
        $content | Should -Match '<table>'
        $content | Should -Match '</html>'
    }
}
