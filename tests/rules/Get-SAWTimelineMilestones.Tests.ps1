BeforeAll {
    . "$PSScriptRoot/../../src/rules/Get-SAWTimelineMilestones.ps1"

    function New-SAWTestMilestonesFile {
        param($Path, $Milestones)
        @{ description = 'test'; milestones = $Milestones } | ConvertTo-Json -Depth 5 | Set-Content -Path $Path
    }
}

Describe 'Get-SAWTimelineMilestones' {
    BeforeEach {
        $script:milestonesPath = Join-Path $TestDrive "$([guid]::NewGuid()).json"
    }

    It 'returns an empty array when the milestones file does not exist' {
        $result = Get-SAWTimelineMilestones -MilestonesPath 'C:\does\not\exist.json' -ReferenceDate ([datetime]'2026-08-04')

        $result.Count | Should -Be 0
    }

    It 'always returns a proper array, even with exactly one milestone' {
        New-SAWTestMilestonesFile -Path $script:milestonesPath -Milestones @(
            @{ Date = '2026-12-25'; Title = 'Test'; Description = 'x'; RelatedRuleIDs = @(); SourceUrl = 'http://x' }
        )

        $result = Get-SAWTimelineMilestones -MilestonesPath $script:milestonesPath -ReferenceDate ([datetime]'2026-08-04')

        $result.GetType().IsArray | Should -BeTrue
        $result.Count | Should -Be 1
        $result[0].Title | Should -Be 'Test'
    }

    It 'sorts milestones ascending by date regardless of file order' {
        New-SAWTestMilestonesFile -Path $script:milestonesPath -Milestones @(
            @{ Date = '2027-01-01'; Title = 'Later'; Description = 'x'; RelatedRuleIDs = @(); SourceUrl = '' }
            @{ Date = '2026-09-01'; Title = 'Earlier'; Description = 'x'; RelatedRuleIDs = @(); SourceUrl = '' }
        )

        $result = Get-SAWTimelineMilestones -MilestonesPath $script:milestonesPath -ReferenceDate ([datetime]'2026-08-04')

        $result[0].Title | Should -Be 'Earlier'
        $result[1].Title | Should -Be 'Later'
    }

    It 'computes positive DaysRemaining and IsPast=false for a future date' {
        New-SAWTestMilestonesFile -Path $script:milestonesPath -Milestones @(
            @{ Date = '2026-08-14'; Title = 'Future'; Description = 'x'; RelatedRuleIDs = @(); SourceUrl = '' }
        )

        $result = Get-SAWTimelineMilestones -MilestonesPath $script:milestonesPath -ReferenceDate ([datetime]'2026-08-04')

        $result[0].DaysRemaining | Should -Be 10
        $result[0].IsPast | Should -BeFalse
    }

    It 'computes negative DaysRemaining and IsPast=true for a past date' {
        New-SAWTestMilestonesFile -Path $script:milestonesPath -Milestones @(
            @{ Date = '2026-07-25'; Title = 'Past'; Description = 'x'; RelatedRuleIDs = @(); SourceUrl = '' }
        )

        $result = Get-SAWTimelineMilestones -MilestonesPath $script:milestonesPath -ReferenceDate ([datetime]'2026-08-04')

        $result[0].DaysRemaining | Should -Be -10
        $result[0].IsPast | Should -BeTrue
    }

    It 'computes DaysRemaining=0 and IsPast=false when the reference date is exactly the milestone date' {
        New-SAWTestMilestonesFile -Path $script:milestonesPath -Milestones @(
            @{ Date = '2026-08-04'; Title = 'Today'; Description = 'x'; RelatedRuleIDs = @(); SourceUrl = '' }
        )

        $result = Get-SAWTimelineMilestones -MilestonesPath $script:milestonesPath -ReferenceDate ([datetime]'2026-08-04')

        $result[0].DaysRemaining | Should -Be 0
        $result[0].IsPast | Should -BeFalse
    }

    It 'carries RelatedRuleIDs and SourceUrl through' {
        New-SAWTestMilestonesFile -Path $script:milestonesPath -Milestones @(
            @{ Date = '2026-09-07'; Title = 'SSPR'; Description = 'x'; RelatedRuleIDs = @('SSPR001'); SourceUrl = 'https://example.com' }
        )

        $result = Get-SAWTimelineMilestones -MilestonesPath $script:milestonesPath -ReferenceDate ([datetime]'2026-08-04')

        $result[0].RelatedRuleIDs | Should -Be @('SSPR001')
        $result[0].SourceUrl | Should -Be 'https://example.com'
    }

    It 'loads the real bundled config/timeline-milestones.json without error and returns 6 milestones' {
        $realPath = "$PSScriptRoot/../../config/timeline-milestones.json"

        $result = Get-SAWTimelineMilestones -MilestonesPath $realPath -ReferenceDate ([datetime]'2026-08-04')

        $result.Count | Should -Be 6
        $result[0].Date | Should -Be '2026-07-06'
    }

    It 'sets UsersImpacted to $null when no -ImpactMetrics is supplied (no fabricated 0)' {
        New-SAWTestMilestonesFile -Path $script:milestonesPath -Milestones @(
            @{ Date = '2026-09-01'; Title = 'Phone users'; Description = 'x'; RelatedRuleIDs = @(); SourceUrl = ''; ImpactMetric = 'PhoneBasedMethodUsers'; ImpactMetricLabel = 'phone users' }
        )

        $result = Get-SAWTimelineMilestones -MilestonesPath $script:milestonesPath -ReferenceDate ([datetime]'2026-08-04')

        $result[0].UsersImpacted | Should -Be $null
    }

    It 'sets UsersImpacted to $null when the milestone declares an ImpactMetric not present in -ImpactMetrics' {
        New-SAWTestMilestonesFile -Path $script:milestonesPath -Milestones @(
            @{ Date = '2026-09-01'; Title = 'Phone users'; Description = 'x'; RelatedRuleIDs = @(); SourceUrl = ''; ImpactMetric = 'PhoneBasedMethodUsers'; ImpactMetricLabel = 'phone users' }
        )

        $result = Get-SAWTimelineMilestones -MilestonesPath $script:milestonesPath -ReferenceDate ([datetime]'2026-08-04') -ImpactMetrics @{ SomeOtherMetric = 99 }

        $result[0].UsersImpacted | Should -Be $null
    }

    It 'looks up UsersImpacted from -ImpactMetrics by the milestone''s ImpactMetric key and carries ImpactMetricLabel through' {
        New-SAWTestMilestonesFile -Path $script:milestonesPath -Milestones @(
            @{ Date = '2026-09-01'; Title = 'Phone users'; Description = 'x'; RelatedRuleIDs = @(); SourceUrl = ''; ImpactMetric = 'PhoneBasedMethodUsers'; ImpactMetricLabel = 'phone users still registered' }
        )

        $result = Get-SAWTimelineMilestones -MilestonesPath $script:milestonesPath -ReferenceDate ([datetime]'2026-08-04') -ImpactMetrics @{ PhoneBasedMethodUsers = 7 }

        $result[0].UsersImpacted | Should -Be 7
        $result[0].ImpactMetricLabel | Should -Be 'phone users still registered'
    }

    It 'handles UsersImpacted=0 as a real value, not the same as "not computable"' {
        New-SAWTestMilestonesFile -Path $script:milestonesPath -Milestones @(
            @{ Date = '2026-09-01'; Title = 'Phone users'; Description = 'x'; RelatedRuleIDs = @(); SourceUrl = ''; ImpactMetric = 'PhoneBasedMethodUsers'; ImpactMetricLabel = 'phone users' }
        )

        $result = Get-SAWTimelineMilestones -MilestonesPath $script:milestonesPath -ReferenceDate ([datetime]'2026-08-04') -ImpactMetrics @{ PhoneBasedMethodUsers = 0 }

        $result[0].UsersImpacted | Should -Be 0
        $result[0].UsersImpacted | Should -Not -Be $null
    }

    It 'sets NotApplicableReason and leaves UsersImpacted $null when the ImpactMetric key is in -NotApplicableReasons' {
        New-SAWTestMilestonesFile -Path $script:milestonesPath -Milestones @(
            @{ Date = '2026-09-07'; Title = 'SSPR enforcement'; Description = 'x'; RelatedRuleIDs = @(); SourceUrl = ''; ImpactMetric = 'SsprEnabledNotRegisteredUsers'; ImpactMetricLabel = 'SSPR-enabled users not yet registered' }
        )

        $result = Get-SAWTimelineMilestones -MilestonesPath $script:milestonesPath -ReferenceDate ([datetime]'2026-08-04') -ImpactMetrics @{ SsprEnabledNotRegisteredUsers = 0 } -NotApplicableReasons @{ SsprEnabledNotRegisteredUsers = "SSPR isn't enabled for any user in this tenant" }

        $result[0].UsersImpacted | Should -Be $null
        $result[0].NotApplicableReason | Should -Be "SSPR isn't enabled for any user in this tenant"
    }

    It '-NotApplicableReasons takes priority over -ImpactMetrics for the same key even when the count is non-zero' {
        New-SAWTestMilestonesFile -Path $script:milestonesPath -Milestones @(
            @{ Date = '2026-09-07'; Title = 'SSPR enforcement'; Description = 'x'; RelatedRuleIDs = @(); SourceUrl = ''; ImpactMetric = 'SsprEnabledNotRegisteredUsers'; ImpactMetricLabel = 'x' }
        )

        $result = Get-SAWTimelineMilestones -MilestonesPath $script:milestonesPath -ReferenceDate ([datetime]'2026-08-04') -ImpactMetrics @{ SsprEnabledNotRegisteredUsers = 5 } -NotApplicableReasons @{ SsprEnabledNotRegisteredUsers = 'not applicable' }

        $result[0].UsersImpacted | Should -Be $null
        $result[0].NotApplicableReason | Should -Be 'not applicable'
    }

    It 'leaves NotApplicableReason $null when -NotApplicableReasons is empty (default)' {
        New-SAWTestMilestonesFile -Path $script:milestonesPath -Milestones @(
            @{ Date = '2026-09-01'; Title = 'Phone users'; Description = 'x'; RelatedRuleIDs = @(); SourceUrl = ''; ImpactMetric = 'PhoneBasedMethodUsers'; ImpactMetricLabel = 'phone users' }
        )

        $result = Get-SAWTimelineMilestones -MilestonesPath $script:milestonesPath -ReferenceDate ([datetime]'2026-08-04') -ImpactMetrics @{ PhoneBasedMethodUsers = 3 }

        $result[0].NotApplicableReason | Should -Be $null
        $result[0].UsersImpacted | Should -Be 3
    }
}
