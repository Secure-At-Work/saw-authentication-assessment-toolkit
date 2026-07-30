BeforeAll {
    . "$PSScriptRoot/../../src/rules/Invoke-SAWRulesEngine.ps1"

    function New-SAWTestRule {
        param(
            [Parameter(Mandatory)]
            [string]$Path,
            [string]$RuleID = 'T001',
            [string]$Category = 'Test Category',
            [string]$Setting = 'Test Setting',
            [string]$Expected = 'Enabled',
            [string]$Severity = 'High',
            [string]$Recommendation = 'Fix it.',
            [int]$Phase = 1,
            [string]$PhaseName = 'Test Phase',
            [string[]]$DependsOn = @()
        )
        $rule = [ordered]@{
            RuleID         = $RuleID
            Category       = $Category
            Setting        = $Setting
            Expected       = $Expected
            Severity       = $Severity
            Phase          = $Phase
            PhaseName      = $PhaseName
            DependsOn      = $DependsOn
            Recommendation = $Recommendation
        }
        $rule | ConvertTo-Json | Set-Content -Path (Join-Path $Path "$RuleID.json")
    }
}

Describe 'Invoke-SAWRulesEngine' {
    BeforeEach {
        # Fresh, isolated rules directory per test - Invoke-SAWRulesEngine loads every *.json
        # in -RulesPath, so tests must not share a folder or they'd see each other's rules.
        $script:rulesDir = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $script:rulesDir | Out-Null
    }

    It 'throws when the rules path does not exist' {
        { Invoke-SAWRulesEngine -RulesPath 'C:\does\not\exist' -NormalizedData @() } | Should -Throw
    }

    It 'marks a rule Green when the actual state matches Expected' {
        New-SAWTestRule -Path $script:rulesDir -Expected 'Enabled'
        $normalized = @(@{ Category = 'Test Category'; Setting = 'Test Setting'; State = 'Enabled' })

        $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized

        $result.Status | Should -Be 'Green'
        $result.Actual | Should -Be 'Enabled'
    }

    It 'marks a High severity mismatch Red' {
        New-SAWTestRule -Path $script:rulesDir -Expected 'Enabled' -Severity 'High'
        $normalized = @(@{ Category = 'Test Category'; Setting = 'Test Setting'; State = 'Disabled' })

        $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized

        $result.Status | Should -Be 'Red'
    }

    It 'marks a Medium severity mismatch Yellow' {
        New-SAWTestRule -Path $script:rulesDir -Expected 'Enabled' -Severity 'Medium'
        $normalized = @(@{ Category = 'Test Category'; Setting = 'Test Setting'; State = 'Disabled' })

        $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized

        $result.Status | Should -Be 'Yellow'
    }

    It 'marks a Low severity mismatch Yellow' {
        New-SAWTestRule -Path $script:rulesDir -Expected 'Enabled' -Severity 'Low'
        $normalized = @(@{ Category = 'Test Category'; Setting = 'Test Setting'; State = 'Disabled' })

        $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized

        $result.Status | Should -Be 'Yellow'
    }

    It 'marks a rule Grey when no normalized data matches its Category/Setting' {
        New-SAWTestRule -Path $script:rulesDir
        $normalized = @(@{ Category = 'Some Other Category'; Setting = 'Some Other Setting'; State = 'Enabled' })

        $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized

        $result.Status | Should -Be 'Grey'
        $result.Actual | Should -BeNullOrEmpty
    }

    It 'marks a rule Grey when NormalizedData is empty' {
        New-SAWTestRule -Path $script:rulesDir

        $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData @()

        $result.Status | Should -Be 'Grey'
    }

    It 'preserves the RuleID, Category, Setting, Expected, Severity, and Recommendation from the rule file' {
        New-SAWTestRule -Path $script:rulesDir -RuleID 'T007' -Category 'My Category' -Setting 'My Setting' `
            -Expected 'Enabled' -Severity 'High' -Recommendation 'Do the thing.'
        $normalized = @(@{ Category = 'My Category'; Setting = 'My Setting'; State = 'Enabled' })

        $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized

        $result.RuleID | Should -Be 'T007'
        $result.Category | Should -Be 'My Category'
        $result.Setting | Should -Be 'My Setting'
        $result.Severity | Should -Be 'High'
        $result.Recommendation | Should -Be 'Do the thing.'
    }

    It 'preserves Phase, PhaseName, and DependsOn from the rule file' {
        New-SAWTestRule -Path $script:rulesDir -RuleID 'T010' -Category 'My Category' -Setting 'My Setting' `
            -Phase 3 -PhaseName 'Drive Registration Coverage' -DependsOn @('BOOT001', 'AUTH004')
        $normalized = @(@{ Category = 'My Category'; Setting = 'My Setting'; State = 'Enabled' })

        $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized

        $result.Phase | Should -Be 3
        $result.PhaseName | Should -Be 'Drive Registration Coverage'
        $result.DependsOn | Should -Be @('BOOT001', 'AUTH004')
    }

    It 'yields a zero-length DependsOn array when the rule file has none' {
        New-SAWTestRule -Path $script:rulesDir -DependsOn @()
        $normalized = @(@{ Category = 'Test Category'; Setting = 'Test Setting'; State = 'Enabled' })

        $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized

        $result.ContainsKey('DependsOn') | Should -BeTrue
        @($result.DependsOn).Count | Should -Be 0
    }

    It 'preserves Phase/PhaseName/DependsOn on a Grey (no matching data) result too' {
        New-SAWTestRule -Path $script:rulesDir -Phase 2 -PhaseName 'Test Phase' -DependsOn @('AUTH004')
        $normalized = @(@{ Category = 'Some Other Category'; Setting = 'Some Other Setting'; State = 'Enabled' })

        $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized

        $result.Status | Should -Be 'Grey'
        $result.Phase | Should -Be 2
        $result.DependsOn | Should -Be @('AUTH004')
    }

    It 'evaluates every rule file found in the rules directory' {
        New-SAWTestRule -Path $script:rulesDir -RuleID 'T008A' -Category 'Cat A' -Setting 'Setting A'
        New-SAWTestRule -Path $script:rulesDir -RuleID 'T008B' -Category 'Cat B' -Setting 'Setting B'
        $normalized = @(
            @{ Category = 'Cat A'; Setting = 'Setting A'; State = 'Enabled' },
            @{ Category = 'Cat B'; Setting = 'Setting B'; State = 'Enabled' }
        )

        $result = @(Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized)

        $result.Count | Should -Be 2
        ($result | Where-Object { $_.Status -eq 'Green' }).Count | Should -Be 2
    }

    Context 'baseline overrides' {
        It 'evaluates exactly as authored when BaselineOverrides is not supplied' {
            New-SAWTestRule -Path $script:rulesDir -Expected 'Enabled' -Severity 'High'
            $normalized = @(@{ Category = 'Test Category'; Setting = 'Test Setting'; State = 'Disabled' })

            $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized

            $result.Status | Should -Be 'Red'
            $result.Severity | Should -Be 'High'
        }

        It 'overrides Expected so a previously-mismatched actual now reads Green' {
            New-SAWTestRule -Path $script:rulesDir -Expected 'Disabled' -Severity 'High'
            $normalized = @(@{ Category = 'Test Category'; Setting = 'Test Setting'; State = 'Enabled' })
            $overrides = @{ T001 = @{ Expected = 'Enabled' } }

            $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized -BaselineOverrides $overrides

            $result.Status | Should -Be 'Green'
            $result.Expected | Should -Be 'Enabled'
        }

        It 'overrides Severity, changing Red to Yellow for the same mismatch' {
            New-SAWTestRule -Path $script:rulesDir -Expected 'Enabled' -Severity 'High'
            $normalized = @(@{ Category = 'Test Category'; Setting = 'Test Setting'; State = 'Disabled' })
            $overrides = @{ T001 = @{ Severity = 'Low' } }

            $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized -BaselineOverrides $overrides

            $result.Status | Should -Be 'Yellow'
            $result.Severity | Should -Be 'Low'
        }

        It 'marks a rule Grey with no Actual when NotApplicable is true, even though normalized data exists and would otherwise match' {
            New-SAWTestRule -Path $script:rulesDir -Expected 'Enabled' -Severity 'High'
            $normalized = @(@{ Category = 'Test Category'; Setting = 'Test Setting'; State = 'Enabled' })
            $overrides = @{ T001 = @{ NotApplicable = $true } }

            $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized -BaselineOverrides $overrides

            $result.Status | Should -Be 'Grey'
            $result.Actual | Should -BeNullOrEmpty
        }

        It 'appends the baseline Note to the Recommendation text' {
            New-SAWTestRule -Path $script:rulesDir -Expected 'Enabled' -Severity 'High' -Recommendation 'Original text.'
            $normalized = @(@{ Category = 'Test Category'; Setting = 'Test Setting'; State = 'Enabled' })
            $overrides = @{ T001 = @{ Severity = 'Low'; Note = 'Explained here.' } }

            $result = Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized -BaselineOverrides $overrides

            $result.Recommendation | Should -Match 'Original text\.'
            $result.Recommendation | Should -Match 'Explained here\.'
        }

        It 'only applies an override to the RuleID it targets, leaving other rules untouched' {
            New-SAWTestRule -Path $script:rulesDir -RuleID 'T009A' -Category 'Cat A' -Setting 'Setting A' -Expected 'Enabled' -Severity 'High'
            New-SAWTestRule -Path $script:rulesDir -RuleID 'T009B' -Category 'Cat B' -Setting 'Setting B' -Expected 'Enabled' -Severity 'High'
            $normalized = @(
                @{ Category = 'Cat A'; Setting = 'Setting A'; State = 'Disabled' },
                @{ Category = 'Cat B'; Setting = 'Setting B'; State = 'Disabled' }
            )
            $overrides = @{ T009A = @{ Severity = 'Low' } }

            $result = @(Invoke-SAWRulesEngine -RulesPath $script:rulesDir -NormalizedData $normalized -BaselineOverrides $overrides)

            ($result | Where-Object { $_.RuleID -eq 'T009A' }).Status | Should -Be 'Yellow'
            ($result | Where-Object { $_.RuleID -eq 'T009B' }).Status | Should -Be 'Red'
        }
    }
}
