BeforeAll {
    . "$PSScriptRoot/../../src/rules/Get-SAWBaselineOverrides.ps1"
}

Describe 'Get-SAWBaselineOverrides' {
    It 'returns an empty hashtable when neither path is supplied' {
        $result = Get-SAWBaselineOverrides

        $result.Count | Should -Be 0
    }

    It 'throws when -BaselinePath does not exist' {
        { Get-SAWBaselineOverrides -BaselinePath 'C:\does\not\exist.json' } | Should -Throw
    }

    It 'throws when -OverridePath does not exist' {
        { Get-SAWBaselineOverrides -OverridePath 'C:\does\not\exist.json' } | Should -Throw
    }

    It 'loads overrides from a baseline preset file' {
        $path = Join-Path $TestDrive 'baseline.json'
        @{ name = 'Test'; overrides = @{ RULE1 = @{ Severity = 'Low' } } } | ConvertTo-Json -Depth 5 | Set-Content -Path $path

        $result = Get-SAWBaselineOverrides -BaselinePath $path

        $result.ContainsKey('RULE1') | Should -BeTrue
        $result['RULE1']['Severity'] | Should -Be 'Low'
    }

    It 'layers an override file on top of a baseline preset, override wins on conflicts' {
        $baselinePath = Join-Path $TestDrive 'baseline2.json'
        @{ name = 'Test'; overrides = @{ RULE1 = @{ Severity = 'Low'; Expected = 'Enabled' } } } | ConvertTo-Json -Depth 5 | Set-Content -Path $baselinePath

        $overridePath = Join-Path $TestDrive 'override2.json'
        @{ overrides = @{ RULE1 = @{ Severity = 'High' } } } | ConvertTo-Json -Depth 5 | Set-Content -Path $overridePath

        $result = Get-SAWBaselineOverrides -BaselinePath $baselinePath -OverridePath $overridePath

        $result['RULE1']['Severity'] | Should -Be 'High'
        $result['RULE1']['Expected'] | Should -Be 'Enabled'
    }

    It 'merges rules that only exist in the override file, alongside baseline-only rules' {
        $baselinePath = Join-Path $TestDrive 'baseline3.json'
        @{ name = 'Test'; overrides = @{ RULE1 = @{ Severity = 'Low' } } } | ConvertTo-Json -Depth 5 | Set-Content -Path $baselinePath

        $overridePath = Join-Path $TestDrive 'override3.json'
        @{ overrides = @{ RULE2 = @{ NotApplicable = $true } } } | ConvertTo-Json -Depth 5 | Set-Content -Path $overridePath

        $result = Get-SAWBaselineOverrides -BaselinePath $baselinePath -OverridePath $overridePath

        $result.ContainsKey('RULE1') | Should -BeTrue
        $result.ContainsKey('RULE2') | Should -BeTrue
        $result['RULE2']['NotApplicable'] | Should -BeTrue
    }

    It 'handles a file with no overrides section without error' {
        $path = Join-Path $TestDrive 'empty.json'
        @{ name = 'Test' } | ConvertTo-Json | Set-Content -Path $path

        { Get-SAWBaselineOverrides -BaselinePath $path } | Should -Not -Throw
    }
}
