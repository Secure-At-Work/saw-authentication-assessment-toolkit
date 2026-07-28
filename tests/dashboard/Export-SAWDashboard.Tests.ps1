BeforeAll {
    . "$PSScriptRoot/../../src/dashboard/Export-SAWDashboard.ps1"

    # Representative mixed dataset, generated once and reused across It blocks below -
    # Export-SAWDashboard also copies the real (multi-hundred-KB) vendor/ folder, so
    # avoid re-running it once per assertion.
    $script:MixedResults = @(
        @{ RuleID = 'A1'; Category = 'Authentication Methods'; Setting = 'Setting A1'; Expected = 'Enabled'; Actual = 'Enabled'; Severity = 'High'; Status = 'Green'; Recommendation = 'Keep it enabled.' }
        @{ RuleID = 'A2'; Category = 'Authentication Methods'; Setting = 'Setting A2'; Expected = 'Enabled'; Actual = 'Disabled'; Severity = 'Medium'; Status = 'Yellow'; Recommendation = 'Consider enabling <b>this</b>.' }
        @{ RuleID = 'C1'; Category = 'Conditional Access'; Setting = 'Setting C1'; Expected = 'Enabled'; Actual = 'Disabled'; Severity = 'High'; Status = 'Red'; Recommendation = 'Fix this urgently.' }
        @{ RuleID = 'C2'; Category = 'Conditional Access'; Setting = 'Setting C2'; Expected = 'Enabled'; Actual = 'Disabled'; Severity = 'Low'; Status = 'Yellow'; Recommendation = 'Minor tweak.' }
        @{ RuleID = 'C3'; Category = 'Conditional Access'; Setting = 'Setting C3'; Expected = 'Enabled'; Actual = $null; Severity = 'Medium'; Status = 'Grey'; Recommendation = 'Not applicable right now.' }
    )

    $script:DashboardPath = Join-Path $TestDrive 'mixed\index.html'
    Export-SAWDashboard -RuleResults $script:MixedResults -OutputPath $script:DashboardPath | Out-Null
    $script:DashboardContent = Get-Content -Path $script:DashboardPath -Raw
    $script:DashboardDir = Split-Path -Path $script:DashboardPath -Parent
}

Describe 'Export-SAWDashboard' {
    It 'creates index.html' {
        Test-Path $script:DashboardPath | Should -BeTrue
    }

    It 'copies the vendor assets alongside index.html' {
        Test-Path (Join-Path $script:DashboardDir 'vendor\bootstrap\bootstrap.min.css') | Should -BeTrue
        Test-Path (Join-Path $script:DashboardDir 'vendor\bootstrap\bootstrap.bundle.min.js') | Should -BeTrue
        Test-Path (Join-Path $script:DashboardDir 'vendor\chartjs\chart.umd.min.js') | Should -BeTrue
    }

    It 'references the vendor assets with relative (non-CDN) paths' {
        $script:DashboardContent | Should -Match 'href="vendor/bootstrap/bootstrap\.min\.css"'
        $script:DashboardContent | Should -Not -Match 'https://cdn\.'
    }

    It 'computes the status chart data to match the actual status counts' {
        # 1 Green, 2 Yellow, 1 Red, 1 Grey
        $script:DashboardContent | Should -Match '\[1,2,1,1\]'
    }

    It 'creates one nav tab per distinct category, each matching a tab pane id' {
        $script:DashboardContent | Should -Match 'data-bs-target="#pane-AuthenticationMethods"'
        $script:DashboardContent | Should -Match 'id="pane-AuthenticationMethods"'
        $script:DashboardContent | Should -Match 'data-bs-target="#pane-ConditionalAccess"'
        $script:DashboardContent | Should -Match 'id="pane-ConditionalAccess"'
    }

    It 'lists non-Green, non-Grey findings sorted High severity first' {
        $ruleIdOrder = [regex]::Matches($script:DashboardContent, '<strong>([A-Z0-9]+)</strong>') |
            ForEach-Object { $_.Groups[1].Value }

        # C1 (High) must come before both Medium/Low findings (A2, C2)
        ([array]::IndexOf($ruleIdOrder, 'C1')) | Should -BeLessThan ([array]::IndexOf($ruleIdOrder, 'A2'))
        ([array]::IndexOf($ruleIdOrder, 'C1')) | Should -BeLessThan ([array]::IndexOf($ruleIdOrder, 'C2'))
    }

    It 'excludes Green and Grey rules from the findings list' {
        $script:DashboardContent | Should -Not -Match '<strong>A1</strong>'
        $script:DashboardContent | Should -Not -Match '<strong>C3</strong>'
    }

    It 'HTML-encodes recommendation text so it cannot inject markup' {
        $script:DashboardContent | Should -Not -Match 'Consider enabling <b>this</b>'
        $script:DashboardContent | Should -Match 'Consider enabling &lt;b&gt;this&lt;/b&gt;'
    }

    It 'shows a "no open findings" message when every rule is Green' {
        $allGreenPath = Join-Path $TestDrive 'allgreen\index.html'
        $allGreen = @(@{ RuleID = 'G1'; Category = 'Cat'; Setting = 'S'; Expected = 'Enabled'; Actual = 'Enabled'; Severity = 'High'; Status = 'Green'; Recommendation = 'R' })

        Export-SAWDashboard -RuleResults $allGreen -OutputPath $allGreenPath | Out-Null

        $content = Get-Content -Path $allGreenPath -Raw
        $content | Should -Match 'No open findings'
    }

    It 'handles an empty result set without error' {
        $emptyPath = Join-Path $TestDrive 'empty\index.html'

        { Export-SAWDashboard -RuleResults @() -OutputPath $emptyPath } | Should -Not -Throw
        Test-Path $emptyPath | Should -BeTrue
    }
}
