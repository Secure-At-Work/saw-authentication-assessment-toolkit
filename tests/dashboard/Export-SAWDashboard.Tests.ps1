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

    It 'omits the user triage section entirely when no roster is supplied' {
        $script:DashboardContent | Should -Not -Match 'User Triage'
    }

    It 'renders the user triage section with correct bucket counts and admin badges when a roster is supplied' {
        $rosterPath = Join-Path $TestDrive 'roster\index.html'
        $roster = @(
            @{ UserPrincipalName = 'remove.admin@contoso.com'; DisplayName = 'Remove Admin'; IsAdmin = $true; Bucket = 'Remove'; MethodsRegistered = 'fido2, mobilePhone' }
            @{ UserPrincipalName = 'hunt.user@contoso.com'; DisplayName = 'Hunt User'; IsAdmin = $false; Bucket = 'Hunt'; MethodsRegistered = '' }
            @{ UserPrincipalName = 'ok.user@contoso.com'; DisplayName = 'Ok User'; IsAdmin = $false; Bucket = 'OK'; MethodsRegistered = 'fido2' }
        )

        Export-SAWDashboard -RuleResults $script:MixedResults -UserRoster $roster -OutputPath $rosterPath | Out-Null
        $content = Get-Content -Path $rosterPath -Raw

        $content | Should -Match 'User Triage'
        $content | Should -Match 'remove\.admin@contoso\.com'
        $content | Should -Match '<span class="badge bg-dark">Admin</span>'
        # 1 Remove (1 admin), 1 Hunt (0 admin), 1 OK (0 admin)
        $content | Should -Match 'Remove weak fallback \(1 admin\)'
        $content | Should -Match 'Hunt for registration \(0 admin\)'
    }

    It 'renders the Guest (FIDO2 Not Supported) bucket with its own count and badge' {
        $rosterPath = Join-Path $TestDrive 'guestroster\index.html'
        $roster = @(
            @{ UserPrincipalName = 'guest.partner@contoso.com'; DisplayName = 'Guest Partner'; IsAdmin = $false; IsGuest = $true; Bucket = 'Guest (FIDO2 Not Supported)'; MethodsRegistered = '' }
            @{ UserPrincipalName = 'ok.user@contoso.com'; DisplayName = 'Ok User'; IsAdmin = $false; IsGuest = $false; Bucket = 'OK'; MethodsRegistered = 'fido2' }
        )

        Export-SAWDashboard -RuleResults $script:MixedResults -UserRoster $roster -OutputPath $rosterPath | Out-Null
        $content = Get-Content -Path $rosterPath -Raw

        $content | Should -Match 'guest\.partner@contoso\.com'
        $content | Should -Match 'Guests \(FIDO2 not supported\)'
        $content | Should -Match '<span class="badge bg-secondary">Guest \(FIDO2 Not Supported\)</span>'
    }

    It 'defaults the baseline label to "no customer-specific baseline" when -BaselineName is not supplied' {
        $script:DashboardContent | Should -Match 'no customer-specific baseline applied'
    }

    It 'shows the supplied baseline name' {
        $path = Join-Path $TestDrive 'namedbaseline\index.html'

        Export-SAWDashboard -RuleResults $script:MixedResults -BaselineName 'Cloud-Native, Passwordless-First' -OutputPath $path | Out-Null

        $content = Get-Content -Path $path -Raw
        $content | Should -Match 'Cloud-Native, Passwordless-First'
    }

    It 'omits the CA policy inventory section entirely when none is supplied' {
        $script:DashboardContent | Should -Not -Match 'Conditional Access Policy Inventory'
    }

    It 'renders the CA policy inventory section with policy details when supplied' {
        $caPath = Join-Path $TestDrive 'cainventory\index.html'
        $inventory = @(
            @{ DisplayName = 'Block Legacy Auth'; State = 'Enabled'; UserTargetSummary = 'All users (1 excluded)'; AppTargetSummary = 'All apps'; GrantControlsSummary = 'Block access'; TargetsSecurityInfoRegistration = $false }
            @{ DisplayName = 'Require MFA for Security Info Registration'; State = 'Enabled'; UserTargetSummary = 'All users'; AppTargetSummary = 'Register security information'; GrantControlsSummary = 'Require MFA'; TargetsSecurityInfoRegistration = $true }
        )

        Export-SAWDashboard -RuleResults $script:MixedResults -CaPolicyInventory $inventory -OutputPath $caPath | Out-Null
        $content = Get-Content -Path $caPath -Raw

        $content | Should -Match 'Conditional Access Policy Inventory'
        $content | Should -Match 'Block Legacy Auth'
        $content | Should -Match 'Block access'
        $content | Should -Match '<span class="badge bg-info text-dark">Security Info Registration</span>'
    }

    It 'omits the Remediation Roadmap section entirely when none is supplied' {
        $script:DashboardContent | Should -Not -Match 'Remediation Roadmap'
    }

    It 'renders phase progress, an outstanding rule, and its Blocked badge when a roadmap is supplied' {
        $roadmapPath = Join-Path $TestDrive 'roadmap\index.html'
        $roadmap = @(
            @{ Phase = 1; PhaseName = '1. Foundation'; TotalCount = 2; CompletedCount = 1; NotApplicableCount = 0; OutstandingCount = 1; IsComplete = $false
               OutstandingRules = @(@{ RuleID = 'B'; Category = 'Conditional Access'; Setting = 'Setting B'; Status = 'Red'; Severity = 'High'; Recommendation = 'Fix B.'; Blocked = $false; BlockedBy = @() }) }
            @{ Phase = 2; PhaseName = '2. Capability'; TotalCount = 1; CompletedCount = 0; NotApplicableCount = 0; OutstandingCount = 1; IsComplete = $false
               OutstandingRules = @(@{ RuleID = 'D'; Category = 'Passkeys'; Setting = 'Setting D'; Status = 'Yellow'; Severity = 'Low'; Recommendation = 'Fix D.'; Blocked = $true; BlockedBy = @('B') }) }
            @{ Phase = 3; PhaseName = '3. All Done'; TotalCount = 1; CompletedCount = 1; NotApplicableCount = 0; OutstandingCount = 0; IsComplete = $true
               OutstandingRules = @() }
        )

        Export-SAWDashboard -RuleResults $script:MixedResults -Roadmap $roadmap -OutputPath $roadmapPath | Out-Null
        $content = Get-Content -Path $roadmapPath -Raw

        $content | Should -Match 'Remediation Roadmap'
        $content | Should -Match '1\. Foundation'
        $content | Should -Match '1/2 complete'
        $content | Should -Match 'Blocked - waiting on B'
        $content | Should -Match 'All rules in this phase are already Green or not applicable\.'
    }

    It 'omits the Domain Services note by default' {
        $script:DashboardContent | Should -Not -Match 'Entra Domain Services'
    }

    It 'shows the Domain Services note when -DomainServicesDetected is true' {
        $path = Join-Path $TestDrive 'domainservices\index.html'

        Export-SAWDashboard -RuleResults $script:MixedResults -DomainServicesDetected $true -OutputPath $path | Out-Null

        $content = Get-Content -Path $path -Raw
        $content | Should -Match 'Entra Domain Services'
    }

    It 'omits the Trend Over Time section entirely when -Trend is not supplied' {
        $script:DashboardContent | Should -Not -Match 'Trend Over Time'
    }

    It 'shows a "not enough history" note when -Trend has fewer than 2 runs' {
        $path = Join-Path $TestDrive 'trendonepoint\index.html'
        $trend = @(@{ RunTimestamp = 't1'; BaselineName = 'B'; Counts = @{ Green = 1; Yellow = 0; Red = 0; Grey = 0 }; RosterCounts = @{} })

        Export-SAWDashboard -RuleResults $script:MixedResults -Trend $trend -OutputPath $path | Out-Null

        $content = Get-Content -Path $path -Raw
        $content | Should -Match 'Trend Over Time'
        $content | Should -Match 'Not enough history yet'
        $content | Should -Not -Match 'id="trendChart"'
    }

    It 'renders a trend chart and per-run table when -Trend has 2 or more runs' {
        $path = Join-Path $TestDrive 'trendtwopoint\index.html'
        $trend = @(
            @{ RunTimestamp = '20260101-000000'; BaselineName = 'B'; Counts = @{ Green = 1; Yellow = 2; Red = 3; Grey = 4 }; RosterCounts = @{} }
            @{ RunTimestamp = '20260201-000000'; BaselineName = 'B'; Counts = @{ Green = 5; Yellow = 1; Red = 0; Grey = 4 }; RosterCounts = @{} }
        )

        Export-SAWDashboard -RuleResults $script:MixedResults -Trend $trend -OutputPath $path | Out-Null

        $content = Get-Content -Path $path -Raw
        $content | Should -Match 'id="trendChart"'
        $content | Should -Match "getElementById\('trendChart'\)"
        $content | Should -Match '20260101-000000'
        $content | Should -Match '20260201-000000'
        $content | Should -Match '2 runs for this tenant'
    }

    It 'omits the Upcoming Microsoft Deadlines section when no -TimelineMilestones are supplied' {
        $script:DashboardContent | Should -Not -Match 'Upcoming Microsoft Deadlines'
    }

    It 'renders a milestone with correct urgency class and days-left/days-ago labels' {
        $path = Join-Path $TestDrive 'timeline\index.html'
        $milestones = @(
            @{ Date = '2026-08-06'; Title = 'Imminent Thing'; Description = 'Desc A'; RelatedRuleIDs = @('SSPR001'); SourceUrl = 'https://example.com/a'; DaysRemaining = 2; IsPast = $false }
            @{ Date = '2026-01-01'; Title = 'Past Thing'; Description = 'Desc D'; RelatedRuleIDs = @(); SourceUrl = 'https://example.com/d'; DaysRemaining = -215; IsPast = $true }
        )

        Export-SAWDashboard -RuleResults $script:MixedResults -TimelineMilestones $milestones -OutputPath $path | Out-Null

        $content = Get-Content -Path $path -Raw
        $content | Should -Match 'Upcoming Microsoft Deadlines'
        $content | Should -Match 'Imminent Thing'
        $content | Should -Match '2 day\(s\) left'
        $content | Should -Match 'border-danger'
        $content | Should -Match 'Past Thing'
        $content | Should -Match '215 day\(s\) ago'
        $content | Should -Match 'border-secondary'
        $content | Should -Match '>SSPR001<'
        $content | Should -Match 'href="https://example.com/a"'
    }
}
