BeforeAll {
    . "$PSScriptRoot/../../src/dashboard/Export-SAWHtmlReport.ps1"
}

Describe 'Export-SAWHtmlReport' {
    It 'creates the output file' {
        $outputPath = Join-Path $TestDrive 'report.html'
        $results = @(@{ RuleID = 'T001'; Category = 'Cat'; Setting = 'Setting'; Expected = 'Enabled'; Actual = 'Enabled'; Severity = 'High'; Status = 'Green'; Recommendation = 'Do the thing.' })

        Export-SAWHtmlReport -RuleResults $results -OutputPath $outputPath | Out-Null

        Test-Path $outputPath | Should -BeTrue
    }

    It 'creates the parent directory if it does not exist' {
        $outputPath = Join-Path $TestDrive 'nested\deeper\report.html'
        $results = @()

        Export-SAWHtmlReport -RuleResults $results -OutputPath $outputPath | Out-Null

        Test-Path $outputPath | Should -BeTrue
    }

    It 'produces a valid HTML shell even with zero results' {
        $outputPath = Join-Path $TestDrive 'empty.html'

        Export-SAWHtmlReport -RuleResults @() -OutputPath $outputPath | Out-Null

        $content = Get-Content -Path $outputPath -Raw
        $content | Should -Match '<table>'
        $content | Should -Match '</html>'
    }

    It 'includes each rule''s data in the output' {
        $outputPath = Join-Path $TestDrive 'data.html'
        $results = @(@{ RuleID = 'AUTH999'; Category = 'Authentication Methods'; Setting = 'Some Setting'; Expected = 'Enabled'; Actual = 'Disabled'; Severity = 'High'; Status = 'Red'; Recommendation = 'Enable it.' })

        Export-SAWHtmlReport -RuleResults $results -OutputPath $outputPath | Out-Null

        $content = Get-Content -Path $outputPath -Raw
        $content | Should -Match 'AUTH999'
        $content | Should -Match 'Some Setting'
        $content | Should -Match 'Enable it\.'
    }

    It 'lists distinct categories in the generated meta line' {
        $outputPath = Join-Path $TestDrive 'categories.html'
        $results = @(
            @{ RuleID = 'A1'; Category = 'Authentication Methods'; Setting = 'S1'; Expected = 'Enabled'; Actual = 'Enabled'; Severity = 'High'; Status = 'Green'; Recommendation = 'R1' },
            @{ RuleID = 'A2'; Category = 'Conditional Access'; Setting = 'S2'; Expected = 'Enabled'; Actual = 'Enabled'; Severity = 'High'; Status = 'Green'; Recommendation = 'R2' },
            @{ RuleID = 'A3'; Category = 'Authentication Methods'; Setting = 'S3'; Expected = 'Enabled'; Actual = 'Enabled'; Severity = 'High'; Status = 'Green'; Recommendation = 'R3' }
        )

        Export-SAWHtmlReport -RuleResults $results -OutputPath $outputPath | Out-Null

        $content = Get-Content -Path $outputPath -Raw
        $content | Should -Match 'Authentication Methods, Conditional Access'
    }

    It 'HTML-encodes recommendation text so it cannot inject markup' {
        $outputPath = Join-Path $TestDrive 'encoded.html'
        $results = @(@{ RuleID = 'X1'; Category = 'Cat'; Setting = 'Setting'; Expected = 'Enabled'; Actual = 'Disabled'; Severity = 'High'; Status = 'Red'; Recommendation = '<script>alert(1)</script>' })

        Export-SAWHtmlReport -RuleResults $results -OutputPath $outputPath | Out-Null

        $content = Get-Content -Path $outputPath -Raw
        $content | Should -Not -Match '<script>alert'
        $content | Should -Match '&lt;script&gt;'
    }

    It 'applies the correct color per status' {
        $outputPath = Join-Path $TestDrive 'colors.html'
        $results = @(
            @{ RuleID = 'G'; Category = 'Cat'; Setting = 'S'; Expected = 'Enabled'; Actual = 'Enabled'; Severity = 'High'; Status = 'Green'; Recommendation = 'R' },
            @{ RuleID = 'Y'; Category = 'Cat'; Setting = 'S'; Expected = 'Enabled'; Actual = 'Disabled'; Severity = 'Low'; Status = 'Yellow'; Recommendation = 'R' },
            @{ RuleID = 'R'; Category = 'Cat'; Setting = 'S'; Expected = 'Enabled'; Actual = 'Disabled'; Severity = 'High'; Status = 'Red'; Recommendation = 'R' },
            @{ RuleID = 'GR'; Category = 'Cat'; Setting = 'S'; Expected = 'Enabled'; Actual = $null; Severity = 'High'; Status = 'Grey'; Recommendation = 'R' }
        )

        Export-SAWHtmlReport -RuleResults $results -OutputPath $outputPath | Out-Null

        $content = Get-Content -Path $outputPath -Raw
        $content | Should -Match '#2e7d32'
        $content | Should -Match '#f9a825'
        $content | Should -Match '#c62828'
        $content | Should -Match '#9e9e9e'
    }
}
