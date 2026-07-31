BeforeAll {
    . "$PSScriptRoot/../../src/rules/Get-SAWHistoryTrend.ps1"

    function New-SAWTestSnapshotFile {
        param($Directory, $FileName, $RunTimestamp, $BaselineName = 'B', $Statuses = @('Green'), $RosterCounts = @{})
        $results = foreach ($status in $Statuses) { @{ RuleID = [guid]::NewGuid().ToString(); Status = $status } }
        $snapshot = @{
            RunTimestamp = $RunTimestamp
            GeneratedAt  = "$RunTimestamp-generated"
            BaselineName = $BaselineName
            Results      = @($results)
            RosterCounts = $RosterCounts
        }
        $snapshot | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $Directory $FileName)
    }
}

Describe 'Get-SAWHistoryTrend' {
    BeforeEach {
        $script:historyRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $script:historyRoot | Out-Null
    }

    It 'returns an empty array when the tenant history directory does not exist' {
        $trend = Get-SAWHistoryTrend -HistoryPath $script:historyRoot -TenantSlug 'no-such-tenant'

        $trend.Count | Should -Be 0
    }

    It 'returns an empty array when the tenant history directory exists but has no snapshot files' {
        $tenantDir = Join-Path $script:historyRoot 'empty-tenant'
        New-Item -ItemType Directory -Path $tenantDir | Out-Null

        $trend = Get-SAWHistoryTrend -HistoryPath $script:historyRoot -TenantSlug 'empty-tenant'

        $trend.Count | Should -Be 0
    }

    It 'always returns a proper array, even with exactly one snapshot' {
        $tenantDir = Join-Path $script:historyRoot 'one-snapshot'
        New-Item -ItemType Directory -Path $tenantDir | Out-Null
        New-SAWTestSnapshotFile -Directory $tenantDir -FileName 't1.json' -RunTimestamp 't1'

        $trend = Get-SAWHistoryTrend -HistoryPath $script:historyRoot -TenantSlug 'one-snapshot'

        $trend.GetType().IsArray | Should -BeTrue
        $trend.Count | Should -Be 1
        $trend[0].RunTimestamp | Should -Be 't1'
    }

    It 'sorts snapshots ascending by filename (chronological, given the yyyyMMdd-HHmmss format)' {
        $tenantDir = Join-Path $script:historyRoot 'multi-tenant'
        New-Item -ItemType Directory -Path $tenantDir | Out-Null
        New-SAWTestSnapshotFile -Directory $tenantDir -FileName '20260201-000000.json' -RunTimestamp '20260201-000000'
        New-SAWTestSnapshotFile -Directory $tenantDir -FileName '20260101-000000.json' -RunTimestamp '20260101-000000'

        $trend = Get-SAWHistoryTrend -HistoryPath $script:historyRoot -TenantSlug 'multi-tenant'

        $trend[0].RunTimestamp | Should -Be '20260101-000000'
        $trend[1].RunTimestamp | Should -Be '20260201-000000'
    }

    It 'computes correct Green/Yellow/Red/Grey counts per snapshot' {
        $tenantDir = Join-Path $script:historyRoot 'counts-tenant'
        New-Item -ItemType Directory -Path $tenantDir | Out-Null
        New-SAWTestSnapshotFile -Directory $tenantDir -FileName 't1.json' -RunTimestamp 't1' -Statuses @('Green', 'Green', 'Yellow', 'Red', 'Red', 'Red', 'Grey')

        $trend = Get-SAWHistoryTrend -HistoryPath $script:historyRoot -TenantSlug 'counts-tenant'

        $trend[0].Counts.Green | Should -Be 2
        $trend[0].Counts.Yellow | Should -Be 1
        $trend[0].Counts.Red | Should -Be 3
        $trend[0].Counts.Grey | Should -Be 1
    }

    It 'carries roster counts through from the snapshot' {
        $tenantDir = Join-Path $script:historyRoot 'roster-tenant'
        New-Item -ItemType Directory -Path $tenantDir | Out-Null
        New-SAWTestSnapshotFile -Directory $tenantDir -FileName 't1.json' -RunTimestamp 't1' -RosterCounts @{ Remove = 2; Hunt = 5; 'Guest (FIDO2 Not Supported)' = 1; OK = 1 }

        $trend = Get-SAWHistoryTrend -HistoryPath $script:historyRoot -TenantSlug 'roster-tenant'

        $trend[0].RosterCounts.Remove | Should -Be 2
        $trend[0].RosterCounts.OK | Should -Be 1
    }

    It 'skips an unreadable/corrupt snapshot file rather than throwing' {
        $tenantDir = Join-Path $script:historyRoot 'corrupt-tenant'
        New-Item -ItemType Directory -Path $tenantDir | Out-Null
        New-SAWTestSnapshotFile -Directory $tenantDir -FileName '20260101-000000.json' -RunTimestamp '20260101-000000'
        'not valid json {{{' | Set-Content -Path (Join-Path $tenantDir '20260102-000000.json')

        $trend = Get-SAWHistoryTrend -HistoryPath $script:historyRoot -TenantSlug 'corrupt-tenant'

        $trend.Count | Should -Be 1
        $trend[0].RunTimestamp | Should -Be '20260101-000000'
    }
}
