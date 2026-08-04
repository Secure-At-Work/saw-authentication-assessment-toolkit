BeforeAll {
    . "$PSScriptRoot/../src/Connect-SAWGraph.ps1"

    # Constant stand-ins for Microsoft.Graph.Authentication's real cmdlets - module/command
    # presence checks always succeed here, so every test focuses purely on the
    # connect/reuse/reconnect decision logic.
    function Get-Module { param([switch]$ListAvailable, $Name) @{ Version = [version]'2.0.0' } }
    function Import-Module { param($Name, $ErrorAction) }
    function Get-Command { param($Name, $ErrorAction) @{ Name = $Name } }
}

Describe 'Connect-SAWGraph' {
    BeforeEach {
        $script:connectCalls = @()
        $script:disconnectCalls = 0
        $script:currentContext = $null

        function Connect-MgGraph {
            param($Scopes, [switch]$NoWelcome, $ErrorAction, $TenantId)
            $script:connectCalls += @{ Scopes = $Scopes; TenantId = $TenantId }
            $effectiveTenantId = 'aaaaaaaa-tenant-a'
            if ($TenantId) { $effectiveTenantId = $TenantId }
            $script:currentContext = @{ Account = 'kenneth@contoso.com'; Scopes = $Scopes; TenantId = $effectiveTenantId }
        }
        function Disconnect-MgGraph { param($ErrorAction) $script:disconnectCalls++; $script:currentContext = $null }
        function Get-MgContext { $script:currentContext }
    }

    $requiredScopes = @('Policy.Read.All')

    It 'connects fresh with no -TenantId when there is no active connection' {
        Connect-SAWGraph -Scopes $requiredScopes | Out-Null

        $script:connectCalls.Count | Should -Be 1
        $script:connectCalls[0].TenantId | Should -BeNullOrEmpty
    }

    It 'passes -TenantId through to Connect-MgGraph when there is no active connection' {
        Connect-SAWGraph -Scopes $requiredScopes -TenantId 'tenant-b-guid' | Out-Null

        $script:connectCalls.Count | Should -Be 1
        $script:connectCalls[0].TenantId | Should -Be 'tenant-b-guid'
        $script:disconnectCalls | Should -Be 0
    }

    It 'reuses an existing connection when its tenant matches the requested -TenantId' {
        $script:currentContext = @{ Account = 'kenneth@contoso.com'; Scopes = $requiredScopes; TenantId = 'tenant-a-guid' }

        Connect-SAWGraph -Scopes $requiredScopes -TenantId 'tenant-a-guid' | Out-Null

        $script:connectCalls.Count | Should -Be 0
        $script:disconnectCalls | Should -Be 0
    }

    It 'disconnects and reconnects to the REQUESTED tenant when the active connection is for a different one' {
        # This is the exact real-world bug: same account, PIM-active in both tenants, works
        # against tenant A, then silently keeps using tenant A when tenant B was intended.
        $script:currentContext = @{ Account = 'kenneth@contoso.com'; Scopes = $requiredScopes; TenantId = 'tenant-a-guid' }

        $result = Connect-SAWGraph -Scopes $requiredScopes -TenantId 'tenant-b-guid' 3>$null

        $script:disconnectCalls | Should -Be 1
        $script:connectCalls.Count | Should -Be 1
        $script:connectCalls[0].TenantId | Should -Be 'tenant-b-guid'
        $result.TenantId | Should -Be 'tenant-b-guid'
    }

    It 'warns when disconnecting a mismatched tenant connection' {
        $script:currentContext = @{ Account = 'kenneth@contoso.com'; Scopes = $requiredScopes; TenantId = 'tenant-a-guid' }

        $warnings = Connect-SAWGraph -Scopes $requiredScopes -TenantId 'tenant-b-guid' 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }

        $warnings.Count | Should -BeGreaterThan 0
        $warnings[0].Message | Should -Match 'tenant-a-guid'
        $warnings[0].Message | Should -Match 'tenant-b-guid'
    }

    It 'reuses an existing connection with sufficient scopes when -TenantId is not supplied at all (unchanged default behavior)' {
        $script:currentContext = @{ Account = 'kenneth@contoso.com'; Scopes = $requiredScopes; TenantId = 'whatever-tenant' }

        Connect-SAWGraph -Scopes $requiredScopes | Out-Null

        $script:connectCalls.Count | Should -Be 0
        $script:disconnectCalls | Should -Be 0
    }

    It 'reconnects (without disconnecting first) when scopes are insufficient and -TenantId is not involved' {
        $script:currentContext = @{ Account = 'kenneth@contoso.com'; Scopes = @('SomeOther.Scope'); TenantId = 'tenant-a-guid' }

        Connect-SAWGraph -Scopes $requiredScopes | Out-Null

        $script:connectCalls.Count | Should -Be 1
        $script:disconnectCalls | Should -Be 0
    }

    It 'throws if Connect-MgGraph never establishes a context' {
        function Connect-MgGraph { param($Scopes, [switch]$NoWelcome, $ErrorAction, $TenantId) }
        function Get-MgContext { $null }

        { Connect-SAWGraph -Scopes $requiredScopes } | Should -Throw
    }

    It '-ForceReauth disconnects and reconnects even when the existing connection already matches tenant and scopes' {
        # Real-world case: a role was just activated via PIM (or PIM for Groups), but
        # Connect-MgGraph is silently reusing a still-valid cached token from before the
        # activation - reusing it (the normal path) would keep hitting 403s.
        $script:currentContext = @{ Account = 'kenneth@contoso.com'; Scopes = $requiredScopes; TenantId = 'tenant-a-guid' }

        $result = Connect-SAWGraph -Scopes $requiredScopes -TenantId 'tenant-a-guid' -ForceReauth 3>$null

        $script:disconnectCalls | Should -Be 1
        $script:connectCalls.Count | Should -Be 1
        $script:connectCalls[0].TenantId | Should -Be 'tenant-a-guid'
        $result.TenantId | Should -Be 'tenant-a-guid'
    }

    It '-ForceReauth connects with -ContextScope Process so the token is not the shared, disk-persisted context' {
        $script:currentContext = @{ Account = 'kenneth@contoso.com'; Scopes = $requiredScopes; TenantId = 'tenant-a-guid' }
        $script:connectContextScopes = @()
        function Connect-MgGraph {
            param($Scopes, [switch]$NoWelcome, $ErrorAction, $TenantId, $ContextScope)
            $script:connectCalls += @{ Scopes = $Scopes; TenantId = $TenantId }
            $script:connectContextScopes += $ContextScope
            $script:currentContext = @{ Account = 'kenneth@contoso.com'; Scopes = $Scopes; TenantId = 'tenant-a-guid' }
        }

        Connect-SAWGraph -Scopes $requiredScopes -TenantId 'tenant-a-guid' -ForceReauth 3>$null | Out-Null

        $script:connectContextScopes | Should -Be @('Process')
    }

    It '-ForceReauth with no active connection just connects fresh (nothing to disconnect)' {
        $script:currentContext = $null

        Connect-SAWGraph -Scopes $requiredScopes -ForceReauth | Out-Null

        $script:disconnectCalls | Should -Be 0
        $script:connectCalls.Count | Should -Be 1
    }

    It 'warns when -ForceReauth disconnects an existing connection' {
        $script:currentContext = @{ Account = 'kenneth@contoso.com'; Scopes = $requiredScopes; TenantId = 'tenant-a-guid' }

        $warnings = Connect-SAWGraph -Scopes $requiredScopes -TenantId 'tenant-a-guid' -ForceReauth 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }

        $warnings.Count | Should -BeGreaterThan 0
        $warnings[0].Message | Should -Match 'ForceReauth'
    }
}
