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
}
