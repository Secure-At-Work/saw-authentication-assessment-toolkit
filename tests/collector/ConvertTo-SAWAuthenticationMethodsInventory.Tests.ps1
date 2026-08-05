BeforeAll {
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWAuthenticationMethodsInventory.ps1"

    function New-SAWTestMethodConfig {
        param(
            [string]$Id = 'Fido2',
            [string]$State = 'enabled',
            [object[]]$IncludeTargets = @(),
            [object[]]$ExcludeTargets = @(),
            [hashtable]$ExtraProperties = @{}
        )
        $config = @{ id = $Id; state = $State; includeTargets = $IncludeTargets; excludeTargets = $ExcludeTargets }
        foreach ($key in $ExtraProperties.Keys) { $config[$key] = $ExtraProperties[$key] }
        return $config
    }
}

Describe 'ConvertTo-SAWAuthenticationMethodsInventory' {
    It 'maps a known method id to its display name' {
        $policy = @{ authenticationMethodConfigurations = @((New-SAWTestMethodConfig -Id 'Fido2')) }

        $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

        $result[0].Setting | Should -Be 'FIDO2'
    }

    It 'falls back to the raw id for an unrecognized method id' {
        $policy = @{ authenticationMethodConfigurations = @((New-SAWTestMethodConfig -Id 'SomeNewMethod')) }

        $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

        $result[0].Setting | Should -Be 'SomeNewMethod'
    }

    It 'capitalizes state (enabled/disabled) for display' {
        $policy = @{ authenticationMethodConfigurations = @(
            (New-SAWTestMethodConfig -Id 'Fido2' -State 'enabled'),
            (New-SAWTestMethodConfig -Id 'Sms' -State 'disabled')
        ) }

        $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

        ($result | Where-Object { $_.Setting -eq 'FIDO2' }).State | Should -Be 'Enabled'
        ($result | Where-Object { $_.Setting -eq 'SMS' }).State | Should -Be 'Disabled'
    }

    It 'summarizes "All users" when includeTargets contains the special all_users id' {
        $policy = @{ authenticationMethodConfigurations = @(
            (New-SAWTestMethodConfig -IncludeTargets @(@{ id = 'all_users'; targetType = 'group' }))
        ) }

        $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

        $result[0].TargetSummary | Should -Be 'All users'
    }

    It 'appends the exclude count to "All users" when excludeTargets is non-empty' {
        $policy = @{ authenticationMethodConfigurations = @(
            (New-SAWTestMethodConfig -IncludeTargets @(@{ id = 'all_users'; targetType = 'group' }) -ExcludeTargets @(@{ id = 'g1'; targetType = 'group' }, @{ id = 'g2'; targetType = 'group' }))
        ) }

        $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

        $result[0].TargetSummary | Should -Be 'All users (2 group(s)/user(s) excluded)'
    }

    It 'summarizes specific group/user counts when all_users is not targeted' {
        $policy = @{ authenticationMethodConfigurations = @(
            (New-SAWTestMethodConfig -IncludeTargets @(@{ id = 'g1'; targetType = 'group' }, @{ id = 'g2'; targetType = 'group' }, @{ id = 'u1'; targetType = 'user' }))
        ) }

        $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

        $result[0].TargetSummary | Should -Be '2 group(s), 1 user(s)'
    }

    It 'summarizes "None" when there are no include targets at all' {
        $policy = @{ authenticationMethodConfigurations = @((New-SAWTestMethodConfig -IncludeTargets @())) }

        $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

        $result[0].TargetSummary | Should -Be 'None'
    }

    It 'builds a plain-language settings summary for FIDO2' {
        $policy = @{ authenticationMethodConfigurations = @(
            (New-SAWTestMethodConfig -Id 'Fido2' -ExtraProperties @{ isSelfServiceRegistrationAllowed = $true; isAttestationEnforced = $false })
        ) }

        $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

        $result[0].SettingsSummary | Should -Be 'Self-service registration: Allowed; Attestation enforced: No'
    }

    It 'builds a plain-language settings summary for Temporary Access Pass' {
        $policy = @{ authenticationMethodConfigurations = @(
            (New-SAWTestMethodConfig -Id 'TemporaryAccessPass' -ExtraProperties @{ defaultLifetimeInMinutes = 30; isUsableOnce = $false })
        ) }

        $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

        $result[0].SettingsSummary | Should -Be 'Default lifetime: 30 min; One-time use: No (reusable)'
    }

    It 'shows "-" for a method type with no plain-language settings mapped' {
        $policy = @{ authenticationMethodConfigurations = @((New-SAWTestMethodConfig -Id 'Sms')) }

        $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

        $result[0].SettingsSummary | Should -Be '-'
    }

    It 'handles a policy with no authenticationMethodConfigurations at all without error' {
        $result = ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy @{}

        @($result).Count | Should -Be 0
    }

    It 'processes the real bundled sample fixture without error and returns 8 methods' {
        $realPath = "$PSScriptRoot/../../sampledata/raw/authenticationMethodsPolicy.raw.json"
        $policy = Get-Content -Path $realPath -Raw | ConvertFrom-Json

        $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

        $result.Count | Should -Be 8
        ($result | Where-Object { $_.Setting -eq 'FIDO2' }).State | Should -Be 'Disabled'
    }
}
