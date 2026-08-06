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

    It 'processes the real bundled sample fixture without error and returns 8 methods plus Registration Campaign plus System-Preferred Authentication' {
        $realPath = "$PSScriptRoot/../../sampledata/raw/authenticationMethodsPolicy.raw.json"
        $policy = Get-Content -Path $realPath -Raw | ConvertFrom-Json

        $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

        $result.Count | Should -Be 10
        ($result | Where-Object { $_.Setting -eq 'FIDO2' }).State | Should -Be 'Disabled'
    }

    Context 'Registration Campaign row' {
        It 'reports Disabled with no nudge' {
            $policy = @{ registrationEnforcement = @{ authenticationMethodsRegistrationCampaign = @{ state = 'disabled' } } }

            $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

            $row = $result | Where-Object { $_.Setting -eq 'Registration Campaign' }
            $row.State | Should -Be 'Disabled'
            $row.SettingsSummary | Should -Be 'No registration nudge occurs'
            $row.RolloutNote | Should -BeNullOrEmpty
        }

        It 'reports the admin-configured target/snooze settings verbatim when Enabled' {
            $policy = @{ registrationEnforcement = @{ authenticationMethodsRegistrationCampaign = @{
                state = 'enabled'
                snoozeDurationInDays = 3
                enforceRegistrationAfterAllowedSnoozes = $true
                includeTargets = @(@{ targetedAuthenticationMethod = 'fido2' })
            } } }

            $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

            $row = $result | Where-Object { $_.Setting -eq 'Registration Campaign' }
            $row.State | Should -Be 'Enabled'
            $row.SettingsSummary | Should -Be 'Target: passkey (FIDO2); Snooze: 3 day(s); Snooze limit: limited (required after 3 skips)'
            $row.RolloutNote | Should -BeNullOrEmpty
        }

        It 'reports Microsoft managed with a RolloutNote when state is default' {
            $policy = @{ registrationEnforcement = @{ authenticationMethodsRegistrationCampaign = @{ state = 'default' } } }

            $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

            $row = $result | Where-Object { $_.Setting -eq 'Registration Campaign' }
            $row.State | Should -Be 'Microsoft managed'
            $row.RolloutNote | Should -Not -BeNullOrEmpty
        }

        It 'treats a completely absent registrationEnforcement the same as default (Microsoft managed)' {
            $policy = @{}

            $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

            $row = $result | Where-Object { $_.Setting -eq 'Registration Campaign' }
            $row.State | Should -Be 'Microsoft managed'
            $row.RolloutNote | Should -Not -BeNullOrEmpty
        }
    }

    Context 'System-Preferred Authentication row' {
        It 'reports Disabled with no sign-in order change' {
            $policy = @{ systemCredentialPreferences = @{ state = 'disabled'; includeTargets = @(); excludeTargets = @() } }

            $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

            $row = $result | Where-Object { $_.Setting -eq 'System-Preferred Authentication' }
            $row.State | Should -Be 'Disabled'
            $row.SettingsSummary | Should -Be 'No change to sign-in order'
        }

        It 'reports second-factor-only scope when state is enabled' {
            $policy = @{ systemCredentialPreferences = @{ state = 'enabled'; includeTargets = @(@{ id = 'all_users'; targetType = 'group' }); excludeTargets = @() } }

            $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

            $row = $result | Where-Object { $_.Setting -eq 'System-Preferred Authentication' }
            $row.State | Should -Be 'Enabled (second factor only)'
            $row.TargetSummary | Should -Be 'All users'
        }

        It 'reports Microsoft managed (first + second factor) when state is default' {
            $policy = @{ systemCredentialPreferences = @{ state = 'default'; includeTargets = @(); excludeTargets = @() } }

            $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

            $row = $result | Where-Object { $_.Setting -eq 'System-Preferred Authentication' }
            $row.State | Should -Match 'Microsoft managed'
            $row.RolloutNote | Should -Not -BeNullOrEmpty
        }

        It 'treats a completely absent systemCredentialPreferences the same as default (Microsoft managed)' {
            $policy = @{}

            $result = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $policy)

            $row = $result | Where-Object { $_.Setting -eq 'System-Preferred Authentication' }
            $row.State | Should -Match 'Microsoft managed'
            $row.RolloutNote | Should -Not -BeNullOrEmpty
        }

        It 'does not set RolloutNote for the non-Microsoft-managed states' {
            $disabledPolicy = @{ systemCredentialPreferences = @{ state = 'disabled' } }
            $enabledPolicy = @{ systemCredentialPreferences = @{ state = 'enabled' } }

            $disabledRow = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $disabledPolicy) | Where-Object { $_.Setting -eq 'System-Preferred Authentication' }
            $enabledRow = @(ConvertTo-SAWAuthenticationMethodsInventory -RawPolicy $enabledPolicy) | Where-Object { $_.Setting -eq 'System-Preferred Authentication' }

            $disabledRow.RolloutNote | Should -BeNullOrEmpty
            $enabledRow.RolloutNote | Should -BeNullOrEmpty
        }
    }
}
