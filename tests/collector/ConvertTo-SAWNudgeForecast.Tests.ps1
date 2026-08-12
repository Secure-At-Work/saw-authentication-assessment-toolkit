BeforeAll {
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWNudgeForecast.ps1"

    $script:Roster = @(
        @{ UserPrincipalName = 'alice@c.com'; DisplayName = 'Alice'; IsAdmin = $true;  IsGuest = $false; MethodsRegistered = 'fido2, microsoftAuthenticatorPush' }
        @{ UserPrincipalName = 'bob@c.com';   DisplayName = 'Bob';   IsAdmin = $false; IsGuest = $false; MethodsRegistered = 'sms' }
        @{ UserPrincipalName = 'carol@c.com'; DisplayName = 'Carol'; IsAdmin = $false; IsGuest = $false; MethodsRegistered = 'microsoftAuthenticatorPush' }
        @{ UserPrincipalName = 'dan@c.com';   DisplayName = 'Dan';   IsAdmin = $false; IsGuest = $true;  MethodsRegistered = 'sms' }
    )

    $script:RegistrationRaw = @{ value = @(
            @{ userPrincipalName = 'alice@c.com'; isSsprEnabled = $true;  isSsprRegistered = $true }
            @{ userPrincipalName = 'bob@c.com';   isSsprEnabled = $true;  isSsprRegistered = $false }
            @{ userPrincipalName = 'carol@c.com'; isSsprEnabled = $false; isSsprRegistered = $false }
            @{ userPrincipalName = 'dan@c.com';   isSsprEnabled = $false; isSsprRegistered = $false }
        ) }

    function New-SAWTestNudgePolicy {
        param(
            [string]$State = 'enabled',
            [string]$Target = 'fido2',
            [bool]$AttestationEnforced = $false,
            [bool]$KeyRestrictionsEnforced = $false,
            [bool]$SelfServiceAllowed = $true,
            [string]$IncludeId = 'all_users'
        )
        @{
            registrationEnforcement            = @{
                authenticationMethodsRegistrationCampaign = @{
                    state          = $State
                    includeTargets = @(@{ id = $IncludeId; targetType = 'group'; targetedAuthenticationMethod = $Target })
                }
            }
            authenticationMethodConfigurations = @(
                @{
                    id                               = 'Fido2'
                    isAttestationEnforced            = $AttestationEnforced
                    isSelfServiceRegistrationAllowed = $SelfServiceAllowed
                    keyRestrictions                  = @{ isEnforced = $KeyRestrictionsEnforced }
                }
            )
        }
    }
}

Describe 'ConvertTo-SAWNudgeForecast' {
    Context 'registration campaign targeting passkey' {
        It 'forecasts a nudge for users without a passkey, and not for users who have one' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy)

            ($result.Users | Where-Object { $_.UserPrincipalName -eq 'alice@c.com' }).NudgePasskeyCampaign | Should -BeFalse
            ($result.Users | Where-Object { $_.UserPrincipalName -eq 'carol@c.com' }).NudgePasskeyCampaign | Should -BeTrue
            $result.Summary.PasskeyCampaignCount | Should -Be 2
        }

        It 'never forecasts a passkey nudge for guests, since Microsoft does not support passkey registration for them' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy)

            ($result.Users | Where-Object { $_.UserPrincipalName -eq 'dan@c.com' }).NudgePasskeyCampaign | Should -BeFalse
        }

        It 'treats the Microsoft-managed (default) campaign state as active and targeting passkeys' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy -State 'default' -Target $null)

            $result.Summary.CampaignActive | Should -BeTrue
            $result.Summary.CampaignTargetsPasskey | Should -BeTrue
        }

        It 'reports scope as uncertain (reason: group) when the campaign targets a specific group rather than all users' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy -IncludeId 'aaaa-bbbb-cccc')

            $result.Summary.CampaignScopeUncertain | Should -BeTrue
            $result.Summary.CampaignScopeUncertainReason | Should -Be 'group'
            @($result.Summary.Caveats | Where-Object { $_ -match 'scoped to specific groups' }).Count | Should -BeGreaterThan 0
        }

        It 'still reports scope as uncertain (reason: group) for a Microsoft-managed campaign with a specific group target, since Microsoft documents include/exclude targets as configurable even when Microsoft managed' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy -State 'default' -IncludeId 'aaaa-bbbb-cccc')

            $result.Summary.CampaignScopeUncertain | Should -BeTrue
            $result.Summary.CampaignScopeUncertainReason | Should -Be 'group'
        }

        It 'reports scope as uncertain (reason: msft-managed-rollout), not group, for a Microsoft-managed campaign with no include/exclude targets key at all - the shape Microsoft returns for an untouched Microsoft-managed campaign' {
            $policy = @{
                registrationEnforcement            = @{
                    authenticationMethodsRegistrationCampaign = @{ state = 'default' }
                }
                authenticationMethodConfigurations = @()
            }
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy $policy

            $result.Summary.CampaignScopeUncertain | Should -BeTrue
            $result.Summary.CampaignScopeUncertainReason | Should -Be 'msft-managed-rollout'
            @($result.Summary.Caveats | Where-Object { $_ -match 'rolling out incrementally per tenant' }).Count | Should -BeGreaterThan 0
        }

        It 'reports scope as certain (no reason) when the campaign explicitly targets all_users, Microsoft managed or not' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy)

            $result.Summary.CampaignScopeUncertain | Should -BeFalse
            $result.Summary.CampaignScopeUncertainReason | Should -BeNullOrEmpty
        }
    }

    Context 'documented tenant-wide nudge suppressors' {
        It 'suppresses the passkey campaign entirely when attestation is enforced' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy -AttestationEnforced $true)

            $result.Summary.PasskeyNudgeSuppressed | Should -BeTrue
            $result.Summary.PasskeyCampaignCount | Should -Be 0
            @($result.Summary.Suppressors | Where-Object { $_ -match 'attestation' }).Count | Should -BeGreaterThan 0
        }

        It 'suppresses the passkey campaign entirely when AAGUID key restrictions are enforced' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy -KeyRestrictionsEnforced $true)

            $result.Summary.PasskeyNudgeSuppressed | Should -BeTrue
            $result.Summary.PasskeyCampaignCount | Should -Be 0
        }

        It 'suppresses the campaign when a Conditional Access policy blocks the registration page' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy) -SecurityInfoRegistrationBlockedByCa $true

            $result.Summary.PasskeyNudgeSuppressed | Should -BeTrue
            $result.Summary.PasskeyCampaignCount | Should -Be 0
        }

        It 'does NOT let campaign suppressors mask the 2026-09-01 automatic enablement, which Microsoft drives independently' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy -AttestationEnforced $true)

            $result.Summary.PasskeyCampaignCount | Should -Be 0
            $result.Summary.AutoPasskeySept2026Count | Should -Be 1
        }
    }

    Context 'SSPR interrupts' {
        It 'forecasts an SSPR registration interrupt only for SSPR-enabled users who are not registered' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy)

            ($result.Users | Where-Object { $_.UserPrincipalName -eq 'bob@c.com' }).NudgeSsprRegistration | Should -BeTrue
            ($result.Users | Where-Object { $_.UserPrincipalName -eq 'alice@c.com' }).NudgeSsprRegistration | Should -BeFalse
            $result.Summary.SsprRegistrationCount | Should -Be 1
        }

        It 'flags the broken admin case when admin SSPR is disabled but admins remain in the user SSPR policy' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy) -AdminSsprEnabled $false

            $result.Summary.SsprBrokenForAdminCount | Should -Be 1
            ($result.Users | Where-Object { $_.UserPrincipalName -eq 'alice@c.com' }).NudgeSsprBrokenForAdmin | Should -BeTrue
        }

        It 'does not flag the broken admin case when admin SSPR is enabled (the default)' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy) -AdminSsprEnabled $true

            $result.Summary.SsprBrokenForAdminCount | Should -Be 0
        }
    }

    Context 'campaign reachability from sign-in logs' {
        It 'reports reachability as unavailable when no sign-in logs are supplied' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy)

            $result.Summary.ReachabilityAvailable | Should -BeFalse
            $result.Summary.UnreachableInWindowCount | Should -Be 0
        }

        It 'flags an eligible user with no interactive sign-in as unreachable by a campaign' {
            $logs = @{ value = @(
                    @{ userPrincipalName = 'carol@c.com'; isInteractive = $true }
                    @{ userPrincipalName = 'bob@c.com';   isInteractive = $false }
                ) }

            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy) -SignInLogs $logs -SignInWindowDays 30

            ($result.Users | Where-Object { $_.UserPrincipalName -eq 'bob@c.com' }).NudgeUnreachableInWindow | Should -BeTrue
            ($result.Users | Where-Object { $_.UserPrincipalName -eq 'carol@c.com' }).NudgeUnreachableInWindow | Should -BeFalse
        }

        It 'treats a sign-in with no isInteractive value as interactive, rather than inventing unreachable users' {
            # v1.0 /auditLogs/signIns is documented as returning interactive sign-ins, so presence
            # in the log without the flag should not be read as non-interactive.
            $logs = @{ value = @(
                    @{ userPrincipalName = 'bob@c.com' }
                    @{ userPrincipalName = 'carol@c.com' }
                ) }

            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy) -SignInLogs $logs -SignInWindowDays 7

            $result.Summary.UnreachableInWindowCount | Should -Be 0
        }

        It 'caps the reported window at Entra 30-day retention and says it did so' {
            $logs = @{ value = @(@{ userPrincipalName = 'carol@c.com'; isInteractive = $true }) }

            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy) -SignInLogs $logs -SignInWindowDays 90

            $result.Summary.SignInWindowDays | Should -Be 30
            $result.Summary.SignInWindowRetentionCapped | Should -BeTrue
            @($result.Summary.Caveats | Where-Object { $_ -match 'cannot return more than 30 days' }).Count | Should -BeGreaterThan 0
        }

        It 'always states that reachability means "not within retention" rather than "never"' {
            $logs = @{ value = @(@{ userPrincipalName = 'carol@c.com'; isInteractive = $true }) }

            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy) -SignInLogs $logs -SignInWindowDays 30

            @($result.Summary.Caveats | Where-Object { $_ -match "not within retention" }).Count | Should -BeGreaterThan 0
        }
    }

    Context 'output shape and honesty caveats' {
        It 'always carries the per-device passkey caveat, since the nudge is evaluated per device and browser' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy)

            @($result.Summary.Caveats | Where-Object { $_ -match 'per device-and-browser' }).Count | Should -BeGreaterThan 0
        }

        It 'preserves the original roster fields while adding the forecast fields' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy)
            $alice = $result.Users | Where-Object { $_.UserPrincipalName -eq 'alice@c.com' }

            $alice.DisplayName | Should -Be 'Alice'
            $alice.IsAdmin | Should -BeTrue
            $alice.PSObject.Properties.Name -contains 'WillBeNudged' -or $alice.ContainsKey('WillBeNudged') | Should -BeTrue
        }

        It 'gives every forecast user a human-readable reason for each predicted interrupt' {
            $result = ConvertTo-SAWNudgeForecast -Roster $script:Roster -RegistrationRaw $script:RegistrationRaw -AuthenticationMethodsPolicy (New-SAWTestNudgePolicy)

            foreach ($u in @($result.Users | Where-Object { $_.WillBeNudged })) {
                @($u.NudgeReasons).Count | Should -BeGreaterThan 0
            }
        }
    }
}
