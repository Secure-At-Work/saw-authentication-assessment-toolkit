BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWRegistration.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWNormalizedRegistration.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWUserRegistrationRoster.ps1"

    . "$PSScriptRoot/../../src/Invoke-SAWGraphRequest.ps1"

    function Get-MgContext { }
    function Invoke-MgGraphRequest { param($Method, $Uri) }

    function New-SAWTestUser {
        param(
            [bool]$IsAdmin = $false,
            [bool]$IsMfaRegistered = $true,
            [bool]$IsSsprEnabled = $false,
            [bool]$IsSsprRegistered = $false,
            [string]$UserPrincipalName = 'user@contoso.com',
            [string]$DisplayName = 'Test User',
            [string[]]$MethodsRegistered = @(),
            [string]$UserType = 'member',
            [AllowNull()]
            [string]$SystemPreferredAuthenticationMethod = $null
        )
        return @{
            isAdmin              = $IsAdmin
            isMfaRegistered      = $IsMfaRegistered
            isSsprEnabled        = $IsSsprEnabled
            isSsprRegistered     = $IsSsprRegistered
            userPrincipalName    = $UserPrincipalName
            userDisplayName      = $DisplayName
            methodsRegistered    = $MethodsRegistered
            userType             = $UserType
            systemPreferredAuthenticationMethod = $SystemPreferredAuthenticationMethod
        }
    }
}

Describe 'Get-SAWRegistration' {
    Context '-UseSampleData' {
        It 'returns the bundled sample data' {
            $result = Get-SAWRegistration -UseSampleData
            $result.value | Should -Not -BeNullOrEmpty
        }

        It 'throws if the sample data file does not exist' {
            { Get-SAWRegistration -UseSampleData -SampleDataPath 'C:\does\not\exist.json' } | Should -Throw
        }
    }

    Context 'live Graph calls' {
        It 'throws when not connected to Microsoft Graph' {
            Mock Get-MgContext { $null }
            { Get-SAWRegistration } | Should -Throw
        }

        It 'calls the user registration details report endpoint' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest { @{ value = @() } }

            Get-SAWRegistration | Out-Null

            Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                $Method -eq 'GET' -and $Uri -eq 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails'
            }
        }

        It 'follows @odata.nextLink to collect every page' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            $script:pageNumber = 0
            Mock Invoke-MgGraphRequest {
                $script:pageNumber++
                if ($script:pageNumber -eq 1) {
                    return @{
                        value             = @(@{ id = 'page1-user' })
                        '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$skiptoken=abc'
                    }
                }
                return @{ value = @(@{ id = 'page2-user' }) }
            }

            $result = Get-SAWRegistration

            $result.value.Count | Should -Be 2
            Should -Invoke Invoke-MgGraphRequest -Times 2
        }
    }
}

Describe 'ConvertTo-SAWNormalizedRegistration' {
    It 'reports all admins registered when every admin has MFA registered' {
        $raw = @{
            value = @(
                (New-SAWTestUser -IsAdmin $true -IsMfaRegistered $true),
                (New-SAWTestUser -IsAdmin $false -IsMfaRegistered $false)
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedRegistration

        ($result | Where-Object { $_.Setting -eq 'All Privileged Admins MFA Registered' }).State | Should -Be 'Enabled'
    }

    It 'flags a gap when any admin is missing MFA registration' {
        $raw = @{
            value = @(
                (New-SAWTestUser -IsAdmin $true -IsMfaRegistered $true),
                (New-SAWTestUser -IsAdmin $true -IsMfaRegistered $false)
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedRegistration

        ($result | Where-Object { $_.Setting -eq 'All Privileged Admins MFA Registered' }).State | Should -Be 'Disabled'
    }

    It 'reports the admin check as Disabled when there are no admins at all' {
        $raw = @{
            value = @(
                (New-SAWTestUser -IsAdmin $false -IsMfaRegistered $true)
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedRegistration

        ($result | Where-Object { $_.Setting -eq 'All Privileged Admins MFA Registered' }).State | Should -Be 'Disabled'
    }

    It 'reports coverage Enabled when at least 90 percent of users are MFA registered' {
        $raw = @{
            value = @(
                1..9 | ForEach-Object { New-SAWTestUser -IsMfaRegistered $true }
            ) + @((New-SAWTestUser -IsMfaRegistered $false))
        }

        $result = $raw | ConvertTo-SAWNormalizedRegistration

        ($result | Where-Object { $_.Setting -like 'Overall MFA Registration Coverage*' }).State | Should -Be 'Enabled'
    }

    It 'reports coverage Disabled when below 90 percent' {
        $raw = @{
            value = @(
                1..5 | ForEach-Object { New-SAWTestUser -IsMfaRegistered $true }
            ) + @(1..5 | ForEach-Object { New-SAWTestUser -IsMfaRegistered $false })
        }

        $result = $raw | ConvertTo-SAWNormalizedRegistration

        ($result | Where-Object { $_.Setting -like 'Overall MFA Registration Coverage*' }).State | Should -Be 'Disabled'
    }

    It 'reports coverage Disabled when there are no users at all' {
        $raw = @{ value = @() }

        $result = $raw | ConvertTo-SAWNormalizedRegistration

        ($result | Where-Object { $_.Setting -like 'Overall MFA Registration Coverage*' }).State | Should -Be 'Disabled'
    }

    It 'reports SSPR coverage Enabled when at least 90 percent of SSPR-enabled users are registered' {
        $raw = @{
            value = @(
                1..9 | ForEach-Object { New-SAWTestUser -IsSsprEnabled $true -IsSsprRegistered $true }
            ) + @((New-SAWTestUser -IsSsprEnabled $true -IsSsprRegistered $false))
        }

        $result = $raw | ConvertTo-SAWNormalizedRegistration

        ($result | Where-Object { $_.Setting -like 'SSPR Registration Coverage*' }).State | Should -Be 'Enabled'
    }

    It 'reports SSPR coverage Disabled when below 90 percent' {
        $raw = @{
            value = @(
                1..5 | ForEach-Object { New-SAWTestUser -IsSsprEnabled $true -IsSsprRegistered $true }
            ) + @(1..5 | ForEach-Object { New-SAWTestUser -IsSsprEnabled $true -IsSsprRegistered $false })
        }

        $result = $raw | ConvertTo-SAWNormalizedRegistration

        ($result | Where-Object { $_.Setting -like 'SSPR Registration Coverage*' }).State | Should -Be 'Disabled'
    }

    It 'emits no SSPR fact at all when no users are SSPR-enabled' {
        $raw = @{
            value = @(
                (New-SAWTestUser -IsSsprEnabled $false),
                (New-SAWTestUser -IsSsprEnabled $false)
            )
        }

        $result = @($raw | ConvertTo-SAWNormalizedRegistration)

        ($result | Where-Object { $_.Setting -like 'SSPR Registration Coverage*' }) | Should -BeNullOrEmpty
    }

    It 'ignores users where SSPR is not enabled when computing SSPR coverage' {
        # 1 of 1 SSPR-enabled user is registered (100%), even though most users have SSPR off
        $raw = @{
            value = @(
                (New-SAWTestUser -IsSsprEnabled $true -IsSsprRegistered $true),
                (New-SAWTestUser -IsSsprEnabled $false -IsSsprRegistered $false),
                (New-SAWTestUser -IsSsprEnabled $false -IsSsprRegistered $false)
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedRegistration

        ($result | Where-Object { $_.Setting -like 'SSPR Registration Coverage*' }).State | Should -Be 'Enabled'
    }
}

Describe 'ConvertTo-SAWUserRegistrationRoster' {
    It 'buckets a user with a phishing-resistant method and no weak fallback as OK' {
        $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @('fido2'))) }

        $result = $raw | ConvertTo-SAWUserRegistrationRoster

        $result.Bucket | Should -Be 'OK'
    }

    It 'buckets a user with no phishing-resistant method as Hunt' {
        $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @('microsoftAuthenticatorPush'))) }

        $result = $raw | ConvertTo-SAWUserRegistrationRoster

        $result.Bucket | Should -Be 'Hunt'
    }

    It 'buckets a user with no methods registered at all as Hunt' {
        $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @())) }

        $result = $raw | ConvertTo-SAWUserRegistrationRoster

        $result.Bucket | Should -Be 'Hunt'
    }

    It 'buckets a user with a phishing-resistant method AND a phone-based fallback as Remove' {
        $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @('fido2', 'mobilePhone'))) }

        $result = $raw | ConvertTo-SAWUserRegistrationRoster

        $result.Bucket | Should -Be 'Remove'
    }

    It 'recognizes windowsHelloForBusiness and passKeyDeviceBound variants as phishing-resistant' {
        foreach ($method in @('windowsHelloForBusiness', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello')) {
            $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @($method))) }
            $result = $raw | ConvertTo-SAWUserRegistrationRoster
            $result.Bucket | Should -Be 'OK' -Because "method '$method' should count as phishing-resistant"
        }
    }

    It 'does not treat a phone-based-only user as Remove (no phishing-resistant method to begin with)' {
        $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @('mobilePhone'))) }

        $result = $raw | ConvertTo-SAWUserRegistrationRoster

        $result.Bucket | Should -Be 'Hunt'
    }

    Context 'guest users' {
        It 'buckets a guest with no phishing-resistant method as Guest (FIDO2 Not Supported), not Hunt' {
            $raw = @{ value = @((New-SAWTestUser -UserType 'guest' -MethodsRegistered @('microsoftAuthenticatorPush'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.Bucket | Should -Be 'Guest (FIDO2 Not Supported)'
            $result.IsGuest | Should -BeTrue
        }

        It 'buckets a guest with no methods registered at all as Guest (FIDO2 Not Supported), not Hunt' {
            $raw = @{ value = @((New-SAWTestUser -UserType 'guest' -MethodsRegistered @())) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.Bucket | Should -Be 'Guest (FIDO2 Not Supported)'
        }

        It 'still buckets a guest who already has a phishing-resistant method as OK' {
            $raw = @{ value = @((New-SAWTestUser -UserType 'guest' -MethodsRegistered @('fido2'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.Bucket | Should -Be 'OK'
        }

        It 'still buckets a guest with a phishing-resistant method AND a phone fallback as Remove' {
            $raw = @{ value = @((New-SAWTestUser -UserType 'guest' -MethodsRegistered @('fido2', 'mobilePhone'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.Bucket | Should -Be 'Remove'
        }

        It 'sets IsGuest false for a member user' {
            $raw = @{ value = @((New-SAWTestUser -UserType 'member' -MethodsRegistered @('fido2'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.IsGuest | Should -BeFalse
        }
    }

    Context 'possible external member detection' {
        It 'flags a member user whose UPN has the #EXT# shape as a possible external member' {
            $raw = @{ value = @((New-SAWTestUser -UserType 'member' -UserPrincipalName 'former.guest_partner.com#EXT#@contoso.onmicrosoft.com' -MethodsRegistered @('fido2'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.IsPossibleExternalMember | Should -BeTrue
        }

        It 'does not flag a genuine guest (userType guest) even with the #EXT# UPN shape - IsGuest already covers that case' {
            $raw = @{ value = @((New-SAWTestUser -UserType 'guest' -UserPrincipalName 'guest.partner_fabrikam.com#EXT#@contoso.onmicrosoft.com' -MethodsRegistered @('fido2'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.IsPossibleExternalMember | Should -BeFalse
        }

        It 'does not flag an ordinary internal member UPN' {
            $raw = @{ value = @((New-SAWTestUser -UserType 'member' -UserPrincipalName 'alice@contoso.com' -MethodsRegistered @('fido2'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.IsPossibleExternalMember | Should -BeFalse
        }

        It 'does not move a possible external member out of their normal bucket (heuristic flag only, not a bucket override)' {
            $raw = @{ value = @((New-SAWTestUser -UserType 'member' -UserPrincipalName 'former.guest_partner.com#EXT#@contoso.onmicrosoft.com' -MethodsRegistered @())) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.Bucket | Should -Be 'Hunt'
            $result.IsPossibleExternalMember | Should -BeTrue
        }
    }

    Context 'WHfB-only (not portable) detection' {
        It 'flags a user whose only phishing-resistant method is Windows Hello for Business' {
            $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @('windowsHelloForBusiness'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.IsWhfbOnly | Should -BeTrue
            $result.Bucket | Should -Be 'OK'
        }

        It 'does not flag a user who has WHfB alongside a portable method (FIDO2)' {
            $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @('windowsHelloForBusiness', 'fido2'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.IsWhfbOnly | Should -BeFalse
        }

        It 'does not flag a user with only a portable phishing-resistant method (no WHfB at all)' {
            $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @('fido2'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.IsWhfbOnly | Should -BeFalse
        }

        It 'does not flag a user with no phishing-resistant method at all' {
            $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @('microsoftAuthenticatorPush'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.IsWhfbOnly | Should -BeFalse
        }
    }

    Context 'SMS/Voice-only MFA detection (2027-02-01 milestone population)' {
        It 'flags a user whose only registered method is mobilePhone' {
            $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @('mobilePhone'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.IsSmsVoiceOnlyMfa | Should -BeTrue
        }

        It 'flags a user whose only registered method is officePhone' {
            $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @('officePhone'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.IsSmsVoiceOnlyMfa | Should -BeTrue
        }

        It 'does not flag a user with mobilePhone AND a stronger method registered - narrower than HasDowngradeRiskMethod' {
            $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @('mobilePhone', 'microsoftAuthenticatorPush'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.IsSmsVoiceOnlyMfa | Should -BeFalse
            $result.HasDowngradeRiskMethod | Should -BeTrue
        }

        It 'does not flag a user with mobilePhone AND a phishing-resistant method registered (Remove bucket)' {
            $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @('mobilePhone', 'fido2'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.IsSmsVoiceOnlyMfa | Should -BeFalse
            $result.Bucket | Should -Be 'Remove'
        }

        It 'does not flag a user with no methods registered at all - distinct from "relies on SMS/Voice"' {
            $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @())) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.IsSmsVoiceOnlyMfa | Should -BeFalse
        }

        It 'does not flag a user with only a non-phone, non-phishing-resistant method' {
            $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @('microsoftAuthenticatorPush'))) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.IsSmsVoiceOnlyMfa | Should -BeFalse
        }
    }

    Context 'System-Preferred Authentication pass-through' {
        It 'passes through systemPreferredAuthenticationMethod as-is' {
            $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @('fido2') -SystemPreferredAuthenticationMethod 'fido2')) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.SystemPreferredMethod | Should -Be 'fido2'
        }

        It 'passes through a null value when the system has no preference yet' {
            $raw = @{ value = @((New-SAWTestUser -MethodsRegistered @() -SystemPreferredAuthenticationMethod $null)) }

            $result = $raw | ConvertTo-SAWUserRegistrationRoster

            $result.SystemPreferredMethod | Should -BeNullOrEmpty
        }
    }

    It 'sorts Remove > Hunt > Guest (FIDO2 Not Supported) > OK, admins first within each bucket' {
        $raw = @{
            value = @(
                (New-SAWTestUser -UserPrincipalName 'ok.user@contoso.com' -IsAdmin $false -MethodsRegistered @('fido2')),
                (New-SAWTestUser -UserPrincipalName 'guest.user@contoso.com' -UserType 'guest' -MethodsRegistered @()),
                (New-SAWTestUser -UserPrincipalName 'hunt.admin@contoso.com' -IsAdmin $true -MethodsRegistered @()),
                (New-SAWTestUser -UserPrincipalName 'hunt.user@contoso.com' -IsAdmin $false -MethodsRegistered @()),
                (New-SAWTestUser -UserPrincipalName 'remove.user@contoso.com' -IsAdmin $false -MethodsRegistered @('fido2', 'mobilePhone')),
                (New-SAWTestUser -UserPrincipalName 'remove.admin@contoso.com' -IsAdmin $true -MethodsRegistered @('fido2', 'mobilePhone'))
            )
        }

        $result = @($raw | ConvertTo-SAWUserRegistrationRoster)

        $result[0].UserPrincipalName | Should -Be 'remove.admin@contoso.com'
        $result[1].UserPrincipalName | Should -Be 'remove.user@contoso.com'
        $result[2].UserPrincipalName | Should -Be 'hunt.admin@contoso.com'
        $result[3].UserPrincipalName | Should -Be 'hunt.user@contoso.com'
        $result[4].UserPrincipalName | Should -Be 'guest.user@contoso.com'
        $result[5].UserPrincipalName | Should -Be 'ok.user@contoso.com'
    }
}
