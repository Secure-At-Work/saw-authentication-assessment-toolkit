BeforeAll {
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWPolicyDisabledMethodRoster.ps1"

    function New-SAWTestRosterEntry {
        param(
            [string]$UserPrincipalName = 'user@contoso.com',
            [string]$DisplayName = 'Test User',
            [string]$MethodsRegistered = ''
        )
        return @{
            UserPrincipalName = $UserPrincipalName
            DisplayName       = $DisplayName
            MethodsRegistered = $MethodsRegistered
        }
    }

    function New-SAWTestPolicy {
        param([hashtable]$States = @{})
        $configs = foreach ($id in $States.Keys) { @{ id = $id; state = $States[$id] } }
        return @{ authenticationMethodConfigurations = @($configs) }
    }
}

Describe 'ConvertTo-SAWPolicyDisabledMethodRoster' {
    It 'flags a registered method whose policy toggle is Disabled' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'fido2'))
        $policy = New-SAWTestPolicy -States @{ Fido2 = 'disabled' }

        $result = ConvertTo-SAWPolicyDisabledMethodRoster -Roster $roster -AuthenticationMethodsPolicy $policy

        $result[0].PolicyDisabledMethods | Should -Be 'fido2'
        $result[0].HasPolicyDisabledMethod | Should -BeTrue
    }

    It 'does not flag a registered method whose policy toggle is Enabled' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'fido2'))
        $policy = New-SAWTestPolicy -States @{ Fido2 = 'enabled' }

        $result = ConvertTo-SAWPolicyDisabledMethodRoster -Roster $roster -AuthenticationMethodsPolicy $policy

        $result[0].PolicyDisabledMethods | Should -Be ''
        $result[0].HasPolicyDisabledMethod | Should -BeFalse
    }

    It 'flags a registered mobilePhone if EITHER Sms or Voice is disabled (per decided scope, not only when both are)' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'mobilePhone'))
        $policy = New-SAWTestPolicy -States @{ Sms = 'disabled'; Voice = 'enabled' }

        $result = ConvertTo-SAWPolicyDisabledMethodRoster -Roster $roster -AuthenticationMethodsPolicy $policy

        $result[0].HasPolicyDisabledMethod | Should -BeTrue
    }

    It 'does not flag mobilePhone when both Sms and Voice are enabled' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'mobilePhone'))
        $policy = New-SAWTestPolicy -States @{ Sms = 'enabled'; Voice = 'enabled' }

        $result = ConvertTo-SAWPolicyDisabledMethodRoster -Roster $roster -AuthenticationMethodsPolicy $policy

        $result[0].HasPolicyDisabledMethod | Should -BeFalse
    }

    It 'maps officePhone to Voice only, not Sms' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'officePhone'))
        $policy = New-SAWTestPolicy -States @{ Sms = 'disabled'; Voice = 'enabled' }

        $result = ConvertTo-SAWPolicyDisabledMethodRoster -Roster $roster -AuthenticationMethodsPolicy $policy

        # Sms being disabled is irrelevant to officePhone (voice-only) - only Voice matters.
        $result[0].HasPolicyDisabledMethod | Should -BeFalse
    }

    It 'never flags windowsHelloForBusiness - no tenant policy toggle exists to check it against' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'windowsHelloForBusiness'))
        $policy = New-SAWTestPolicy -States @{ Fido2 = 'disabled'; Sms = 'disabled'; Voice = 'disabled' }

        $result = ConvertTo-SAWPolicyDisabledMethodRoster -Roster $roster -AuthenticationMethodsPolicy $policy

        $result[0].HasPolicyDisabledMethod | Should -BeFalse
    }

    It 'skips an unmapped method type (e.g. passkey variants) rather than guessing' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'passKeyDeviceBound'))
        $policy = New-SAWTestPolicy -States @{ Fido2 = 'disabled' }

        $result = ConvertTo-SAWPolicyDisabledMethodRoster -Roster $roster -AuthenticationMethodsPolicy $policy

        $result[0].HasPolicyDisabledMethod | Should -BeFalse
    }

    It 'lists multiple disabled methods comma-joined' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'fido2, temporaryAccessPass'))
        $policy = New-SAWTestPolicy -States @{ Fido2 = 'disabled'; TemporaryAccessPass = 'disabled' }

        $result = ConvertTo-SAWPolicyDisabledMethodRoster -Roster $roster -AuthenticationMethodsPolicy $policy

        $result[0].PolicyDisabledMethods | Should -Be 'fido2, temporaryAccessPass'
    }

    It 'preserves existing roster fields untouched alongside the new ones' {
        $roster = @(@{ UserPrincipalName = 'user@contoso.com'; DisplayName = 'Test'; MethodsRegistered = 'fido2'; Bucket = 'OK'; IsAdmin = $true })
        $policy = New-SAWTestPolicy -States @{ Fido2 = 'enabled' }

        $result = ConvertTo-SAWPolicyDisabledMethodRoster -Roster $roster -AuthenticationMethodsPolicy $policy

        $result[0].Bucket | Should -Be 'OK'
        $result[0].IsAdmin | Should -BeTrue
    }

    It 'always returns a proper array, even with exactly one roster entry' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'fido2'))
        $policy = New-SAWTestPolicy -States @{ Fido2 = 'enabled' }

        $result = ConvertTo-SAWPolicyDisabledMethodRoster -Roster $roster -AuthenticationMethodsPolicy $policy

        $result.GetType().IsArray | Should -BeTrue
        $result.Count | Should -Be 1
    }

    It 'handles an empty roster without error' {
        $policy = New-SAWTestPolicy -States @{ Fido2 = 'enabled' }

        $result = ConvertTo-SAWPolicyDisabledMethodRoster -Roster @() -AuthenticationMethodsPolicy $policy

        $result.Count | Should -Be 0
    }
}
