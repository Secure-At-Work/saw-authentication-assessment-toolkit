BeforeAll {
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWMethodUsageRoster.ps1"

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

    function New-SAWTestSignIn {
        param(
            [string]$UserPrincipalName = 'user@contoso.com',
            [object[]]$AuthenticationDetails = @()
        )
        return @{
            userPrincipalName    = $UserPrincipalName
            authenticationDetails = $AuthenticationDetails
        }
    }
}

Describe 'ConvertTo-SAWMethodUsageRoster' {
    It 'flags a registered method with no matching successful sign-in as unused' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'fido2, microsoftAuthenticatorPush'))
        $signIns = @{ value = @((New-SAWTestSignIn -AuthenticationDetails @(@{ authenticationMethod = 'Mobile app notification'; succeeded = $true }))) }

        $result = ConvertTo-SAWMethodUsageRoster -Roster $roster -SignInLogs $signIns

        $result[0].UnusedRegisteredMethods | Should -Be 'fido2'
        $result[0].HasUnusedRegisteredMethod | Should -BeTrue
    }

    It 'does not flag a registered method that was used successfully' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'mobilePhone'))
        $signIns = @{ value = @((New-SAWTestSignIn -AuthenticationDetails @(@{ authenticationMethod = 'Text message'; succeeded = $true }))) }

        $result = ConvertTo-SAWMethodUsageRoster -Roster $roster -SignInLogs $signIns

        $result[0].UnusedRegisteredMethods | Should -Be ''
        $result[0].HasUnusedRegisteredMethod | Should -BeFalse
    }

    It 'flags every registered (mappable) method as unused when the user has no sign-ins at all' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'windowsHelloForBusiness'))
        $signIns = @{ value = @() }

        $result = ConvertTo-SAWMethodUsageRoster -Roster $roster -SignInLogs $signIns

        $result[0].UnusedRegisteredMethods | Should -Be 'windowsHelloForBusiness'
        $result[0].HasUnusedRegisteredMethod | Should -BeTrue
    }

    It 'does not count a failed sign-in step as usage' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'fido2'))
        $signIns = @{ value = @((New-SAWTestSignIn -AuthenticationDetails @(@{ authenticationMethod = 'FIDO2 security key'; succeeded = $false }))) }

        $result = ConvertTo-SAWMethodUsageRoster -Roster $roster -SignInLogs $signIns

        $result[0].HasUnusedRegisteredMethod | Should -BeTrue
    }

    It 'skips a registered method type with no confident name mapping (e.g. passkey variants) rather than guessing' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'passKeyDeviceBound'))
        $signIns = @{ value = @() }

        $result = ConvertTo-SAWMethodUsageRoster -Roster $roster -SignInLogs $signIns

        $result[0].UnusedRegisteredMethods | Should -Be ''
        $result[0].HasUnusedRegisteredMethod | Should -BeFalse
    }

    It 'matches sign-ins to the right user by UPN (case-insensitively) and does not cross-contaminate' {
        $roster = @(
            (New-SAWTestRosterEntry -UserPrincipalName 'Alice@Contoso.com' -MethodsRegistered 'fido2'),
            (New-SAWTestRosterEntry -UserPrincipalName 'bob@contoso.com' -MethodsRegistered 'fido2')
        )
        $signIns = @{ value = @((New-SAWTestSignIn -UserPrincipalName 'alice@contoso.com' -AuthenticationDetails @(@{ authenticationMethod = 'FIDO2 security key'; succeeded = $true }))) }

        # Note: ConvertTo-SAWMethodUsageRoster.ps1 returns via `, @($result)` (comma-protected,
        # same idiom as Get-SAWTimelineMilestones.ps1 etc.) so its output is already exactly one
        # array - do NOT wrap the call site in @(...) too, that double-nests it into a 1-element
        # array containing the real array, which silently breaks Where-Object's per-item
        # filtering (member-access auto-enumeration makes every filter look like it matches).
        $result = ConvertTo-SAWMethodUsageRoster -Roster $roster -SignInLogs $signIns

        ($result | Where-Object { $_.UserPrincipalName -eq 'Alice@Contoso.com' }).HasUnusedRegisteredMethod | Should -BeFalse
        ($result | Where-Object { $_.UserPrincipalName -eq 'bob@contoso.com' }).HasUnusedRegisteredMethod | Should -BeTrue
    }

    It 'preserves existing roster fields untouched (e.g. Bucket, IsAdmin) alongside the new ones' {
        $roster = @(@{ UserPrincipalName = 'user@contoso.com'; DisplayName = 'Test'; MethodsRegistered = 'fido2'; Bucket = 'OK'; IsAdmin = $true })
        $signIns = @{ value = @() }

        $result = ConvertTo-SAWMethodUsageRoster -Roster $roster -SignInLogs $signIns

        $result[0].Bucket | Should -Be 'OK'
        $result[0].IsAdmin | Should -BeTrue
    }

    It 'always returns a proper array, even with exactly one roster entry' {
        $roster = @((New-SAWTestRosterEntry -MethodsRegistered 'fido2'))
        $signIns = @{ value = @() }

        $result = ConvertTo-SAWMethodUsageRoster -Roster $roster -SignInLogs $signIns

        $result.GetType().IsArray | Should -BeTrue
        $result.Count | Should -Be 1
    }

    It 'handles an empty roster without error' {
        $result = ConvertTo-SAWMethodUsageRoster -Roster @() -SignInLogs @{ value = @() }

        $result.Count | Should -Be 0
    }
}
