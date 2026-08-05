BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWAuthorizationPolicy.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWNormalizedAuthorizationPolicy.ps1"

    . "$PSScriptRoot/../../src/Invoke-SAWGraphRequest.ps1"

    function Get-MgContext { }
    function Invoke-MgGraphRequest { param($Method, $Uri) }

    function New-SAWTestUser {
        param(
            [bool]$IsAdmin = $false,
            [bool]$IsSsprEnabled = $false,
            [string]$UserPrincipalName = 'user@contoso.com'
        )
        return @{ isAdmin = $IsAdmin; isSsprEnabled = $IsSsprEnabled; userPrincipalName = $UserPrincipalName }
    }
}

Describe 'Get-SAWAuthorizationPolicy' {
    Context '-UseSampleData' {
        It 'returns the bundled sample data' {
            $result = Get-SAWAuthorizationPolicy -UseSampleData
            $result | Should -Not -BeNullOrEmpty
            $result.id | Should -Be 'authorizationPolicy'
        }

        It 'throws if the sample data file does not exist' {
            { Get-SAWAuthorizationPolicy -UseSampleData -SampleDataPath 'C:\does\not\exist.json' } | Should -Throw
        }
    }

    Context 'live Graph calls' {
        It 'throws when not connected to Microsoft Graph' {
            Mock Get-MgContext { $null }
            { Get-SAWAuthorizationPolicy } | Should -Throw
        }

        It 'calls the authorization policy endpoint' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest { @{ id = 'authorizationPolicy'; allowedToUseSSPR = $true } }

            Get-SAWAuthorizationPolicy | Out-Null

            Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                $Method -eq 'GET' -and $Uri -eq 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
            }
        }
    }
}

Describe 'ConvertTo-SAWNormalizedAuthorizationPolicy' {
    It 'emits nothing when allowedToUseSSPR is true (admin SSPR enabled via the default policy)' {
        $policy = @{ allowedToUseSSPR = $true }
        $registration = @{ value = @((New-SAWTestUser -IsAdmin $true -IsSsprEnabled $true)) }

        $result = @(ConvertTo-SAWNormalizedAuthorizationPolicy -AuthorizationPolicy $policy -RegistrationRaw $registration)

        $result.Count | Should -Be 0
    }

    It 'emits nothing when allowedToUseSSPR is absent (defaults to enabled)' {
        $policy = @{}
        $registration = @{ value = @((New-SAWTestUser -IsAdmin $true -IsSsprEnabled $true)) }

        $result = @(ConvertTo-SAWNormalizedAuthorizationPolicy -AuthorizationPolicy $policy -RegistrationRaw $registration)

        $result.Count | Should -Be 0
    }

    It 'reports Enabled (no problem) when allowedToUseSSPR is false and no admin still shows isSsprEnabled' {
        $policy = @{ allowedToUseSSPR = $false }
        $registration = @{ value = @(
            (New-SAWTestUser -IsAdmin $true -IsSsprEnabled $false -UserPrincipalName 'admin@contoso.com'),
            (New-SAWTestUser -IsAdmin $false -IsSsprEnabled $true -UserPrincipalName 'user@contoso.com')
        ) }

        $result = @(ConvertTo-SAWNormalizedAuthorizationPolicy -AuthorizationPolicy $policy -RegistrationRaw $registration)

        $result.Count | Should -Be 1
        $result[0].State | Should -Be 'Enabled'
    }

    It 'reports Disabled (the documented broken-UX trap) when allowedToUseSSPR is false but an admin still shows isSsprEnabled' {
        $policy = @{ allowedToUseSSPR = $false }
        $registration = @{ value = @((New-SAWTestUser -IsAdmin $true -IsSsprEnabled $true -UserPrincipalName 'admin@contoso.com')) }

        $result = @(ConvertTo-SAWNormalizedAuthorizationPolicy -AuthorizationPolicy $policy -RegistrationRaw $registration)

        $result.Count | Should -Be 1
        $result[0].State | Should -Be 'Disabled'
    }

    It 'ignores a non-admin user with isSsprEnabled=true - only admins matter for this check' {
        $policy = @{ allowedToUseSSPR = $false }
        $registration = @{ value = @((New-SAWTestUser -IsAdmin $false -IsSsprEnabled $true -UserPrincipalName 'user@contoso.com')) }

        $result = @(ConvertTo-SAWNormalizedAuthorizationPolicy -AuthorizationPolicy $policy -RegistrationRaw $registration)

        $result[0].State | Should -Be 'Enabled'
    }

    It 'sets Category and Setting correctly when emitted' {
        $policy = @{ allowedToUseSSPR = $false }
        $registration = @{ value = @() }

        $result = @(ConvertTo-SAWNormalizedAuthorizationPolicy -AuthorizationPolicy $policy -RegistrationRaw $registration)

        $result[0].Category | Should -Be 'Registration'
        $result[0].Setting | Should -Be 'Admins Excluded From User SSPR Policy When Admin SSPR Is Disabled'
    }
}
