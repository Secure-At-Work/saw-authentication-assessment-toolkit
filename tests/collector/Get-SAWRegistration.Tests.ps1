BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWRegistration.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWNormalizedRegistration.ps1"

    function Get-MgContext { }
    function Invoke-MgGraphRequest { param($Method, $Uri) }

    function New-SAWTestUser {
        param(
            [bool]$IsAdmin = $false,
            [bool]$IsMfaRegistered = $true
        )
        return @{ isAdmin = $IsAdmin; isMfaRegistered = $IsMfaRegistered }
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
}
