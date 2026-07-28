BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWAuthenticationMethods.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWNormalizedAuthenticationMethods.ps1"

    # Stub commands from Microsoft.Graph.Authentication so Mock has something to intercept
    # even when that module isn't installed in the test environment.
    function Get-MgContext { }
    function Invoke-MgGraphRequest { param($Method, $Uri) }
}

Describe 'Get-SAWAuthenticationMethods' {
    Context '-UseSampleData' {
        It 'returns the bundled sample data' {
            $result = Get-SAWAuthenticationMethods -UseSampleData
            $result | Should -Not -BeNullOrEmpty
            $result.authenticationMethodConfigurations | Should -Not -BeNullOrEmpty
        }

        It 'throws if the sample data file does not exist' {
            { Get-SAWAuthenticationMethods -UseSampleData -SampleDataPath 'C:\does\not\exist.json' } | Should -Throw
        }
    }

    Context 'live Graph calls' {
        It 'throws when not connected to Microsoft Graph' {
            Mock Get-MgContext { $null }
            { Get-SAWAuthenticationMethods } | Should -Throw
        }

        It 'calls the tenant-wide authenticationMethodsPolicy endpoint' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest { @{ authenticationMethodConfigurations = @() } }

            Get-SAWAuthenticationMethods | Out-Null

            Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                $Method -eq 'GET' -and $Uri -eq 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
            }
        }
    }
}

Describe 'ConvertTo-SAWNormalizedAuthenticationMethods' {
    It 'maps a known method id to its display name and title-cases the state' {
        $raw = @{
            authenticationMethodConfigurations = @(
                @{ id = 'MicrosoftAuthenticator'; state = 'enabled' }
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

        $result.Count | Should -Be 1
        $result[0].Category | Should -Be 'Authentication Methods'
        $result[0].Setting | Should -Be 'Microsoft Authenticator'
        $result[0].State | Should -Be 'Enabled'
    }

    It 'falls back to the raw id when no display name mapping exists' {
        $raw = @{
            authenticationMethodConfigurations = @(
                @{ id = 'SomeFutureMethod'; state = 'disabled' }
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

        $result[0].Setting | Should -Be 'SomeFutureMethod'
        $result[0].State | Should -Be 'Disabled'
    }

    It 'emits one normalized entry per configured method' {
        $raw = @{
            authenticationMethodConfigurations = @(
                @{ id = 'Sms'; state = 'enabled' },
                @{ id = 'Voice'; state = 'enabled' },
                @{ id = 'Fido2'; state = 'disabled' }
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

        $result.Count | Should -Be 3
        ($result | Where-Object { $_.Setting -eq 'FIDO2' }).State | Should -Be 'Disabled'
    }
}
