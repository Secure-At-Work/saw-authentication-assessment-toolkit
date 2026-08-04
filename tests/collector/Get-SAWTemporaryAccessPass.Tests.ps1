BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWTemporaryAccessPass.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWNormalizedTemporaryAccessPass.ps1"

    . "$PSScriptRoot/../../src/Invoke-SAWGraphRequest.ps1"

    function Get-MgContext { }
    function Invoke-MgGraphRequest { param($Method, $Uri) }
}

Describe 'Get-SAWTemporaryAccessPass' {
    Context '-UseSampleData' {
        It 'returns the bundled sample data' {
            $result = Get-SAWTemporaryAccessPass -UseSampleData
            $result | Should -Not -BeNullOrEmpty
            $result.id | Should -Be 'TemporaryAccessPass'
        }

        It 'throws if the sample data file does not exist' {
            { Get-SAWTemporaryAccessPass -UseSampleData -SampleDataPath 'C:\does\not\exist.json' } | Should -Throw
        }
    }

    Context 'live Graph calls' {
        It 'throws when not connected to Microsoft Graph' {
            Mock Get-MgContext { $null }
            { Get-SAWTemporaryAccessPass } | Should -Throw
        }

        It 'calls the TAP-specific authentication method configuration endpoint' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest { @{ id = 'TemporaryAccessPass'; state = 'enabled' } }

            Get-SAWTemporaryAccessPass | Out-Null

            Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                $Method -eq 'GET' -and $Uri -eq 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass'
            }
        }
    }
}

Describe 'ConvertTo-SAWNormalizedTemporaryAccessPass' {
    It 'reports one-time use enforced when isUsableOnce is true' {
        $raw = @{ isUsableOnce = $true; maximumLifetimeInMinutes = 60 }

        $result = $raw | ConvertTo-SAWNormalizedTemporaryAccessPass

        ($result | Where-Object { $_.Setting -eq 'One-Time Use Enforced' }).State | Should -Be 'Enabled'
    }

    It 'reports one-time use not enforced when isUsableOnce is false' {
        $raw = @{ isUsableOnce = $false; maximumLifetimeInMinutes = 60 }

        $result = $raw | ConvertTo-SAWNormalizedTemporaryAccessPass

        ($result | Where-Object { $_.Setting -eq 'One-Time Use Enforced' }).State | Should -Be 'Disabled'
    }

    It 'reports lifetime within 8 hours when maximumLifetimeInMinutes is exactly 480' {
        $raw = @{ isUsableOnce = $true; maximumLifetimeInMinutes = 480 }

        $result = $raw | ConvertTo-SAWNormalizedTemporaryAccessPass

        ($result | Where-Object { $_.Setting -eq 'Maximum Lifetime Within 8 Hours' }).State | Should -Be 'Enabled'
    }

    It 'reports lifetime not within 8 hours when maximumLifetimeInMinutes exceeds 480' {
        $raw = @{ isUsableOnce = $true; maximumLifetimeInMinutes = 1440 }

        $result = $raw | ConvertTo-SAWNormalizedTemporaryAccessPass

        ($result | Where-Object { $_.Setting -eq 'Maximum Lifetime Within 8 Hours' }).State | Should -Be 'Disabled'
    }

    It 'reports lifetime not within 8 hours when maximumLifetimeInMinutes is missing' {
        $raw = @{ isUsableOnce = $true }

        $result = $raw | ConvertTo-SAWNormalizedTemporaryAccessPass

        ($result | Where-Object { $_.Setting -eq 'Maximum Lifetime Within 8 Hours' }).State | Should -Be 'Disabled'
    }
}
