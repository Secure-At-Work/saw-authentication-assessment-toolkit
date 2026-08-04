BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWAuthenticationStrengths.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWNormalizedAuthenticationStrengths.ps1"

    . "$PSScriptRoot/../../src/Invoke-SAWGraphRequest.ps1"

    function Get-MgContext { }
    function Invoke-MgGraphRequest { param($Method, $Uri) }
}

Describe 'Get-SAWAuthenticationStrengths' {
    Context '-UseSampleData' {
        It 'returns the bundled sample data' {
            $result = Get-SAWAuthenticationStrengths -UseSampleData
            $result.value | Should -Not -BeNullOrEmpty
        }

        It 'throws if the sample data file does not exist' {
            { Get-SAWAuthenticationStrengths -UseSampleData -SampleDataPath 'C:\does\not\exist.json' } | Should -Throw
        }
    }

    Context 'live Graph calls' {
        It 'throws when not connected to Microsoft Graph' {
            Mock Get-MgContext { $null }
            { Get-SAWAuthenticationStrengths } | Should -Throw
        }

        It 'calls the authentication strength policies endpoint' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest { @{ value = @() } }

            Get-SAWAuthenticationStrengths | Out-Null

            Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                $Method -eq 'GET' -and $Uri -eq 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies'
            }
        }

        It 'follows @odata.nextLink to collect every page' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            $script:pageNumber = 0
            Mock Invoke-MgGraphRequest {
                $script:pageNumber++
                if ($script:pageNumber -eq 1) {
                    return @{
                        value             = @(@{ id = 'page1-strength' })
                        '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies?$skiptoken=abc'
                    }
                }
                return @{ value = @(@{ id = 'page2-strength' }) }
            }

            $result = Get-SAWAuthenticationStrengths

            $result.value.Count | Should -Be 2
            Should -Invoke Invoke-MgGraphRequest -Times 2
        }
    }
}

Describe 'ConvertTo-SAWNormalizedAuthenticationStrengths' {
    It 'reports available when a policy allows only phishing-resistant methods' {
        $raw = @{
            value = @(
                @{ displayName = 'Phishing-resistant MFA'; allowedCombinations = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor') }
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedAuthenticationStrengths

        $result.State | Should -Be 'Enabled'
    }

    It 'does not count a policy that also allows weaker combinations' {
        $raw = @{
            value = @(
                @{ displayName = 'Multifactor authentication'; allowedCombinations = @('password,sms', 'fido2') }
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedAuthenticationStrengths

        $result.State | Should -Be 'Disabled'
    }

    It 'reports disabled when there are no strength policies at all' {
        $raw = @{ value = @() }

        $result = $raw | ConvertTo-SAWNormalizedAuthenticationStrengths

        $result.State | Should -Be 'Disabled'
    }

    It 'ignores a policy with no allowedCombinations' {
        $raw = @{
            value = @(
                @{ displayName = 'Empty policy'; allowedCombinations = @() },
                @{ displayName = 'Phishing-resistant MFA'; allowedCombinations = @('fido2') }
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedAuthenticationStrengths

        $result.State | Should -Be 'Enabled'
    }
}
