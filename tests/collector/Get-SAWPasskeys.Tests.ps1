BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWPasskeys.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWNormalizedPasskeys.ps1"

    function Get-MgContext { }
    function Invoke-MgGraphRequest { param($Method, $Uri) }
}

Describe 'Get-SAWPasskeys' {
    Context '-UseSampleData' {
        It 'returns the bundled sample data' {
            $result = Get-SAWPasskeys -UseSampleData
            $result | Should -Not -BeNullOrEmpty
            $result.id | Should -Be 'Fido2'
        }

        It 'throws if the sample data file does not exist' {
            { Get-SAWPasskeys -UseSampleData -SampleDataPath 'C:\does\not\exist.json' } | Should -Throw
        }
    }

    Context 'live Graph calls' {
        It 'throws when not connected to Microsoft Graph' {
            Mock Get-MgContext { $null }
            { Get-SAWPasskeys } | Should -Throw
        }

        It 'calls the FIDO2-specific authentication method configuration endpoint' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest { @{ id = 'Fido2'; state = 'enabled' } }

            Get-SAWPasskeys | Out-Null

            Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                $Method -eq 'GET' -and $Uri -eq 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Fido2'
            }
        }
    }
}

Describe 'ConvertTo-SAWNormalizedPasskeys' {
    It 'emits no facts at all when FIDO2 is disabled tenant-wide' {
        $raw = @{ state = 'disabled'; isAttestationEnforced = $true; keyRestrictions = @{ isEnforced = $true } }

        $result = @($raw | ConvertTo-SAWNormalizedPasskeys)

        $result.Count | Should -Be 0
    }

    It 'reports attestation and key restrictions when FIDO2 is enabled and both are configured' {
        $raw = @{ state = 'enabled'; isAttestationEnforced = $true; keyRestrictions = @{ isEnforced = $true } }

        $result = $raw | ConvertTo-SAWNormalizedPasskeys

        $result.Count | Should -Be 2
        ($result | Where-Object { $_.Setting -eq 'FIDO2 Attestation Enforced' }).State | Should -Be 'Enabled'
        ($result | Where-Object { $_.Setting -eq 'FIDO2 Key Restrictions Enforced' }).State | Should -Be 'Enabled'
    }

    It 'reports gaps when FIDO2 is enabled but attestation and key restrictions are off' {
        $raw = @{ state = 'enabled'; isAttestationEnforced = $false; keyRestrictions = @{ isEnforced = $false } }

        $result = $raw | ConvertTo-SAWNormalizedPasskeys

        ($result | Where-Object { $_.Setting -eq 'FIDO2 Attestation Enforced' }).State | Should -Be 'Disabled'
        ($result | Where-Object { $_.Setting -eq 'FIDO2 Key Restrictions Enforced' }).State | Should -Be 'Disabled'
    }
}
