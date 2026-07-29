BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWTenantProfile.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWTenantProfile.ps1"

    function Get-MgContext { }
    function Invoke-MgGraphRequest { param($Method, $Uri) }
}

Describe 'Get-SAWTenantProfile' {
    Context '-UseSampleData' {
        It 'returns the bundled sample data' {
            $result = Get-SAWTenantProfile -UseSampleData
            $result.value | Should -Not -BeNullOrEmpty
        }

        It 'throws if the sample data file does not exist' {
            { Get-SAWTenantProfile -UseSampleData -SampleDataPath 'C:\does\not\exist.json' } | Should -Throw
        }
    }

    Context 'live Graph calls' {
        It 'throws when not connected to Microsoft Graph' {
            Mock Get-MgContext { $null }
            { Get-SAWTenantProfile } | Should -Throw
        }

        It 'calls the organization endpoint' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest { @{ value = @() } }

            Get-SAWTenantProfile | Out-Null

            Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                $Method -eq 'GET' -and $Uri -eq 'https://graph.microsoft.com/v1.0/organization'
            }
        }
    }
}

Describe 'ConvertTo-SAWTenantProfile' {
    It 'detects Hybrid when onPremisesSyncEnabled is true' {
        $raw = @{ value = @(@{ displayName = 'Contoso'; onPremisesSyncEnabled = $true; onPremisesLastSyncDateTime = '2026-07-28T03:15:00Z' }) }

        $result = $raw | ConvertTo-SAWTenantProfile

        $result.HybridState | Should -Be 'Hybrid'
        $result.RecommendedBaseline | Should -Be 'hybrid-ad-passwords-required'
    }

    It 'detects FormerlyHybrid when onPremisesSyncEnabled is explicitly false' {
        $raw = @{ value = @(@{ displayName = 'Contoso'; onPremisesSyncEnabled = $false }) }

        $result = $raw | ConvertTo-SAWTenantProfile

        $result.HybridState | Should -Be 'FormerlyHybrid'
        $result.RecommendedBaseline | Should -Be 'hybrid-ad-passwords-required'
    }

    It 'detects CloudNative when onPremisesSyncEnabled is null' {
        $raw = @{ value = @(@{ displayName = 'Contoso'; onPremisesSyncEnabled = $null }) }

        $result = $raw | ConvertTo-SAWTenantProfile

        $result.HybridState | Should -Be 'CloudNative'
        $result.RecommendedBaseline | Should -Be 'cloud-native-passwordless'
    }

    It 'detects CloudNative when the organization object has no onPremisesSyncEnabled property at all' {
        $raw = @{ value = @(@{ displayName = 'Contoso' }) }

        $result = $raw | ConvertTo-SAWTenantProfile

        $result.HybridState | Should -Be 'CloudNative'
    }

    It 'detects CloudNative when there is no organization entry at all' {
        $raw = @{ value = @() }

        $result = $raw | ConvertTo-SAWTenantProfile

        $result.HybridState | Should -Be 'CloudNative'
        $result.DisplayName | Should -BeNullOrEmpty
    }

    It 'uses only the first organization entry when more than one is present' {
        $raw = @{
            value = @(
                @{ displayName = 'First'; onPremisesSyncEnabled = $true },
                @{ displayName = 'Second'; onPremisesSyncEnabled = $false }
            )
        }

        $result = $raw | ConvertTo-SAWTenantProfile

        $result.DisplayName | Should -Be 'First'
        $result.HybridState | Should -Be 'Hybrid'
    }
}
