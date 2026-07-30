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

        It 'throws if the Domain Services group sample data file does not exist' {
            { Get-SAWTenantProfile -UseSampleData -DomainServicesGroupSampleDataPath 'C:\does\not\exist.json' } | Should -Throw
        }

        It 'merges an empty aadDcAdministratorsGroups array from the bundled (not-detected) fixture' {
            $result = Get-SAWTenantProfile -UseSampleData

            @($result.aadDcAdministratorsGroups).Count | Should -Be 0
        }

        It 'merges a populated aadDcAdministratorsGroups array when the group sample data has an entry' {
            $groupPath = Join-Path $TestDrive 'dc-admins-detected.json'
            '{ "value": [{ "id": "g1", "displayName": "AAD DC Administrators" }] }' | Set-Content -Path $groupPath

            $result = Get-SAWTenantProfile -UseSampleData -DomainServicesGroupSampleDataPath $groupPath

            @($result.aadDcAdministratorsGroups).Count | Should -Be 1
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

        It 'also calls the AAD DC Administrators groups endpoint and merges the result' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest {
                param($Method, $Uri)
                if ($Uri -like '*groups*') { return @{ value = @(@{ id = 'g1'; displayName = 'AAD DC Administrators' }) } }
                return @{ value = @(@{ id = 'aaaa'; displayName = 'Contoso' }) }
            }

            $result = Get-SAWTenantProfile

            Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                $Method -eq 'GET' -and $Uri -like "*/groups?`$filter=displayName eq 'AAD DC Administrators'"
            }
            @($result.aadDcAdministratorsGroups).Count | Should -Be 1
        }
    }
}

Describe 'ConvertTo-SAWTenantProfile' {
    It 'detects Hybrid when onPremisesSyncEnabled is true' {
        $raw = @{ value = @(@{ id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'; displayName = 'Contoso'; onPremisesSyncEnabled = $true; onPremisesLastSyncDateTime = '2026-07-28T03:15:00Z' }) }

        $result = $raw | ConvertTo-SAWTenantProfile

        $result.HybridState | Should -Be 'Hybrid'
        $result.RecommendedBaseline | Should -Be 'hybrid-ad-passwords-required'
        $result.TenantId | Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        $result.Slug | Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
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
        $result.TenantId | Should -BeNullOrEmpty
        $result.Slug | Should -Be 'unknown-tenant'
    }

    It 'derives a filesystem-safe Slug from DisplayName when TenantId is missing' {
        $raw = @{ value = @(@{ displayName = 'Contoso Ltd! (EU)' }) }

        $result = $raw | ConvertTo-SAWTenantProfile

        $result.Slug | Should -Be 'contoso-ltd-eu'
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

    Context 'Entra Domain Services proxy signal (DomainServicesDetected)' {
        It 'reports true when aadDcAdministratorsGroups has at least one entry' {
            $raw = @{
                value                     = @(@{ displayName = 'Contoso' })
                aadDcAdministratorsGroups = @(@{ id = 'g1'; displayName = 'AAD DC Administrators' })
            }

            $result = $raw | ConvertTo-SAWTenantProfile

            $result.DomainServicesDetected | Should -BeTrue
        }

        It 'reports false when aadDcAdministratorsGroups is an empty array' {
            $raw = @{
                value                     = @(@{ displayName = 'Contoso' })
                aadDcAdministratorsGroups = @()
            }

            $result = $raw | ConvertTo-SAWTenantProfile

            $result.DomainServicesDetected | Should -BeFalse
        }

        It 'reports false when aadDcAdministratorsGroups is absent entirely (no crash)' {
            $raw = @{ value = @(@{ displayName = 'Contoso' }) }

            $result = $raw | ConvertTo-SAWTenantProfile

            $result.DomainServicesDetected | Should -BeFalse
        }
    }
}
