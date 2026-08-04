BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWPasskeys.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWNormalizedPasskeys.ps1"

    . "$PSScriptRoot/../../src/Invoke-SAWGraphRequest.ps1"

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

        $result = @($raw | ConvertTo-SAWNormalizedPasskeys)

        $result.Count | Should -Be 3
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

Describe 'ConvertTo-SAWNormalizedPasskeys - synced passkeys (PASS003)' {
    It 'allows synced passkeys by default when no key restrictions are enforced' {
        $raw = @{ state = 'enabled'; isAttestationEnforced = $true; keyRestrictions = @{ isEnforced = $false } }

        $result = $raw | ConvertTo-SAWNormalizedPasskeys

        ($result | Where-Object { $_.Setting -eq 'Synced Passkeys Currently Allowed' }).State | Should -Be 'Enabled'
    }

    It 'allows synced passkeys when an allow-list includes a known synced provider AAGUID' {
        $raw = @{
            state                 = 'enabled'
            isAttestationEnforced = $true
            keyRestrictions       = @{
                isEnforced      = $true
                enforcementType = 'allow'
                aaGuids          = @('ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4') # Google Password Manager
            }
        }

        $result = $raw | ConvertTo-SAWNormalizedPasskeys

        ($result | Where-Object { $_.Setting -eq 'Synced Passkeys Currently Allowed' }).State | Should -Be 'Enabled'
    }

    It 'blocks synced passkeys when an allow-list contains only non-synced (e.g. hardware key) AAGUIDs' {
        $raw = @{
            state                 = 'enabled'
            isAttestationEnforced = $true
            keyRestrictions       = @{
                isEnforced      = $true
                enforcementType = 'allow'
                aaGuids          = @('11111111-1111-1111-1111-111111111111')
            }
        }

        $result = $raw | ConvertTo-SAWNormalizedPasskeys

        ($result | Where-Object { $_.Setting -eq 'Synced Passkeys Currently Allowed' }).State | Should -Be 'Disabled'
    }

    It 'blocks synced passkeys when a block-list explicitly blocks every known synced provider AAGUID' {
        $raw = @{
            state                 = 'enabled'
            isAttestationEnforced = $true
            keyRestrictions       = @{
                isEnforced      = $true
                enforcementType = 'block'
                aaGuids          = @(
                    'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4', 'dd4ec289-e01d-41c9-bb89-70fa845d4bf2',
                    'fbfc3007-154e-4ecc-8c0b-6e020557d7bd', '531126d6-e717-415c-9320-3d9aa6981239',
                    'bada5566-a7aa-401f-bd96-45619a55120d', 'b84e4048-15dc-4dd0-8640-f4f60813c8af',
                    '0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6', '891494da-2c90-4d31-a9cd-4eab0aed1309',
                    'f3809540-7f14-49c1-a8b3-8f813b225541', 'd548826e-79b4-db40-a3d8-11116f7e8349',
                    '53414d53-554e-4700-0000-000000000000'
                )
            }
        }

        $result = $raw | ConvertTo-SAWNormalizedPasskeys

        ($result | Where-Object { $_.Setting -eq 'Synced Passkeys Currently Allowed' }).State | Should -Be 'Disabled'
    }

    It 'allows synced passkeys when a block-list omits at least one known synced provider AAGUID' {
        $raw = @{
            state                 = 'enabled'
            isAttestationEnforced = $true
            keyRestrictions       = @{
                isEnforced      = $true
                enforcementType = 'block'
                aaGuids          = @('ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4') # only Google blocked, others still get through
            }
        }

        $result = $raw | ConvertTo-SAWNormalizedPasskeys

        ($result | Where-Object { $_.Setting -eq 'Synced Passkeys Currently Allowed' }).State | Should -Be 'Enabled'
    }

    It 'matches known synced provider AAGUIDs case-insensitively' {
        $raw = @{
            state                 = 'enabled'
            isAttestationEnforced = $true
            keyRestrictions       = @{
                isEnforced      = $true
                enforcementType = 'allow'
                aaGuids          = @('EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4')
            }
        }

        $result = $raw | ConvertTo-SAWNormalizedPasskeys

        ($result | Where-Object { $_.Setting -eq 'Synced Passkeys Currently Allowed' }).State | Should -Be 'Enabled'
    }
}
