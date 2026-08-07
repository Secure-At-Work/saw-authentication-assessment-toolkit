BeforeAll {
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWFido2KeyInventory.ps1"
}

Describe 'ConvertTo-SAWFido2KeyInventory' {
    It 'returns $null when FIDO2 is disabled tenant-wide, even if key restrictions are configured' {
        $raw = @{
            state           = 'disabled'
            keyRestrictions = @{ isEnforced = $true; enforcementType = 'allow'; aaGuids = @('cb69481e-8ff7-4039-93ec-0a2729a154a8') }
        }

        $result = $raw | ConvertTo-SAWFido2KeyInventory

        $result | Should -BeNullOrEmpty
    }

    It 'reports IsEnforced false and a plain-language summary when key restrictions are not enforced' {
        $raw = @{
            state           = 'enabled'
            keyRestrictions = @{ isEnforced = $false; enforcementType = 'block'; aaGuids = @() }
        }

        $result = $raw | ConvertTo-SAWFido2KeyInventory

        $result.IsEnforced | Should -BeFalse
        $result.EnforcementSummary | Should -Match 'Not enforced'
    }

    It 'resolves a known Yubico hardware key AAGUID to its readable name' {
        $raw = @{
            state           = 'enabled'
            keyRestrictions = @{ isEnforced = $true; enforcementType = 'allow'; aaGuids = @('cb69481e-8ff7-4039-93ec-0a2729a154a8') }
        }

        $result = $raw | ConvertTo-SAWFido2KeyInventory

        $result.AllowedKeys.Count | Should -Be 1
        $result.AllowedKeys[0].Recognized | Should -BeTrue
        $result.AllowedKeys[0].KnownName | Should -Match 'YubiKey'
    }

    It 'resolves a known Feitian hardware key AAGUID to its readable name' {
        $raw = @{
            state           = 'enabled'
            keyRestrictions = @{ isEnforced = $true; enforcementType = 'allow'; aaGuids = @('12755c32-8ad1-46eb-881c-e0b38d848b09') }
        }

        $result = $raw | ConvertTo-SAWFido2KeyInventory

        $result.AllowedKeys[0].Recognized | Should -BeTrue
        $result.AllowedKeys[0].KnownName | Should -Match 'Feitian ePass FIDO'
    }

    It 'resolves both documented Microsoft Authenticator AAGUIDs (Android and iOS)' {
        $raw = @{
            state           = 'enabled'
            keyRestrictions = @{ isEnforced = $true; enforcementType = 'allow'; aaGuids = @('de1e552d-db1d-4423-a619-566b625cdc84', '90a3ccdf-635c-4729-a248-9b709135078f') }
        }

        $result = $raw | ConvertTo-SAWFido2KeyInventory

        $result.AllowedKeys.Count | Should -Be 2
        ($result.AllowedKeys | Where-Object { $_.Aaguid -eq 'de1e552d-db1d-4423-a619-566b625cdc84' }).KnownName | Should -Match 'Microsoft Authenticator \(Android\)'
        ($result.AllowedKeys | Where-Object { $_.Aaguid -eq '90a3ccdf-635c-4729-a248-9b709135078f' }).KnownName | Should -Match 'Microsoft Authenticator \(iOS\)'
        $result.AllowedKeys | ForEach-Object { $_.Recognized | Should -BeTrue }
    }

    It 'resolves a known synced-passkey provider AAGUID to its readable name too, not just hardware keys' {
        $raw = @{
            state           = 'enabled'
            keyRestrictions = @{ isEnforced = $true; enforcementType = 'allow'; aaGuids = @('ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4') }
        }

        $result = $raw | ConvertTo-SAWFido2KeyInventory

        $result.AllowedKeys[0].Recognized | Should -BeTrue
        $result.AllowedKeys[0].KnownName | Should -Match 'Google Password Manager'
    }

    It 'marks an unrecognized AAGUID as such rather than omitting it or guessing' {
        $raw = @{
            state           = 'enabled'
            keyRestrictions = @{ isEnforced = $true; enforcementType = 'allow'; aaGuids = @('00000000-0000-0000-0000-000000000099') }
        }

        $result = $raw | ConvertTo-SAWFido2KeyInventory

        $result.AllowedKeys.Count | Should -Be 1
        $result.AllowedKeys[0].Recognized | Should -BeFalse
        $result.AllowedKeys[0].KnownName | Should -Match 'Unrecognized AAGUID'
    }

    It 'matches known AAGUIDs case-insensitively' {
        $raw = @{
            state           = 'enabled'
            keyRestrictions = @{ isEnforced = $true; enforcementType = 'allow'; aaGuids = @('CB69481E-8FF7-4039-93EC-0A2729A154A8') }
        }

        $result = $raw | ConvertTo-SAWFido2KeyInventory

        $result.AllowedKeys[0].Recognized | Should -BeTrue
    }

    It 'summarizes an allow-list enforcement type with the correct count' {
        $raw = @{
            state           = 'enabled'
            keyRestrictions = @{ isEnforced = $true; enforcementType = 'allow'; aaGuids = @('cb69481e-8ff7-4039-93ec-0a2729a154a8', 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4') }
        }

        $result = $raw | ConvertTo-SAWFido2KeyInventory

        $result.EnforcementSummary | Should -Match 'Allow-list'
        $result.EnforcementSummary | Should -Match '2 key'
    }

    It 'summarizes a block-list enforcement type with the correct count' {
        $raw = @{
            state           = 'enabled'
            keyRestrictions = @{ isEnforced = $true; enforcementType = 'block'; aaGuids = @('cb69481e-8ff7-4039-93ec-0a2729a154a8') }
        }

        $result = $raw | ConvertTo-SAWFido2KeyInventory

        $result.EnforcementSummary | Should -Match 'Block-list'
        $result.EnforcementSummary | Should -Match '1 below'
    }

    It 'does not expose the allowed-keys array under the name "Keys" (collides with Hashtable''s own intrinsic member)' {
        $raw = @{
            state           = 'enabled'
            keyRestrictions = @{ isEnforced = $true; enforcementType = 'allow'; aaGuids = @('cb69481e-8ff7-4039-93ec-0a2729a154a8') }
        }

        $result = $raw | ConvertTo-SAWFido2KeyInventory

        # $result.Keys is the Hashtable's own intrinsic member (its dictionary key names, e.g.
        # "IsEnforced", "AllowedKeys") - regression guard that the real per-key data lives under
        # the differently-named AllowedKeys property, not shadowed by that intrinsic member.
        $result.Keys | Should -Contain 'AllowedKeys'
        $result.Keys | Should -Not -Contain 'Aaguid'
        $result.AllowedKeys.Count | Should -Be 1
        $result.AllowedKeys[0].Aaguid | Should -Be 'cb69481e-8ff7-4039-93ec-0a2729a154a8'
    }
}
