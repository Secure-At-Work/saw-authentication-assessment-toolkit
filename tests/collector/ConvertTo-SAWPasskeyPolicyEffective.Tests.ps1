BeforeAll {
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWPasskeyPolicyEffective.ps1"
}

Describe 'ConvertTo-SAWPasskeyPolicyEffective' {
    Context 'no config' {
        It 'reports the Unknown sentinel, never a false negative, when RawConfig is null' {
            $result = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $null

            $result.IsKnown | Should -Be $false
            $result.AttestationEnforced | Should -Be $null
            $result.KeyRestrictionsEnforced | Should -Be $null
            $result.PasskeyTypeRestriction | Should -Be $null
        }
    }

    Context 'legacy properties path - the pre-existing dead-code regression' {
        # This is the important one: Hashtable.PSObject.Properties['key'] silently returns nothing
        # even when the key exists (.Contains() is the correct test for a dictionary), and an
        # earlier version of this function checked PSObject.Properties BEFORE the IDictionary
        # branch - since every object has a non-null PSObject.Properties, that made the IDictionary
        # branch unreachable. A live tenant whose Graph response comes back as a Hashtable (the
        # documented live shape, vs. PSCustomObject for ConvertFrom-Json'd sample data) would
        # silently report "Unknown" instead of the real attestation/key-restriction state -
        # a false negative on a security control, presented as "couldn't determine".
        It 'resolves attestation and key restrictions from a Hashtable-shaped config (the live Graph SDK shape)' {
            $config = @{
                id                     = 'Fido2'
                isAttestationEnforced  = $true
                keyRestrictions        = @{ isEnforced = $true }
            }

            $result = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $config

            $result.IsKnown | Should -Be $true
            $result.Source | Should -Be 'LegacyProperties'
            $result.AttestationEnforced | Should -Be $true
            $result.KeyRestrictionsEnforced | Should -Be $true
        }

        It 'resolves attestation and key restrictions from a PSCustomObject-shaped config (the sample-data shape)' {
            $config = [PSCustomObject]@{
                id                    = 'Fido2'
                isAttestationEnforced = $true
                keyRestrictions       = [PSCustomObject]@{ isEnforced = $false }
            }

            $result = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $config

            $result.IsKnown | Should -Be $true
            $result.Source | Should -Be 'LegacyProperties'
            $result.AttestationEnforced | Should -Be $true
            $result.KeyRestrictionsEnforced | Should -Be $false
        }

        It 'reports Unknown, not $false, when neither legacy property nor passkeyProfiles is present' {
            $config = @{ id = 'Fido2'; isSelfServiceRegistrationAllowed = $true }

            $result = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $config

            $result.IsKnown | Should -Be $false
            $result.AttestationEnforced | Should -Be $null
        }

        It 'PasskeyTypeRestriction is always null on the legacy path - no per-type control exists there' {
            $config = @{ id = 'Fido2'; isAttestationEnforced = $false; keyRestrictions = @{ isEnforced = $false } }

            $result = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $config

            $result.PasskeyTypeRestriction | Should -Be $null
        }
    }

    Context 'passkeyProfiles path (authoritative when present)' {
        It 'reads attestation and key restrictions from a single profile' {
            $config = @{
                id                    = 'Fido2'
                defaultPasskeyProfile = 'p1'
                passkeyProfiles       = @(
                    @{ id = 'p1'; attestationEnforcement = 'registrationOnly'; keyRestrictions = @{ isEnforced = $true }; passkeyTypes = 'deviceBound' }
                )
            }

            $result = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $config

            $result.Source | Should -Be 'PasskeyProfiles'
            $result.AttestationEnforced | Should -Be $true
            $result.KeyRestrictionsEnforced | Should -Be $true
            $result.PasskeyTypeRestriction | Should -Be 'deviceBound'
        }

        It 'requires EVERY profile to enforce before reporting attestation as tenant-wide enforced' {
            $config = @{
                id              = 'Fido2'
                passkeyProfiles = @(
                    @{ id = 'p1'; attestationEnforcement = 'registrationOnly'; keyRestrictions = @{ isEnforced = $false } }
                    @{ id = 'p2'; attestationEnforcement = 'disabled'; keyRestrictions = @{ isEnforced = $false } }
                )
            }

            $result = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $config

            $result.AttestationEnforced | Should -Be $false
            $result.MixedEnforcement | Should -Be $true
        }

        It "treats 'disabled' attestationEnforcement as not enforcing" {
            $config = @{
                id              = 'Fido2'
                passkeyProfiles = @(@{ id = 'p1'; attestationEnforcement = 'disabled'; keyRestrictions = @{ isEnforced = $false } })
            }

            $result = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $config

            $result.AttestationEnforced | Should -Be $false
        }

        It "treats an unrecognized attestationEnforcement value as NOT enforcing, never assumed safe or enforced" {
            $config = @{
                id              = 'Fido2'
                passkeyProfiles = @(@{ id = 'p1'; attestationEnforcement = 'unknownFutureValue'; keyRestrictions = @{ isEnforced = $false } })
            }

            $result = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $config

            $result.AttestationEnforced | Should -Be $false
        }

        It 'reads PasskeyTypeRestriction from the default profile, not an aggregate across profiles' {
            $config = @{
                id                    = 'Fido2'
                defaultPasskeyProfile = 'p2'
                passkeyProfiles       = @(
                    @{ id = 'p1'; passkeyTypes = 'deviceBound'; attestationEnforcement = 'disabled'; keyRestrictions = @{ isEnforced = $false } }
                    @{ id = 'p2'; passkeyTypes = 'synced'; attestationEnforcement = 'disabled'; keyRestrictions = @{ isEnforced = $false } }
                )
            }

            $result = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $config

            $result.PasskeyTypeRestriction | Should -Be 'synced'
        }

        It 'falls back to the first profile for PasskeyTypeRestriction when defaultPasskeyProfile does not resolve' {
            $config = @{
                id                    = 'Fido2'
                defaultPasskeyProfile = 'does-not-exist'
                passkeyProfiles       = @(
                    @{ id = 'p1'; passkeyTypes = 'deviceBound'; attestationEnforcement = 'disabled'; keyRestrictions = @{ isEnforced = $false } }
                )
            }

            $result = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $config

            $result.PasskeyTypeRestriction | Should -Be 'deviceBound'
        }

        It 'reports PasskeyTypeRestriction as null for an unrecognized passkeyTypes value, not guessed either direction' {
            $config = @{
                id              = 'Fido2'
                passkeyProfiles = @(@{ id = 'p1'; passkeyTypes = 'unknownFutureValue'; attestationEnforcement = 'disabled'; keyRestrictions = @{ isEnforced = $false } })
            }

            $result = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $config

            $result.PasskeyTypeRestriction | Should -Be $null
        }

        It 'SyncedPasskeysAllowed is true if ANY profile targets synced' {
            $config = @{
                id              = 'Fido2'
                passkeyProfiles = @(
                    @{ id = 'p1'; passkeyTypes = 'deviceBound'; attestationEnforcement = 'disabled'; keyRestrictions = @{ isEnforced = $false } }
                    @{ id = 'p2'; passkeyTypes = 'synced'; attestationEnforcement = 'disabled'; keyRestrictions = @{ isEnforced = $false } }
                )
            }

            $result = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $config

            $result.SyncedPasskeysAllowed | Should -Be $true
        }

        It 'passkeyProfiles takes priority over legacy properties when both are present' {
            $config = @{
                id                     = 'Fido2'
                isAttestationEnforced  = $true
                keyRestrictions        = @{ isEnforced = $true }
                passkeyProfiles        = @(@{ id = 'p1'; attestationEnforcement = 'disabled'; keyRestrictions = @{ isEnforced = $false } })
            }

            $result = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $config

            $result.Source | Should -Be 'PasskeyProfiles'
            $result.AttestationEnforced | Should -Be $false
        }
    }
}
