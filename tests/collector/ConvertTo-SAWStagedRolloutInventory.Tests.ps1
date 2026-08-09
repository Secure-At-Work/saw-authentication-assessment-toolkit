BeforeAll {
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWStagedRolloutInventory.ps1"
}

Describe 'ConvertTo-SAWStagedRolloutInventory' {

    Context 'when the collector could not read the policies' {
        BeforeAll {
            $script:result = @{
                value                = @()
                sawCollectionStatus  = 'Unavailable'
                sawUnavailableReason = 'missing scope'
            } | ConvertTo-SAWStagedRolloutInventory
        }

        It 'reports unavailable rather than pretending there are none' {
            $script:result.IsAvailable | Should -BeFalse
            $script:result.IsActive | Should -BeFalse
        }

        It 'carries the reason through so the dashboard can explain it' {
            $script:result.UnavailableReason | Should -Be 'missing scope'
        }

        It 'emits no caveats, because it does not know whether any apply' {
            $script:result.Caveats.Count | Should -Be 0
        }
    }

    Context 'when read successfully but no policies exist' {
        BeforeAll {
            $script:result = @{ value = @(); sawCollectionStatus = 'Collected' } |
                ConvertTo-SAWStagedRolloutInventory
        }

        It 'is available and inactive' {
            $script:result.IsAvailable | Should -BeTrue
            $script:result.IsActive | Should -BeFalse
        }

        It 'emits no caveats' {
            $script:result.Caveats.Count | Should -Be 0
        }
    }

    Context 'when policies exist but every one is disabled' {
        BeforeAll {
            $script:result = @{
                sawCollectionStatus = 'Collected'
                value               = @(
                    @{ id = 'a'; displayName = 'Leftover PTA pilot'; feature = 'passthroughAuthentication'
                       isEnabled = $false; isAppliedToOrganization = $false; appliesTo = @() }
                )
            } | ConvertTo-SAWStagedRolloutInventory
        }

        It 'is not active' {
            $script:result.IsActive | Should -BeFalse
        }

        It 'still inventories the policy so it can be tidied up' {
            $script:result.Policies.Count | Should -Be 1
        }

        It 'emits no caveats, since nothing is being enforced today' {
            $script:result.Caveats.Count | Should -Be 0
        }
    }

    Context 'when a rollout is enabled against pilot groups' {
        BeforeAll {
            $script:result = @{
                sawCollectionStatus = 'Collected'
                value               = @(
                    @{ id = 'b'; displayName = 'PHS pilot'; feature = 'passwordHashSync'
                       isEnabled = $true; isAppliedToOrganization = $false
                       appliesTo = @(
                           @{ id = 'g1'; displayName = 'Wave1' },
                           @{ id = 'g2'; displayName = 'Wave2' }
                       ) }
                )
            } | ConvertTo-SAWStagedRolloutInventory
        }

        It 'is active' {
            $script:result.IsActive | Should -BeTrue
        }

        It 'resolves the targeted group names' {
            $script:result.Policies[0].GroupNames | Should -Be @('Wave1', 'Wave2')
            $script:result.Policies[0].GroupCount | Should -Be 2
        }

        It 'labels the feature for a non-specialist reader' {
            $script:result.Policies[0].FeatureLabel | Should -Be 'Password hash sync'
            $script:result.Policies[0].FeatureRecognized | Should -BeTrue
        }

        It 'emits exactly the three always-on caveats' {
            $script:result.Caveats.Count | Should -Be 3
        }

        It 'names SSPR001/SSPR002 on the password writeback caveat' {
            @($script:result.Caveats | Where-Object { $_.AffectsRules -match 'SSPR001' }).Count | Should -Be 1
        }

        It 'names the TAP rules on the federated-sign-in caveat' {
            @($script:result.Caveats | Where-Object { $_.AffectsRules -match 'TAP001' }).Count | Should -Be 1
        }
    }

    Context 'when a rollout applies to the entire organization' {
        BeforeAll {
            $script:result = @{
                sawCollectionStatus = 'Collected'
                value               = @(
                    @{ id = 'c'; displayName = 'MFA org-wide'; feature = 'multiFactorAuthentication'
                       isEnabled = $true; isAppliedToOrganization = $true; appliesTo = @() }
                )
            } | ConvertTo-SAWStagedRolloutInventory
        }

        It 'flags the org-wide scope' {
            $script:result.AppliesToOrganization | Should -BeTrue
            $script:result.Policies[0].ScopeText | Should -Be 'Entire organization'
        }

        It 'adds a fourth caveat about it not being a steady state' {
            $script:result.Caveats.Count | Should -Be 4
        }

        It 'names Entra MFA rather than collapsing it to unknown' {
            # Only arrives by name because Get-SAWStagedRollout sends
            # Prefer: include-unknown-enum-members. Without that header Graph returns
            # unknownFutureValue for this member and the label would be wrong, not absent.
            $script:result.Policies[0].FeatureLabel | Should -Be 'Microsoft Entra multifactor authentication'
        }
    }

    Context 'when a disabled policy is org-wide but the enabled one is not' {
        BeforeAll {
            $script:result = @{
                sawCollectionStatus = 'Collected'
                value               = @(
                    @{ id = 'd'; displayName = 'Disabled org-wide leftover'; feature = 'seamlessSso'
                       isEnabled = $false; isAppliedToOrganization = $true; appliesTo = @() },
                    @{ id = 'e'; displayName = 'Enabled pilot'; feature = 'passwordHashSync'
                       isEnabled = $true; isAppliedToOrganization = $false
                       appliesTo = @( @{ id = 'g'; displayName = 'W1' } ) }
                )
            } | ConvertTo-SAWStagedRolloutInventory
        }

        It 'does not raise the org-wide caveat for a policy that is switched off' {
            $script:result.AppliesToOrganization | Should -BeFalse
            $script:result.Caveats.Count | Should -Be 3
        }
    }

    Context 'when Microsoft ships a rollout feature newer than this mapping' {
        BeforeAll {
            $script:result = @{
                sawCollectionStatus = 'Collected'
                value               = @(
                    @{ id = 'f'; displayName = 'Something new'; feature = 'someFutureFeature'
                       isEnabled = $true; isAppliedToOrganization = $false; appliesTo = @() }
                )
            } | ConvertTo-SAWStagedRolloutInventory
        }

        It 'reports it as unrecognized instead of silently relabelling it' {
            $script:result.Policies[0].FeatureRecognized | Should -BeFalse
            $script:result.Policies[0].FeatureLabel | Should -Match 'someFutureFeature'
        }

        It 'still treats the tenant as being in a rollout' {
            $script:result.IsActive | Should -BeTrue
        }
    }
}
