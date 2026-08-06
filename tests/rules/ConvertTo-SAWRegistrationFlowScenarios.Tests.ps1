BeforeAll {
    . "$PSScriptRoot/../../src/rules/ConvertTo-SAWRegistrationFlowScenarios.ps1"

    function New-SAWTestAuthMethodsPolicy {
        param(
            [bool]$TapEnabled = $true,
            [bool]$Fido2Enabled = $true,
            [bool]$Fido2SelfService = $true,
            [bool]$AuthenticatorEnabled = $true,
            [string]$CampaignState = 'enabled',
            [string]$CampaignTargetMethod = 'fido2',
            [Nullable[bool]]$EnforceAfterSnoozes = $true,
            [Nullable[int]]$ReconfirmationInDays = $null,
            [string]$SystemPreferredState = 'disabled'
        )
        return @{
            reconfirmationInDays = $ReconfirmationInDays
            registrationEnforcement = @{
                authenticationMethodsRegistrationCampaign = @{
                    state = $CampaignState
                    enforceRegistrationAfterAllowedSnoozes = $EnforceAfterSnoozes
                    includeTargets = @(@{ targetedAuthenticationMethod = $CampaignTargetMethod })
                }
            }
            systemCredentialPreferences = @{
                state = $SystemPreferredState
                includeTargets = @()
                excludeTargets = @()
            }
            authenticationMethodConfigurations = @(
                @{ id = 'TemporaryAccessPass'; state = if ($TapEnabled) { 'enabled' } else { 'disabled' } },
                @{ id = 'Fido2'; state = if ($Fido2Enabled) { 'enabled' } else { 'disabled' }; isSelfServiceRegistrationAllowed = $Fido2SelfService },
                @{ id = 'MicrosoftAuthenticator'; state = if ($AuthenticatorEnabled) { 'enabled' } else { 'disabled' } }
            )
        }
    }

    function New-SAWTestUser {
        param([bool]$IsSsprEnabled = $false)
        return @{ isSsprEnabled = $IsSsprEnabled }
    }
}

Describe 'ConvertTo-SAWRegistrationFlowScenarios' {
    It 'returns exactly 4 flows with the expected FlowIDs' {
        $authPolicy = New-SAWTestAuthMethodsPolicy
        $authzPolicy = @{ allowedToUseSSPR = $true }
        $registration = @{ value = @() }

        $result = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicy -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory @()

        $result.Count | Should -Be 4
        ($result | ForEach-Object { $_.FlowID }) | Should -Contain 'BOOTSTRAP'
        ($result | ForEach-Object { $_.FlowID }) | Should -Contain 'SSPR'
        ($result | ForEach-Object { $_.FlowID }) | Should -Contain 'REREGISTRATION'
        ($result | ForEach-Object { $_.FlowID }) | Should -Contain 'CAGATED'
    }

    It 'marks the Bootstrap flow not applicable when TAP is disabled' {
        $authPolicy = New-SAWTestAuthMethodsPolicy -TapEnabled $false
        $authzPolicy = @{ allowedToUseSSPR = $true }
        $registration = @{ value = @() }

        $result = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicy -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory @()

        $bootstrap = $result | Where-Object { $_.FlowID -eq 'BOOTSTRAP' }
        $bootstrap.Applicable | Should -Be $false
        ($bootstrap.Steps | Where-Object { $_.Step -like 'Admin issues*' }).Applies | Should -Be $false
    }

    It 'marks the passkey self-registration step as not applying when FIDO2 self-service is off' {
        $authPolicy = New-SAWTestAuthMethodsPolicy -Fido2SelfService $false
        $authzPolicy = @{ allowedToUseSSPR = $true }
        $registration = @{ value = @() }

        $result = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicy -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory @()

        $bootstrap = $result | Where-Object { $_.FlowID -eq 'BOOTSTRAP' }
        ($bootstrap.Steps | Where-Object { $_.Step -like 'User registers a passkey*' }).Applies | Should -Be $false
    }

    It 'marks the SSPR flow not applicable when no user is SSPR-enabled' {
        $authPolicy = New-SAWTestAuthMethodsPolicy
        $authzPolicy = @{ allowedToUseSSPR = $true }
        $registration = @{ value = @((New-SAWTestUser -IsSsprEnabled $false)) }

        $result = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicy -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory @()

        $sspr = $result | Where-Object { $_.FlowID -eq 'SSPR' }
        $sspr.Applicable | Should -Be $false
    }

    It 'marks the SSPR flow applicable when at least one user is SSPR-enabled' {
        $authPolicy = New-SAWTestAuthMethodsPolicy
        $authzPolicy = @{ allowedToUseSSPR = $true }
        $registration = @{ value = @((New-SAWTestUser -IsSsprEnabled $true)) }

        $result = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicy -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory @()

        $sspr = $result | Where-Object { $_.FlowID -eq 'SSPR' }
        $sspr.Applicable | Should -Be $true
    }

    It 'reflects allowedToUseSSPR=false in the admin two-gate step detail' {
        $authPolicy = New-SAWTestAuthMethodsPolicy
        $authzPolicy = @{ allowedToUseSSPR = $false }
        $registration = @{ value = @() }

        $result = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicy -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory @()

        $sspr = $result | Where-Object { $_.FlowID -eq 'SSPR' }
        $adminStep = $sspr.Steps | Where-Object { $_.Step -like 'Administrator accounts follow*' }
        $adminStep.Detail | Should -Match 'SSPR002'
    }

    It 'marks the reconfirmation step applicable only when reconfirmationInDays is set' {
        $authPolicyNoReconfirm = New-SAWTestAuthMethodsPolicy -ReconfirmationInDays $null
        $authPolicyWithReconfirm = New-SAWTestAuthMethodsPolicy -ReconfirmationInDays 180
        $authzPolicy = @{ allowedToUseSSPR = $true }
        $registration = @{ value = @() }

        $resultNoReconfirm = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicyNoReconfirm -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory @()
        $resultWithReconfirm = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicyWithReconfirm -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory @()

        $reregNo = $resultNoReconfirm | Where-Object { $_.FlowID -eq 'REREGISTRATION' }
        $reregYes = $resultWithReconfirm | Where-Object { $_.FlowID -eq 'REREGISTRATION' }

        ($reregNo.Steps | Where-Object { $_.Step -like 'If reconfirmation*' }).Applies | Should -Be $false
        ($reregYes.Steps | Where-Object { $_.Step -like 'If reconfirmation*' }).Applies | Should -Be $true
    }

    It 'marks the CA-Gated flow not applicable when no enabled policy targets security info registration' {
        $authPolicy = New-SAWTestAuthMethodsPolicy
        $authzPolicy = @{ allowedToUseSSPR = $true }
        $registration = @{ value = @() }
        $caInventory = @(@{ DisplayName = 'Unrelated Policy'; State = 'Enabled'; TargetsSecurityInfoRegistration = $false })

        $result = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicy -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory $caInventory

        $caGated = $result | Where-Object { $_.FlowID -eq 'CAGATED' }
        $caGated.Applicable | Should -Be $false
    }

    It 'marks the CA-Gated flow applicable and names the policy when an enabled policy targets security info registration' {
        $authPolicy = New-SAWTestAuthMethodsPolicy
        $authzPolicy = @{ allowedToUseSSPR = $true }
        $registration = @{ value = @() }
        $caInventory = @(@{ DisplayName = 'Require MFA for Security Info Registration'; State = 'Enabled'; TargetsSecurityInfoRegistration = $true; GrantControlsSummary = 'Require MFA' })

        $result = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicy -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory $caInventory

        $caGated = $result | Where-Object { $_.FlowID -eq 'CAGATED' }
        $caGated.Applicable | Should -Be $true
        $caGated.ISTSummary | Should -Match 'Require MFA for Security Info Registration'
    }

    Context 'System-Preferred Authentication steps' {
        It 'marks the Bootstrap system-preferred step as not applying when the state is disabled' {
            $authPolicy = New-SAWTestAuthMethodsPolicy -SystemPreferredState 'disabled'
            $authzPolicy = @{ allowedToUseSSPR = $true }
            $registration = @{ value = @() }

            $result = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicy -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory @()

            $bootstrap = $result | Where-Object { $_.FlowID -eq 'BOOTSTRAP' }
            ($bootstrap.Steps | Where-Object { $_.Step -like '*System-Preferred Authentication may start presenting*' }).Applies | Should -Be $false
        }

        It 'marks the Bootstrap and Re-Registration system-preferred steps as applying when the state is enabled' {
            $authPolicy = New-SAWTestAuthMethodsPolicy -SystemPreferredState 'enabled'
            $authzPolicy = @{ allowedToUseSSPR = $true }
            $registration = @{ value = @() }

            $result = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicy -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory @()

            $bootstrap = $result | Where-Object { $_.FlowID -eq 'BOOTSTRAP' }
            $rereg = $result | Where-Object { $_.FlowID -eq 'REREGISTRATION' }

            ($bootstrap.Steps | Where-Object { $_.Step -like '*System-Preferred Authentication may start presenting*' }).Applies | Should -Be $true
            ($rereg.Steps | Where-Object { $_.Step -like 'BEFORE any of the below*' }).Applies | Should -Be $true
        }

        It 'treats an absent systemCredentialPreferences the same as default (Microsoft managed, applies)' {
            $authPolicy = New-SAWTestAuthMethodsPolicy
            $authPolicy.Remove('systemCredentialPreferences')
            $authzPolicy = @{ allowedToUseSSPR = $true }
            $registration = @{ value = @() }

            $result = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicy -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory @()

            $rereg = $result | Where-Object { $_.FlowID -eq 'REREGISTRATION' }
            $step = $rereg.Steps | Where-Object { $_.Step -like 'BEFORE any of the below*' }
            $step.Applies | Should -Be $true
            $step.Detail | Should -Match 'Microsoft managed'
        }

        It 'marks the CA-Gated first-factor note as a fixed Microsoft behavior (Applies is null), not tenant-conditioned' {
            $authPolicy = New-SAWTestAuthMethodsPolicy
            $authzPolicy = @{ allowedToUseSSPR = $true }
            $registration = @{ value = @() }

            $result = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicy -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory @()

            $caGated = $result | Where-Object { $_.FlowID -eq 'CAGATED' }
            $step = $caGated.Steps | Where-Object { $_.Step -like 'Conditional Access does NOT override*' }
            $step | Should -Not -BeNullOrEmpty
            $null -eq $step.Applies | Should -Be $true
        }
    }

    It 'ignores a disabled CA policy that targets security info registration' {
        $authPolicy = New-SAWTestAuthMethodsPolicy
        $authzPolicy = @{ allowedToUseSSPR = $true }
        $registration = @{ value = @() }
        $caInventory = @(@{ DisplayName = 'Disabled Policy'; State = 'Disabled'; TargetsSecurityInfoRegistration = $true })

        $result = ConvertTo-SAWRegistrationFlowScenarios -AuthenticationMethodsPolicyRaw $authPolicy -AuthorizationPolicyRaw $authzPolicy -RegistrationRaw $registration -CaPolicyInventory $caInventory

        $caGated = $result | Where-Object { $_.FlowID -eq 'CAGATED' }
        $caGated.Applicable | Should -Be $false
    }
}
