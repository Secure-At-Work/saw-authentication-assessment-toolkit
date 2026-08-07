BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWConditionalAccess.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWNormalizedConditionalAccess.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWConditionalAccessInventory.ps1"

    . "$PSScriptRoot/../../src/Invoke-SAWGraphRequest.ps1"

    function Get-MgContext { }
    function Invoke-MgGraphRequest { param($Method, $Uri) }

    function New-SAWTestCaPolicy {
        param(
            [string]$State = 'enabled',
            [string[]]$IncludeUsers = @('All'),
            [string[]]$IncludeApplications = @('All'),
            [string[]]$IncludeUserActions = @(),
            [string[]]$IncludeRoles = @(),
            [string[]]$ClientAppTypes = @('all'),
            [string[]]$BuiltInControls = @(),
            [object]$AuthenticationStrength = $null
        )
        return @{
            state      = $State
            conditions = @{
                users        = @{ includeUsers = $IncludeUsers; includeRoles = $IncludeRoles }
                applications = @{ includeApplications = $IncludeApplications; includeUserActions = $IncludeUserActions }
                clientAppTypes = $ClientAppTypes
            }
            grantControls = @{ builtInControls = $BuiltInControls; authenticationStrength = $AuthenticationStrength }
        }
    }
}

Describe 'Get-SAWConditionalAccess' {
    Context '-UseSampleData' {
        It 'returns the bundled sample data' {
            $result = Get-SAWConditionalAccess -UseSampleData
            $result.value | Should -Not -BeNullOrEmpty
        }

        It 'throws if the sample data file does not exist' {
            { Get-SAWConditionalAccess -UseSampleData -SampleDataPath 'C:\does\not\exist.json' } | Should -Throw
        }
    }

    Context 'live Graph calls' {
        It 'throws when not connected to Microsoft Graph' {
            Mock Get-MgContext { $null }
            { Get-SAWConditionalAccess } | Should -Throw
        }

        It 'calls the conditional access policies endpoint' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest { @{ value = @() } }

            Get-SAWConditionalAccess | Out-Null

            Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                $Method -eq 'GET' -and $Uri -eq 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
            }
        }

        It 'follows @odata.nextLink to collect every page' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            $script:pageNumber = 0
            Mock Invoke-MgGraphRequest {
                $script:pageNumber++
                if ($script:pageNumber -eq 1) {
                    return @{
                        value             = @(@{ id = 'page1-policy' })
                        '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=abc'
                    }
                }
                return @{ value = @(@{ id = 'page2-policy' }) }
            }

            $result = Get-SAWConditionalAccess

            $result.value.Count | Should -Be 2
            Should -Invoke Invoke-MgGraphRequest -Times 2
        }
    }
}

Describe 'ConvertTo-SAWNormalizedConditionalAccess' {
    It 'reports legacy auth blocked when an enabled policy blocks it for all users and apps' {
        $raw = @{
            value = @(
                (New-SAWTestCaPolicy -ClientAppTypes @('exchangeActiveSync', 'other') -BuiltInControls @('block'))
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

        ($result | Where-Object { $_.Setting -eq 'Block Legacy Authentication' }).State | Should -Be 'Enabled'
    }

    It 'does not count a report-only policy as enforcing MFA' {
        $raw = @{
            value = @(
                (New-SAWTestCaPolicy -State 'enabledForReportingButNotEnforced' -BuiltInControls @('mfa'))
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

        ($result | Where-Object { $_.Setting -eq 'Require MFA For All Users' }).State | Should -Be 'Disabled'
    }

    It 'does not count a disabled policy as enforcing compliant device for admins' {
        $raw = @{
            value = @(
                (New-SAWTestCaPolicy -State 'disabled' -IncludeUsers @() -IncludeRoles @('role-1') -BuiltInControls @('compliantDevice'))
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

        ($result | Where-Object { $_.Setting -eq 'Require Compliant Device For Admins' }).State | Should -Be 'Disabled'
    }

    It 'reports compliant device enforced when an enabled policy targets admin roles' {
        $raw = @{
            value = @(
                (New-SAWTestCaPolicy -IncludeUsers @() -IncludeRoles @('role-1', 'role-2') -BuiltInControls @('compliantDevice'))
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

        ($result | Where-Object { $_.Setting -eq 'Require Compliant Device For Admins' }).State | Should -Be 'Enabled'
    }

    It 'returns Disabled for every capability when there are no policies at all, except the TAP-lockout check (absence of a blocking policy is the good state)' {
        $raw = @{ value = @() }

        $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

        $result.Count | Should -Be 7
        ($result | Where-Object { $_.Setting -ne 'Security Info Registration Reachable With Only A Temporary Access Pass' -and $_.State -eq 'Enabled' }).Count | Should -Be 0
        ($result | Where-Object { $_.Setting -eq 'Security Info Registration Reachable With Only A Temporary Access Pass' }).State | Should -Be 'Enabled'
    }

    Context 'admin protection composite' {
        It 'reports phishing-resistant strength for admins Enabled when an enabled policy targets admin roles with a pure phishing-resistant strength' {
            $strength = @{ displayName = 'Phishing-resistant MFA'; allowedCombinations = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor') }
            $raw = @{
                value = @(
                    (New-SAWTestCaPolicy -IncludeUsers @() -IncludeRoles @('role-1') -AuthenticationStrength $strength)
                )
            }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq 'Require Phishing-Resistant Auth Strength For Admins' }).State | Should -Be 'Enabled'
        }

        It 'does not count an authentication strength that also allows weaker combinations' {
            $strength = @{ displayName = 'Multifactor authentication'; allowedCombinations = @('password,sms', 'fido2') }
            $raw = @{
                value = @(
                    (New-SAWTestCaPolicy -IncludeUsers @() -IncludeRoles @('role-1') -AuthenticationStrength $strength)
                )
            }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq 'Require Phishing-Resistant Auth Strength For Admins' }).State | Should -Be 'Disabled'
        }

        It 'falls back to matching the displayName when allowedCombinations is not present' {
            $strength = @{ displayName = 'Phishing-Resistant MFA' }
            $raw = @{
                value = @(
                    (New-SAWTestCaPolicy -IncludeUsers @() -IncludeRoles @('role-1') -AuthenticationStrength $strength)
                )
            }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq 'Require Phishing-Resistant Auth Strength For Admins' }).State | Should -Be 'Enabled'
        }

        It 'does not count a phishing-resistant strength policy that does not target admin roles' {
            $strength = @{ displayName = 'Phishing-resistant MFA'; allowedCombinations = @('fido2') }
            $raw = @{
                value = @(
                    (New-SAWTestCaPolicy -IncludeRoles @() -AuthenticationStrength $strength)
                )
            }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq 'Require Phishing-Resistant Auth Strength For Admins' }).State | Should -Be 'Disabled'
        }

        It 'reports the composite Enabled when compliant device is in place, even without a phishing-resistant strength' {
            $raw = @{
                value = @(
                    (New-SAWTestCaPolicy -IncludeUsers @() -IncludeRoles @('role-1') -BuiltInControls @('compliantDevice'))
                )
            }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -like 'Privileged Access Protection In Place*' }).State | Should -Be 'Enabled'
        }

        It 'reports the composite Enabled when a phishing-resistant strength is in place, even without compliant device' {
            $strength = @{ displayName = 'Phishing-resistant MFA'; allowedCombinations = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor') }
            $raw = @{
                value = @(
                    (New-SAWTestCaPolicy -IncludeUsers @() -IncludeRoles @('role-1') -AuthenticationStrength $strength)
                )
            }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -like 'Privileged Access Protection In Place*' }).State | Should -Be 'Enabled'
        }

        It 'reports the composite Disabled when neither alternative is in place' {
            $raw = @{ value = @() }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -like 'Privileged Access Protection In Place*' }).State | Should -Be 'Disabled'
        }
    }

    Context 'Register Security Information reachable with only a Temporary Access Pass (CA004)' {
        $settingName = 'Security Info Registration Reachable With Only A Temporary Access Pass'

        It 'is Enabled when no policy targets registersecurityinfo at all' {
            $raw = @{ value = @((New-SAWTestCaPolicy -BuiltInControls @('mfa'))) }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Enabled'
        }

        It 'is Enabled when the policy targeting registersecurityinfo only requires plain mfa (no custom strength)' {
            $raw = @{ value = @((New-SAWTestCaPolicy -IncludeUserActions @('urn:user:registersecurityinfo') -BuiltInControls @('mfa'))) }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Enabled'
        }

        It 'is Disabled (the lockout) when the policy requires a phishing-resistant-only strength with no TAP escape' {
            $strength = @{ displayName = 'Phishing-resistant MFA'; allowedCombinations = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor') }
            $raw = @{ value = @((New-SAWTestCaPolicy -IncludeUserActions @('urn:user:registersecurityinfo') -AuthenticationStrength $strength)) }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Disabled'
        }

        It 'is Enabled when the required strength explicitly allows temporaryAccessPassOneTime' {
            $strength = @{ displayName = 'Custom'; allowedCombinations = @('fido2', 'temporaryAccessPassOneTime') }
            $raw = @{ value = @((New-SAWTestCaPolicy -IncludeUserActions @('urn:user:registersecurityinfo') -AuthenticationStrength $strength)) }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Enabled'
        }

        It 'is Enabled when the required strength explicitly allows temporaryAccessPassMultiUse' {
            $strength = @{ displayName = 'Custom'; allowedCombinations = @('windowsHelloForBusiness', 'temporaryAccessPassMultiUse') }
            $raw = @{ value = @((New-SAWTestCaPolicy -IncludeUserActions @('urn:user:registersecurityinfo') -AuthenticationStrength $strength)) }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Enabled'
        }

        It 'ignores a report-only policy even if its strength would otherwise block TAP-only users' {
            $strength = @{ displayName = 'Phishing-resistant MFA'; allowedCombinations = @('fido2') }
            $raw = @{ value = @((New-SAWTestCaPolicy -State 'enabledForReportingButNotEnforced' -IncludeUserActions @('urn:user:registersecurityinfo') -AuthenticationStrength $strength)) }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Enabled'
        }

        It 'does not false-positive when the authentication strength reference has no allowedCombinations data' {
            $strength = @{ displayName = 'Unresolved reference' }
            $raw = @{ value = @((New-SAWTestCaPolicy -IncludeUserActions @('urn:user:registersecurityinfo') -AuthenticationStrength $strength)) }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Enabled'
        }
    }

    Context 'Register Security Information requires strong authentication (CA005)' {
        $settingName = 'Security Info Registration Requires Strong Authentication'

        It 'is Disabled when no policy targets registersecurityinfo at all' {
            $raw = @{ value = @((New-SAWTestCaPolicy -BuiltInControls @('mfa'))) }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Disabled'
        }

        It 'is Disabled when a policy targets registersecurityinfo but has no grant control at all' {
            $raw = @{ value = @((New-SAWTestCaPolicy -IncludeUserActions @('urn:user:registersecurityinfo') -BuiltInControls @())) }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Disabled'
        }

        It 'is Enabled when an enabled policy targets registersecurityinfo with a plain mfa control' {
            $raw = @{ value = @((New-SAWTestCaPolicy -IncludeUserActions @('urn:user:registersecurityinfo') -BuiltInControls @('mfa'))) }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Enabled'
        }

        It 'is Enabled when an enabled policy targets registersecurityinfo with an authentication strength' {
            $strength = @{ displayName = 'Phishing-resistant MFA'; allowedCombinations = @('fido2') }
            $raw = @{ value = @((New-SAWTestCaPolicy -IncludeUserActions @('urn:user:registersecurityinfo') -AuthenticationStrength $strength)) }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Enabled'
        }

        It 'does not credit a policy scoped to All resources as covering registersecurityinfo' {
            $raw = @{ value = @((New-SAWTestCaPolicy -IncludeApplications @('All') -IncludeUserActions @() -BuiltInControls @('mfa'))) }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Disabled'
        }

        It 'does not count a report-only policy targeting registersecurityinfo' {
            $raw = @{ value = @((New-SAWTestCaPolicy -State 'enabledForReportingButNotEnforced' -IncludeUserActions @('urn:user:registersecurityinfo') -BuiltInControls @('mfa'))) }

            $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Disabled'
        }
    }
}

Describe 'ConvertTo-SAWConditionalAccessInventory' {
    It 'summarizes "All users" with an exclusion count' {
        $raw = @{
            value = @(
                @{
                    displayName = 'Test Policy'
                    state       = 'enabled'
                    conditions  = @{
                        users        = @{ includeUsers = @('All'); excludeUsers = @('u1'); includeRoles = @(); includeGroups = @() }
                        applications = @{ includeApplications = @('All') }
                    }
                    grantControls = @{ builtInControls = @('mfa') }
                }
            )
        }

        $result = $raw | ConvertTo-SAWConditionalAccessInventory

        $result.UserTargetSummary | Should -Be 'All users (1 excluded)'
        $result.AppTargetSummary | Should -Be 'All apps'
        $result.GrantControlsSummary | Should -Be 'Require MFA'
    }

    It 'summarizes admin role targeting by count' {
        $raw = @{
            value = @(
                @{
                    displayName = 'Test Policy'
                    state       = 'enabled'
                    conditions  = @{
                        users        = @{ includeUsers = @(); excludeUsers = @(); includeRoles = @('r1', 'r2'); includeGroups = @() }
                        applications = @{ includeApplications = @('All') }
                    }
                    grantControls = @{ builtInControls = @('compliantDevice') }
                }
            )
        }

        $result = $raw | ConvertTo-SAWConditionalAccessInventory

        $result.UserTargetSummary | Should -Be '2 admin role(s)'
        $result.GrantControlsSummary | Should -Be 'Require compliant device'
    }

    It 'reports the authentication strength display name in the grant controls summary' {
        $raw = @{
            value = @(
                @{
                    displayName = 'Test Policy'
                    state       = 'enabled'
                    conditions  = @{
                        users        = @{ includeUsers = @(); excludeUsers = @(); includeRoles = @('r1'); includeGroups = @() }
                        applications = @{ includeApplications = @('All') }
                    }
                    grantControls = @{ builtInControls = @(); authenticationStrength = @{ displayName = 'Phishing-resistant MFA' } }
                }
            )
        }

        $result = $raw | ConvertTo-SAWConditionalAccessInventory

        $result.GrantControlsSummary | Should -Be 'Require auth strength: Phishing-resistant MFA'
    }

    It 'identifies a policy targeting Register Security Information' {
        $raw = @{
            value = @(
                @{
                    displayName = 'Test Policy'
                    state       = 'enabled'
                    conditions  = @{
                        users        = @{ includeUsers = @('All'); excludeUsers = @(); includeRoles = @(); includeGroups = @() }
                        applications = @{ includeApplications = @(); includeUserActions = @('urn:user:registersecurityinfo') }
                    }
                    grantControls = @{ builtInControls = @('mfa') }
                }
            )
        }

        $result = $raw | ConvertTo-SAWConditionalAccessInventory

        $result.TargetsSecurityInfoRegistration | Should -BeTrue
        $result.AppTargetSummary | Should -Be 'Register security information'
    }

    It 'maps enabledForReportingButNotEnforced to a readable label' {
        $raw = @{
            value = @(
                @{
                    displayName = 'Test Policy'
                    state       = 'enabledForReportingButNotEnforced'
                    conditions  = @{
                        users        = @{ includeUsers = @('All'); excludeUsers = @(); includeRoles = @(); includeGroups = @() }
                        applications = @{ includeApplications = @('All') }
                    }
                    grantControls = @{ builtInControls = @('mfa') }
                }
            )
        }

        $result = $raw | ConvertTo-SAWConditionalAccessInventory

        $result.State | Should -Be 'Enabled (report-only)'
    }

    It 'reports None for grant controls when there are none' {
        $raw = @{
            value = @(
                @{
                    displayName = 'Test Policy'
                    state       = 'disabled'
                    conditions  = @{
                        users        = @{ includeUsers = @('All'); excludeUsers = @(); includeRoles = @(); includeGroups = @() }
                        applications = @{ includeApplications = @('All') }
                    }
                    grantControls = @{ builtInControls = @() }
                }
            )
        }

        $result = $raw | ConvertTo-SAWConditionalAccessInventory

        $result.GrantControlsSummary | Should -Be 'None'
    }

    It 'produces one inventory entry per policy' {
        $raw = @{
            value = @(
                @{ displayName = 'Policy A'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = @(); includeRoles = @(); includeGroups = @() }; applications = @{ includeApplications = @('All') } }; grantControls = @{ builtInControls = @() } },
                @{ displayName = 'Policy B'; state = 'disabled'; conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = @(); includeRoles = @(); includeGroups = @() }; applications = @{ includeApplications = @('All') } }; grantControls = @{ builtInControls = @() } }
            )
        }

        $result = @($raw | ConvertTo-SAWConditionalAccessInventory)

        $result.Count | Should -Be 2
    }
}
