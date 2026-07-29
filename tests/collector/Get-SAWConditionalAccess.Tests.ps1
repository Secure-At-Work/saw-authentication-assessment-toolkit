BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWConditionalAccess.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWNormalizedConditionalAccess.ps1"

    function Get-MgContext { }
    function Invoke-MgGraphRequest { param($Method, $Uri) }

    function New-SAWTestCaPolicy {
        param(
            [string]$State = 'enabled',
            [string[]]$IncludeUsers = @('All'),
            [string[]]$IncludeApplications = @('All'),
            [string[]]$IncludeRoles = @(),
            [string[]]$ClientAppTypes = @('all'),
            [string[]]$BuiltInControls = @(),
            [object]$AuthenticationStrength = $null
        )
        return @{
            state      = $State
            conditions = @{
                users        = @{ includeUsers = $IncludeUsers; includeRoles = $IncludeRoles }
                applications = @{ includeApplications = $IncludeApplications }
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

    It 'returns Disabled for every capability when there are no policies at all' {
        $raw = @{ value = @() }

        $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

        $result.Count | Should -Be 5
        ($result | Where-Object { $_.State -eq 'Enabled' }).Count | Should -Be 0
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
}
