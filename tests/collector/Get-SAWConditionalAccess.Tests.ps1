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
            [string[]]$BuiltInControls = @()
        )
        return @{
            state      = $State
            conditions = @{
                users        = @{ includeUsers = $IncludeUsers; includeRoles = $IncludeRoles }
                applications = @{ includeApplications = $IncludeApplications }
                clientAppTypes = $ClientAppTypes
            }
            grantControls = @{ builtInControls = $BuiltInControls }
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

    It 'returns Disabled for all three capabilities when there are no policies at all' {
        $raw = @{ value = @() }

        $result = $raw | ConvertTo-SAWNormalizedConditionalAccess

        $result.Count | Should -Be 3
        ($result | Where-Object { $_.State -eq 'Enabled' }).Count | Should -Be 0
    }
}
