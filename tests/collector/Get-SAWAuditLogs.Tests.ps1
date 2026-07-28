BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWAuditLogs.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWNormalizedAuditLogs.ps1"

    function Get-MgContext { }
    function Invoke-MgGraphRequest { param($Method, $Uri) }

    # Must match the placeholder break-glass account id used in
    # ConvertTo-SAWNormalizedAuditLogs.ps1 and the Conditional Access sample data.
    $script:BreakGlassUserId = '99999999-9999-9999-9999-999999999999'
}

Describe 'Get-SAWAuditLogs' {
    Context '-UseSampleData' {
        It 'returns the bundled sample data' {
            $result = Get-SAWAuditLogs -UseSampleData
            $result.value | Should -Not -BeNullOrEmpty
        }

        It 'throws if the sample data file does not exist' {
            { Get-SAWAuditLogs -UseSampleData -SampleDataPath 'C:\does\not\exist.json' } | Should -Throw
        }
    }

    Context 'live Graph calls' {
        It 'throws when not connected to Microsoft Graph' {
            Mock Get-MgContext { $null }
            { Get-SAWAuditLogs } | Should -Throw
        }

        It 'calls the directory audits endpoint scoped to an activityDateTime filter' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest { @{ value = @() } }

            Get-SAWAuditLogs | Out-Null

            # Not an exact URI match - the filter's date value is computed at call time.
            # This endpoint must be date-bounded: unfiltered, the sibling Get-SAWSignInLogs
            # collector timed out against a live tenant (see
            # docs/powershell-coding-notes.md), and this collector has the same shape.
            Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                $Method -eq 'GET' -and
                $Uri -like 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?*' -and
                $Uri -match '\$filter=activityDateTime%20ge%20'
            }
        }

        It 'follows @odata.nextLink to collect every page' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            $script:pageNumber = 0
            Mock Invoke-MgGraphRequest {
                $script:pageNumber++
                if ($script:pageNumber -eq 1) {
                    return @{
                        value             = @(@{ id = 'page1-audit' })
                        '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=abc'
                    }
                }
                return @{ value = @(@{ id = 'page2-audit' }) }
            }

            $result = Get-SAWAuditLogs

            $result.value.Count | Should -Be 2
            Should -Invoke Invoke-MgGraphRequest -Times 2
        }

        It 'stops paginating once -MaxPages is reached' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest {
                @{
                    value             = @(@{ id = 'audit-entry' })
                    '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=nextpage'
                }
            }

            $result = Get-SAWAuditLogs -MaxPages 3

            $result.value.Count | Should -Be 3
            Should -Invoke Invoke-MgGraphRequest -Times 3
        }
    }
}

Describe 'ConvertTo-SAWNormalizedAuditLogs' {
    It 'flags a password change targeting the break-glass account' {
        $raw = @{
            value = @(
                @{
                    activityDisplayName = 'Reset user password'
                    initiatedBy         = @{ user = @{ userPrincipalName = 'alice.admin@contoso.com' }; app = $null }
                    targetResources     = @(@{ id = $script:BreakGlassUserId })
                }
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedAuditLogs

        ($result | Where-Object { $_.Setting -eq 'No Unexpected Break Glass Credential Changes' }).State | Should -Be 'Disabled'
    }

    It 'does not flag a password change targeting a regular user' {
        $raw = @{
            value = @(
                @{
                    activityDisplayName = 'Change user password'
                    initiatedBy         = @{ user = @{ userPrincipalName = 'bob.admin@contoso.com' }; app = $null }
                    targetResources     = @(@{ id = 'some-other-user-id' })
                }
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedAuditLogs

        ($result | Where-Object { $_.Setting -eq 'No Unexpected Break Glass Credential Changes' }).State | Should -Be 'Enabled'
    }

    It 'does not flag a non-password change targeting the break-glass account' {
        $raw = @{
            value = @(
                @{
                    activityDisplayName = 'Update user'
                    initiatedBy         = @{ user = @{ userPrincipalName = 'alice.admin@contoso.com' }; app = $null }
                    targetResources     = @(@{ id = $script:BreakGlassUserId })
                }
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedAuditLogs

        ($result | Where-Object { $_.Setting -eq 'No Unexpected Break Glass Credential Changes' }).State | Should -Be 'Enabled'
    }

    It 'flags a Conditional Access policy change initiated by an application' {
        $raw = @{
            value = @(
                @{
                    activityDisplayName = 'Update conditional access policy'
                    initiatedBy         = @{ user = $null; app = @{ displayName = 'Contoso CI/CD Pipeline' } }
                    targetResources     = @(@{ id = 'ca-policy-id' })
                }
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedAuditLogs

        ($result | Where-Object { $_.Setting -eq 'Conditional Access Changes Not Made By Applications' }).State | Should -Be 'Disabled'
    }

    It 'does not flag a Conditional Access policy change initiated by a named admin' {
        $raw = @{
            value = @(
                @{
                    activityDisplayName = 'Update conditional access policy'
                    initiatedBy         = @{ user = @{ userPrincipalName = 'alice.admin@contoso.com' }; app = $null }
                    targetResources     = @(@{ id = 'ca-policy-id' })
                }
            )
        }

        $result = $raw | ConvertTo-SAWNormalizedAuditLogs

        ($result | Where-Object { $_.Setting -eq 'Conditional Access Changes Not Made By Applications' }).State | Should -Be 'Enabled'
    }

    It 'reports both checks Enabled when there are no audit entries at all' {
        $raw = @{ value = @() }

        $result = $raw | ConvertTo-SAWNormalizedAuditLogs

        ($result | Where-Object { $_.State -eq 'Disabled' }).Count | Should -Be 0
    }
}
