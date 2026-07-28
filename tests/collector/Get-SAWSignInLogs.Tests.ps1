BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWSignInLogs.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWNormalizedSignInLogs.ps1"

    function Get-MgContext { }
    function Invoke-MgGraphRequest { param($Method, $Uri) }

    function New-SAWTestSignIn {
        param(
            [string]$ClientAppUsed = 'Browser',
            [string]$AuthenticationProtocol = 'oAuth2',
            [int]$ErrorCode = 0
        )
        return @{
            clientAppUsed         = $ClientAppUsed
            authenticationProtocol = $AuthenticationProtocol
            status                = @{ errorCode = $ErrorCode }
        }
    }
}

Describe 'Get-SAWSignInLogs' {
    Context '-UseSampleData' {
        It 'returns the bundled sample data' {
            $result = Get-SAWSignInLogs -UseSampleData
            $result.value | Should -Not -BeNullOrEmpty
        }

        It 'throws if the sample data file does not exist' {
            { Get-SAWSignInLogs -UseSampleData -SampleDataPath 'C:\does\not\exist.json' } | Should -Throw
        }
    }

    Context 'live Graph calls' {
        It 'throws when not connected to Microsoft Graph' {
            Mock Get-MgContext { $null }
            { Get-SAWSignInLogs } | Should -Throw
        }

        It 'calls the sign-ins endpoint scoped to a createdDateTime filter' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest { @{ value = @() } }

            Get-SAWSignInLogs | Out-Null

            # Not an exact URI match - the filter's date value is computed at call time
            # (see Get-SAWAuditLogs.Tests.ps1 for why this endpoint must be date-bounded:
            # unfiltered, it timed out against a live tenant per
            # docs/powershell-coding-notes.md).
            Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                $Method -eq 'GET' -and
                $Uri -like 'https://graph.microsoft.com/v1.0/auditLogs/signIns?*' -and
                $Uri -match '\$filter=createdDateTime%20ge%20'
            }
        }

        It 'stops paginating once -MaxPages is reached' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest {
                @{
                    value             = @(@{ id = 'signin' })
                    '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=nextpage'
                }
            }

            $result = Get-SAWSignInLogs -MaxPages 3

            $result.value.Count | Should -Be 3
            Should -Invoke Invoke-MgGraphRequest -Times 3
        }

        It 'follows @odata.nextLink to collect every page' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            $script:pageNumber = 0
            Mock Invoke-MgGraphRequest {
                $script:pageNumber++
                if ($script:pageNumber -eq 1) {
                    return @{
                        value             = @(@{ id = 'page1-signin' })
                        '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=abc'
                    }
                }
                return @{ value = @(@{ id = 'page2-signin' }) }
            }

            $result = Get-SAWSignInLogs

            $result.value.Count | Should -Be 2
            Should -Invoke Invoke-MgGraphRequest -Times 2
        }
    }
}

Describe 'ConvertTo-SAWNormalizedSignInLogs' {
    It 'flags a successful legacy authentication sign-in' {
        $raw = @{ value = @( (New-SAWTestSignIn -ClientAppUsed 'IMAP4' -ErrorCode 0) ) }

        $result = $raw | ConvertTo-SAWNormalizedSignInLogs

        ($result | Where-Object { $_.Setting -eq 'No Successful Legacy Authentication Sign-ins' }).State | Should -Be 'Disabled'
    }

    It 'does not flag a failed legacy authentication attempt' {
        $raw = @{ value = @( (New-SAWTestSignIn -ClientAppUsed 'IMAP4' -ErrorCode 50126) ) }

        $result = $raw | ConvertTo-SAWNormalizedSignInLogs

        ($result | Where-Object { $_.Setting -eq 'No Successful Legacy Authentication Sign-ins' }).State | Should -Be 'Enabled'
    }

    It 'flags a successful device code flow sign-in' {
        $raw = @{ value = @( (New-SAWTestSignIn -AuthenticationProtocol 'deviceCode' -ErrorCode 0) ) }

        $result = $raw | ConvertTo-SAWNormalizedSignInLogs

        ($result | Where-Object { $_.Setting -eq 'No Successful Device Code Flow Sign-ins' }).State | Should -Be 'Disabled'
    }

    It 'reports both checks Enabled when sign-ins are all normal browser/oAuth2' {
        $raw = @{ value = @( (New-SAWTestSignIn), (New-SAWTestSignIn) ) }

        $result = $raw | ConvertTo-SAWNormalizedSignInLogs

        ($result | Where-Object { $_.Setting -eq 'No Successful Legacy Authentication Sign-ins' }).State | Should -Be 'Enabled'
        ($result | Where-Object { $_.Setting -eq 'No Successful Device Code Flow Sign-ins' }).State | Should -Be 'Enabled'
    }

    It 'reports both checks Enabled when there are no sign-ins at all' {
        $raw = @{ value = @() }

        $result = $raw | ConvertTo-SAWNormalizedSignInLogs

        ($result | Where-Object { $_.State -eq 'Disabled' }).Count | Should -Be 0
    }
}
