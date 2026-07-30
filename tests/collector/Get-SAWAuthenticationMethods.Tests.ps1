BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWAuthenticationMethods.ps1"
    . "$PSScriptRoot/../../src/collector/ConvertTo-SAWNormalizedAuthenticationMethods.ps1"

    # Stub commands from Microsoft.Graph.Authentication so Mock has something to intercept
    # even when that module isn't installed in the test environment.
    function Get-MgContext { }
    function Invoke-MgGraphRequest { param($Method, $Uri) }
}

Describe 'Get-SAWAuthenticationMethods' {
    Context '-UseSampleData' {
        It 'returns the bundled sample data' {
            $result = Get-SAWAuthenticationMethods -UseSampleData
            $result | Should -Not -BeNullOrEmpty
            $result.authenticationMethodConfigurations | Should -Not -BeNullOrEmpty
        }

        It 'throws if the sample data file does not exist' {
            { Get-SAWAuthenticationMethods -UseSampleData -SampleDataPath 'C:\does\not\exist.json' } | Should -Throw
        }
    }

    Context 'live Graph calls' {
        It 'throws when not connected to Microsoft Graph' {
            Mock Get-MgContext { $null }
            { Get-SAWAuthenticationMethods } | Should -Throw
        }

        It 'calls the tenant-wide authenticationMethodsPolicy endpoint' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest {
                param($Method, $Uri)
                if ($Uri -like '*/beta/*') { return @{ optOutSettings = @{ passkeyDynamicMigration = $false } } }
                return @{ authenticationMethodConfigurations = @() }
            }

            Get-SAWAuthenticationMethods | Out-Null

            Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                $Method -eq 'GET' -and $Uri -eq 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
            }
        }

        It 'also calls the beta endpoint for optOutSettings and merges it onto the v1.0 response' {
            Mock Get-MgContext { @{ Account = 'assessor@contoso.com' } }
            Mock Invoke-MgGraphRequest {
                param($Method, $Uri)
                if ($Uri -like '*/beta/*') { return @{ optOutSettings = @{ passkeyDynamicMigration = $true } } }
                return @{ authenticationMethodConfigurations = @() }
            }

            $result = Get-SAWAuthenticationMethods

            Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter {
                $Method -eq 'GET' -and $Uri -eq 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy?$select=optOutSettings'
            }
            $result.optOutSettings.passkeyDynamicMigration | Should -BeTrue
        }
    }
}

Describe 'ConvertTo-SAWNormalizedAuthenticationMethods' {
    # Registration campaign / bootstrap facts (Category 'Registration') are always appended
    # after the per-method ones, so per-method assertions below filter to Category
    # 'Authentication Methods' rather than asserting on the raw total count.

    It 'maps a known method id to its display name and title-cases the state' {
        $raw = @{
            authenticationMethodConfigurations = @(
                @{ id = 'MicrosoftAuthenticator'; state = 'enabled' }
            )
        }

        $result = @($raw | ConvertTo-SAWNormalizedAuthenticationMethods | Where-Object { $_.Category -eq 'Authentication Methods' })

        $result.Count | Should -Be 1
        $result[0].Category | Should -Be 'Authentication Methods'
        $result[0].Setting | Should -Be 'Microsoft Authenticator'
        $result[0].State | Should -Be 'Enabled'
    }

    It 'falls back to the raw id when no display name mapping exists' {
        $raw = @{
            authenticationMethodConfigurations = @(
                @{ id = 'SomeFutureMethod'; state = 'disabled' }
            )
        }

        $result = @($raw | ConvertTo-SAWNormalizedAuthenticationMethods | Where-Object { $_.Category -eq 'Authentication Methods' })

        $result[0].Setting | Should -Be 'SomeFutureMethod'
        $result[0].State | Should -Be 'Disabled'
    }

    It 'emits one normalized entry per configured method' {
        $raw = @{
            authenticationMethodConfigurations = @(
                @{ id = 'Sms'; state = 'enabled' },
                @{ id = 'Voice'; state = 'enabled' },
                @{ id = 'Fido2'; state = 'disabled' }
            )
        }

        $result = @($raw | ConvertTo-SAWNormalizedAuthenticationMethods | Where-Object { $_.Category -eq 'Authentication Methods' })

        $result.Count | Should -Be 3
        ($result | Where-Object { $_.Setting -eq 'FIDO2' }).State | Should -Be 'Disabled'
    }

    Context 'registration campaign' {
        It 'reports the campaign as not actively enabled when state is "default"' {
            $raw = @{
                authenticationMethodConfigurations = @()
                registrationEnforcement            = @{
                    authenticationMethodsRegistrationCampaign = @{ state = 'default' }
                }
            }

            $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

            ($result | Where-Object { $_.Setting -eq 'Registration Campaign Actively Enabled' }).State | Should -Be 'Disabled'
        }

        It 'reports the campaign as not actively enabled when state is enabled but includeTargets is empty' {
            $raw = @{
                authenticationMethodConfigurations = @()
                registrationEnforcement            = @{
                    authenticationMethodsRegistrationCampaign = @{ state = 'enabled'; includeTargets = @() }
                }
            }

            $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

            ($result | Where-Object { $_.Setting -eq 'Registration Campaign Actively Enabled' }).State | Should -Be 'Disabled'
        }

        It 'reports the campaign as actively enabled when state is enabled with at least one target' {
            $raw = @{
                authenticationMethodConfigurations = @()
                registrationEnforcement            = @{
                    authenticationMethodsRegistrationCampaign = @{
                        state          = 'enabled'
                        includeTargets = @(@{ targetType = 'group'; id = 'all_users'; targetedAuthenticationMethod = 'microsoftAuthenticator' })
                    }
                }
            }

            $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

            ($result | Where-Object { $_.Setting -eq 'Registration Campaign Actively Enabled' }).State | Should -Be 'Enabled'
        }

        It 'omits the passkey-targeting check entirely when no campaign is active' {
            $raw = @{
                authenticationMethodConfigurations = @()
                registrationEnforcement            = @{
                    authenticationMethodsRegistrationCampaign = @{ state = 'default' }
                }
            }

            $result = @($raw | ConvertTo-SAWNormalizedAuthenticationMethods)

            ($result | Where-Object { $_.Setting -eq 'Registration Campaign Targets Passkey (FIDO2)' }) | Should -BeNullOrEmpty
        }

        It 'reports passkey-targeting Enabled when an active campaign targets fido2' {
            $raw = @{
                authenticationMethodConfigurations = @()
                registrationEnforcement            = @{
                    authenticationMethodsRegistrationCampaign = @{
                        state          = 'enabled'
                        includeTargets = @(@{ targetType = 'group'; id = 'all_users'; targetedAuthenticationMethod = 'fido2' })
                    }
                }
            }

            $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

            ($result | Where-Object { $_.Setting -eq 'Registration Campaign Targets Passkey (FIDO2)' }).State | Should -Be 'Enabled'
        }

        It 'reports passkey-targeting Disabled when an active campaign targets only microsoftAuthenticator' {
            $raw = @{
                authenticationMethodConfigurations = @()
                registrationEnforcement            = @{
                    authenticationMethodsRegistrationCampaign = @{
                        state          = 'enabled'
                        includeTargets = @(@{ targetType = 'group'; id = 'all_users'; targetedAuthenticationMethod = 'microsoftAuthenticator' })
                    }
                }
            }

            $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

            ($result | Where-Object { $_.Setting -eq 'Registration Campaign Targets Passkey (FIDO2)' }).State | Should -Be 'Disabled'
        }
    }

    Context 'phishing-resistant registration bootstrap' {
        It 'reports Enabled when FIDO2 self-service registration is allowed' {
            $raw = @{
                authenticationMethodConfigurations = @(
                    @{ id = 'Fido2'; state = 'enabled'; isSelfServiceRegistrationAllowed = $true },
                    @{ id = 'TemporaryAccessPass'; state = 'disabled' }
                )
            }

            $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

            ($result | Where-Object { $_.Setting -like 'Phishing-Resistant Registration Bootstrap*' }).State | Should -Be 'Enabled'
        }

        It 'reports Enabled when TAP is enabled, even if FIDO2 self-service is not allowed' {
            $raw = @{
                authenticationMethodConfigurations = @(
                    @{ id = 'Fido2'; state = 'disabled'; isSelfServiceRegistrationAllowed = $false },
                    @{ id = 'TemporaryAccessPass'; state = 'enabled' }
                )
            }

            $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

            ($result | Where-Object { $_.Setting -like 'Phishing-Resistant Registration Bootstrap*' }).State | Should -Be 'Enabled'
        }

        It 'reports Disabled when neither FIDO2 self-service nor TAP is available' {
            $raw = @{
                authenticationMethodConfigurations = @(
                    @{ id = 'Fido2'; state = 'disabled'; isSelfServiceRegistrationAllowed = $false },
                    @{ id = 'TemporaryAccessPass'; state = 'disabled' }
                )
            }

            $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

            ($result | Where-Object { $_.Setting -like 'Phishing-Resistant Registration Bootstrap*' }).State | Should -Be 'Disabled'
        }

        It 'reports Disabled when FIDO2 is enabled but self-service registration is not allowed, and TAP is off' {
            $raw = @{
                authenticationMethodConfigurations = @(
                    @{ id = 'Fido2'; state = 'enabled'; isSelfServiceRegistrationAllowed = $false },
                    @{ id = 'TemporaryAccessPass'; state = 'disabled' }
                )
            }

            $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

            ($result | Where-Object { $_.Setting -like 'Phishing-Resistant Registration Bootstrap*' }).State | Should -Be 'Disabled'
        }

        It 'reports Disabled when Fido2/TemporaryAccessPass configs are absent entirely' {
            $raw = @{ authenticationMethodConfigurations = @() }

            $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

            ($result | Where-Object { $_.Setting -like 'Phishing-Resistant Registration Bootstrap*' }).State | Should -Be 'Disabled'
        }
    }

    Context 'passkey dynamic migration opt-out (AUTH006)' {
        # true = opted OUT = tenant EXCLUDED from Microsoft's automatic passkey rollout.
        # Verified verbatim against Microsoft's own docs after an initial misread got this
        # backwards - see ConvertTo-SAWNormalizedAuthenticationMethods.ps1's .DESCRIPTION.
        $settingName = 'Passkey Dynamic Migration Not Opted Out'

        It 'reports Enabled (rollout applies) when optOutSettings is absent entirely' {
            $raw = @{ authenticationMethodConfigurations = @() }

            $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Enabled'
        }

        It 'reports Enabled (rollout applies) when passkeyDynamicMigration is explicitly false' {
            $raw = @{ authenticationMethodConfigurations = @(); optOutSettings = @{ passkeyDynamicMigration = $false } }

            $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Enabled'
        }

        It 'reports Disabled (tenant excluded from rollout) when passkeyDynamicMigration is true' {
            $raw = @{ authenticationMethodConfigurations = @(); optOutSettings = @{ passkeyDynamicMigration = $true } }

            $result = $raw | ConvertTo-SAWNormalizedAuthenticationMethods

            ($result | Where-Object { $_.Setting -eq $settingName }).State | Should -Be 'Disabled'
        }
    }
}
