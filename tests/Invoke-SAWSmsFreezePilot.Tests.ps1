Describe 'Invoke-SAWSmsFreezePilot' {
    It 'maps current SMS users into a pilot-safe allowlist with a dry-run plan' {
        $users = @(
            @{ id = 'u1'; userPrincipalName = 'alice@contoso.com'; methods = @(@{ @odata.type = '#microsoft.graph.phoneAuthenticationMethod'; phoneType = 'mobile'; smsSignInState = 'notAllowed' }) },
            @{ id = 'u2'; userPrincipalName = 'bob@contoso.com'; methods = @() },
            @{ id = 'u3'; userPrincipalName = 'carol@contoso.com'; methods = @(@{ @odata.type = '#microsoft.graph.phoneAuthenticationMethod'; phoneType = 'alternateMobile'; smsSignInState = 'notAllowed' }) }
        )

        $plan = Get-SAWSmsPilotPlan -Users $users -GroupName 'SMS-Allowed-CurrentUsers'

        $plan.GroupName | Should -Be 'SMS-Allowed-CurrentUsers'
        $plan.AllowedUsers.Count | Should -Be 2
        $plan.AllowedUsers[0] | Should -Be 'alice@contoso.com'
        $plan.AllowedUsers[1] | Should -Be 'carol@contoso.com'
        $plan.ExcludedUsers.Count | Should -Be 1
        $plan.ExcludedUsers[0] | Should -Be 'bob@contoso.com'
    }

    It 'keeps a small exception list outside the main allowlist so a pilot can exclude some users intentionally' {
        $users = @(
            @{ id = 'u1'; userPrincipalName = 'alice@contoso.com'; methods = @(@{ '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod'; phoneType = 'mobile' }) },
            @{ id = 'u2'; userPrincipalName = 'bob@contoso.com'; methods = @(@{ '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod'; phoneType = 'mobile' }) },
            @{ id = 'u3'; userPrincipalName = 'carol@contoso.com'; methods = @() }
        )

        $plan = Get-SAWSmsPilotPlan -Users $users -GroupName 'SMS-Allowed-CurrentUsers' -ExceptionUserPrincipalNames @('bob@contoso.com')

        $plan.AllowedUsers | Should -Be @('alice@contoso.com')
        $plan.ExceptionUsers | Should -Be @('bob@contoso.com')
        $plan.ExcludedUsers | Should -Be @('carol@contoso.com')
    }

    It 'requires an explicit pilot group name or object id before applying the freeze' {
        { Set-SAWSmsFreezePolicy -Apply -DryRun:$false -GroupObjectId $null } | Should -Throw
    }

    It 'loads custom SMS pilot names from a config file when no explicit names are passed' {
        $configPath = Join-Path $PSScriptRoot '..' 'config' 'config.sample.json'

        $config = Get-SAWSmsFreezePilotConfig -ConfigPath $configPath

        $config.GroupName | Should -Be 'SAW-SMS-CurrentUsers-Allowed'
        $config.ExceptionGroupName | Should -Be 'SAW-SMS-Exceptions'
    }

    It 'prefers explicit parameter values over config values when both are present' {
        $configPath = Join-Path $PSScriptRoot '..' 'config' 'config.sample.json'

        $resolved = Resolve-SAWSmsPilotNames -ConfigPath $configPath -GroupName 'Custom-Allowlist' -ExceptionGroupName 'Custom-Exceptions'

        $resolved.GroupName | Should -Be 'Custom-Allowlist'
        $resolved.ExceptionGroupName | Should -Be 'Custom-Exceptions'
    }
}
