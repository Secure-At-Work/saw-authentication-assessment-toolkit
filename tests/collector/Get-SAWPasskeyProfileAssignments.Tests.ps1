BeforeAll {
    . "$PSScriptRoot/../../src/collector/Get-SAWPasskeyProfileAssignments.ps1"
    . "$PSScriptRoot/../../src/Invoke-SAWGraphRequest.ps1"
}

Describe 'Get-SAWPasskeyProfileAssignments' {
    BeforeEach {
        $script:roster = @(
            @{ UserId = 'user-1'; UserPrincipalName = 'one@contoso.com' }
            @{ UserId = 'user-2'; UserPrincipalName = 'two@contoso.com' }
        )
    }

    It 'assigns profiles targeted to all users' {
        $config = @{
            passkeyProfiles = @(@{ id = 'profile-a' })
            includeTargets = @(@{ id = 'all_users'; allowedPasskeyProfiles = @('profile-a') })
        }

        $result = Get-SAWPasskeyProfileAssignments -Fido2Configuration $config -Roster $script:roster

        $result.IsKnown | Should -BeTrue
        $result.ByUserId['user-1'] | Should -Contain 'profile-a'
        $result.ByUserId['user-2'] | Should -Contain 'profile-a'
    }

    It 'assigns profiles to an individual user target' {
        $config = @{
            passkeyProfiles = @(@{ id = 'profile-a' })
            includeTargets = @(@{ id = 'user-2'; targetType = 'user'; allowedPasskeyProfiles = @('profile-a') })
        }

        $result = Get-SAWPasskeyProfileAssignments -Fido2Configuration $config -Roster $script:roster

        $result.ByUserId['user-1'].Count | Should -Be 0
        $result.ByUserId['user-2'] | Should -Contain 'profile-a'
    }

    It 'resolves group assignments using read-only Graph membership' {
        $config = @{
            passkeyProfiles = @(@{ id = 'profile-a' })
            includeTargets = @(@{ id = 'group-1'; targetType = 'group'; allowedPasskeyProfiles = @('profile-a') })
        }
        Mock Invoke-SAWGraphRequest { @{ value = @(@{ id = 'user-2' }) } }

        $result = Get-SAWPasskeyProfileAssignments -Fido2Configuration $config -Roster $script:roster

        $result.IsKnown | Should -BeTrue
        $result.ByUserId['user-1'].Count | Should -Be 0
        $result.ByUserId['user-2'] | Should -Contain 'profile-a'
        Should -Invoke Invoke-SAWGraphRequest -Times 1 -ParameterFilter { $Uri -match '/groups/group-1/transitiveMembers/' }
    }

    It 'marks group-targeted profiles unknown in sample mode rather than guessing membership' {
        $config = @{
            passkeyProfiles = @(@{ id = 'profile-a' })
            includeTargets = @(@{ id = 'group-1'; targetType = 'group'; allowedPasskeyProfiles = @('profile-a') })
        }

        $result = Get-SAWPasskeyProfileAssignments -Fido2Configuration $config -Roster $script:roster -UseSampleData

        $result.IsKnown | Should -BeFalse
        $result.UnresolvedTargetIds | Should -Contain 'group-1'
    }

    It 'marks profile assignments unknown when the roster has no Graph user IDs' {
        $config = @{
            passkeyProfiles = @(@{ id = 'profile-a' })
            includeTargets = @(@{ id = 'all_users'; allowedPasskeyProfiles = @('profile-a') })
        }

        $result = Get-SAWPasskeyProfileAssignments -Fido2Configuration $config -Roster @(@{ UserPrincipalName = 'one@contoso.com' })

        $result.IsKnown | Should -BeFalse
        $result.UnresolvedTargetIds | Should -Contain 'user IDs unavailable'
    }

    It 'ignores FIDO2 exclude targets when resolving managed-campaign profile eligibility' {
        $config = @{
            passkeyProfiles = @(@{ id = 'profile-a' })
            includeTargets = @(@{ id = 'all_users'; allowedPasskeyProfiles = @('profile-a') })
            excludeTargets = @(@{ id = 'user-2'; targetType = 'user' })
        }

        $result = Get-SAWPasskeyProfileAssignments -Fido2Configuration $config -Roster $script:roster

        $result.ByUserId['user-1'] | Should -Contain 'profile-a'
        $result.ByUserId['user-2'] | Should -Contain 'profile-a'
    }
}