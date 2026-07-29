function ConvertTo-SAWNormalizedRegistration {
    <#
    .SYNOPSIS
        Normalizes raw per-user registration details into Secure At Work capability checks.
    .DESCRIPTION
        Scans every user's registration record and derives three aggregate facts: whether
        every admin account is MFA registered, whether overall MFA registration coverage
        across all users meets a 90% target, and - among users the tenant actually allows to
        use self-service password reset (isSsprEnabled) - whether SSPR registration coverage
        meets a 90% target. All thresholds are evaluated here (not in a rule JSON) per spec
        section 8 - rules stay pure Category/Setting/Expected comparisons.

        Whether SSPR should be enabled at all is a customer-baseline question (a fully
        cloud-native, passwordless-only tenant may not need SSPR - there's no password to
        reset), not something this normalizer decides; it only reports observed coverage
        among users the tenant has SSPR turned on for. There is no supported Microsoft Graph
        endpoint for tenant-wide SSPR scope/policy (which users/groups) - only the per-user
        effective state collected here.
    .PARAMETER RawResponse
        The object returned by Get-SAWRegistration (has a .value array of user records).
    .OUTPUTS
        Hashtable[]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$RawResponse
    )

    begin {
        function ConvertTo-SAWStateLabel {
            param([bool]$Value)
            if ($Value) { return 'Enabled' }
            return 'Disabled'
        }
    }

    process {
        $users = $RawResponse.value
        if (-not $users) { $users = @() }

        $totalUsers = 0
        $mfaRegisteredUsers = 0
        $adminUsers = 0
        $adminUsersMissingMfa = 0
        $ssprEnabledUsers = 0
        $ssprRegisteredUsers = 0

        foreach ($user in $users) {
            $totalUsers++
            if ($user.isMfaRegistered) { $mfaRegisteredUsers++ }
            if ($user.isAdmin) {
                $adminUsers++
                if (-not $user.isMfaRegistered) {
                    $adminUsersMissingMfa++
                    Write-Verbose "ConvertTo-SAWNormalizedRegistration: admin '$($user.userPrincipalName)' is not MFA registered"
                }
            }
            if ($user.isSsprEnabled) {
                $ssprEnabledUsers++
                if ($user.isSsprRegistered) { $ssprRegisteredUsers++ }
            }
        }

        $allAdminsMfaRegistered = ($adminUsers -gt 0) -and ($adminUsersMissingMfa -eq 0)

        $coveragePercent = 0
        $coverageMeetsTarget = $false
        if ($totalUsers -gt 0) {
            $coveragePercent = $mfaRegisteredUsers / $totalUsers * 100
            $coverageMeetsTarget = $coveragePercent -ge 90
        }

        Write-Verbose ("ConvertTo-SAWNormalizedRegistration: {0}/{1} users MFA registered ({2:N1}%); {3}/{4} admins missing MFA" -f `
            $mfaRegisteredUsers, $totalUsers, $coveragePercent, $adminUsersMissingMfa, $adminUsers)

        @{
            Category = 'Registration'
            Setting  = 'All Privileged Admins MFA Registered'
            State    = ConvertTo-SAWStateLabel $allAdminsMfaRegistered
        }
        @{
            Category = 'Registration'
            Setting  = 'Overall MFA Registration Coverage At Least 90 Percent'
            State    = ConvertTo-SAWStateLabel $coverageMeetsTarget
        }

        if ($ssprEnabledUsers -gt 0) {
            $ssprCoveragePercent = $ssprRegisteredUsers / $ssprEnabledUsers * 100
            $ssprCoverageMeetsTarget = $ssprCoveragePercent -ge 90

            Write-Verbose ("ConvertTo-SAWNormalizedRegistration: {0}/{1} SSPR-enabled users are SSPR registered ({2:N1}%)" -f `
                $ssprRegisteredUsers, $ssprEnabledUsers, $ssprCoveragePercent)

            @{
                Category = 'Registration'
                Setting  = 'SSPR Registration Coverage At Least 90 Percent (Among SSPR-Enabled Users)'
                State    = ConvertTo-SAWStateLabel $ssprCoverageMeetsTarget
            }
        }
        else {
            Write-Verbose 'ConvertTo-SAWNormalizedRegistration: no users are SSPR-enabled - SSPR coverage check not applicable'
        }
    }
}
