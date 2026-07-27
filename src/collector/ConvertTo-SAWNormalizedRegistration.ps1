function ConvertTo-SAWNormalizedRegistration {
    <#
    .SYNOPSIS
        Normalizes raw per-user registration details into Secure At Work capability checks.
    .DESCRIPTION
        Scans every user's registration record and derives two aggregate facts:
        whether every admin account is MFA registered, and whether overall MFA
        registration coverage across all users meets an 90% target. Both thresholds
        are evaluated here (not in a rule JSON) per spec section 8 - rules stay
        pure Category/Setting/Expected comparisons.
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
    }
}
