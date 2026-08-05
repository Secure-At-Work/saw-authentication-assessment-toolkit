function ConvertTo-SAWNormalizedAuthorizationPolicy {
    <#
    .SYNOPSIS
        Detects a real, Microsoft-documented SSPR misconfiguration: admin SSPR disabled
        tenant-wide, but admins not excluded from the regular user-facing SSPR policy.
    .DESCRIPTION
        By default, administrator accounts get SSPR through their own built-in "two-gate"
        policy (two methods required, no security questions), entirely separate from whatever
        the tenant's general SSPR configuration says for end users - so an admin showing
        SSPR-enabled while the general tenant SSPR setting looks "off" is expected default
        behavior, not a bug. allowedToUseSSPR on the authorization policy is the actual switch
        that turns admin SSPR off - and Microsoft's own documentation
        (https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy,
        "Administrator reset policy differences") explicitly warns about the trap this checks
        for: "When the password reset policy for administrators is disabled, administrators
        can't reset their passwords via SSPR, even if they are in scope of the password reset
        policy for users... they're still prompted to register but see a message indicating
        they can't register any methods. To avoid this experience, explicitly exclude
        administrators from the password reset policy for users when the password reset policy
        for administrators is disabled."

        Only emits a fact (Category/Setting/State) when allowedToUseSSPR is explicitly false -
        when it's true or absent (the default - admin SSPR enabled via the built-in policy),
        this whole question doesn't apply, so nothing is emitted and the rules engine correctly
        shows Grey rather than a fabricated pass. That Grey is itself informative: it means
        admin SSPR is currently enabled tenant-wide (the default), which is worth knowing even
        though it's "not applicable" in the pass/fail sense.

        Admin-enabled-for-SSPR detection reuses userRegistrationDetails.isSsprEnabled per admin
        user (already collected by Get-SAWRegistration.ps1) - no extra Graph call.
    .PARAMETER AuthorizationPolicy
        The object returned by Get-SAWAuthorizationPolicy (has .allowedToUseSSPR).
    .PARAMETER RegistrationRaw
        The object returned by Get-SAWRegistration (has a .value array of user records, each
        with .isAdmin and .isSsprEnabled).
    .OUTPUTS
        Hashtable[] - empty when not applicable, otherwise one Category/Setting/State fact.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$AuthorizationPolicy,

        [Parameter(Mandatory)]
        [object]$RegistrationRaw
    )

    $adminSsprAllowed = $AuthorizationPolicy.allowedToUseSSPR
    if ($adminSsprAllowed -ne $false) {
        Write-Verbose 'ConvertTo-SAWNormalizedAuthorizationPolicy: allowedToUseSSPR is true/absent (admin SSPR enabled via the default built-in policy) - exclusion check not applicable'
        return @()
    }

    $users = @($RegistrationRaw.value)
    $adminsStillSsprEnabled = @($users | Where-Object { $_.isAdmin -and $_.isSsprEnabled })

    if ($adminsStillSsprEnabled.Count -gt 0) {
        foreach ($admin in $adminsStillSsprEnabled) {
            Write-Verbose "ConvertTo-SAWNormalizedAuthorizationPolicy: admin '$($admin.userPrincipalName)' still shows isSsprEnabled=true despite allowedToUseSSPR=false - will see a broken SSPR registration prompt"
        }
    }

    @{
        Category = 'Registration'
        Setting  = 'Admins Excluded From User SSPR Policy When Admin SSPR Is Disabled'
        State    = if ($adminsStillSsprEnabled.Count -eq 0) { 'Enabled' } else { 'Disabled' }
    }
}
