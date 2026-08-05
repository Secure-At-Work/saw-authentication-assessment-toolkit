function ConvertTo-SAWMethodUsageRoster {
    <#
    .SYNOPSIS
        Cross-references registered authentication methods against sign-in activity, and flags
        any registered method not observed as actually used in a wider analysis window.
    .DESCRIPTION
        Registration alone (ConvertTo-SAWUserRegistrationRoster.ps1) only answers "is a method
        currently registered" - it says nothing about whether that method is actually usable in
        practice. This matters most for a device-bound method like Windows Hello for Business
        (see IsWhfbOnly), but also more generally: a registered method nobody has actually used
        in months is a real question mark, whether that's because the device it lived on is
        gone, the user fell back to a weaker method day-to-day, or the registration is simply
        stale.

        Takes an already-built roster (ConvertTo-SAWUserRegistrationRoster.ps1's output) and
        raw sign-in log data covering the analysis window, and adds two fields per user:
        UnusedRegisteredMethods (comma-joined list of registered methods not observed as used)
        and HasUnusedRegisteredMethod. A method only counts as "used" if at least one sign-in in
        the window has a successful authenticationDetails step for it - a failed attempt doesn't
        count, but the step succeeding is what matters, not necessarily the overall sign-in
        (a sign-in can still fail later in the flow after a real factor genuinely succeeded).

        Method-name mapping caveat: userRegistrationDetails.methodsRegistered and
        signIns.authenticationDetails[].authenticationMethod are two different Microsoft Graph
        vocabularies (e.g. "fido2" vs "FIDO2 security key") with no documented 1:1 crosswalk.
        $script:methodUsageNameMap below covers the well-established, high-confidence pairings
        only (password, FIDO2, WHfB, TAP, SMS, voice, Authenticator push/OTP, email, certificate)
        - confirmed against Microsoft's own sign-in log documentation, but NOT verified against
        a real tenant's actual field values, which is worth doing before trusting this in
        production. A registered method type with no entry in the map is deliberately left out
        of UnusedRegisteredMethods entirely (neither flagged used nor unused) rather than risking
        a false "unused" claim from a wrong or missing string match - most notably this means
        passkey variants (passKeyDeviceBound*) are NOT currently evaluated by this function.
    .PARAMETER Roster
        Output of ConvertTo-SAWUserRegistrationRoster.ps1 - one hashtable per user.
    .PARAMETER SignInLogs
        The object returned by Get-SAWSignInLogs (has a .value array of sign-in entries),
        collected over whatever window the caller wants "recently used" to mean - this function
        does no date filtering of its own, it trusts the window it's given.
    .OUTPUTS
        Hashtable[] - the same shape as -Roster, each entry with two added fields:
        UnusedRegisteredMethods (comma-joined string, possibly empty) and
        HasUnusedRegisteredMethod (bool).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Roster,

        [Parameter(Mandatory)]
        [object]$SignInLogs
    )

    # registered-method-name -> the authenticationDetails.authenticationMethod string(s) Graph
    # is documented to use for a successful sign-in step with that method. High-confidence,
    # well-established values only - see the caveat in .DESCRIPTION.
    $methodUsageNameMap = @{
        fido2                    = @('FIDO2 security key')
        windowsHelloForBusiness  = @('Windows Hello for Business')
        microsoftAuthenticatorPush = @('Mobile app notification')
        softwareOneTimePasscode = @('Mobile app verification code')
        mobilePhone              = @('Text message', 'Voice call', 'Mobile phone')
        alternateMobilePhone     = @('Text message', 'Voice call', 'Mobile phone')
        officePhone              = @('Voice call', 'Office phone')
        temporaryAccessPass      = @('Temporary Access Pass')
        email                    = @('Email address')
        certificate              = @('Certificate')
    }

    $signIns = @($SignInLogs.value)
    if (-not $signIns) { $signIns = @() }

    # userPrincipalName (lowercased) -> Set of authenticationMethod strings used successfully
    # anywhere in the window, built once rather than re-scanning all sign-ins per user.
    $usedMethodsByUser = @{}
    foreach ($signIn in $signIns) {
        $upn = $signIn.userPrincipalName
        if (-not $upn) { continue }
        $upnKey = $upn.ToLowerInvariant()

        $details = @($signIn.authenticationDetails)
        if (-not $details) { continue }

        foreach ($step in $details) {
            if (-not $step.succeeded) { continue }
            if (-not $step.authenticationMethod) { continue }

            if (-not $usedMethodsByUser.ContainsKey($upnKey)) {
                $usedMethodsByUser[$upnKey] = @{}
            }
            $usedMethodsByUser[$upnKey][$step.authenticationMethod] = $true
        }
    }

    $result = foreach ($user in $Roster) {
        $registeredMethods = @()
        if ($user.MethodsRegistered) {
            $registeredMethods = @($user.MethodsRegistered -split ',\s*' | Where-Object { $_ })
        }

        $upnKey = $null
        if ($user.UserPrincipalName) { $upnKey = $user.UserPrincipalName.ToLowerInvariant() }
        $usedMethods = @{}
        if ($upnKey -and $usedMethodsByUser.ContainsKey($upnKey)) {
            $usedMethods = $usedMethodsByUser[$upnKey]
        }

        $unusedMethods = @()
        foreach ($method in $registeredMethods) {
            if (-not $methodUsageNameMap.ContainsKey($method)) {
                # No confident mapping for this method type - skip rather than guess.
                continue
            }
            $candidateNames = $methodUsageNameMap[$method]
            $wasUsed = $false
            foreach ($name in $candidateNames) {
                if ($usedMethods.ContainsKey($name)) { $wasUsed = $true; break }
            }
            if (-not $wasUsed) { $unusedMethods += $method }
        }

        $userCopy = $user.Clone()
        $userCopy['UnusedRegisteredMethods'] = ($unusedMethods -join ', ')
        $userCopy['HasUnusedRegisteredMethod'] = ($unusedMethods.Count -gt 0)
        $userCopy
    }

    , @($result)
}
