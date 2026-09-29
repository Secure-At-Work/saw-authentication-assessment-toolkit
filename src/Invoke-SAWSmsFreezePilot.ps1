function Get-SAWSmsFreezePilotConfig {
    <#
    .SYNOPSIS
        Reads the SMS freeze pilot naming values from a config file if present.
    .DESCRIPTION
        Supports a default config file at config/config.json, with a fallback to
        config/config.sample.json for repository examples. The settings are intentionally
        lightweight: names for the allowlist and exception group only.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath
    )

    $defaultGroupName = 'SAW-SMS-CurrentUsers-Allowed'
    $defaultExceptionGroupName = 'SAW-SMS-Exceptions'

    if (-not $ConfigPath) {
        $defaultConfigPath = Join-Path (Join-Path $PSScriptRoot '..') 'config/config.json'
        if (-not (Test-Path $defaultConfigPath)) {
            $defaultConfigPath = Join-Path (Join-Path $PSScriptRoot '..') 'config/config.sample.json'
        }
        if (Test-Path $defaultConfigPath) {
            $ConfigPath = $defaultConfigPath
        }
    }

    $result = [ordered]@{
        GroupName = $defaultGroupName
        ExceptionGroupName = $defaultExceptionGroupName
    }

    if (-not $ConfigPath -or -not (Test-Path $ConfigPath)) {
        return $result
    }

    try {
        $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json -Depth 10
    }
    catch {
        Write-Verbose "Get-SAWSmsFreezePilotConfig: unable to parse config file '$ConfigPath'; using default names."
        return $result
    }

    $smsConfig = $null
    if ($config) {
        $smsConfig = $config.SMSFreezePilot
        if (-not $smsConfig) {
            $smsConfig = $config.SmsFreezePilot
        }
    }

    if ($smsConfig) {
        if ($smsConfig.GroupName) {
            $result.GroupName = [string]$smsConfig.GroupName
        }
        if ($smsConfig.ExceptionGroupName) {
            $result.ExceptionGroupName = [string]$smsConfig.ExceptionGroupName
        }
    }

    return $result
}

function Resolve-SAWSmsPilotNames {
    <#
    .SYNOPSIS
        Resolves SMS pilot group names, preferring explicit parameters over config values.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,

        [string]$GroupName,

        [string]$ExceptionGroupName
    )

    $config = Get-SAWSmsFreezePilotConfig -ConfigPath $ConfigPath

    $resolvedGroupName = if (-not [string]::IsNullOrWhiteSpace($GroupName)) { $GroupName } else { $config.GroupName }
    $resolvedExceptionGroupName = if (-not [string]::IsNullOrWhiteSpace($ExceptionGroupName)) { $ExceptionGroupName } else { $config.ExceptionGroupName }

    return [ordered]@{
        GroupName = $resolvedGroupName
        ExceptionGroupName = $resolvedExceptionGroupName
    }
}

function Get-SAWSmsPilotPlan {
    <#
    .SYNOPSIS
        Builds a safe pilot allowlist for the current SMS/voice authentication method.
    .DESCRIPTION
        Looks only at users who currently have a phone-based authentication method registered
        and treats them as the allowed cohort for a temporary freeze. Everyone else is kept in
        the excluded bucket, so the plan is explicit and suitable for a pilot before a broader
        rollback or policy change. An optional set of exception users can be kept in a separate
        group for review while other new entrants remain blocked.
    .PARAMETER Users
        List of user objects with an `id`, `userPrincipalName`, and `methods` array.
    .PARAMETER GroupName
        Security group that will be used as the allowlist target for the pilot.
    .PARAMETER ExceptionUserPrincipalNames
        Optional list of users to keep in a small exception group while the main pilot stays
        restricted to the current SMS cohort.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Users,

        [Parameter(Mandatory)]
        [string]$GroupName,

        [string[]]$ExceptionUserPrincipalNames = @()
    )

    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        throw 'GroupName cannot be empty when building an SMS freeze plan.'
    }

    $allowed = @()
    $excluded = @()
    $exceptions = @()
    $exceptionSet = @($ExceptionUserPrincipalNames | ForEach-Object { [string]$_ })

    foreach ($user in @($Users)) {
        $upn = [string]$user.userPrincipalName
        $methods = @($user.methods)
        $smsMethods = @($methods | Where-Object {
            $_ -and (
                $_.'@odata.type' -eq '#microsoft.graph.phoneAuthenticationMethod' -or
                $_.'@odata.type' -eq '#microsoft.graph.smsAuthenticationMethod' -or
                $_.phoneType -or
                $_.smsSignInState
            )
        })

        if ($smsMethods.Count -gt 0) {
            if ($exceptionSet -contains $upn) {
                $exceptions += $upn
            }
            else {
                $allowed += $upn
            }
        }
        else {
            $excluded += $upn
        }
    }

    return [ordered]@{
        GroupName                    = $GroupName
        AllowedUsers                 = @($allowed | Sort-Object -Unique)
        ExceptionUsers               = @($exceptions | Sort-Object -Unique)
        ExcludedUsers                = @($excluded | Sort-Object -Unique)
        ExceptionUserPrincipalNames  = @($exceptionSet | Sort-Object -Unique)
    }
}

function Get-SAWSmsCurrentUsers {
    <#
    .SYNOPSIS
        Returns all users with their currently registered authentication methods, limited to the
        phone-based entries relevant to the SMS pilot freeze.
    #>
    [CmdletBinding()]
    param()

    $result = Invoke-SAWGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,displayName&$top=999'
    $users = @()

    foreach ($user in @($result.value)) {
        $methods = Invoke-SAWGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)/authentication/methods"
        $users += [pscustomobject]@{
            id = $user.id
            userPrincipalName = $user.userPrincipalName
            displayName = $user.displayName
            methods = @($methods.value)
        }
    }

    return $users
}

function Resolve-SAWSmsAllowlistGroup {
    <#
    .SYNOPSIS
        Finds or creates the Entra security group used as the pilot allowlist.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,

        [string]$GroupObjectId,

        [switch]$CreateIfMissing
    )

    if ($GroupObjectId) {
        return [ordered]@{ id = $GroupObjectId; displayName = $GroupName }
    }

    $searchUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$GroupName'&`$select=id,displayName"
    $group = Invoke-SAWGraphRequest -Method GET -Uri $searchUri
    $match = @($group.value)[0]

    if ($match) {
        return [pscustomobject]@{ id = $match.id; displayName = $match.displayName }
    }

    if (-not $CreateIfMissing) {
        throw "No group named '$GroupName' was found and -CreateIfMissing was not supplied."
    }

    $mailNickname = ($GroupName -replace '[^A-Za-z0-9]', '').Substring(0, [Math]::Min(20, ($GroupName -replace '[^A-Za-z0-9]', '').Length))
    if (-not $mailNickname) { $mailNickname = 'smsallowlist' }

    $payload = [ordered]@{
        displayName = $GroupName
        description = 'Pilot allowlist for SMS/voice authentication freeze; only these users keep SMS MFA enabled during the pilot.'
        mailEnabled = $false
        mailNickname = $mailNickname
        securityEnabled = $true
    }

    $created = Invoke-SAWGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/groups' -Body $payload
    return [ordered]@{ id = $created.id; displayName = $created.displayName }
}

function Add-SAWSmsAllowlistMembers {
    <#
    .SYNOPSIS
        Adds users from the current SMS allowlist to the pilot group.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupObjectId,

        [Parameter(Mandatory)]
        [object[]]$Users
    )

    foreach ($user in @($Users)) {
        if (-not $user.id) { continue }

        $ref = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.id)"
        try {
            Invoke-SAWGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/groups/$GroupObjectId/members/`$ref" -Body @{ '@odata.id' = $ref }
        }
        catch {
            $message = $_.Exception.Message
            if ($message -match 'AlreadyExists|already exists|already a member') {
                Write-Verbose "User $($user.userPrincipalName) is already a member of the SMS pilot group."
                continue
            }
            throw
        }
    }
}

function Set-SAWSmsFreezePolicy {
    <#
    .SYNOPSIS
        Applies the pilot allowlist to the VoiceAndPhone authentication method configuration.
    .DESCRIPTION
        This is intentionally conservative: by default it uses a dry-run plan and requires an
        explicit -Apply flag to change the live tenant state. For a pilot, the group should be
        pre-populated with the users who currently have SMS/voice MFA; everyone else is excluded.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupObjectId,

        [switch]$Apply,

        [switch]$DryRun
    )

    if ([string]::IsNullOrWhiteSpace($GroupObjectId)) {
        throw 'A group object id is required before applying the SMS freeze policy.'
    }

    $policyUri = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/VoiceAndPhone'
    $body = [ordered]@{
        state = 'enabled'
        includeTargets = @(
            [ordered]@{
                id = $GroupObjectId
                targetType = 'group'
                isRegistrationRequired = $false
            }
        )
        excludeTargets = @()
    }

    if ($DryRun -and -not $Apply) {
        return [ordered]@{
            DryRun = $true
            Uri = $policyUri
            Body = $body
            Message = 'Dry-run only. No change has been applied to the live tenant.'
        }
    }

    if (-not $Apply) {
        throw 'Set-SAWSmsFreezePolicy requires either -Apply or -DryRun, and a target group id.'
    }

    Invoke-SAWGraphRequest -Method PATCH -Uri $policyUri -Body $body

    return [ordered]@{
        DryRun = $false
        Uri = $policyUri
        Body = $body
        Message = "SMS/voice auth method is now restricted to the allowlist group '$GroupObjectId'."
    }
}

function Invoke-SAWSmsFreezePilot {
    <#
    .SYNOPSIS
        Pilot-safe freeze of the current SMS/voice usage to an allowlist group.
    .DESCRIPTION
        This does not guess what the tenant should be; it uses the current state as the starting
        point and freezes the current SMS users into a dedicated security group. New users who
        are not in that group are not allowed to register or use the SMS/voice method until the
        pilot is reviewed and the broader rollout plan is approved.
    .PARAMETER GroupName
        Name of the security group used for the pilot allowlist. Defaults to a clear, specific name.
    .PARAMETER ConfigPath
        Optional path to a JSON config containing SMSFreezePilot.GroupName and SMSFreezePilot.ExceptionGroupName.
    .PARAMETER GroupObjectId
        Optional object id to reuse an existing group instead of creating one.
    .PARAMETER Apply
        If supplied, a live Graph change is made. Without it, this function returns a plan only.
    .PARAMETER DryRun
        Explicitly preview the plan without changing anything.
    .PARAMETER TenantId
        Optional tenant id passed through to Connect-SAWGraph.
    .PARAMETER ForceReauth
        Reconnects with a fresh token before the pilot change is applied.
    #>
    [CmdletBinding()]
    param(
        [string]$GroupName,

        [string]$ConfigPath,

        [string]$GroupObjectId,

        [string]$ExceptionGroupName,

        [string]$ExceptionGroupObjectId,

        [string[]]$ExceptionUsers = @(),

        [switch]$Apply,

        [switch]$DryRun,

        [string]$TenantId,

        [switch]$ForceReauth,

        [switch]$CreateGroupIfMissing,

        [switch]$CreateExceptionGroupIfMissing
    )

    $resolvedNames = Resolve-SAWSmsPilotNames -ConfigPath $ConfigPath -GroupName $GroupName -ExceptionGroupName $ExceptionGroupName
    $GroupName = $resolvedNames.GroupName
    $ExceptionGroupName = $resolvedNames.ExceptionGroupName

    if (-not $GroupName -and -not $GroupObjectId) {
        throw 'Either -GroupName or -GroupObjectId is required.'
    }

    $doDryRun = $DryRun -or (-not $Apply)
    $doApply = [bool]$Apply

    if ($doApply) {
        Connect-SAWGraph -TenantId $TenantId -ForceReauth:$ForceReauth | Out-Null
    }

    $users = Get-SAWSmsCurrentUsers
    $plan = Get-SAWSmsPilotPlan -Users $users -GroupName $GroupName -ExceptionUserPrincipalNames $ExceptionUsers

    if ($doDryRun) {
        return [ordered]@{
            DryRun = $true
            GroupName = $GroupName
            GroupObjectId = $GroupObjectId
            ExceptionGroupName = $ExceptionGroupName
            ExceptionGroupObjectId = $ExceptionGroupObjectId
            AllowedUsers = $plan.AllowedUsers
            ExceptionUsers = $plan.ExceptionUsers
            ExcludedUsers = $plan.ExcludedUsers
            Message = 'Preview only. No tenant changes were made.'
        }
    }

    $group = Resolve-SAWSmsAllowlistGroup -GroupName $GroupName -GroupObjectId $GroupObjectId -CreateIfMissing:$CreateGroupIfMissing
    $allowedUsers = foreach ($upn in $plan.AllowedUsers) {
        $match = $users | Where-Object { $_.userPrincipalName -eq $upn } | Select-Object -First 1
        if ($match) { $match }
    }

    if ($allowedUsers.Count -eq 0) {
        throw 'The SMS pilot allowlist is empty. No current SMS users were found to freeze into the group.'
    }

    Add-SAWSmsAllowlistMembers -GroupObjectId $group.id -Users $allowedUsers

    if ($ExceptionGroupName -and $plan.ExceptionUsers.Count -gt 0) {
        $exceptionGroup = Resolve-SAWSmsAllowlistGroup -GroupName $ExceptionGroupName -GroupObjectId $ExceptionGroupObjectId -CreateIfMissing:$CreateExceptionGroupIfMissing
        $exceptionUsers = foreach ($upn in $plan.ExceptionUsers) {
            $match = $users | Where-Object { $_.userPrincipalName -eq $upn } | Select-Object -First 1
            if ($match) { $match }
        }
        if ($exceptionUsers.Count -gt 0) {
            Add-SAWSmsAllowlistMembers -GroupObjectId $exceptionGroup.id -Users $exceptionUsers
        }
    }

    $result = Set-SAWSmsFreezePolicy -GroupObjectId $group.id -Apply

    return [ordered]@{
        DryRun = $false
        GroupName = $group.displayName
        GroupObjectId = $group.id
        ExceptionGroupName = if ($ExceptionGroupName) { $ExceptionGroupName } else { $null }
        ExceptionGroupObjectId = if ($ExceptionGroupObjectId) { $ExceptionGroupObjectId } else { $null }
        AllowedUsers = $plan.AllowedUsers
        ExceptionUsers = $plan.ExceptionUsers
        ExcludedUsers = $plan.ExcludedUsers
        PolicyUpdate = $result
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $params = @{}
    if ($PSBoundParameters.ContainsKey('GroupName')) { $params['GroupName'] = $GroupName }
    if ($PSBoundParameters.ContainsKey('ConfigPath')) { $params['ConfigPath'] = $ConfigPath }
    if ($PSBoundParameters.ContainsKey('GroupObjectId')) { $params['GroupObjectId'] = $GroupObjectId }
    if ($PSBoundParameters.ContainsKey('ExceptionGroupName')) { $params['ExceptionGroupName'] = $ExceptionGroupName }
    if ($PSBoundParameters.ContainsKey('ExceptionGroupObjectId')) { $params['ExceptionGroupObjectId'] = $ExceptionGroupObjectId }
    if ($PSBoundParameters.ContainsKey('ExceptionUsers')) { $params['ExceptionUsers'] = $ExceptionUsers }
    if ($PSBoundParameters.ContainsKey('Apply')) { $params['Apply'] = $Apply }
    if ($PSBoundParameters.ContainsKey('DryRun')) { $params['DryRun'] = $DryRun }
    if ($PSBoundParameters.ContainsKey('TenantId')) { $params['TenantId'] = $TenantId }
    if ($PSBoundParameters.ContainsKey('ForceReauth')) { $params['ForceReauth'] = $ForceReauth }
    if ($PSBoundParameters.ContainsKey('CreateGroupIfMissing')) { $params['CreateGroupIfMissing'] = $CreateGroupIfMissing }
    if ($PSBoundParameters.ContainsKey('CreateExceptionGroupIfMissing')) { $params['CreateExceptionGroupIfMissing'] = $CreateExceptionGroupIfMissing }

    Invoke-SAWSmsFreezePilot @params | Format-List
}
