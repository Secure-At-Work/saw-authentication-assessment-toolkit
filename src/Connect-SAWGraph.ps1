function Connect-SAWGraph {
    <#
    .SYNOPSIS
        Ensures Microsoft.Graph.Authentication is installed and a read-only Microsoft
        Graph connection is active before any collector runs against a live tenant.
    .DESCRIPTION
        Read-only helper for the assessment orchestrator (only relevant when NOT using
        -UseSampleData). Every collector in this toolkit talks to Graph exclusively via
        Invoke-MgGraphRequest / Get-MgContext - both come from Microsoft.Graph.Authentication
        alone, so that is the only module this toolkit actually depends on (the typed SDK
        modules listed in spec section 5, e.g. Microsoft.Graph.Identity.SignIns, are not
        required - raw Invoke-MgGraphRequest calls keep the dependency footprint small).

        Checks the module is installed (optionally installing it for the current user if
        -InstallMissingModules is passed - off by default, since installing modules is left
        to the caller's judgement unless explicitly opted into), imports it, and connects
        via Connect-MgGraph if there is no active connection or the active connection is
        missing a required scope. Never requests write scopes.

        Real-world gotcha this function used to make easy to hit silently: if you already ran
        this against tenant A earlier in the same PowerShell session, then run it again
        intending tenant B, the old logic would see an existing connection with all the right
        scopes and just reuse it - still tenant A - with no indication anything was wrong.
        Confirmed against a real case: same account, PIM-eligible admin in both tenants,
        active/native member in both, worked fine on the first (tenant A) run and then failed
        with what looked like a permissions error on the second (tenant B) run in the same
        session - the actual cause was that it silently never reconnected to tenant B at all.
        Passing -TenantId now closes that gap: if the active connection's tenant doesn't match
        what was asked for, this disconnects and reconnects fresh instead of reusing it.
    .PARAMETER Scopes
        Graph delegated scopes to request. Defaults to the union of every read-only scope
        the toolkit's collectors need. All are read-only; none of them permit a write, which is
        deliberate and load-bearing for this toolkit. Note that Policy.Read.All does not cover
        every policy endpoint: Staged Rollout needs Policy.Read.HybridAuthentication as well, so
        that scope is requested separately (see the default list below).
    .PARAMETER TenantId
        Optional. The tenant (GUID or verified domain name, same as Connect-MgGraph's own
        -TenantId) you intend to assess. If an active connection already exists but belongs to
        a different tenant, it is disconnected and a fresh connection to this tenant is
        established instead of silently reusing the wrong one. If omitted (the default),
        behavior is unchanged from before: an existing connection with sufficient scopes is
        reused as-is, whichever tenant it happens to be for - so when switching tenants in the
        same session, either pass -TenantId here or run Disconnect-MgGraph yourself first.
    .PARAMETER InstallMissingModules
        Install Microsoft.Graph.Authentication for the current user if it isn't already
        installed, instead of throwing with install instructions.
    .PARAMETER ForceReauth
        Always disconnect and re-authenticate, even if an active connection already exists for
        the right tenant with sufficient scopes. Also connects with -ContextScope Process
        instead of the default CurrentUser, so the new token isn't the shared, disk-persisted
        context other terminals on this machine can see.

        Use this when a role was just activated via PIM (including PIM for Groups) and the
        assessment still gets a 403 on an endpoint that role should now cover: Connect-MgGraph
        happily reuses a still-valid cached access/refresh token rather than authenticating
        fresh, and that cached token can predate the activation - so it doesn't carry the new
        role's claims even though PIM shows the role as Activated. Closing every open
        PowerShell/pwsh window and starting over would also clear this, but -ForceReauth does it
        without needing to hunt down every other terminal that might hold the shared context.

        If -ForceReauth alone doesn't clear a persistent 403 on a role-gated endpoint, also try
        -UseDeviceCode (see below) - confirmed against a real case where -ForceReauth wasn't
        enough on its own.
    .PARAMETER UseDeviceCode
        Sign in via OAuth device code flow (a URL + one-time code, completed in any browser)
        instead of Windows' default Web Account Manager (WAM) broker. On Windows, Connect-MgGraph
        normally signs in through WAM even for an otherwise-plain interactive login, and WAM
        brokers tokens through its own OS-level cache (the Primary Refresh Token) that lives
        outside both Microsoft.Graph.Authentication's own token cache and -ContextScope Process -
        so -ForceReauth alone doesn't necessarily force a truly from-scratch token.

        Confirmed against a real case (2026-08-04): a role was verifiably active - confirmed via
        a live GET /me/transitiveMemberOf, not just the PIM UI - a role-gated endpoint still
        403'd even after -ForceReauth, but the identical call succeeded immediately once signed
        in with -UseDeviceCode instead. Browser-based auth (e.g. Graph Explorer) never goes
        through WAM at all, which is consistent with Graph Explorer working throughout while
        every WAM-based Connect-MgGraph attempt kept failing.

        WARNING, confirmed against a real tenant (2026-08-12), and this now conflicts with the
        recommendation above: on the SDK version installed at the time (Microsoft.Graph.
        Authentication 2.37.0), -UseDeviceCode completed the sign-in cleanly (the device-code
        prompt showed, the code was entered, Connect-SAWGraph reported "connected as ...") but
        the very next Graph call - the first real request of the run - failed outright:

            Invoke-MgGraphRequest: DeviceCodeCredential authentication failed: Object reference
            not set to an instance of an object.

        This matches a confirmed, unresolved upstream bug, not anything in this toolkit's code:
        https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3495 ("Connect-MgGraph
        auth token unusable when -UseDeviceCode"), reported against SDK 2.34 on PowerShell 7,
        stack trace bottoming out in Azure.Identity.DeviceCodeCredential.<GetTokenImplAsync>,
        root cause not identified, status "Needs Investigation" as of this writing, no fix
        version. The 2026-08-04 case above and this one are not necessarily the same bug - one
        is a role/claims-freshness problem, this one is a null reference on the very first
        token use after a successful device-code connect - but on whatever SDK version is
        actually installed, -UseDeviceCode cannot currently be assumed to work end to end.
        Check the installed version before reaching for this switch:

            (Get-Module Microsoft.Graph.Authentication -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version

        and if a live run has to proceed today, the working fallback is the plain WAM path
        (no -UseDeviceCode) - the double sign-in prompt is real but every documented report of
        this specific crash is device-code-flow-only; WAM-based connects complete their actual
        Graph calls fine on the same SDK version.

        Every internal Connect-MgGraph call is piped through Out-Host rather than left bare, for
        exactly this switch: PowerShell only streams a command's output live to the console when
        nothing downstream claims it. This function's own caller (Invoke-SAWAssessment.ps1) pipes
        the whole Connect-SAWGraph call to Out-Null to discard its return value - which, without
        Out-Host here, silently swallowed Connect-MgGraph's live device-code prompt too, so the
        script sat waiting the full 120-second device-code timeout for a sign-in nobody was ever
        shown (confirmed: calling this function directly, uncaptured, displayed the prompt fine;
        going through the orchestrator's `| Out-Null` did not). Out-Host forces immediate display
        and produces no further pipeline output of its own, so it's immune to whatever the
        top-level caller does with this function's own return value.

        Do NOT try `Set-MgGraphOption -DisableLoginByWAM $true` as an alternative to this switch -
        it silently does nothing for this toolkit. Per
        https://msendpointmgr.com/2026/08/09/microsoft-graph-sdk-wam/, quoting the SDK's own
        authentication documentation: "Sign-in by Web Account Manager (WAM) is enabled by default
        on Windows and cannot be disabled. Setting this option to $False will have no effect on
        Windows systems. Except if you use your own app." The setting is only honored when
        Connect-MgGraph is called with a custom -ClientId from your own Entra app registration
        (which additionally needs two redirect URIs configured: http://localhost and
        ms-appx-web://Microsoft.AAD.BrokerPlugin/<your-client-id>). This toolkit deliberately
        connects with the default Microsoft Graph PowerShell app (no -ClientId anywhere in
        $connectArgs below) precisely so nobody has to register an app in the customer's tenant
        just to run a read-only assessment - so -DisableLoginByWAM is a dead end here by design,
        not an oversight. -UseDeviceCode remains the only supported way to sign in without
        going through WAM at all - but per the 2026-08-12 warning above, "avoids WAM" and
        "works end to end" are not currently the same claim on every SDK version, so verify a
        real Graph call succeeds after connecting, don't just trust a clean sign-in message.
        (Custom-app WAM-disable capability landed in SDK 2.35.0, 2.35.1 for the browser
        fallback to actually take effect - both irrelevant to us for the reason above.)
    .OUTPUTS
        The Microsoft.Graph.Authentication context object (Get-MgContext).
    #>
    [CmdletBinding()]
    param(
        [string[]]$Scopes = @(
            'Policy.Read.All',
            'UserAuthenticationMethod.Read.All',
            'Reports.Read.All',
            'AuditLog.Read.All',
            'Directory.Read.All',
            # Staged Rollout inventory only (Get-SAWStagedRollout). Listed separately because
            # it's the one scope here that isn't implied by the others: Policy.Read.All does NOT
            # cover /policies/featureRolloutPolicies - Microsoft's own permissions table for that
            # endpoint names Policy.Read.HybridAuthentication as the least-privileged option, and
            # otherwise only write scopes this read-only toolkit will never request.
            #
            # CONFIRMED AGAINST A REAL TENANT (2026-08-12): Entra can reject this exact scope
            # outright at connect time with AADSTS70011 ("the scope ... does not exist"), despite
            # it matching Microsoft's own documented permission name character for character
            # (re-checked twice against learn.microsoft.com/graph/api/featurerolloutpolicies-list
            # after the failure - the string is right; something about live availability for this
            # tenant/app combination is not). That contradiction between documentation and the
            # live token endpoint is unresolved and not something this toolkit can fix. What it
            # CAN fix is the blast radius: AADSTS70011 fails the entire Connect-MgGraph call
            # atomically, for every scope requested alongside it, not just this one - so a single
            # rejected scope for one optional inventory row was taking down the whole 30-rule
            # assessment. See the retry-without-this-scope handling below, the same
            # try-the-richer-request-then-fall-back shape already used in Get-SAWPasskeys.ps1 for
            # $expand=passkeyProfiles. Get-SAWStagedRollout already degrades to reporting
            # "not read" rather than failing when this scope is absent from the connection - that
            # existing behavior is exactly what makes the fallback safe.
            'Policy.Read.HybridAuthentication'
        ),

        [string]$TenantId,

        [switch]$InstallMissingModules,

        [switch]$ForceReauth,

        [switch]$UseDeviceCode
    )

    $module = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
        Sort-Object -Property { $_.Version } -Descending |
        Select-Object -First 1

    if (-not $module) {
        if ($InstallMissingModules) {
            Write-Verbose 'Connect-SAWGraph: Microsoft.Graph.Authentication not found, installing for the current user'
            Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Force -ErrorAction Stop
        }
        else {
            throw 'Microsoft.Graph.Authentication is not installed. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser (or re-run with -InstallMissingModules).'
        }
    }

    Write-Verbose 'Connect-SAWGraph: importing Microsoft.Graph.Authentication'
    # -ErrorAction SilentlyContinue (explicitly, overriding a caller's $ErrorActionPreference =
    # 'Stop') rather than -ErrorAction Stop: on a WDAC/ConstrainedLanguage-restricted machine,
    # Import-Module surfaces non-fatal errors from an internal script-cmdlet loader that uses
    # [PSCustomObject] (see docs/powershell-coding-notes.md) even though the actual cmdlets this
    # function needs still load fine. -ErrorAction Stop would incorrectly treat that noise as a
    # real failure. The real success signal is whether the required cmdlets resolve afterward.
    Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue

    $requiredCommands = 'Connect-MgGraph', 'Invoke-MgGraphRequest', 'Get-MgContext'
    $missingCommands = $requiredCommands | Where-Object { -not (Get-Command -Name $_ -ErrorAction SilentlyContinue) }
    if ($missingCommands) {
        throw "Microsoft.Graph.Authentication did not load correctly - missing command(s): $($missingCommands -join ', ')."
    }

    # Wraps every Connect-MgGraph attempt in this function (there are three call sites below, one
    # per branch) so the AADSTS70011 self-heal lives in one place instead of three. See the
    # 2026-08-12 note on the -Scopes default above for why this exists: Entra can reject
    # 'Policy.Read.HybridAuthentication' outright, and because a single invalid scope fails the
    # WHOLE token request, that one optional scope was able to block every other check in the
    # assessment. Only that specific scope is ever dropped automatically - anything else Entra
    # rejects still fails loudly, because there's no known-safe fallback for it the way
    # Get-SAWStagedRollout already provides for this one.
    function Connect-SAWMgGraphAttempt {
        param([hashtable]$ConnectArgs)

        try {
            Connect-MgGraph @ConnectArgs | Out-Host
        }
        catch {
            $message = $_.Exception.Message
            if ($message -match 'AADSTS70011' -and $ConnectArgs.Scopes -contains 'Policy.Read.HybridAuthentication') {
                Write-Warning "Connect-SAWGraph: Entra rejected the requested scopes (AADSTS70011) with 'Policy.Read.HybridAuthentication' among them - retrying once without it. Staged Rollout inventory will report as not read; every other check is unaffected. Original error: $($message.Split([char]10)[0])"
                $retryArgs = @{}
                foreach ($key in $ConnectArgs.Keys) { $retryArgs[$key] = $ConnectArgs[$key] }
                $retryArgs['Scopes'] = @($ConnectArgs.Scopes | Where-Object { $_ -ne 'Policy.Read.HybridAuthentication' })
                Connect-MgGraph @retryArgs | Out-Host
            }
            else {
                throw
            }
        }
    }

    $context = Get-MgContext

    $connectArgs = @{ Scopes = $Scopes; NoWelcome = $true; ErrorAction = 'Stop' }
    if ($TenantId) { $connectArgs['TenantId'] = $TenantId }
    if ($ForceReauth) { $connectArgs['ContextScope'] = 'Process' }
    if ($UseDeviceCode) { $connectArgs['UseDeviceCode'] = $true }

    if (($ForceReauth -or $UseDeviceCode) -and $context) {
        Write-Warning "Connect-SAWGraph: -ForceReauth/-UseDeviceCode was requested - disconnecting the existing connection (tenant '$($context.TenantId)', account $($context.Account)) and re-authenticating fresh instead of reusing a possibly stale cached token."
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        $context = $null
    }

    if (-not $context) {
        Write-Verbose "Connect-SAWGraph: no active connection, connecting with scopes: $($Scopes -join ', ')"
        Connect-SAWMgGraphAttempt -ConnectArgs $connectArgs
        $context = Get-MgContext
    }
    elseif ($TenantId -and $context.TenantId -ne $TenantId) {
        Write-Warning "Connect-SAWGraph: an active connection exists for tenant '$($context.TenantId)' (account $($context.Account)), but -TenantId '$TenantId' was requested - disconnecting and reconnecting to the requested tenant instead of silently reusing the wrong one."
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Connect-SAWMgGraphAttempt -ConnectArgs $connectArgs
        $context = Get-MgContext
    }
    else {
        $missingScopes = $Scopes | Where-Object { $_ -notin $context.Scopes }
        if ($missingScopes) {
            Write-Verbose "Connect-SAWGraph: active connection is missing scope(s) ($($missingScopes -join ', ')), reconnecting"
            Connect-SAWMgGraphAttempt -ConnectArgs $connectArgs
            $context = Get-MgContext
        }
        else {
            Write-Verbose "Connect-SAWGraph: already connected as $($context.Account) with the required scopes"
        }
    }

    if (-not $context) {
        throw 'Failed to establish a Microsoft Graph connection.'
    }

    # Write-Host, not Write-Verbose: which tenant is actually being queried is safety-relevant
    # information the caller should always see, not just under -Verbose - the whole point of
    # the -TenantId mismatch guard above is undermined if the confirmation of what it did is
    # itself hidden by default.
    Write-Host "Connect-SAWGraph: connected as $($context.Account) (tenant $($context.TenantId))"
    return $context
}
