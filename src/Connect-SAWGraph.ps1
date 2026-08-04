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
        the toolkit's collectors need.
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
            'Directory.Read.All'
        ),

        [string]$TenantId,

        [switch]$InstallMissingModules
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

    $context = Get-MgContext

    $connectArgs = @{ Scopes = $Scopes; NoWelcome = $true; ErrorAction = 'Stop' }
    if ($TenantId) { $connectArgs['TenantId'] = $TenantId }

    if (-not $context) {
        Write-Verbose "Connect-SAWGraph: no active connection, connecting with scopes: $($Scopes -join ', ')"
        Connect-MgGraph @connectArgs
        $context = Get-MgContext
    }
    elseif ($TenantId -and $context.TenantId -ne $TenantId) {
        Write-Warning "Connect-SAWGraph: an active connection exists for tenant '$($context.TenantId)' (account $($context.Account)), but -TenantId '$TenantId' was requested - disconnecting and reconnecting to the requested tenant instead of silently reusing the wrong one."
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Connect-MgGraph @connectArgs
        $context = Get-MgContext
    }
    else {
        $missingScopes = $Scopes | Where-Object { $_ -notin $context.Scopes }
        if ($missingScopes) {
            Write-Verbose "Connect-SAWGraph: active connection is missing scope(s) ($($missingScopes -join ', ')), reconnecting"
            Connect-MgGraph @connectArgs
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
