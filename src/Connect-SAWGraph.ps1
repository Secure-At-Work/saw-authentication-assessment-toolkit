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
    .PARAMETER Scopes
        Graph delegated scopes to request. Defaults to the union of every read-only scope
        the toolkit's collectors need.
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

    if (-not $context) {
        Write-Verbose "Connect-SAWGraph: no active connection, connecting with scopes: $($Scopes -join ', ')"
        Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
        $context = Get-MgContext
    }
    else {
        $missingScopes = $Scopes | Where-Object { $_ -notin $context.Scopes }
        if ($missingScopes) {
            Write-Verbose "Connect-SAWGraph: active connection is missing scope(s) ($($missingScopes -join ', ')), reconnecting"
            Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
            $context = Get-MgContext
        }
        else {
            Write-Verbose "Connect-SAWGraph: already connected as $($context.Account) with the required scopes"
        }
    }

    if (-not $context) {
        throw 'Failed to establish a Microsoft Graph connection.'
    }

    Write-Verbose "Connect-SAWGraph: connected as $($context.Account) (tenant $($context.TenantId))"
    return $context
}
