function Invoke-SAWGraphRequest {
    <#
    .SYNOPSIS
        Thin wrapper around Invoke-MgGraphRequest that turns a 401/403 into an actionable
        error message, instead of a raw HTTP error dump.
    .DESCRIPTION
        Drop-in replacement for `Invoke-MgGraphRequest -Method $Method -Uri $Uri` - every
        collector in this toolkit calls this instead of the raw cmdlet directly. It changes
        nothing about the request itself (still read-only, same scopes, same endpoint); it only
        catches a failure and, for the specific case of an authorization error, rethrows with
        guidance before the original error detail (which is preserved, never hidden).

        Two real things prompted this, both hit against a real tenant (2026-08-04):
          - Microsoft enforces role-based access on top of delegated OAuth scopes for several
            sensitive endpoints (Conditional Access policies among them) - having
            Policy.Read.All consented is not sufficient by itself; the signed-in user also
            needs to hold one of a specific set of Entra directory roles (Graph's own error
            names exactly which ones for that call - already about as helpful as it gets, so
            that detail is preserved verbatim rather than re-derived or summarized).
          - The much more common real-world cause for someone who DOES hold a qualifying role:
            Privileged Identity Management (PIM). An "eligible" assignment is not an "active"
            one - if the qualifying role was never activated (or activation expired) before
            Connect-MgGraph ran, the issued token carries none of it, and every call needing
            that role 403s exactly like a user who was never assigned it at all. This is easy
            to misread as "I don't have permission" when the real fix is "activate the role,
            then reconnect" - Connect-MgGraph doesn't pick up a newly-activated PIM role on an
            already-issued token, a fresh Connect-MgGraph (after Disconnect-MgGraph) is needed.
    .PARAMETER Method
        HTTP method, passed straight through to Invoke-MgGraphRequest.
    .PARAMETER Uri
        Request URI, passed straight through to Invoke-MgGraphRequest.
    .OUTPUTS
        Whatever Invoke-MgGraphRequest returns (Hashtable, typically).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri
    )

    try {
        return Invoke-MgGraphRequest -Method $Method -Uri $Uri
    }
    catch {
        $errorText = $_.Exception.Message
        $statusCode = $null
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        $looksLikeAuthzFailure = ($statusCode -eq 401) -or ($statusCode -eq 403) -or
            ($errorText -match 'AccessDenied') -or ($errorText -match '\b401\b') -or ($errorText -match '\b403\b') -or
            ($errorText -match 'Forbidden') -or ($errorText -match 'Authorization_RequestDenied')

        if (-not $looksLikeAuthzFailure) {
            throw
        }

        $guidance = @"
Invoke-SAWGraphRequest: GET $Uri was denied (permission/authorization error, not a toolkit bug).

Two likely causes:
  1. The signed-in account doesn't hold a role Graph requires for this specific endpoint - having
     the right delegated scope consented (e.g. Policy.Read.All) is not always enough by itself;
     some endpoints also enforce a specific Entra directory role. If the error below names the
     roles that would work, any ONE of them is sufficient - Global Reader or Security Reader
     typically cover everything this toolkit reads.
  2. If you access that role via Privileged Identity Management (PIM), being ELIGIBLE for it is
     not the same as having it ACTIVE. If the role wasn't actively activated before this script
     connected, the token it's using carries none of it. Activate the role in PIM (Entra admin
     center > Identity Governance > Privileged Identity Management, or via the PIM Graph API),
     then run Disconnect-MgGraph and re-run this script - Connect-MgGraph does not pick up a
     newly-activated PIM role on an already-issued token, a fresh connection is needed.

Original error follows:
$errorText
"@
        throw $guidance
    }
}
