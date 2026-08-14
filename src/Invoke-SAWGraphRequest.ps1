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

        A third, rarer case surfaced the same day: both of the above can be individually ruled
        out (fresh token, role confirmed active via a live GET /me/transitiveMemberOf) and the
        same endpoint still denies it - a genuine Microsoft-side inconsistency for that tenant,
        not anything this toolkit or the caller's configuration controls. There's nothing to
        "fix" for that case beyond escalating to Microsoft support, so this function's only job
        for it is to make that escalation easy: it captures the request-id/client-request-id
        from the failed response (from the HTTP headers if present, falling back to the JSON
        error body) and surfaces them, since those are exactly what support needs to trace the
        request server-side.
    .PARAMETER Method
        HTTP method, passed straight through to Invoke-MgGraphRequest.
    .PARAMETER Uri
        Request URI, passed straight through to Invoke-MgGraphRequest.
    .PARAMETER Headers
        Optional extra request headers. Only needed by callers reading an "evolvable enum",
        where newer members are collapsed to `unknownFutureValue` unless the request opts in
        with `Prefer: include-unknown-enum-members` (see
        https://learn.microsoft.com/graph/best-practices-concept#handling-future-members-in-evolvable-enumerations).
        Get-SAWStagedRollout is currently the only caller: without the header, a staged rollout
        of certificate-based authentication or of Entra MFA - the two members most relevant to
        this toolkit - reads back as `unknownFutureValue` and would be reported as an
        unrecognized feature rather than by name. Omitted by every other collector, which keeps
        their behavior byte-for-byte unchanged.
    .OUTPUTS
        Whatever Invoke-MgGraphRequest returns (Hashtable, typically).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [hashtable]$Headers
    )

    try {
        if ($Headers -and $Headers.Count -gt 0) {
            return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Headers $Headers
        }
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

        $requestId = $null
        $clientRequestId = $null
        try {
            if ($_.Exception.Response -and $_.Exception.Response.Headers) {
                $values = $null
                if ($_.Exception.Response.Headers.TryGetValues('request-id', [ref]$values)) { $requestId = @($values)[0] }
                $values = $null
                if ($_.Exception.Response.Headers.TryGetValues('client-request-id', [ref]$values)) { $clientRequestId = @($values)[0] }
            }
        }
        catch {
            Write-Debug "Could not read request-id/client-request-id headers off the failed response: $_"
        }

        if ((-not $requestId) -and $_.ErrorDetails -and $_.ErrorDetails.Message) {
            try {
                $body = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop
                if ($body.error.innerError) {
                    if (-not $requestId) { $requestId = $body.error.innerError.'request-id' }
                    if (-not $clientRequestId) { $clientRequestId = $body.error.innerError.'client-request-id' }
                }
            }
            catch {
                Write-Debug "Could not parse the error response body as JSON: $_"
            }
        }

        $requestIdBlock = ''
        if ($requestId -or $clientRequestId) {
            $requestIdBlock = @"


If none of the causes above fit - role confirmed active via a live GET /me/transitiveMemberOf,
-ForceReauth -UseDeviceCode still gets the same result, and this isn't a one-off - that's a
genuine Microsoft-side inconsistency for this tenant, worth a Microsoft support case rather than
more local troubleshooting. These are what support needs to trace the request server-side:
  request-id:        $requestId
  client-request-id: $clientRequestId
"@
        }

        $guidance = @"
Invoke-SAWGraphRequest: GET $Uri was denied (permission/authorization error, not a toolkit bug).

Likely causes, roughly in order of how often they're the real one:
  1. The signed-in account doesn't hold a role Graph requires for this specific endpoint - having
     the right delegated scope consented (e.g. Policy.Read.All) is not always enough by itself;
     some endpoints also enforce a specific Entra directory role. If the error below names the
     roles that would work, any ONE of them is sufficient - Global Reader or Security Reader
     typically cover everything this toolkit reads.
  2. If you access that role via Privileged Identity Management (PIM), being ELIGIBLE for it is
     not the same as having it ACTIVE. If the role wasn't actively activated before this script
     connected, the token it's using carries none of it. Re-run with -ForceReauth (see
     Connect-SAWGraph.ps1) after activating the role - Connect-MgGraph does not pick up a
     newly-activated PIM role on an already-issued token, a fresh connection is needed.
  3. If -ForceReauth alone doesn't clear it, try also adding -UseDeviceCode. Confirmed against a
     real case: a role was verifiably active (checked via a live GET /me/transitiveMemberOf, not
     just the PIM UI) and -ForceReauth still 403'd, but the identical call succeeded immediately
     once signed in via device code instead of Windows' default WAM broker - WAM brokers tokens
     through its own OS-level cache (the Primary Refresh Token) that -ForceReauth doesn't reach.
$requestIdBlock
Original error follows:
$errorText
"@
        throw $guidance
    }
}
