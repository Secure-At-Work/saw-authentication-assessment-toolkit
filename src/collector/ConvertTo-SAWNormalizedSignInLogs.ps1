function ConvertTo-SAWNormalizedSignInLogs {
    <#
    .SYNOPSIS
        Normalizes raw sign-in log entries into Secure At Work sign-in behavior checks.
    .DESCRIPTION
        Scans every sign-in log entry and derives two facts: whether any sign-in that
        succeeded used a legacy authentication client (IMAP4, POP3, SMTP, Exchange
        ActiveSync, or other legacy clients), and whether any succeeded via the device
        code flow authentication protocol - a known phishing vector. Only successful
        sign-ins count; a blocked/failed attempt at legacy auth or device code flow is
        evidence controls are working, not a gap.
    .PARAMETER RawResponse
        The object returned by Get-SAWSignInLogs (has a .value array of sign-in entries).
    .OUTPUTS
        Hashtable[]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$RawResponse
    )

    begin {
        $legacyClientAppTypes = @('Exchange ActiveSync', 'IMAP4', 'POP3', 'SMTP', 'Authenticated SMTP', 'Other clients')

        function ConvertTo-SAWStateLabel {
            param([bool]$Value)
            if ($Value) { return 'Enabled' }
            return 'Disabled'
        }
    }

    process {
        $signIns = $RawResponse.value
        if (-not $signIns) { $signIns = @() }

        $successfulLegacyAuthFound = $false
        $successfulDeviceCodeFound = $false

        foreach ($signIn in $signIns) {
            $succeeded = ($signIn.status.errorCode -eq 0)
            if (-not $succeeded) {
                continue
            }

            if (-not $successfulLegacyAuthFound -and ($legacyClientAppTypes -contains $signIn.clientAppUsed)) {
                $successfulLegacyAuthFound = $true
                Write-Verbose "ConvertTo-SAWNormalizedSignInLogs: successful legacy auth sign-in by '$($signIn.userPrincipalName)' via '$($signIn.clientAppUsed)'"
            }

            if (-not $successfulDeviceCodeFound -and $signIn.authenticationProtocol -eq 'deviceCode') {
                $successfulDeviceCodeFound = $true
                Write-Verbose "ConvertTo-SAWNormalizedSignInLogs: successful device code flow sign-in by '$($signIn.userPrincipalName)'"
            }
        }

        @{
            Category = 'Sign-In Analysis'
            Setting  = 'No Successful Legacy Authentication Sign-ins'
            State    = ConvertTo-SAWStateLabel (-not $successfulLegacyAuthFound)
        }
        @{
            Category = 'Sign-In Analysis'
            Setting  = 'No Successful Device Code Flow Sign-ins'
            State    = ConvertTo-SAWStateLabel (-not $successfulDeviceCodeFound)
        }
    }
}
