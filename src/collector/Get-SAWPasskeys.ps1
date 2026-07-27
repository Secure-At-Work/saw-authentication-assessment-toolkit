function Get-SAWPasskeys {
    <#
    .SYNOPSIS
        Collects Passkey (FIDO2) authentication method configuration via Microsoft Graph.
    .DESCRIPTION
        Read-only collector. Returns the raw Graph response as a PowerShell object.
        Must never create, modify, or delete any tenant object.
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    param()

    Write-Verbose 'Get-SAWPasskeys: not yet implemented'
    throw [System.NotImplementedException]::new('Get-SAWPasskeys is a scaffold placeholder.')
}
