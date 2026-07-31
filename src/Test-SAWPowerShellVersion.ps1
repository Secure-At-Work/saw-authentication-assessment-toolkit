function Test-SAWPowerShellVersion {
    <#
    .SYNOPSIS
        Checks whether the currently running PowerShell host meets this toolkit's minimum
        version, and builds a clear, actionable message if it doesn't.
    .DESCRIPTION
        Every entry-point script (Invoke-SAWAssessment.ps1, Invoke-SAWDriftReport.ps1) used to
        gate on `#Requires -Version 7.4` alone. That works, but PowerShell's own engine refuses
        to run the script at all once it sees a #Requires it can't satisfy - it never reaches a
        single line of our code, so the only message a user sees is the engine's generic one
        ("...does not match the currently running version..."), with no indication of whether
        PowerShell 7 just needs to be launched differently (pwsh.exe instead of the default
        Windows PowerShell 5.1 powershell.exe) or isn't installed at all.

        This function is deliberately written in PowerShell 5.1-compatible syntax (no ternary/
        null-coalescing operators, no classes) and takes everything it needs as parameters
        rather than reading $PSVersionTable/Get-Command directly, so it (a) can actually be
        parsed and run under Windows PowerShell 5.1 to produce a helpful message instead of a
        parse-time failure, and (b) is unit-testable with synthetic inputs. Callers dot-source
        this file FIRST, before any other file, and exit immediately if not Satisfied - nothing
        else in this toolkit is guaranteed to parse under anything older than 7.4.
    .PARAMETER CurrentVersion
        The running host's version. Defaults to $PSVersionTable.PSVersion.
    .PARAMETER CurrentEdition
        The running host's edition ('Core' for PowerShell 6+, 'Desktop' for Windows PowerShell
        up to 5.1). Defaults to $PSVersionTable.PSEdition.
    .PARAMETER MinimumVersion
        The minimum required version. Defaults to 7.4.
    .PARAMETER PwshAvailable
        Whether a `pwsh` command is already resolvable on PATH - used to distinguish "wrong
        host launched, just relaunch with pwsh" from "PowerShell 7 isn't installed at all".
        Defaults to checking Get-Command pwsh.
    .PARAMETER ScriptPath
        Path to the script being launched, used to build the exact relaunch command shown to
        the user. Defaults to $PSCommandPath of the caller's session, if available.
    .OUTPUTS
        Hashtable with Satisfied (bool) and Message (string, only meaningful when not
        Satisfied).
    #>
    param(
        [version]$CurrentVersion = $PSVersionTable.PSVersion,

        [string]$CurrentEdition = $PSVersionTable.PSEdition,

        [version]$MinimumVersion = [version]'7.4',

        [bool]$PwshAvailable = [bool](Get-Command -Name 'pwsh' -ErrorAction SilentlyContinue),

        [string]$ScriptPath = $PSCommandPath
    )

    if ($CurrentVersion -ge $MinimumVersion -and $CurrentEdition -eq 'Core') {
        return @{ Satisfied = $true; Message = $null }
    }

    $scriptDisplay = if ($ScriptPath) { $ScriptPath } else { '<this script>' }

    $lines = @()
    $lines += "This toolkit requires PowerShell $MinimumVersion or later (edition: Core) - the currently running host is PowerShell $CurrentVersion (edition: $CurrentEdition), which is too old."
    $lines += ''

    if ($CurrentEdition -eq 'Core') {
        # Already running pwsh (Core), just an outdated one - relaunching with pwsh would only
        # launch the same outdated version again. Guidance here is "upgrade", not "relaunch".
        $lines += "You're already running PowerShell 7 (pwsh), just an outdated build. Upgrade it (Windows, via winget):"
        $lines += ''
        $lines += '    winget upgrade --id Microsoft.PowerShell --source winget'
        $lines += ''
        $lines += 'Full instructions (all platforms): https://learn.microsoft.com/powershell/scripting/install/install-powershell-on-windows'
    }
    elseif ($PwshAvailable) {
        $lines += "PowerShell 7 already appears to be installed - you're just running the wrong host right now (likely Windows PowerShell, opened via the default 'powershell.exe' / the 'Windows PowerShell' Start Menu entry, rather than 'pwsh.exe' / 'PowerShell 7'). Relaunch with:"
        $lines += ''
        $lines += "    pwsh -File `"$scriptDisplay`""
    }
    else {
        $lines += 'PowerShell 7 does not appear to be installed on this machine yet.'
        $lines += ''
        $lines += 'Install it (Windows, via winget):'
        $lines += ''
        $lines += '    winget install --id Microsoft.PowerShell --source winget'
        $lines += ''
        $lines += 'Full instructions (all platforms): https://learn.microsoft.com/powershell/scripting/install/install-powershell-on-windows'
        $lines += ''
        $lines += "Then relaunch this script with 'pwsh' instead of 'powershell':"
        $lines += ''
        $lines += "    pwsh -File `"$scriptDisplay`""
    }

    @{
        Satisfied = $false
        Message   = ($lines -join "`n")
    }
}
