function Get-SAWBaselineOverrides {
    <#
    .SYNOPSIS
        Loads a customer SOLL baseline preset and an optional per-engagement override file,
        merging them into a single overrides map keyed by RuleID.
    .DESCRIPTION
        SOLL (target state) is customer-specific: a hybrid tenant still tied to on-prem AD
        may legitimately need passwords/SSPR for longer than a cloud-native, passwordless-only
        tenant, and severities that make sense for one don't necessarily make sense for the
        other. Rather than hard-coding one "right" Expected/Severity per rule, a baseline file
        overrides specific rules' Expected/Severity, or marks a rule NotApplicable entirely
        (evaluated as Grey with a note, rather than compared at all).

        A baseline file has the shape:
        {
          "name": "Human-readable name",
          "description": "...",
          "overrides": {
            "<RuleID>": { "Expected": "...", "Severity": "...", "NotApplicable": true, "Note": "..." }
          }
        }
        All fields under a RuleID are optional - set only what differs from the rule's default.

        -OverridePath (a per-engagement file, same shape) is applied on top of -BaselinePath,
        so an engagement-specific tweak wins over the preset for any RuleID both define.
    .PARAMETER BaselinePath
        Path to a named preset baseline JSON file (e.g. config/baselines/hybrid-ad-passwords-required.json).
        Optional - omit to start from no preset (only -OverridePath, if given, applies).
    .PARAMETER OverridePath
        Path to a per-engagement override JSON file, same shape as a baseline preset. Optional.
    .OUTPUTS
        Hashtable keyed by RuleID, each value a hashtable of the overridden properties.
    #>
    [CmdletBinding()]
    param(
        [string]$BaselinePath,
        [string]$OverridePath
    )

    $merged = @{}

    function Merge-SAWOverrideFile {
        param([string]$Path, [hashtable]$Into)

        if (-not (Test-Path -Path $Path)) {
            throw "Baseline/override file not found: $Path"
        }

        $parsed = Get-Content -Path $Path -Raw | ConvertFrom-Json
        if (-not $parsed.overrides) {
            Write-Verbose "Get-SAWBaselineOverrides: $Path has no 'overrides' section"
            return
        }

        foreach ($ruleId in $parsed.overrides.PSObject.Properties.Name) {
            if (-not $Into.ContainsKey($ruleId)) {
                $Into[$ruleId] = @{}
            }
            foreach ($prop in $parsed.overrides.$ruleId.PSObject.Properties) {
                $Into[$ruleId][$prop.Name] = $prop.Value
            }
        }
    }

    if ($BaselinePath) {
        Write-Verbose "Get-SAWBaselineOverrides: loading baseline preset from $BaselinePath"
        Merge-SAWOverrideFile -Path $BaselinePath -Into $merged
    }

    if ($OverridePath) {
        Write-Verbose "Get-SAWBaselineOverrides: layering engagement override from $OverridePath"
        Merge-SAWOverrideFile -Path $OverridePath -Into $merged
    }

    return $merged
}
