# PowerShell coding notes for this repo

## ConstrainedLanguage mode

Assessor workstations in security-conscious environments (this one included) commonly
enforce PowerShell **ConstrainedLanguage mode** via WDAC/AppLocker. Verify with:

```powershell
$ExecutionContext.SessionState.LanguageMode
```

Under ConstrainedLanguage, several idioms that are normally second nature in PowerShell
throw `Cannot convert value ... Only core types are supported in this language mode.` or
`Method invocation is supported only on core types in this language mode.`:

| Avoid | Use instead |
|---|---|
| `[PSCustomObject]@{ A = 1 }` | Plain hashtable literal: `@{ A = 1 }`. Dot-access (`$h.A`) and `Where-Object { $_.A -eq ... }` both work fine on hashtables. |
| `New-Object <Type>` | Cmdlet output (e.g. `ConvertFrom-Json`, `Get-Item`) is unrestricted — only *constructing new instances yourself* is blocked. Prefer cmdlets that return the object you need. |
| `[System.Net.WebUtility]::HtmlEncode(...)` / other static calls to non-core types | Hand-rolled string `-replace` chains, or stick to methods on core types (`System.String`, `System.Int32`, ...) — e.g. `[string]::IsNullOrEmpty(...)`, `"x".Substring(...)`, `"x".ToUpper()` all work. |
| `$obj | Select-Object -Property A,B` on a hashtable | Works on real PSObjects (e.g. cmdlet output), but fails converting a raw hashtable. Filter/select with `Where-Object` instead, or just read keys directly. |
| `$rows | Format-Table -Property ...` on an array of hashtables | Unreliable (prints headers, blank rows) — build the summary with a manual loop and `Write-Host`/string formatting instead. |
| `[math]::Round(...)` / other static calls on `System.Math` | Not needed for threshold comparisons — compare the unrounded value directly (`$percent -ge 90`). For display, use the `-f` format operator (`"{0:N1}" -f $percent`), which works fine since it's an operator, not a method call. |
| `$rows | Sort-Object -Property SomeKey` on an array of hashtables | Same PSObject-conversion failure as `Select-Object -Property`. Use a scriptblock instead: `Sort-Object -Property { $_.SomeKey }` — that works fine, including multiple comma-separated scriptblocks for a multi-key sort. |

Net effect for this codebase: collector/normalizer/rules-engine functions return **arrays
of hashtables**, not `[PSCustomObject]`. Property access (`$_.Category`), `Where-Object`,
`Select-Object -First N`, and `Sort-Object -Property { $_.Key }` (scriptblock form) all work
fine on hashtables — just avoid plain `-Property <name>` projection/sort and any
`[PSCustomObject]`/`New-Object` construction. `ConvertTo-Json` also works fine (it's a
cmdlet) and is the safest way to embed PowerShell arrays/hashtables as JS data literals in
generated HTML — safer than hand-building strings with manual quote escaping.

Objects returned directly by built-in cmdlets (`ConvertFrom-Json`, `Get-Content`,
`Get-ChildItem`, `Invoke-MgGraphRequest`, ...) are unrestricted regardless of language mode —
the restriction is specifically about *script code constructing new typed instances*.

## Importing Microsoft.Graph.Authentication under ConstrainedLanguage

`Import-Module Microsoft.Graph.Authentication` prints alarming-looking errors on this kind
of machine — `Cannot convert value ... [PSCustomObject]` from an internal helper script
(`custom/common/Permissions.ps1`) that the module ships and auto-loads. **This is cosmetic
noise, not a real failure** — the actual cmdlets the toolkit needs (`Connect-MgGraph`,
`Invoke-MgGraphRequest`, `Get-MgContext`) are compiled .NET cmdlets, unaffected by CLM, and
work completely normally once loaded (confirmed: `Get-MgContext` correctly returns `$null`
when unauthenticated, calls succeed after connecting, etc.).

The practical consequence: **never call `Import-Module Microsoft.Graph.Authentication` with
`-ErrorAction Stop`** (or under an ambient `$ErrorActionPreference = 'Stop'` without an
explicit per-call override) — that promotes the harmless internal noise into a real
terminating failure. Use `-ErrorAction SilentlyContinue` on the `Import-Module` call itself,
then verify success the *real* way: `Get-Command -Name Connect-MgGraph, Invoke-MgGraphRequest,
Get-MgContext -ErrorAction SilentlyContinue` and check none are missing. See
`src/Connect-SAWGraph.ps1` for the pattern.

(A quick inline `pwsh -Command "..."` test of this same sequence produced a spurious
`Get-MgContext ... module could not be loaded` error that a clean `-File` run of the identical
logic did not reproduce — that was a shell-quoting artifact from the inline command string,
not a real finding. Prefer a `.ps1` file over a complex inline `-Command` string when
diagnosing anything CLM-related; the extra quoting layer can lie to you.)

## Bound every Graph log/audit endpoint with a date filter

Not a CLM issue - a real-tenant finding. `Get-SAWSignInLogs` and `Get-SAWAuditLogs` originally
queried `/auditLogs/signIns` and `/auditLogs/directoryAudits` with no `$filter`, on the
(wrong) assumption that "keep it simple for the vertical slice" was an acceptable shortcut.
Against a real tenant this timed out:

```
Invoke-MgGraphRequest: The request was canceled due to the configured HttpClient.Timeout of 300 seconds elapsing.
```

Both endpoints are effectively unbounded time-series data - without a filter, Graph tries to
enumerate everything still in the retention window, which for an active tenant can be far
more than a single 300-second request can return. Fixed by:

- Always adding `$filter=createdDateTime ge <N days ago>` (sign-ins) / `activityDateTime ge
  <N days ago>` (audits), built via `Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'` + `-replace ' ',
  '%20'` for the query string. `-DaysBack` (default 7) makes the window a param, not a
  constant - both checks these collectors run only need recent activity, not full history.
- A `-MaxPages` safety cap (default 50) as a second line of defense, in case even the
  date-bounded query is still large for a busy tenant - collection stops early and returns
  whatever was gathered rather than hanging again.

## WAM cannot be disabled for this toolkit, and that's fine - use -UseDeviceCode instead

Came up when a user asked why running the toolkit prompts for sign-in twice. Two independent
things are both true and worth separating:

1. **A confirmed, still-open SDK bug** causes intermittent double-authentication on
   Microsoft.Graph.Authentication 2.26+ with no root cause identified by Microsoft -
   [microsoftgraph/msgraph-sdk-powershell#3319](https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3319),
   status "Needs Investigation" as of this writing. Nothing this toolkit's code can do about
   that; it lives in the SDK.
2. **Expected one-time re-consent** whenever `Connect-SAWGraph.ps1`'s scope list changes (as it
   did when `Policy.Read.HybridAuthentication` was added for Staged Rollout) - a fresh Entra
   consent screen on top of the normal WAM sign-in, the first time only, then cached.

The instinctive fix - disable WAM and fall back to plain browser sign-in - **does not work for
this toolkit**, confirmed via
[a WAM deep-dive published 2026-08-09](https://msendpointmgr.com/2026/08/09/microsoft-graph-sdk-wam/)
that quotes the SDK's own authentication documentation directly:

> "Sign-in by Web Account Manager (WAM) is enabled by default on Windows and cannot be disabled.
> Setting this option to $False will have no effect on Windows systems. Except if you use your
> own app."

`Set-MgGraphOption -DisableLoginByWAM $true` is only honored when `Connect-MgGraph` is called
with a custom `-ClientId` from your own Entra app registration - which additionally needs two
redirect URIs configured (`http://localhost` for the browser path, plus
`ms-appx-web://Microsoft.AAD.BrokerPlugin/<client-id>` for WAM itself, per the same article).
Landed in SDK 2.35.0 for custom apps; 2.35.1 needed for the browser fallback to actually take
effect once set.

`Connect-SAWGraph.ps1` deliberately never passes `-ClientId` - it authenticates with the default
Microsoft Graph PowerShell app, specifically so nobody has to register an app in a customer's
tenant just to run a read-only assessment. That design choice is exactly what makes
`-DisableLoginByWAM` silently do nothing here: setting it and reconnecting with no `-ClientId`
reproduces the identical WAM prompt, not a browser one, because the setting has no default-app
code path to attach to.

**The only supported way to avoid WAM with this toolkit is `-UseDeviceCode`** (see
`Connect-SAWGraph.ps1`'s own `.PARAMETER UseDeviceCode` docs) - one URL and one code, completed
in any browser, no broker involved at all. If sign-in prompts twice on every single run rather
than only after a scope change, that's symptom (1) above and `-UseDeviceCode` sidesteps it too,
since device code flow never touches WAM in the first place.

**Correction (2026-08-12): that recommendation is currently unsafe to give without a caveat.**
Live run against a real tenant, same day: `-UseDeviceCode` completed sign-in cleanly (device-code
prompt shown, code entered, `Connect-SAWGraph` printed "connected as ...") and then the very
first actual Graph call of the run failed:

```
Invoke-MgGraphRequest: DeviceCodeCredential authentication failed: Object reference not set to
an instance of an object.
```

Matches a confirmed, still-open upstream bug:
[microsoftgraph/msgraph-sdk-powershell#3495](https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3495)
("Connect-MgGraph auth token unusable when -UseDeviceCode"), reported against SDK 2.34 on
PowerShell 7 - the installed version here was 2.37.0, also PowerShell 7. Stack trace bottoms out
in `Azure.Identity.DeviceCodeCredential.<GetTokenImplAsync>`; root cause not identified; status
"Needs Investigation"; no fix version. Not necessarily the same bug as #3319 above - that one is
intermittent re-prompting, this one is a hard failure on first token use after a clean connect -
but the practical effect is the same: nothing this toolkit's code can do about it, it lives in
the SDK.

**Revised guidance:** `-UseDeviceCode` is still the only way to avoid WAM outright, but "avoids
WAM" and "the run actually completes" are not the same claim on every SDK version. Check
`(Get-Module Microsoft.Graph.Authentication -ListAvailable | Sort-Object Version -Descending |
Select-Object -First 1).Version` before reaching for it, and treat a clean "connected as ..."
message as necessary, not sufficient - confirm the *next* line of output is real collector data,
not a crash. If it does crash, the fallback that has been confirmed to complete actual Graph
calls on the same SDK version is the plain WAM path (no `-UseDeviceCode`): accept the double
sign-in prompt, since every documented report of this specific crash is device-code-flow-only.

Lesson for any *new* Graph collector added later: if the endpoint is a log/report/audit
resource rather than a small, mostly-static policy object, assume it's unbounded and filter
it from the start - don't wait to find out against a real tenant.
