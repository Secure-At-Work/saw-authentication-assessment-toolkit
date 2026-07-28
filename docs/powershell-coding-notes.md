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

Lesson for any *new* Graph collector added later: if the endpoint is a log/report/audit
resource rather than a small, mostly-static policy object, assume it's unbounded and filter
it from the start - don't wait to find out against a real tenant.
