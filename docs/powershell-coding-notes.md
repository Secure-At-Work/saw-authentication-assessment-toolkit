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

Net effect for this codebase: collector/normalizer/rules-engine functions return **arrays
of hashtables**, not `[PSCustomObject]`. Property access (`$_.Category`), `Where-Object`,
and `Select-Object -First N` all work fine on hashtables — just avoid `-Property` projection
and any `[PSCustomObject]`/`New-Object` construction.

Objects returned directly by built-in cmdlets (`ConvertFrom-Json`, `Get-Content`,
`Get-ChildItem`, `Invoke-MgGraphRequest`, ...) are unrestricted regardless of language mode —
the restriction is specifically about *script code constructing new typed instances*.
