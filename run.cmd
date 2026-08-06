@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

where pwsh >nul 2>nul
if errorlevel 1 (
    echo.
    echo ERROR: PowerShell 7.4+ ^(pwsh^) was not found on PATH.
    echo Install it from https://aka.ms/powershell and try again.
    echo.
    pause
    exit /b 1
)

rem Arguments passed straight to run.cmd bypass the menu entirely and go straight to
rem Invoke-SAWAssessment.ps1 - e.g. `run.cmd -UseSampleData -Verbose`.
if not "%~1"=="" goto :direct

:menu
cls
echo ================================================================
echo   Secure At Work - Authentication Assessment Toolkit
echo ================================================================
echo.
echo   1. Run against sample data (offline demo, no Graph connection)
echo   2. Run against a live tenant (default sign-in)
echo   3. Run against a live tenant (specific Tenant ID or domain)
echo   4. Run against a live tenant (install missing modules first)
echo   5. Run against a live tenant (force fresh sign-in - just activated a PIM role)
echo   6. Run against a live tenant (force fresh sign-in + device code)
echo   7. Compare two previous runs for a tenant (drift report)
echo   8. Custom - pass your own arguments straight through
echo   0. Exit
echo.
set "CHOICE="
set /p CHOICE=Choose an option:

if "%CHOICE%"=="1" goto :sample
if "%CHOICE%"=="2" goto :live
if "%CHOICE%"=="3" goto :live_tenant
if "%CHOICE%"=="4" goto :live_install
if "%CHOICE%"=="5" goto :live_forcereauth
if "%CHOICE%"=="6" goto :live_devicecode
if "%CHOICE%"=="7" goto :drift
if "%CHOICE%"=="8" goto :custom
if "%CHOICE%"=="0" exit /b 0

echo.
echo Not a valid option - try again.
echo.
pause
goto :menu

:sample
pwsh -NoLogo -File "src\Invoke-SAWAssessment.ps1" -UseSampleData -Verbose
goto :done

:live
pwsh -NoLogo -File "src\Invoke-SAWAssessment.ps1" -Verbose
goto :done

:live_tenant
set "TID="
set /p TID=Tenant ID or verified domain (e.g. contoso.onmicrosoft.com):
if "%TID%"=="" (
    echo A tenant ID or domain is required.
    pause
    goto :menu
)
pwsh -NoLogo -File "src\Invoke-SAWAssessment.ps1" -TenantId "%TID%" -Verbose
goto :done

:live_install
pwsh -NoLogo -File "src\Invoke-SAWAssessment.ps1" -InstallMissingModules -Verbose
goto :done

:live_forcereauth
echo.
echo This disconnects and re-authenticates fresh - use after activating a PIM role so the
echo new token actually carries it.
echo.
pwsh -NoLogo -File "src\Invoke-SAWAssessment.ps1" -ForceReauth -Verbose
goto :done

:live_devicecode
echo.
echo This forces a fresh sign-in AND routes around Windows' WAM broker via an OAuth device
echo code (a URL + one-time code you complete in any browser) - try this if -ForceReauth
echo alone didn't clear a persistent 403 on a role-gated endpoint.
echo.
pwsh -NoLogo -File "src\Invoke-SAWAssessment.ps1" -ForceReauth -UseDeviceCode -Verbose
goto :done

:drift
echo.
if exist "history\" (
    echo Tenants with history available:
    dir /b /ad "history" 2^>nul
    echo.
) else (
    echo No history\ directory found yet - run the assessment against a live tenant at least
    echo twice first ^(drift compares two runs of the same tenant^).
    echo.
    pause
    goto :menu
)
set "SLUG="
set /p SLUG=Tenant slug to compare (folder name from history\ above):
if "%SLUG%"=="" (
    echo A tenant slug is required.
    pause
    goto :menu
)
pwsh -NoLogo -File "src\Invoke-SAWDriftReport.ps1" -TenantSlug "%SLUG%"
goto :done

:custom
echo.
echo Enter the arguments to pass to Invoke-SAWAssessment.ps1, e.g.:
echo   -UseSampleData -Baseline cloud-native-passwordless -Verbose
echo.
set "ARGS="
set /p ARGS=Arguments:
pwsh -NoLogo -File "src\Invoke-SAWAssessment.ps1" %ARGS%
goto :done

:direct
pwsh -NoLogo -File "src\Invoke-SAWAssessment.ps1" %*
goto :done

:done
echo.
pause
exit /b 0
