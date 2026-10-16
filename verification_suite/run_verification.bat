@echo off
setlocal
echo ===============================================================================
echo   fuckDebug Formal Verification & Adversarial Testing Suite Runner (CMD)
echo ===============================================================================

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_verification.ps1" %*
set EXIT_CODE=%ERRORLEVEL%

if %EXIT_CODE% NEQ 0 (
    echo [ERROR] Verification runner failed with exit code %EXIT_CODE%.
    exit /b %EXIT_CODE%
)

echo [SUCCESS] Verification runner completed successfully.
exit /b 0
