@echo off
setlocal
title wstun - OFF
cd /d "%~dp0"

set "PY="
where python >nul 2>&1 && set "PY=python"
if not defined PY (
  echo [x] Python not found in PATH.
  pause
  exit /b 1
)

echo ================================================================
echo    wstun - restore original network settings
echo ================================================================
echo.
choice /c YN /m "Continue? (Y = restore / N = cancel)"
if errorlevel 2 goto :cancel

echo [1/3] Stopping watchdog ...
"%PY%" "guard.py" --stop

echo [2/3] Stopping tunnel ...
"%PY%" "tools\kill_tunnel.py"

echo [3/3] Restoring system proxy ...
"%PY%" "tools\proxy.py" restore-safe
echo.
echo Done. Your network is back to the original settings.
pause
exit /b 0

:cancel
echo Cancelled.
pause
exit /b 0
