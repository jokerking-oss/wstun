@echo off
setlocal EnableDelayedExpansion
title wstun - ON
cd /d "%~dp0"

set "PY="
set "PYW="
where python  >nul 2>&1 && set "PY=python"
where pythonw >nul 2>&1 && set "PYW=pythonw"
if not defined PYW set "PYW=%PY%"
if not defined PY (
  echo [x] Python not found in PATH. Install Python 3.8+ and retry.
  pause
  exit /b 1
)

if not exist "client\wstun.json" (
  if exist "client\wstun.example.json" (
    copy /y "client\wstun.example.json" "client\wstun.json" >nul
    echo [!] Created client\wstun.json from the template.
    echo     Edit "endpoint" and "token" first, then run again.
    notepad "client\wstun.json"
    pause
    exit /b 1
  )
  echo [x] client\wstun.json not found.
  pause
  exit /b 1
)

echo ================================================================
echo    wstun - residential tunnel
echo ================================================================
echo.

netstat -ano | findstr ":10808" | findstr "LISTENING" >nul
if not errorlevel 1 (
  echo [1/3] Tunnel already running, skip.
  goto :setproxy
)

echo [1/3] Starting tunnel in background ...
start "" "%PYW%" -u "client\wstun.py"

set /a N=0
:wait
set /a N+=1
netstat -ano | findstr ":10808" | findstr "LISTENING" >nul
if not errorlevel 1 goto :ready
if !N! GEQ 45 goto :startfail
timeout /t 1 /nobreak >nul
goto :wait

:startfail
echo.
echo [x] Tunnel did not come up within 45 seconds.
echo     Check client\wstun.log for details.
echo     Possible causes: edge endpoint unreachable, wrong token,
echo     or *.pages.dev blocked on your network.
pause
exit /b 1

:ready
echo       Tunnel is up.

:setproxy
echo [2/3] Pointing the system proxy at the tunnel ...
"%PY%" "tools\proxy.py" on
if errorlevel 1 (
  echo [x] Failed to set the system proxy.
  pause
  exit /b 1
)

echo.
echo [3/3] Checking the exit IP ...
"%PY%" "tools\exit_check.py"
echo.

echo Starting watchdog (auto-restart + failover) ...
start "" /min "%PYW%" -u "guard.py"

echo ================================================================
echo    Done. You are online through the residential tunnel.
echo      Verify : run check-ip.bat, or open https://ip.sb
echo      Revert : run off.bat
echo ================================================================
pause
exit /b 0
