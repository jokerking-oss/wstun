@echo off
title wstun - local proxy (foreground)
cd /d "%~dp0"

if not exist "wstun.json" (
  if exist "wstun.example.json" (
    copy /y "wstun.example.json" "wstun.json" >nul
    echo [!] Created wstun.json from the template.
    echo     Edit "endpoint" and "token" to match your own edge deployment,
    echo     then run this script again.
    echo.
    notepad wstun.json
    pause
    exit /b 1
  )
  echo [x] wstun.json not found.
  pause
  exit /b 1
)

where python >nul 2>&1
if errorlevel 1 (
  echo [x] "python" was not found in PATH. Install Python 3.8+ and retry.
  pause
  exit /b 1
)

echo Starting local proxy on 127.0.0.1:10808
echo Press Ctrl+C to stop.
echo.
python -u wstun.py
pause
