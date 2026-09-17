@echo off
setlocal
cd /d "%~dp0"
set "PY="
where python >nul 2>&1 && set "PY=python"
if not defined PY (
  echo [x] Python not found in PATH.
  pause
  exit /b 1
)
"%PY%" "tools\purity_check.py"
pause
