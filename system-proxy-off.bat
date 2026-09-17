@echo off
setlocal
cd /d "%~dp0"
set "PY="
where python >nul 2>&1 && set "PY=python"
"%PY%" "tools\proxy.py" off
pause
