@echo off
chcp 65001 >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul
echo System proxy disabled (direct connection)
timeout /t 2 >nul
