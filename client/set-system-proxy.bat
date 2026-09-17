@echo off
chcp 65001 >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /d "127.0.0.1:10808" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /d "localhost;127.*;192.168.*;10.*;172.16.*;<local>" /f >nul
echo System proxy -> 127.0.0.1:10808
echo (make sure the tunnel is already running)
timeout /t 3 >nul
