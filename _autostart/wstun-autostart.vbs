' wstun autostart - starts tunnel + watchdog silently at logon
' Installed to the Startup folder by on.bat, removed by off.bat
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
py = "pythonw"
q = Chr(34)
sh.Run q & py & q & " -u " & q & here & "\client\wstun.py" & q, 0, False
sh.Run q & py & q & " -u " & q & here & "\guard.py" & q, 0, False
