@echo off
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /f "C:\certs\software.pfx" /p %KEYPASS% /t http://timestamp.verisign.com/scripts/timstamp.dll ".\build\*.exe"
