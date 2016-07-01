@echo off

"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /f "C:\certs\software.pfx" /p %KEYPASS% /t http://timestamp.verisign.com/scripts/timstamp.dll ".\deps\libgit2\x86\git2.dll"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /f "C:\certs\software.pfx" /p %KEYPASS% /t http://timestamp.verisign.com/scripts/timstamp.dll ".\deps\libgit2\x64\git2.dll"

"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /f "C:\certs\software.pfx" /p %KEYPASS% /t http://timestamp.verisign.com/scripts/timstamp.dll ".\Debug\*.dll"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /f "C:\certs\software.pfx" /p %KEYPASS% /t http://timestamp.verisign.com/scripts/timstamp.dll ".\Debug\*.exe"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /f "C:\certs\software.pfx" /p %KEYPASS% /t http://timestamp.verisign.com/scripts/timstamp.dll ".\x64\Debug\*.dll"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /f "C:\certs\software.pfx" /p %KEYPASS% /t http://timestamp.verisign.com/scripts/timstamp.dll ".\x64\Debug\*.exe"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /f "C:\certs\software.pfx" /p %KEYPASS% /t http://timestamp.verisign.com/scripts/timstamp.dll ".\Release\*.dll"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /f "C:\certs\software.pfx" /p %KEYPASS% /t http://timestamp.verisign.com/scripts/timstamp.dll ".\Release\*.exe"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /f "C:\certs\software.pfx" /p %KEYPASS% /t http://timestamp.verisign.com/scripts/timstamp.dll ".\x64\Release\*.dll"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /f "C:\certs\software.pfx" /p %KEYPASS% /t http://timestamp.verisign.com/scripts/timstamp.dll ".\x64\Release\*.exe"

"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha256 /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha256 ".\Win7Debug\*.sys"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha256 /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha256 ".\x64\Win7Debug\*.sys"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha256 /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha256 ".\Win7Release\*.sys"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha256 /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha256 ".\x64\Win7Release\*.sys"

"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha256 /ph /as /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha256 ".\Win7Debug\*.sys"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha256 /ph /as /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha256 ".\x64\Win7Debug\*.sys"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha256 /ph /as /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha256 ".\Win7Release\*.sys"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha256 /ph /as /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha256 ".\x64\Win7Release\*.sys"

"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha1 /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha1 ".\Win7Debug\*.sys"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha1 /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha1 ".\x64\Win7Debug\*.sys"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha1 /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha1 ".\Win7Release\*.sys"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha1 /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha1 ".\x64\Win7Release\*.sys"

"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha1 /ph /as /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha1 ".\Win7Debug\*.sys"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha1 /ph /as /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha1 ".\x64\Win7Debug\*.sys"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha1 /ph /as /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha1 ".\Win7Release\*.sys"
"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe" sign /ac "c:\certs\Go Daddy Root Certificate Authority - G2.crt" /f "C:\certs\driver.pfx" /fd sha1 /ph /as /p %KEYPASS% /tr http://tsa.starfieldtech.com /td sha1 ".\x64\Win7Release\*.sys"
