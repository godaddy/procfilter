msbuild.exe /p:configuration="Debug" /p:platform="Win32" procfilter.sln
msbuild.exe /p:configuration="Debug" /p:platform="x64" procfilter.sln
msbuild.exe /p:configuration="Release" /p:platform="Win32" procfilter.sln
msbuild.exe /p:configuration="Release" /p:platform="x64" procfilter.sln

sign_binaries.bat & build_installers.bat & sign_installers.ba
