
#define MyAppDir "ProcFilter"
#define MyAppVersion "1.0"

[Setup]
; NOTE: The value of AppId uniquely identifies this application.
; Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{388AF0B9-08E6-4E68-A2EA-F9676A82B30E}
AppName={#MyAppDir}
AppVersion={#MyAppVersion}
;AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultGroupName={#MyAppDir}
AllowNoIcons=yes
LicenseFile=.\COPYING
Compression=lzma
SolidCompression=yes
OutputDir=build

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Dirs]
Name: "{app}\localrules"  
Name: "{app}\remoterules"   
Name: "{app}\doc"  
Name: "{app}\lib"  
Name: "{app}\sys"
Name: "{app}\logs" 
Name: "{app}\quarantine"
Name: "{app}\plugins"
Name: "{app}\sdk\include\procfilter"

[Files]
Source: "{#BuildDir}\procfilter.exe"; DestDir: "{app}"; Flags: ignoreversion 
Source: "{#BuildDir}\performance.dll"; DestDir: "{app}\plugins"; Flags: ignoreversion  
Source: "{#BuildDir}\antimalware.dll"; DestDir: "{app}\plugins"; Flags: ignoreversion 
Source: "{#BuildDir}\interactive.dll"; DestDir: "{app}\plugins"; Flags: ignoreversion    
Source: "{#BuildDir}\filenames.dll"; DestDir: "{app}\plugins"; Flags: ignoreversion   
Source: "{#BuildDir}\users.dll"; DestDir: "{app}\plugins"; Flags: ignoreversion    
Source: "{#BuildDir}\cmdline.dll"; DestDir: "{app}\plugins"; Flags: ignoreversion  
Source: "{#BuildDir}\unpack.dll"; DestDir: "{app}\plugins"; Flags: ignoreversion   
Source: "{#BuildDir}\sha1.dll"; DestDir: "{app}\plugins"; Flags: ignoreversion   
Source: "{#BuildDir}\remotethread.dll"; DestDir: "{app}\plugins"; Flags: ignoreversion 
Source: "{#BuildDir}\core.dll"; DestDir: "{app}\plugins"; Flags: ignoreversion   
Source: "{#DriverBuildDir}\driver.sys"; DestDir: "{app}\sys"; DestName: "procfilter.sys"; Flags: ignoreversion                
Source: ".\testlua\testlua.lua"; DestDir: "{app}\plugins"; Flags: uninsneveruninstall               
Source: ".\files\procfilter.ini"; DestDir: "{app}"; Flags: confirmoverwrite uninsneveruninstall 
Source: ".\service\procfilter.man"; DestDir: "{app}\lib"; Flags: ignoreversion uninsneveruninstall
Source: ".\service\include\procfilter\procfilter.h"; DestDir: "{app}\sdk\include\procfilter"; Flags: ignoreversion
Source: ".\files\localrules\*"; DestDir: "{app}\localrules"; Flags: recursesubdirs createallsubdirs  uninsneveruninstall onlyifdoesntexist
Source: ".\COPYING"; DestDir: "{app}\doc"; DestName: "LICENSE.txt"; Flags: uninsneveruninstall   
Source: ".\files\whitelist_blacklist_example.txt"; DestDir: "{app}"; Flags: ignoreversion   

; NOTE: Don't use "Flags: ignoreversion" on any shared system files

[Icons]
Name: "{group}\{#MyAppDir}"; FileName: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppDir}}"; FileName: "{uninstallexe}"

[Run]                                                      
FileName: "{sys}\wevtutil.exe"; Parameters: """uninstall-manifest"" ""{app}\lib\procfilter.man"""; Flags: runhidden
FileName: "{sys}\wevtutil.exe"; Parameters: """install-manifest"" ""{app}\lib\procfilter.man"" ""/rf:{app}\procfilter.exe"" ""/mf:{app}\procfilter.exe"""; Flags: runhidden
; "256MB ought to be enough for anyone", this should be a configurable later. This also has the effect of re-adjusting a prior setting...
FileName: "{sys}\wevtutil.exe"; Parameters: """sl"" ""procfilter/service"" ""/ms:268435456"""; Flags: runhidden
FileName: "{sys}\wevtutil.exe"; Parameters: """sl"" ""procfilter/plugins"" ""/ms:268435456"""; Flags: runhidden

; Default to delayed-start install since it's safer if ProcFilter were to cause problems
FileName: "{app}\procfilter.exe"; Parameters: "-install-delayed"; Flags: runhidden 

; Questions
FileName: "{app}\procfilter.exe"; Parameters: "-install"; Description: "Set ProcFilter as a boot-time service (vs. delayed start)"; Flags: unchecked postinstall skipifsilent runhidden runascurrentuser
FileName: "{app}\procfilter.exe"; Parameters: "-configure"; Description: "Configure ProcFilter now"; Flags: postinstall skipifsilent runascurrentuser

; Run -restart here since InnoSetup automatically restarts applications that needed to be shutdown to install (including procfilter if it was already running)
; -restart does a Stop and Start and can be used if the service isn't running
FileName: "{app}\procfilter.exe"; Parameters: "-restart"; Description: "Start the ProcFilter service now"; Flags: postinstall skipifsilent runhidden runascurrentuser

[UninstallRun]     
FileName: "{app}\procfilter.exe"; Parameters: "-stop"; Flags: runhidden
FileName: "{app}\procfilter.exe"; Parameters: "-uninstall"; Flags: runhidden
FileName: "{sys}\wevtutil.exe"; Parameters: """uninstall-manifest"" ""{app}\lib\procfilter.man"""; Flags: runhidden
