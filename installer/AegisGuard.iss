; Inno Setup script - builds AegisGuardSetup-<version>.exe
; Build with installer\build.ps1 (it passes /DMyAppVersion=...). Needs Inno Setup 6 (free).

#ifndef MyAppVersion
  #define MyAppVersion "0.1.0"
#endif
#define MyAppName "AegisGuard"
#define MyAppExe "AegisGuard.exe"

[Setup]
AppId={{6F1D3C52-8A47-4B9E-9C0A-2E5B7D41A9C3}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=Darshil Patel
AppPublisherURL=https://github.com/pateldarshil8/AegisGuard
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\dist-installer
OutputBaseFilename=AegisGuardSetup-{#MyAppVersion}
SetupIconFile=aegisguard.ico
UninstallDisplayIcon={app}\{#MyAppExe}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
MinVersion=10.0
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "startup"; Description: "Start AegisGuard protection when I sign in (recommended)"; GroupDescription: "Protection:"

[Files]
Source: "..\dist\AegisGuard\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Dirs]
; Reports, quarantine, settings and logs live here (Program Files is read-only for normal users)
Name: "{commonappdata}\AegisGuard"; Permissions: users-modify

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Run]
; Start-at-sign-in task: runs with the user's highest available rights so network/firewall checks see everything
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""$a = New-ScheduledTaskAction -Execute '{app}\{#MyAppExe}' -Argument '--minimized'; $t = New-ScheduledTaskTrigger -AtLogOn; $p = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Users' -RunLevel Highest; Register-ScheduledTask -TaskName 'AegisGuard' -Action $a -Trigger $t -Principal $p -Force"""; Flags: runhidden; Tasks: startup; StatusMsg: "Setting up start at sign-in..."
Filename: "{app}\{#MyAppExe}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "taskkill.exe"; Parameters: "/F /IM {#MyAppExe}"; Flags: runhidden; RunOnceId: "KillApp"
Filename: "powershell.exe"; Parameters: "-NoProfile -Command ""Unregister-ScheduledTask -TaskName 'AegisGuard' -Confirm:$false -ErrorAction SilentlyContinue"""; Flags: runhidden; RunOnceId: "RemoveStartupTask"

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    if not UninstallSilent then
      if MsgBox('Also delete AegisGuard data (reports, quarantined files and settings)?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(ExpandConstant('{commonappdata}\AegisGuard'), True, True, True);
end;
