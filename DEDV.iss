; Inno Setup script for DEDV. Version is passed in by build.bat (/DAppVersion=x.y.z)
; from dedv/version.py.
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
; Never change AppId: it lets a new installer upgrade an existing install in place.
AppId={{6F1B7C52-3D4A-4E8B-9C21-5A0D3E7B1F44}
AppName=Dynamic Encryption Digital Vault
AppVersion={#AppVersion}
AppPublisher=DEDV
DefaultDirName={autopf}\DEDV
DefaultGroupName=DEDV
DisableProgramGroupPage=yes
OutputDir=installer
OutputBaseFilename=DEDV_Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName=Dynamic Encryption Digital Vault
UninstallDisplayIcon={app}\DEDV.exe
CloseApplications=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
; Application files only. The vault (e.g. D:\Documents\DEDV) and the settings in
; %APPDATA%\DEDV are outside {app}, so installs/updates/uninstalls never touch them.
Source: "dist\DEDV\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\DEDV"; Filename: "{app}\DEDV.exe"
Name: "{autodesktop}\DEDV"; Filename: "{app}\DEDV.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\DEDV.exe"; Description: "Launch DEDV"; Flags: nowait postinstall skipifsilent

; Intentionally NO [InstallDelete]/[UninstallDelete] entries for vault or settings data.
