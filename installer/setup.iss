; Inno Setup script — creates SecureTunnelSetup.exe
; Requires: Inno Setup 6+ (https://jrsoftware.org/isinfo.php)
; Build: ISCC.exe installer\setup.iss

#define AppName      "SecureTunnel"
#define AppVersion   "1.0.0"
#define AppPublisher "SecureTunnel"
#define AppURL       ""
#define AppExeName   "SecureTunnel.exe"
#define AppDataDir   "{userappdata}\SecureTunnel"

[Setup]
AppId={{8F3A2C1D-4B5E-4F6A-9C7D-0E1F2A3B4C5D}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes
OutputDir=..\dist
OutputBaseFilename=SecureTunnelSetup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
UninstallDisplayIcon={app}\{#AppExeName}
SetupIconFile=
MinVersion=10.0.17763
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon";    Description: "{cm:CreateDesktopIcon}";    GroupDescription: "{cm:AdditionalIcons}"
Name: "startupicon";    Description: "Start with Windows";        GroupDescription: "{cm:AdditionalIcons}"

[Files]
; Main executable (built by PyInstaller)
Source: "..\dist\SecureTunnel.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}";                Filename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}";      Filename: "{uninstallexe}"
Name: "{commondesktop}\{#AppName}";        Filename: "{app}\{#AppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#AppName}";          Filename: "{app}\{#AppExeName}"; Tasks: startupicon

[Run]
Filename: "{app}\{#AppExeName}"; \
    Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; \
    Flags: nowait postinstall skipifsilent

[UninstallRun]
; Kill the app before uninstalling
Filename: "taskkill.exe"; Parameters: "/F /IM {#AppExeName}"; Flags: runhidden; RunOnceId: "KillApp"

[Code]
// Auto-select language based on system locale
function GetDefaultLanguage(): String;
var
  LocaleID: Integer;
begin
  LocaleID := GetUILanguage();
  if (LocaleID = 1049) or (LocaleID = 2073) then  // Russian / Belarusian
    Result := 'russian'
  else
    Result := 'english';
end;

procedure InitializeWizard();
begin
  WizardForm.WelcomeLabel2.Caption :=
    'SecureTunnel will be installed on your computer.' + #13#10 + #13#10 +
    'No additional software is required.' + #13#10 +
    'All components are bundled in a single file.';
end;
