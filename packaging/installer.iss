; Inno-Setup-Skript für die Magic-Box-Desktop-App (native Windows-App, WinForms/.NET Framework 4.8)
;
; Bauen (nach „dotnet build desktop\MagicBox -c Release“):  iscc /DAppVersion=0.1.0 packaging\installer.iss
; Ergebnis:                  dist\MagicBox-Setup-<Version>.exe
;
; Stille Installation, z. B. per Softwareverteilung:
;   MagicBox-Setup-0.1.0.exe /VERYSILENT /SERVER=https://magicbox.hackdv.com
;   (/CURRENTUSER = ohne Adminrechte nur für den angemeldeten Benutzer, /ALLUSERS = für alle)

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef DefaultServer
  #define DefaultServer "https://magicbox.hackdv.com"
#endif

[Setup]
AppId={{8C6F1D52-4B7E-4C1E-9D7A-6A2B9E3F1C01}
AppName=Magic Box
AppVersion={#AppVersion}
AppVerName=Magic Box {#AppVersion}
AppPublisher=Magic Box
AppComments=Datei rein – verständliche Doku raus. Statische Analyse mit lokalem LLM.
DefaultDirName={autopf}\Magic Box
DefaultGroupName=Magic Box
DisableProgramGroupPage=yes
; Standardmäßig ohne Adminrechte installierbar, auf Wunsch für alle Benutzer
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
; .NET Framework 4.8 (AnyCPU): auf Windows 10/11 vorinstalliert, läuft auf x64 und ARM64
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=6.1sp1
OutputDir=..\dist
OutputBaseFilename=MagicBox-Setup-{#AppVersion}
SetupIconFile=..\magicbox\assets\magicbox.ico
UninstallDisplayIcon={app}\MagicBox.exe
UninstallDisplayName=Magic Box
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\desktop\MagicBox\bin\Release\net48\MagicBox.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\desktop\MagicBox\bin\Release\net48\MagicBox.exe.config"; DestDir: "{app}"; Flags: ignoreversion

[InstallDelete]
; Reste der früheren, gebündelten Python/Qt-Version entfernen
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{autoprograms}\Magic Box"; Filename: "{app}\MagicBox.exe"; Comment: "Dateien analysieren und dokumentieren"
Name: "{autodesktop}\Magic Box"; Filename: "{app}\MagicBox.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\MagicBox.exe"; Description: "{cm:LaunchProgram,Magic Box}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: files; Name: "{app}\magicbox-defaults.json"

[Code]
var
  ServerPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  ServerPage := CreateInputQueryPage(wpSelectDir,
    'Magic-Box-Server',
    'Mit welchem Server soll sich die App verbinden?',
    'Adresse deines Magic-Box-Servers. Die Analyse läuft dort; die App spricht über die REST-API mit ihm ' +
    'und meldet sich beim ersten Start über den Browser an (z. B. Ory mit Captcha).' + #13#10 + #13#10 +
    'Ändern lässt sich das später in der App unter „Extras → Verbindung …“.');
  ServerPage.Add('Server-Adresse:', False);
  ServerPage.Values[0] := ExpandConstant('{param:SERVER|{#DefaultServer}}');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Url: String;
begin
  Result := True;
  if CurPageID = ServerPage.ID then
  begin
    Url := Trim(ServerPage.Values[0]);
    if (Pos('http://', Lowercase(Url)) <> 1) and (Pos('https://', Lowercase(Url)) <> 1) then
    begin
      MsgBox('Bitte die Adresse mit http:// oder https:// angeben, z. B. https://magicbox.hackdv.com', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

{ .NET Framework 4.8 vorhanden? (Release >= 528040; ab Windows 10 Mai 2019 eingebaut) }
function InitializeSetup: Boolean;
var
  Release: Cardinal;
begin
  Result := True;
  if not RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) or
     (Release < 528040) then
  begin
    if WizardSilent then
      Log('Warnung: .NET Framework 4.8 nicht gefunden')
    else if MsgBox('Magic Box benötigt das .NET Framework 4.8 (bei Windows 10/11 normalerweise schon vorhanden).' + #13#10 +
              'Es wurde nicht gefunden. Trotzdem installieren?' + #13#10 + #13#10 +
              'Download: https://dotnet.microsoft.com/download/dotnet-framework/net48', mbConfirmation, MB_YESNO) = IDNO then
      Result := False;
  end;
end;

function JsonEscape(S: String): String;
begin
  StringChangeEx(S, '\', '\\', True);
  StringChangeEx(S, '"', '\"', True);
  Result := S;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    { Vorgabe für die App: gilt, solange der Benutzer noch keine eigenen Einstellungen gespeichert hat }
    SaveStringToFile(ExpandConstant('{app}\magicbox-defaults.json'),
      '{"server_url": "' + JsonEscape(Trim(ServerPage.Values[0])) + '"}', False);
end;
