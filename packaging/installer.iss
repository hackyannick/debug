; Inno-Setup-Skript für die Magic-Box-Desktop-App (Windows)
;
; Bauen (nach PyInstaller):  iscc /DAppVersion=0.1.0 packaging\installer.iss
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
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
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
Source: "..\dist\MagicBox\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

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
    'Adresse deines Magic-Box-Servers (die Anmeldung läuft dann über dessen Login, z. B. Ory). ' +
    'Leer lassen, um die Analyse lokal auf diesem PC laufen zu lassen.' + #13#10 + #13#10 +
    'Ändern lässt sich das später in der App unter „Magic Box → Server wechseln …“.');
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
    if (Url <> '') and (Pos('http://', Lowercase(Url)) <> 1) and (Pos('https://', Lowercase(Url)) <> 1) then
    begin
      MsgBox('Bitte die Adresse mit http:// oder https:// angeben, z. B. https://magicbox.hackdv.com', mbError, MB_OK);
      Result := False;
    end;
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
