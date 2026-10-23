[Setup]
AppId={{B5EA046E-C42A-4617-8416-CE5932277B54}
AppName=SSH_Keys_Generator
AppVersion=1.5.1
AppPublisher=Adam Wojcieszonek
AppPublisherURL=https://github.com/adamzend/SSH_Keys_Generator
LicenseFile=LICENSE
DefaultDirName={localappdata}\Programs\SSH_Keys_Generator
DefaultGroupName=SSH_Keys_Generator
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=.
OutputBaseFilename=SSH_Keys_Generator_Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LanguageDetectionMethod=none
UninstallDisplayIcon={app}\SSH_Keys_Generator.exe
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "polish"; MessagesFile: "compiler:Languages\Polish.isl"

[CustomMessages]
english.DesktopShortcuts=Create desktop shortcuts
english.Shortcuts=Shortcuts:
english.Launch=Launch SSH_Keys_Generator
polish.DesktopShortcuts=Utwórz skróty na pulpicie
polish.Shortcuts=Skróty:
polish.Launch=Uruchom SSH_Keys_Generator

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopShortcuts}"; GroupDescription: "{cm:Shortcuts}"

[Files]
Source: "SSH_Keys_Generator.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "INSTRUKCJA.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "THIRD_PARTY_LICENSES.txt"; DestDir: "{app}"; Flags: ignoreversion

[Files]
Source: "GUIDE_EN.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs
Source: "locales\*"; DestDir: "{app}\locales"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{autodesktop}\SSH_Keys_Generator - English"; Filename: "{app}\SSH_Keys_Generator.exe"; Parameters: "--lang en"; IconFilename: "{app}\assets\en.ico"; Tasks: desktopicon
Name: "{autodesktop}\SSH_Keys_Generator - Polski"; Filename: "{app}\SSH_Keys_Generator.exe"; Parameters: "--lang pl"; IconFilename: "{app}\assets\pl.ico"; Tasks: desktopicon
Name: "{group}\SSH_Keys_Generator"; Filename: "{app}\SSH_Keys_Generator.exe"
Name: "{group}\User guide (English)"; Filename: "{app}\GUIDE_EN.txt"
Name: "{group}\Instrukcja (Polski)"; Filename: "{app}\INSTRUKCJA.txt"
Name: "{autodesktop}\SSH_Keys_Generator"; Filename: "{app}\SSH_Keys_Generator.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\SSH_Keys_Generator.exe"; Description: "{cm:Launch}"; Flags: nowait postinstall skipifsilent
