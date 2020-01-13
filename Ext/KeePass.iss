; KeePass Password Safe Installation Script
; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!
; Thanks to Lubos Stanek for creating a template for this installer.
; Thanks to Hilbrand Edskes for installer improvements.

#define MyAppName "KeePass"
#define MyAppFullName "KeePass Password Safe"
#define MyAppPublisher "Dominik Reichl"
#define MyAppURL "https://keepass.info/"
#define MyAppExeName "KeePass.exe"
#define MyAppUrlName "KeePass.url"
#define MyAppHelpName "KeePass.chm"

#define KeeVersionStr "1.38"
#define KeeVersionWin "1.38.0.0"
#define KeeVersionWinShort "1.38"

#define KeeDevPeriod "2003-2020"

[Setup]
AppName={#MyAppFullName}
AppVersion={#KeeVersionWinShort}
AppVerName={#MyAppFullName} {#KeeVersionStr}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
AppCopyright=Copyright (c) {#KeeDevPeriod} {#MyAppPublisher}
MinVersion=5.0
DefaultDirName={pf}\{#MyAppFullName}
DefaultGroupName={#MyAppFullName}
AllowNoIcons=yes
LicenseFile=..\Docs\License.txt
OutputDir=..\Build\WinGUI_Distrib
OutputBaseFilename={#MyAppName}-{#KeeVersionStr}-Setup
Compression=lzma2/ultra
SolidCompression=yes
InternalCompressLevel=ultra
UninstallDisplayIcon={app}\{#MyAppExeName}
AppMutex=KeePassApplicationMutex,Global\KeePassAppMutexExI
SetupMutex=KeePassSetupMutex1
ChangesAssociations=yes
VersionInfoVersion={#KeeVersionWin}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppFullName} {#KeeVersionStr} Setup
VersionInfoCopyright=Copyright (c) {#KeeDevPeriod} {#MyAppPublisher}
WizardImageFile=compiler:WizModernImage-IS.bmp
WizardSmallImageFile=compiler:WizModernSmallImage-IS.bmp
DisableDirPage=auto
AlwaysShowDirOnReadyPage=yes
DisableProgramGroupPage=yes
AlwaysShowGroupOnReadyPage=no

[Languages]
Name: en; MessagesFile: "compiler:Default.isl"
Name: ca; MessagesFile: "compiler:Languages\Catalan.isl"
Name: cs; MessagesFile: "compiler:Languages\Czech.isl"
Name: da; MessagesFile: "compiler:Languages\Danish.isl"
Name: de; MessagesFile: "compiler:Languages\German.isl"
Name: es; MessagesFile: "compiler:Languages\Spanish.isl"
Name: fi; MessagesFile: "compiler:Languages\Finnish.isl"
Name: fr; MessagesFile: "compiler:Languages\French.isl"
Name: hu; MessagesFile: "compiler:Languages\Hungarian.isl"
Name: it; MessagesFile: "compiler:Languages\Italian.isl"
Name: ja; MessagesFile: "compiler:Languages\Japanese.isl"
Name: nb; MessagesFile: "compiler:Languages\Norwegian.isl"
Name: nl; MessagesFile: "compiler:Languages\Dutch.isl"
Name: pl; MessagesFile: "compiler:Languages\Polish.isl"
Name: ptBR; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: ptPT; MessagesFile: "compiler:Languages\Portuguese.isl"
Name: ru; MessagesFile: "compiler:Languages\Russian.isl"
; Name: sk; MessagesFile: "compiler:Languages\Slovak.isl"
Name: sl; MessagesFile: "compiler:Languages\Slovenian.isl"

[CustomMessages]
MyOptPlgPage=Open the plugins web page
ca.MyOptPlgPage=Obre el web dels connectors
da.MyOptPlgPage=Åbn websiden med plugins
de.MyOptPlgPage=Die Plugins-Webseite öffnen
es.MyOptPlgPage=Abrir la página web de los complementos
fi.MyOptPlgPage=Avaa liitännäiset ja laajennukset sisältävä sivusto
fr.MyOptPlgPage=Ouvre la page des greffons (plugins) sur la toile
hu.MyOptPlgPage=Nyissa meg a bővítmények weboldalát
it.MyOptPlgPage=Apri la pagina web dei plug-in
ja.MyOptPlgPage=プラグインのWebページを開きます。
nl.MyOptPlgPage=Open de plugins webpagina
pl.MyOptPlgPage=Otwórz stronę internetową z wtyczkami
ptBR.MyOptPlgPage=Abrir página web dos plugins
ptPT.MyOptPlgPage=Abrir a página web dos miniaplicativos
ru.MyOptPlgPage=Открыть веб-страницу плагинов

[Tasks]
Name: fileassoc; Description: {cm:AssocFileExtension,{#MyAppName},.kdb}
Name: desktopicon; Description: {cm:CreateDesktopIcon}; GroupDescription: {cm:AdditionalIcons}; Flags: unchecked
Name: quicklaunchicon; Description: {cm:CreateQuickLaunchIcon}; GroupDescription: {cm:AdditionalIcons}; Flags: unchecked

[Dirs]
Name: "{app}\Languages"; Flags: uninsalwaysuninstall
Name: "{app}\Plugins"; Flags: uninsalwaysuninstall

[Files]
Source: ..\Build\WinGUI_Distrib\KeePass.exe; DestDir: {app}; Flags: ignoreversion
Source: ..\Build\WinGUI_Distrib\KeePass.chm; DestDir: {app}; Flags: ignoreversion
Source: ..\Build\WinGUI_Distrib\KeePass.ini; DestDir: {app}; Flags: onlyifdoesntexist
Source: ..\Build\WinGUI_Distrib\License.txt; DestDir: {app}; Flags: ignoreversion

[Registry]
; Always unregister .kdb association at uninstall
Root: HKCR; Subkey: .kdb; Flags: uninsdeletekey; Tasks: not fileassoc
Root: HKCR; Subkey: kdbfile; Flags: uninsdeletekey; Tasks: not fileassoc
; Register .kdb association at install, and unregister at uninstall
Root: HKCR; Subkey: .kdb; ValueType: string; ValueData: kdbfile; Flags: uninsdeletekey; Tasks: fileassoc
Root: HKCR; Subkey: kdbfile; ValueType: string; ValueData: KeePass Database; Flags: uninsdeletekey; Tasks: fileassoc
Root: HKCR; Subkey: kdbfile; ValueType: string; ValueName: AlwaysShowExt; Flags: uninsdeletekey; Tasks: fileassoc
Root: HKCR; Subkey: kdbfile\DefaultIcon; ValueType: string; ValueData: """{app}\{#MyAppExeName}"",0"; Flags: uninsdeletekey; Tasks: fileassoc
Root: HKCR; Subkey: kdbfile\shell\open; ValueType: string; ValueData: &Open with {#MyAppName}; Flags: uninsdeletekey; Tasks: fileassoc
Root: HKCR; Subkey: kdbfile\shell\open\command; ValueType: string; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Flags: uninsdeletekey; Tasks: fileassoc

; [INI]
; Filename: {app}\{#MyAppUrlName}; Section: InternetShortcut; Key: URL; String: {#MyAppURL}

[Icons]
; Name: {group}\{#MyAppName}; Filename: {app}\{#MyAppExeName}
; Name: {group}\{cm:ProgramOnTheWeb,{#MyAppName}}; Filename: {app}\{#MyAppUrlName}
; Name: {group}\Help; Filename: {app}\{#MyAppHelpName}
; Name: {group}\{cm:UninstallProgram,{#MyAppName}}; Filename: {uninstallexe}
Name: {commonprograms}\{#MyAppName}; Filename: {app}\{#MyAppExeName}
Name: {userdesktop}\{#MyAppName}; Filename: {app}\{#MyAppExeName}; Tasks: desktopicon; Check: MyDesktopCheck
Name: {userappdata}\Microsoft\Internet Explorer\Quick Launch\{#MyAppName}; Filename: {app}\{#MyAppExeName}; Tasks: quicklaunchicon; Check: MyAppDataCheck

[Run]
Filename: {app}\{#MyAppExeName}; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: postinstall nowait skipifsilent
Filename: "https://keepass.info/plugins.html"; Description: "{cm:MyOptPlgPage}"; Flags: postinstall shellexec skipifsilent unchecked

; Delete old files when upgrading
[InstallDelete]
Name: {app}\{#MyAppUrlName}; Type: files
Name: {group}\{#MyAppName}.lnk; Type: files
Name: {group}\{cm:ProgramOnTheWeb,{#MyAppName}}.lnk; Type: files
Name: {group}\Help.lnk; Type: files
Name: {group}\{cm:UninstallProgram,{#MyAppName}}.lnk; Type: files
Name: {group}; Type: dirifempty

; [UninstallDelete]
; Type: files; Name: {app}\{#MyAppUrlName}

[Code]
function MyDesktopCheck(): Boolean;
begin
  try
    ExpandConstant('{userdesktop}');
    Result := True;
  except
    Result := False;
  end;
end;

function MyAppDataCheck(): Boolean;
begin
  try
    ExpandConstant('{userappdata}');
    Result := True;
  except
    Result := False;
  end;
end;
