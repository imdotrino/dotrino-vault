; Instalador de Windows de Dotrino Vault (Inno Setup 6). Lo compila CI (release.yml, job
; `windows`); a mano:  iscc /DAppVersion=0.157.0 /DSrc=..\..\dist\win packaging\windows\dotrino-vault.iss
;
; Se instala POR USUARIO, sin pedir administrador: en %LOCALAPPDATA%\Programs\Dotrino Vault.
; Es lo mismo que en Linux (CONVENCIONES §15): una instalación de usuario es la que se puede
; actualizar sola. Los datos NO viven aquí sino en %LOCALAPPDATA%\Dotrino\vault, y desinstalar
; no los toca: son tu cuenta.

#ifndef AppVersion
  #error Falta /DAppVersion=x.y.z
#endif
#ifndef Src
  #define Src "..\..\dist\win"
#endif

[Setup]
AppId={{6B3A2F4E-2D1C-4E8B-9A7F-D07B1A0C0DE5}
AppName=Dotrino Vault
AppVersion={#AppVersion}
AppVerName=Dotrino Vault {#AppVersion}
AppPublisher=Dotrino
AppPublisherURL=https://vault.dotrino.com/
AppSupportURL=https://wiki.dotrino.com/vault/
DefaultDirName={localappdata}\Programs\Dotrino Vault
DefaultGroupName=Dotrino Vault
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#Src}\..
OutputBaseFilename=dotrino-vault-{#AppVersion}-windows-x64-setup
SetupIconFile=..\..\desktop\assets\icon.ico
UninstallDisplayIcon={app}\dotrino-vault-desktop.exe
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes

[Languages]
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
es.Autostart=Arrancar la bóveda al iniciar sesión (recomendado)
en.Autostart=Start the vault when I sign in (recommended)
es.Shortcut=Crear un acceso en el escritorio
en.Shortcut=Create a desktop shortcut
es.Open=Abrir Dotrino Vault
en.Open=Open Dotrino Vault

[Tasks]
Name: "autostart"; Description: "{cm:Autostart}"
Name: "desktopicon"; Description: "{cm:Shortcut}"; Flags: unchecked

[Files]
Source: "{#Src}\dotrino-vault-desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Src}\dotrino-vaultd.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Src}\dotrino-vault.cmd"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\Dotrino Vault"; Filename: "{app}\dotrino-vault-desktop.exe"
Name: "{userdesktop}\Dotrino Vault"; Filename: "{app}\dotrino-vault-desktop.exe"; Tasks: desktopicon

[Registry]
; El MISMO valor que escribe `dotrino-vault service autostart on` (src/service.js): así el
; ajuste de la ventana y el del instalador son uno solo.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "DotrinoVault"; ValueData: """{app}\dotrino-vault-desktop.exe"" --start-daemon"; Tasks: autostart; Flags: uninsdeletevalue

[Run]
; Arranca la bóveda ya (sin ventana) y ofrece abrir su pantalla.
Filename: "{app}\dotrino-vault-desktop.exe"; Parameters: "--start-daemon"; Flags: runhidden nowait
Filename: "{app}\dotrino-vault-desktop.exe"; Description: "{cm:Open}"; Flags: postinstall nowait skipifsilent

[UninstallRun]
; Para la bóveda antes de borrar sus archivos. Tus datos se quedan.
Filename: "{sys}\taskkill.exe"; Parameters: "/IM dotrino-vaultd.exe /F"; Flags: runhidden; RunOnceId: "StopVault"
Filename: "{sys}\taskkill.exe"; Parameters: "/IM dotrino-vault-desktop.exe /F"; Flags: runhidden; RunOnceId: "StopWindow"
