#define MyAppName "AutoGuard"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "AutoGuard"
#define MyAppExeName "AutoGuard.exe"
#define MyAppUserModelId "AutoGuard.Desktop"

[Setup]
AppId={{7E4D32AF-770F-4CB4-9250-8FE30A5C35F4}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppComments=Automatic protection, threat tracking, quarantine, and recovery.
VersionInfoVersion=1.0.0.0
VersionInfoProductName={#MyAppName}
VersionInfoDescription=AutoGuard Setup

DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableWelcomePage=no
DisableDirPage=no
DisableProgramGroupPage=yes
DisableReadyPage=no
LicenseFile=..\LICENSE.txt

PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\dist\installer
OutputBaseFilename=AutoGuard-Setup-{#MyAppVersion}

SetupIconFile=..\assets\autoguard.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes

; ---------------------------------------------------------------------------
; AutoGuard Final Installer UI
; Inno Setup 6.7+ / 7.x.
;
; IMPORTANT:
; Native Inno Setup controls keep their native DPI-aware geometry.
; We do NOT force SetBounds on License, Destination, Tasks, Ready, or
; Installing controls. This prevents overlap/collapse at 100/125/150% DPI.
; ---------------------------------------------------------------------------
DefaultDialogFontName=Segoe UI
WizardStyle=modern dark includetitlebar hidebevels

; Global background: clean dark -> teal gradient only.
WizardBackColor=#0C1012
WizardBackImageFile=..\assets\installer\autoguard_installer_gradient.png
WizardBackImageOpacity=255

; Dedicated branding artwork.
WizardImageFile=..\assets\installer\autoguard_wizard.png
WizardImageBackColor=#0C1012
WizardImageOpacity=255
WizardImageStretch=yes

WizardSmallImageFile=..\assets\installer\autoguard_wizard_small.png
WizardSmallImageBackColor=none

; Give the native layout more room without manually moving controls.
WizardResizable=no
WizardSizePercent=112
WizardKeepAspectRatio=yes

CloseApplications=yes
RestartApplications=no
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
ButtonNext=&Next
ButtonBack=&Back
ButtonCancel=Cancel
ButtonInstall=&Install
ButtonFinish=&Finish

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts"; Flags: unchecked

[Files]
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; AppUserModelID: "{#MyAppUserModelId}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon; AppUserModelID: "{#MyAppUserModelId}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Keep security history, logs, database, and quarantine data in AutoGuardData.
Type: filesandordirs; Name: "{app}"

[Code]

procedure SetInnerHeading(const ATitle, ADescription: String);
begin
  WizardForm.PageNameLabel.Caption := ATitle;
  WizardForm.PageDescriptionLabel.Caption := ADescription;

  { Keep conservative font sizes so native header geometry remains valid. }
  WizardForm.PageNameLabel.Font.Name := 'Segoe UI Semibold';
  WizardForm.PageNameLabel.Font.Size := 11;
  WizardForm.PageDescriptionLabel.Font.Name := 'Segoe UI';
  WizardForm.PageDescriptionLabel.Font.Size := 9;
end;

procedure StyleNativeControls;
begin
  { Fonts only: no manual positioning. }
  WizardForm.Font.Name := 'Segoe UI';
  WizardForm.Font.Size := 9;

  WizardForm.LicenseLabel1.Font.Name := 'Segoe UI';
  WizardForm.LicenseLabel1.Font.Size := 9;
  WizardForm.LicenseMemo.Font.Name := 'Segoe UI';
  WizardForm.LicenseMemo.Font.Size := 9;

  WizardForm.SelectDirLabel.Font.Name := 'Segoe UI';
  WizardForm.SelectDirBrowseLabel.Font.Name := 'Segoe UI';
  WizardForm.DirEdit.Font.Name := 'Segoe UI';
  WizardForm.DirBrowseButton.Font.Name := 'Segoe UI';
  WizardForm.DiskSpaceLabel.Font.Name := 'Segoe UI';

  WizardForm.SelectTasksLabel.Font.Name := 'Segoe UI';
  WizardForm.TasksList.Font.Name := 'Segoe UI';

  WizardForm.ReadyLabel.Font.Name := 'Segoe UI Semibold';
  WizardForm.ReadyLabel.Font.Size := 9;
  WizardForm.ReadyMemo.Font.Name := 'Segoe UI';
  WizardForm.ReadyMemo.Font.Size := 9;

  WizardForm.StatusLabel.Font.Name := 'Segoe UI Semibold';
  WizardForm.StatusLabel.Font.Size := 9;
  WizardForm.FilenameLabel.Font.Name := 'Segoe UI';
  WizardForm.FilenameLabel.Font.Size := 8;

  WizardForm.BackButton.Font.Name := 'Segoe UI Semibold';
  WizardForm.NextButton.Font.Name := 'Segoe UI Semibold';
  WizardForm.CancelButton.Font.Name := 'Segoe UI Semibold';
end;

procedure StyleWelcomePage;
begin
  { Native Welcome geometry is retained; only content/typography changes. }
  WizardForm.WelcomeLabel1.Caption := 'Welcome to AutoGuard';
  WizardForm.WelcomeLabel1.Font.Name := 'Segoe UI Semibold';
  WizardForm.WelcomeLabel1.Font.Size := 16;

  WizardForm.WelcomeLabel2.Caption :=
    'Install AutoGuard {#MyAppVersion} for automatic protection, threat tracking, ' +
    'quarantine, and recovery.' + #13#10 + #13#10 +
    'AutoGuard will be installed as a normal Windows application.' + #13#10 + #13#10 +
    'Click Next to continue.';
  WizardForm.WelcomeLabel2.Font.Name := 'Segoe UI';
  WizardForm.WelcomeLabel2.Font.Size := 10;
end;

procedure StyleFinishedPage;
begin
  WizardForm.FinishedHeadingLabel.Caption := 'AutoGuard is ready';
  WizardForm.FinishedHeadingLabel.Font.Name := 'Segoe UI Semibold';
  WizardForm.FinishedHeadingLabel.Font.Size := 16;

  WizardForm.FinishedLabel.Caption :=
    'Setup has finished installing AutoGuard on your computer.' + #13#10 + #13#10 +
    'Launch it now or open AutoGuard later from the Start menu.';
  WizardForm.FinishedLabel.Font.Name := 'Segoe UI';
  WizardForm.FinishedLabel.Font.Size := 10;
end;

procedure InitializeWizard;
begin
  WizardForm.Caption := 'AutoGuard Setup';

  StyleNativeControls;
  StyleWelcomePage;
  StyleFinishedPage;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  { Only page text/style changes here. Inno owns every control position/size. }
  case CurPageID of
    wpWelcome:
      begin
        StyleWelcomePage;
      end;

    wpLicense:
      begin
        SetInnerHeading(
          'License Agreement',
          'Review the terms before installing AutoGuard.');
      end;

    wpSelectDir:
      begin
        SetInnerHeading(
          'Select Destination Location',
          'Choose where AutoGuard should be installed.');
      end;

    wpSelectTasks:
      begin
        SetInnerHeading(
          'Additional Tasks',
          'Choose the shortcuts you want Setup to create.');
      end;

    wpReady:
      begin
        SetInnerHeading(
          'Ready to Install',
          'Review your choices before installing AutoGuard.');
      end;

    wpInstalling:
      begin
        SetInnerHeading(
          'Installing AutoGuard',
          'Setup is installing AutoGuard on your computer.');
      end;

    wpFinished:
      begin
        StyleFinishedPage;
      end;
  end;
end;
