# AutoGuard

AutoGuard is a Windows desktop security application designed to provide automatic file protection, threat detection, quarantine, recovery, and security activity tracking.

## Features

### Automatic Protection

AutoGuard can run protection services automatically in the background without requiring the user to manually start every scan.

It supports:

* Real-time file monitoring
* Automatic startup scanning
* Scheduled Quick Scans
* Scheduled Full Scans
* USB/removable-drive protection
* Windows notifications
* System-tray operation

The default schedule runs a Quick Scan every 24 hours and a Full Scan every 7 days.

### Manual File and Folder Scanning

Users can manually scan a file or folder.

AutoGuard supports:

* Custom/manual scans
* Quick Scans
* Full Scans
* Startup Scans
* Scheduled Scans
* USB Scans
* Real-Time Scans

A file or directory can also be provided when launching AutoGuard from the command line.

### Threat Detection

AutoGuard uses SHA-256 signature matching together with heuristic detection rules.

Current detection rules include:

* Double-file-extension detection
* Suspicious filename detection
* Suspicious script patterns
* Executable-extension detection

Known signature matches are treated as high-confidence detections, while heuristic matches are treated as lower-confidence suspicious results.

### Quarantine

High-confidence threats can be automatically quarantined.

AutoGuard verifies the quarantine operation before removing the original file:

1. Copies the detected file into quarantine storage.
2. Verifies the copied file.
3. Verifies the final quarantine object again.
4. Removes the original file only after verification succeeds.
5. Records the quarantine operation in the security history.

### Threat and Incident Tracking

AutoGuard records security incidents throughout their lifecycle.

Possible incident statuses include:

* Open
* Investigating
* Contained
* Reappeared
* Restored
* Resolved

Security events such as detection, quarantine, cleanup, recovery, and reappearance are also recorded.

### Matching-Copy Cleanup

AutoGuard can search monitored locations for other files with the same SHA-256 hash as a detected threat.

This allows exact matching copies to be identified and processed as part of threat cleanup.

### Cleanup Verification

After a threat is contained, AutoGuard can verify whether:

* Quarantined objects still have the expected hash
* Matching copies remain
* Some monitored locations are inaccessible
* Verification errors occurred

Cleanup verification can return:

* `VERIFIED`
* `PARTIAL`
* `FAILED`

### Safe Recovery

A quarantined file can be restored when requested by the user.

Before restoring a file, AutoGuard:

* Verifies quarantine integrity
* Checks for destination conflicts
* Re-evaluates the file using the current detection engine
* Blocks restoration when the file is still classified as high-confidence dangerous
* Verifies the restored file after writing

AutoGuard does not execute or open the restored file during recovery.

### Threat Trail

AutoGuard records observations of identical file content at different locations over time using SHA-256 hashes.

The Threat Trail provides evidence of where identical content was observed. It does not prove an infection source or direction of spread.

### Scan History and Activity

AutoGuard stores scan sessions and security events so previous activity can be reviewed.

The main user interface contains:

* Home
* Scan
* Threats
* Quarantine
* Activity
* Settings

### System Tray

AutoGuard can continue running in the Windows system tray.

The system-tray menu provides access to:

* Open AutoGuard
* Protection status
* Real-time protection status
* USB protection status
* Scheduled scanning status
* Current scan information
* Quick Scan
* Exit AutoGuard

### Local Storage

AutoGuard stores its application data locally in:

```text
%USERPROFILE%\AutoGuardData
```

The application creates:

```text
AutoGuardData/
├── database/
│   └── autoguard.db
├── quarantine/
└── logs/
```

The local SQLite database stores scan history, threat incidents, quarantine records, recovery attempts, and related security evidence.

---

# Requirements

AutoGuard is designed for Windows because several features depend on Windows functionality, including removable-drive detection, Windows notifications, Windows startup integration, and the Windows release/installer process.

For development, use:

* Windows
* Python 3.10
* Git
* PowerShell
* Internet connection

---

# Project Structure

The main project structure is:

```text
AutoGuard/
├── app/
│   ├── ui/
│   ├── cleanup_verifier.py
│   ├── config.py
│   ├── database.py
│   ├── detection_rules.py
│   ├── detector.py
│   ├── file_monitor.py
│   ├── incidents.py
│   ├── quarantine.py
│   ├── recovery.py
│   ├── reports.py
│   ├── scanner.py
│   ├── scheduler.py
│   ├── signatures.py
│   ├── startup.py
│   ├── system_tray.py
│   ├── threat_trail.py
│   ├── usb_monitor.py
│   └── windows_notifications.py
├── assets/
├── data/
├── installer/
├── tests/
├── AutoGuard.spec
├── build_release.ps1
├── main.py
├── requirements.txt
└── requirements-dev.txt
```

---

# Installing AutoGuard

There are two ways to use AutoGuard:

1. Install the prebuilt Windows application.
2. Run AutoGuard directly from the source code.

For normal users, the recommended method is the **prebuilt installer**.

---

# Option 1 — Install the AutoGuard Application

Use this method when you only want to install and use AutoGuard.

## Step 1 — Locate the installer

Open the AutoGuard project folder and go to:

```text
dist/
└── installer/
    └── AutoGuard-Setup-1.0.0.exe
```

The project already contains a built installer named:

```text
AutoGuard-Setup-1.0.0.exe
```

## Step 2 — Start the installer

Double-click:

```text
AutoGuard-Setup-1.0.0.exe
```

The AutoGuard Setup window will open.

## Step 3 — Read the welcome page

The installer displays the AutoGuard welcome page.

Click:

```text
Next
```

to continue.

## Step 4 — Accept the license agreement

Read the AutoGuard Software License Agreement.

Select:

```text
I accept the agreement
```

then click:

```text
Next
```

The installer includes the project's `LICENSE.txt` file as its license agreement.

## Step 5 — Choose the installation folder

The installer will ask where AutoGuard should be installed.

The default installation location is:

```text
%LOCALAPPDATA%\Programs\AutoGuard
```

You can keep the default location or choose another location.

Click:

```text
Next
```

## Step 6 — Choose additional tasks

The installer allows additional shortcuts/options to be selected.

One available option is:

```text
Start AutoGuard with Windows
```

Enable this option when you want AutoGuard to start automatically when Windows starts.

Click:

```text
Next
```

## Step 7 — Review the installation

The installer will show the selected installation options.

Review the settings and click:

```text
Install
```

## Step 8 — Wait for installation to finish

Setup will install AutoGuard and its required application files.

When installation is complete, you will see the completion page.

## Step 9 — Launch AutoGuard

Click:

```text
Finish
```

The installer can launch AutoGuard automatically after installation.

You can also open AutoGuard later from the Windows Start menu.

## Step 10 — Check that AutoGuard is running

After launching, the AutoGuard desktop application should appear.

You should be able to access:

```text
Home
Scan
Threats
Quarantine
Activity
Settings
```

AutoGuard can also continue running in the Windows system tray.

---

# Option 2 — Run AutoGuard Locally from Source

Use this method when developing, modifying, or testing the project.

## Step 1 — Install Python 3.10

Install Python 3.10 on your Windows computer.

Verify the installation:

```powershell
python --version
```

You should see:

```text
Python 3.10.x
```

If the `python` command is unavailable, try:

```powershell
py -3 --version
```

## Step 2 — Open the AutoGuard project

Open PowerShell.

Navigate to the folder containing the AutoGuard source code:

```powershell
cd C:\path\to\AutoGuard
```

For example:

```powershell
cd C:\Users\YourName\Documents\AutoGuard
```

Verify that `main.py` exists:

```powershell
dir
```

You should see files such as:

```text
main.py
requirements.txt
requirements-dev.txt
app
tests
```

## Step 3 — Create a virtual environment

Run:

```powershell
python -m venv .venv
```

This creates:

```text
AutoGuard/
└── .venv/
```

The virtual environment keeps AutoGuard's Python packages separate from your system Python installation.

## Step 4 — Activate the virtual environment

For PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

For Command Prompt:

```cmd
.venv\Scripts\activate
```

After activation, your terminal should look similar to:

```text
(.venv) PS C:\Users\YourName\Documents\AutoGuard>
```

## Step 5 — Upgrade pip

Run:

```powershell
python -m pip install --upgrade pip
```

## Step 6 — Install AutoGuard dependencies

Run:

```powershell
python -m pip install -r requirements.txt
```

The current application dependencies are:

```text
pytest==8.4.2
watchdog>=4.0.0
APScheduler>=3.10,<4
customtkinter>=5.2,<6
winotify>=1.1,<2
pystray>=0.19,<1
Pillow>=9.5,<13
```

## Step 7 — Install development dependencies

For testing and building AutoGuard, run:

```powershell
python -m pip install -r requirements-dev.txt
```

The development requirements include the normal application dependencies and PyInstaller.

## Step 8 — Run AutoGuard

From the AutoGuard project root, run:

```powershell
python main.py
```

`main.py` is the application's entry point. It initializes the application configuration, database, signatures, scanner, monitoring services, scheduler, notifications, and desktop interface.

The AutoGuard window should open.

---

# Running AutoGuard with a Specific File or Folder

You can provide a file or folder when starting the application.

### Scan a folder

```powershell
python main.py "C:\Users\YourName\Downloads"
```

### Scan a file

```powershell
python main.py "C:\Users\YourName\Downloads\example.exe"
```

The supplied path is scanned after the AutoGuard interface opens.

---

# Optional Run Settings

The application supports additional command-line options.

## Disable Real-Time Protection

```powershell
python main.py --no-file-monitor
```

## Disable USB Protection

```powershell
python main.py --no-usb-monitor
```

## Disable Scheduled Scanning

```powershell
python main.py --no-scheduler
```

## Disable the Startup Scan

```powershell
python main.py --no-startup-scan
```

## Disable Windows Notifications

```powershell
python main.py --no-windows-notifications
```

## Disable the System Tray

```powershell
python main.py --no-system-tray
```

## Start AutoGuard Hidden in the System Tray

```powershell
python main.py --start-hidden
```

These options are implemented by `main.py`.

---

# Running Tests

AutoGuard includes a test suite in:

```text
tests/
```

The project contains tests covering scanning, detection, quarantine, recovery, scheduling, monitoring, USB handling, notifications, UI behavior, threat tracking, reports, and integration behavior.

## Step 1 — Make sure the virtual environment is active

```powershell
.\.venv\Scripts\Activate.ps1
```

## Step 2 — Run all tests

```powershell
python -m pytest -q
```

## Step 3 — Run tests with detailed output

```powershell
python -m pytest
```

---

# Building AutoGuard.exe

PyInstaller is configured through:

```text
AutoGuard.spec
```

## Step 1 — Install development dependencies

```powershell
python -m pip install -r requirements-dev.txt
```

## Step 2 — Build the executable

Run:

```powershell
python -m PyInstaller --clean --noconfirm AutoGuard.spec
```

## Step 3 — Find the executable

After a successful build:

```text
dist/
└── AutoGuard.exe
```

The project also contains a prebuilt executable at:

```text
dist/AutoGuard.exe
```

---

# Building the Full Windows Release

AutoGuard includes a PowerShell release script:

```text
build_release.ps1
```

The script can run the tests, build the executable, and build the Windows installer when the required Inno Setup version is available.

## Step 1 — Open PowerShell

Navigate to the AutoGuard project directory:

```powershell
cd C:\path\to\AutoGuard
```

## Step 2 — Run the release script

```powershell
.\build_release.ps1
```

The script performs the release process automatically.

## Step 3 — Find the generated executable

The executable will be created at:

```text
dist/
└── AutoGuard.exe
```

## Step 4 — Find the generated installer

When Inno Setup is installed and supported, the installer will be created at:

```text
dist/
└── installer/
    └── AutoGuard-Setup-1.0.0.exe
```

The release script checks for Inno Setup 6.7 or newer before building the themed installer.

---

# Build Only the Executable

To build the `.exe` while skipping installer creation:

```powershell
.\build_release.ps1 -ExeOnly
```

---

# Skip Tests During the Release Build

To skip the test stage:

```powershell
.\build_release.ps1 -SkipTests
```

The normal release process runs the tests before building the executable.

---

# Default Monitored Locations

AutoGuard's default monitored locations include:

```text
Downloads
Desktop
Documents
Known removable drives
```

These locations are used by the protection and cleanup services.

---

# Application Data

During normal operation, AutoGuard creates:

```text
%USERPROFILE%\AutoGuardData
```

Inside this directory:

```text
AutoGuardData/
├── database/
│   └── autoguard.db
├── quarantine/
└── logs/
```

The application creates these directories automatically when AutoGuard starts.

---

# Quick Start

For someone who already has Python installed:

```powershell
cd C:\path\to\AutoGuard

python -m venv .venv

.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip

python -m pip install -r requirements.txt

python main.py
```

For a normal end-user installation:

```text
1. Open dist\installer
2. Double-click AutoGuard-Setup-1.0.0.exe
3. Follow the Setup Wizard
4. Accept the license
5. Choose the installation location
6. Choose additional tasks
7. Click Install
8. Click Finish
9. Launch AutoGuard
```

---

# Important Security Note

AutoGuard uses configured signatures and heuristic detection rules to evaluate supported files.

A result such as:

```text
No threats detected
```

does not guarantee that a file is completely safe or that every possible malicious file will be detected.

AutoGuard should therefore be considered a security project and protection tool rather than a replacement for a comprehensive commercial antivirus solution. The project's license also explicitly states that no security product can guarantee detection of every malicious, unsafe, or unwanted file.
